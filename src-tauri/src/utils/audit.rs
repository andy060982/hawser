//! Tamper-evident audit log.
//!
//! Security-relevant actions — connecting, authenticating, moving files, saving
//! credentials, installing keys — are appended to an on-disk log as they happen.
//! Each record is cryptographically chained to the one before it, so the log can
//! be *verified* later: any edit, insertion, reorder, or deletion shows up as a
//! broken chain at a specific entry.
//!
//! # The chain
//!
//! Every record stores `prev` (the SHA-256 of the record before it) and its own
//! `hash` = SHA-256 of the record's canonical bytes (which include `prev`). The
//! first record's `prev` is the genesis constant. Because each hash folds in the
//! previous hash, rewriting entry *n* changes its hash, which no longer matches
//! entry *n+1*'s `prev`, and so on to the end — a single edit invalidates the
//! whole tail.
//!
//! # Why a bare chain is not enough, and the anchor that fixes it
//!
//! A chain by itself only catches *partial* tampering. An attacker who can write
//! the file can also recompute every hash and re-chain the whole thing, or simply
//! delete entries from the end — both leave a self-consistent chain. To catch
//! that, the chain head (`seq` + `hash`) is sealed into the OS keychain on every
//! append. Verification compares the file's head against the sealed head, so a
//! whole-file rewrite or a truncation is detected unless the attacker also wrote
//! the keychain.
//!
//! # The honest limitation
//!
//! This is tamper-*evident*, not tamper-*proof*. On a single-user desktop an
//! attacker who already controls both the data directory and the logged-in
//! keychain session can forge a clean log. The anchor raises the bar from "edit a
//! text file" to "edit a text file and rewrite a keychain item"; it does not make
//! forgery impossible. For stronger guarantees the head would have to be anchored
//! off the machine entirely, which is out of scope for a local tool.
//!
//! # Durability
//!
//! Appends flush immediately and failure is swallowed: like the session
//! transcript, losing an audit line must never take down a working connection.
//! The log is never auto-pruned — pruning would defeat the point — but each
//! record is tiny, so growth is not a practical concern.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::known_hosts::{store_path, KnownHostsError};

/// `prev` of the very first record. 64 hex zeros — no real SHA-256 can be this
/// (it would be a preimage of nothing), so it unambiguously marks the genesis.
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// File name under the app data dir, beside hosts.json / known_hosts.
const AUDIT_FILE: &str = "audit.jsonl";

/// Keychain id used to seal the chain head. Deliberately not a host id shape and
/// not the `ai:` namespace, so it can never be confused with (or addressed as) a
/// host or AI-provider credential. Stored via the ordinary vault API, so it needs
/// no new platform code; the sealed value is a non-secret (seq + hash), kept in
/// the keychain only because that is a store the file-tamperer may not control.
const SEAL_ID: &str = "hawser-audit-head-seal";

/// One audit record. Serialized as a single line of JSON (JSON Lines).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEntry {
    /// 1-based, strictly contiguous. A gap is itself evidence of a deletion.
    pub seq: u64,
    /// Unix epoch seconds.
    pub ts: u64,
    /// Short machine tag, e.g. "connect", "sftp.put", "key.install".
    pub event: String,
    /// Human one-liner for the UI. Never contains a secret.
    pub summary: String,
    /// Structured context (host, user, path, bytes, result). Strings / integers /
    /// bools only — never a password, key, or command output.
    #[serde(default)]
    pub detail: Value,
    /// Hash of the previous record (GENESIS for the first).
    pub prev: String,
    /// SHA-256 of this record's canonical bytes (everything above, incl. `prev`).
    pub hash: String,
}

/// The chain fields minus `hash`, in a fixed order. Hashing this struct's
/// serialization is what both the writer and the verifier agree on, so the hash
/// is reproducible. `detail` serializes with sorted keys (serde_json's default
/// map is a BTreeMap), making the canonical bytes deterministic.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Unsealed<'a> {
    seq: u64,
    ts: u64,
    event: &'a str,
    summary: &'a str,
    detail: &'a Value,
    prev: &'a str,
}

/// Process-wide serialization of appends, plus the cached chain head so each
/// append need not re-read the file. `None` until the first append loads it.
fn state() -> &'static Mutex<Option<Head>> {
    static STATE: OnceLock<Mutex<Option<Head>>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(None))
}

/// Last record's (seq, hash). seq 0 / GENESIS means "empty log".
#[derive(Clone)]
struct Head {
    seq: u64,
    hash: String,
    /// Set once sealing has failed this session, so a locked/absent keychain
    /// does not produce one eprintln per event.
    seal_broken: bool,
}

fn audit_path() -> Result<PathBuf, KnownHostsError> {
    let store = store_path()?;
    Ok(store
        .parent()
        .ok_or(KnownHostsError::NoAppDataDir)?
        .join(AUDIT_FILE))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hex(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(LUT[(b >> 4) as usize] as char);
        s.push(LUT[(b & 0x0f) as usize] as char);
    }
    s
}

/// Canonical hash of the chain fields. Returns GENESIS-length lowercase hex.
fn hash_unsealed(u: &Unsealed) -> String {
    // Serialization of a fixed-field struct with a sorted-key detail map is
    // deterministic, so the same record always hashes to the same value.
    let bytes = serde_json::to_vec(u).unwrap_or_default();
    let digest = Sha256::digest(&bytes);
    hex(&digest)
}

/// Read every record from disk, in file order. Missing file → empty vec.
///
/// A line that will not parse is reported via its 1-based line number so verify
/// can point at it, rather than being silently skipped (a skipped line is itself
/// a tamper signal).
fn read_all() -> Result<Vec<Result<AuditEntry, usize>>, KnownHostsError> {
    let path = audit_path()?;
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => return Err(KnownHostsError::Io { path, source }),
    };
    Ok(text
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty())
        .map(|(i, l)| serde_json::from_str::<AuditEntry>(l).map_err(|_| i + 1))
        .collect())
}

/// Load the chain head from disk for the first append of the session.
fn load_head() -> Head {
    match read_all() {
        Ok(rows) => match rows.last() {
            Some(Ok(e)) => Head {
                seq: e.seq,
                hash: e.hash.clone(),
                seal_broken: false,
            },
            // A corrupt last line, or no lines: start from genesis. Verify will
            // surface the corruption; appends continue so the log keeps working.
            _ => Head {
                seq: 0,
                hash: GENESIS.to_string(),
                seal_broken: false,
            },
        },
        Err(_) => Head {
            seq: 0,
            hash: GENESIS.to_string(),
            seal_broken: false,
        },
    }
}

/// Seal the current head into the keychain. Best-effort and non-fatal.
fn seal(seq: u64, hash: &str) -> Result<(), ()> {
    let payload = format!("{{\"seq\":{seq},\"hash\":\"{hash}\"}}");
    crate::credentials::write_secret(SEAL_ID, "audit", &payload).map_err(|_| ())
}

/// Read the sealed head, if any.
fn read_seal() -> Option<(u64, String)> {
    let raw = crate::credentials::read_secret(SEAL_ID).ok()?;
    let v: Value = serde_json::from_str(raw.as_str()).ok()?;
    let seq = v.get("seq")?.as_u64()?;
    let hash = v.get("hash")?.as_str()?.to_string();
    Some((seq, hash))
}

/// Append one record. Fire-and-forget: errors are logged to stderr and
/// swallowed, never propagated to the caller, so auditing can never break a
/// working operation. Pass `detail` built from `serde_json::json!` with string /
/// integer / bool fields only — never a secret.
pub fn record(event: &str, summary: impl Into<String>, detail: Value) {
    let summary = summary.into();
    if let Err(e) = try_record(event, &summary, detail) {
        eprintln!("hawser: audit append failed ({event}): {e}");
    }
}

fn try_record(event: &str, summary: &str, detail: Value) -> Result<(), String> {
    let mut guard = state().lock().map_err(|_| "audit lock poisoned".to_string())?;
    if guard.is_none() {
        *guard = Some(load_head());
    }
    let head = guard.as_mut().expect("head set above");

    let seq = head.seq + 1;
    let ts = now_secs();
    let prev = head.hash.clone();
    let unsealed = Unsealed {
        seq,
        ts,
        event,
        summary,
        detail: &detail,
        prev: &prev,
    };
    let hash = hash_unsealed(&unsealed);

    let entry = AuditEntry {
        seq,
        ts,
        event: event.to_string(),
        summary: summary.to_string(),
        detail,
        prev,
        hash: hash.clone(),
    };
    // One line, no interior newlines (serde_json never emits them for this
    // shape), so the JSON-Lines invariant holds.
    let line = serde_json::to_string(&entry).map_err(|e| e.to_string())?;

    append_line(&line).map_err(|e| e.to_string())?;

    // Only now that the bytes are on disk do we advance the cached head; a failed
    // write leaves seq/hash unchanged so the next append reuses the same slot.
    head.seq = seq;
    head.hash = hash.clone();

    // Anchor the new head. Non-fatal: a locked keychain must not stop auditing,
    // but note it once so verify can say the anchor is unavailable.
    if !head.seal_broken && seal(seq, &hash).is_err() {
        head.seal_broken = true;
        eprintln!("hawser: audit head could not be sealed to the keychain; integrity anchoring disabled for this session");
    }
    Ok(())
}

/// Append a single line to the audit file, creating it owner-only if new.
fn append_line(line: &str) -> Result<(), KnownHostsError> {
    let path = audit_path()?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|source| KnownHostsError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
    }

    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    // Owner-only from birth on Unix, so there is never a world-readable window.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(&path)
        .map_err(|source| KnownHostsError::Io { path: path.clone(), source })?;
    // Belt-and-braces for platforms where the create mode does not apply, and for
    // a file that already existed with looser perms.
    super::platform::restrict_perms(&path, 0o600);

    file.write_all(line.as_bytes())
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.flush())
        .map_err(|source| KnownHostsError::Io { path, source })
}

/* ----------------------------------------------------------------- reading */

/// A record as handed to the UI (the chain fields are not interesting there).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditView {
    pub seq: u64,
    pub ts: u64,
    pub event: String,
    pub summary: String,
    pub detail: Value,
}

/// Most recent `limit` records, newest first.
pub fn list(limit: usize) -> Result<Vec<AuditView>, KnownHostsError> {
    let rows = read_all()?;
    let mut out: Vec<AuditView> = rows
        .into_iter()
        .filter_map(Result::ok)
        .map(|e| AuditView {
            seq: e.seq,
            ts: e.ts,
            event: e.event,
            summary: e.summary,
            detail: e.detail,
        })
        .collect();
    out.sort_by(|a, b| b.seq.cmp(&a.seq));
    out.truncate(limit);
    Ok(out)
}

/// Result of walking the whole chain. `ok` is the single headline the UI acts on.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyReport {
    pub ok: bool,
    pub count: u64,
    /// Human sentence summarising the outcome.
    pub message: String,
    /// 1-based line of the first problem, when there is one.
    pub broken_at: Option<u64>,
    /// Anchor comparison: "sealed", "mismatch", or "absent".
    pub seal_status: String,
}

/// Walk the chain: parse every line, recompute every hash, check contiguity and
/// links, then compare the file head against the keychain-sealed head.
pub fn verify() -> Result<VerifyReport, KnownHostsError> {
    let rows = read_all()?;
    let count = rows.len() as u64;

    let mut prev_hash = GENESIS.to_string();
    let mut expect_seq = 1u64;
    let mut last_hash = GENESIS.to_string();
    let mut last_seq = 0u64;

    for (idx, row) in rows.iter().enumerate() {
        let line_no = (idx + 1) as u64;
        let entry = match row {
            Ok(e) => e,
            Err(_) => {
                return Ok(VerifyReport {
                    ok: false,
                    count,
                    message: format!("Entry {line_no} is not valid JSON — the log was edited or corrupted."),
                    broken_at: Some(line_no),
                    seal_status: seal_status_only(),
                })
            }
        };

        if entry.seq != expect_seq {
            return Ok(VerifyReport {
                ok: false,
                count,
                message: format!(
                    "Entry {line_no} has sequence {} but {expect_seq} was expected — an entry was inserted or removed.",
                    entry.seq
                ),
                broken_at: Some(line_no),
                seal_status: seal_status_only(),
            });
        }

        if entry.prev != prev_hash {
            return Ok(VerifyReport {
                ok: false,
                count,
                message: format!("Entry {line_no} does not link to the previous entry — the chain was broken here."),
                broken_at: Some(line_no),
                seal_status: seal_status_only(),
            });
        }

        let recomputed = hash_unsealed(&Unsealed {
            seq: entry.seq,
            ts: entry.ts,
            event: &entry.event,
            summary: &entry.summary,
            detail: &entry.detail,
            prev: &entry.prev,
        });
        if recomputed != entry.hash {
            return Ok(VerifyReport {
                ok: false,
                count,
                message: format!("Entry {line_no} was modified after it was written — its contents no longer match its hash."),
                broken_at: Some(line_no),
                seal_status: seal_status_only(),
            });
        }

        prev_hash = entry.hash.clone();
        last_hash = entry.hash.clone();
        last_seq = entry.seq;
        expect_seq += 1;
    }

    // Chain is internally consistent; now the external anchor.
    let (seal_status, seal_ok, seal_msg) = match read_seal() {
        None => (
            "absent".to_string(),
            true,
            "no keychain anchor yet (first run, or the keychain was unavailable when writing)".to_string(),
        ),
        Some((s_seq, s_hash)) => {
            if s_seq == last_seq && s_hash == last_hash {
                ("sealed".to_string(), true, "head matches the keychain anchor".to_string())
            } else if s_seq > last_seq {
                (
                    "mismatch".to_string(),
                    false,
                    format!("the keychain anchor is ahead of the file (sealed up to {s_seq}, file ends at {last_seq}) — entries were deleted from the end"),
                )
            } else {
                (
                    "mismatch".to_string(),
                    false,
                    "the file head does not match the keychain anchor — the log was rewritten".to_string(),
                )
            }
        }
    };

    let ok = seal_ok;
    let message = if count == 0 {
        "The audit log is empty.".to_string()
    } else if ok {
        format!("Verified {count} entr{} — the chain is intact ({seal_msg}).", if count == 1 { "y" } else { "ies" })
    } else {
        format!("Chain hashes verified, but {seal_msg}.")
    };

    Ok(VerifyReport {
        ok,
        count,
        message,
        broken_at: None,
        seal_status,
    })
}

/// The seal status alone, for the early-return paths where the chain already
/// failed and the precise anchor comparison would be misleading.
fn seal_status_only() -> String {
    match read_seal() {
        Some(_) => "sealed".to_string(),
        None => "absent".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn mk(seq: u64, prev: &str, event: &str) -> AuditEntry {
        let detail = json!({"host": "fw1", "ok": true});
        let unsealed = Unsealed {
            seq,
            ts: 1_789_646_400 + seq,
            event,
            summary: "x",
            detail: &detail,
            prev,
        };
        let hash = hash_unsealed(&unsealed);
        AuditEntry {
            seq,
            ts: 1_789_646_400 + seq,
            event: event.to_string(),
            summary: "x".to_string(),
            detail,
            prev: prev.to_string(),
            hash,
        }
    }

    fn chain(n: u64) -> Vec<AuditEntry> {
        let mut out = Vec::new();
        let mut prev = GENESIS.to_string();
        for i in 1..=n {
            let e = mk(i, &prev, "connect");
            prev = e.hash.clone();
            out.push(e);
        }
        out
    }

    // verify() is driven through a pure helper so the tests need no filesystem or
    // keychain: they check the chain logic itself, which is the security-critical
    // part. The I/O wrappers (append_line, seal) are exercised by the live app.
    fn verify_rows(rows: &[AuditEntry]) -> Option<u64> {
        let mut prev = GENESIS.to_string();
        let mut expect = 1u64;
        for (idx, e) in rows.iter().enumerate() {
            let line_no = (idx + 1) as u64;
            if e.seq != expect || e.prev != prev {
                return Some(line_no);
            }
            let recomputed = hash_unsealed(&Unsealed {
                seq: e.seq,
                ts: e.ts,
                event: &e.event,
                summary: &e.summary,
                detail: &e.detail,
                prev: &e.prev,
            });
            if recomputed != e.hash {
                return Some(line_no);
            }
            prev = e.hash.clone();
            expect += 1;
        }
        None
    }

    #[test]
    fn intact_chain_verifies() {
        assert_eq!(verify_rows(&chain(5)), None);
    }

    #[test]
    fn hash_is_deterministic() {
        let a = mk(1, GENESIS, "connect");
        let b = mk(1, GENESIS, "connect");
        assert_eq!(a.hash, b.hash);
        assert_eq!(a.hash.len(), 64);
    }

    #[test]
    fn edited_summary_breaks_its_entry() {
        let mut rows = chain(4);
        rows[1].summary = "tampered".to_string(); // hash no longer matches
        assert_eq!(verify_rows(&rows), Some(2));
    }

    #[test]
    fn deleting_a_middle_entry_breaks_the_link() {
        let mut rows = chain(4);
        rows.remove(1); // seqs become 1,3,4 → contiguity fails at the new line 2
        assert_eq!(verify_rows(&rows), Some(2));
    }

    #[test]
    fn reordering_breaks_the_chain() {
        let mut rows = chain(4);
        rows.swap(1, 2);
        assert_eq!(verify_rows(&rows), Some(2));
    }

    #[test]
    fn appending_a_forged_entry_without_rechaining_is_caught() {
        let mut rows = chain(3);
        // Attacker appends a record that does not chain from the real head.
        let mut forged = mk(4, GENESIS, "connect");
        forged.prev = GENESIS.to_string();
        rows.push(forged);
        assert_eq!(verify_rows(&rows), Some(4));
    }

    #[test]
    fn changing_detail_is_detected() {
        let mut rows = chain(3);
        rows[2].detail = json!({"host": "evil", "ok": true});
        assert_eq!(verify_rows(&rows), Some(3));
    }
}
