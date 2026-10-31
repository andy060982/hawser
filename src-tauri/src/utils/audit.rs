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
//! # The anchor, and why the file is never trusted on its own
//!
//! A chain by itself only catches *partial* tampering: whoever can write the
//! file can also re-hash the whole thing, or cut entries off the end, and leave a
//! self-consistent chain. So the chain head (`seq` + `hash`) is sealed into the OS
//! keychain after every append, under a reserved vault id (`hawser:audit-head`)
//! that no host or credential command can address.
//!
//! The file is only ever extended after it has been reconciled against that seal
//! (see [`reconcile`]). If the two disagree, the seal is replaced by a
//! permanent "frozen" marker and the app keeps recording without ever sealing
//! again, so every later verify fails, even if the original file is put back.
//! Otherwise a file-only attacker could truncate or rewrite the log, wait for
//! the next legitimate event, and have the app seal the forged history for them.
//! The only way out is "archive": the log is set aside (never deleted) and the
//! new log's first, anchored record pins it by SHA-256, so the archive itself
//! stays tamper-evident.
//!
//! Entries that exist on disk but were never anchored (the app stopped between
//! the file write and the seal, the keychain refused a write, or there was no
//! seal at all) cannot be vouched for. Before anchoring resumes, an explicit
//! `audit.unanchored` record naming them is appended. Verify then reports a
//! warning, never a clean pass, until the user archives the log and starts fresh.
//!
//! # The honest limitations
//!
//! This is tamper-*evident*, not tamper-*proof*:
//! - Anyone who controls both the data directory and the logged-in keychain can
//!   forge a clean log.
//! - Records written while the seal cannot be updated (keychain locked, or just
//!   before a crash) can be cut off the end without a failure; verify reports
//!   them as not vouched for while they exist, but cannot miss what is gone.
//! - The app assumes a single running instance. Two instances writing the same
//!   log would race on `seq` and produce a (false) failed verify.
//! - Each append writes the keychain synchronously; a keychain that prompts
//!   (e.g. after a macOS keychain lock) delays the audited command until it is
//!   answered.
//! - Deleting *both* the file and the seal is indistinguishable from a first
//!   run. Detecting that needs a witness that lives off the machine, which is out
//!   of scope for a local tool. Verify reports this state as "empty", not
//!   "verified".
//!
//! # What is (and is not) recorded
//!
//! Records hold metadata: host, port, user, paths, byte counts, outcome. The app
//! never deliberately writes passwords, key material, command text, or command
//! output. Paths, usernames, and error messages are stored as given, capped in
//! length. They are not normally secret, but nothing here can guarantee that. Public
//! keys are recorded by fingerprint, not by their (free-text) comment.
//!
//! # Durability
//!
//! Each append is one `write` of the whole line, followed by `fsync`. A failed
//! write is rolled back to the previous length where the platform allows it. A
//! torn final line left by a crash is dropped at the next start, and that is
//! recorded in the log. Auditing never fails the operation being audited:
//! errors go to stderr and are swallowed.
//!
//! On Unix the file is created 0600 and its directory restricted to 0700. On
//! Windows both inherit the per-user `%APPDATA%` ACL; no extra ACL is applied.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::known_hosts::{store_path, KnownHostsError};

/// `prev` of the very first record. 64 hex zeros — no real SHA-256 can be this
/// (it would be a preimage of nothing), so it unambiguously marks the genesis.
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// File name under the app data dir, beside hosts.json / known_hosts.
const AUDIT_FILE: &str = "audit.jsonl";

/// Vault id of the sealed chain head. Lives in the reserved `hawser:` namespace,
/// which `credentials::is_reserved_id` refuses everywhere a host or credential id
/// is accepted (save / status / delete / bind / migrate / connect), so nothing
/// reachable from the UI can overwrite or delete it.
pub const SEAL_ID: &str = "hawser:audit-head";

/// Longest string kept in a record's summary or detail. Long enough for any real
/// path or error message, short enough that a pasted blob cannot bloat the log.
const MAX_FIELD: usize = 512;

/// Event tag of the record noting entries that were written without an anchor.
const EV_UNANCHORED: &str = "audit.unanchored";
/// Event tag of the record noting a discarded incomplete trailing line.
const EV_TORN: &str = "audit.torn";
/// Event tag recorded when the startup check found the log does not match its anchor.
const EV_INTEGRITY: &str = "audit.integrity_failed";
/// Event tag that opens a fresh log after the old one was archived.
const EV_ARCHIVED: &str = "audit.archived";

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
    /// Human one-liner for the UI.
    pub summary: String,
    /// Flat map of strings / integers / bools / nulls (see [`sanitize`]).
    #[serde(default)]
    pub detail: BTreeMap<String, Value>,
    /// Hash of the previous record (GENESIS for the first).
    pub prev: String,
    /// SHA-256 of this record's canonical bytes (everything above, incl. `prev`).
    pub hash: String,
}

/// The chain fields minus `hash`, in a fixed order. Hashing this struct's
/// serialization is what both the writer and the verifier agree on. `detail` is
/// a `BTreeMap` of primitives, so its keys serialize sorted no matter how the
/// caller built it or which serde_json features are enabled.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Unsealed<'a> {
    seq: u64,
    ts: u64,
    event: &'a str,
    summary: &'a str,
    detail: &'a BTreeMap<String, Value>,
    prev: &'a str,
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
    let bytes = serde_json::to_vec(u).unwrap_or_default();
    hex(&Sha256::digest(&bytes))
}

fn hash_entry(e: &AuditEntry) -> String {
    hash_unsealed(&Unsealed {
        seq: e.seq,
        ts: e.ts,
        event: &e.event,
        summary: &e.summary,
        detail: &e.detail,
        prev: &e.prev,
    })
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Cut `s` to at most [`MAX_FIELD`] bytes on a char boundary.
fn cap(mut s: String) -> String {
    if s.len() > MAX_FIELD {
        let mut end = MAX_FIELD;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
        s.push('…');
    }
    s
}

/// Flatten caller-supplied detail into the only shape the canonical hash relies
/// on: a sorted map of strings, integers, bools, and nulls. Floats, arrays, and
/// nested objects are stored as their JSON text; a non-object becomes `value`.
/// Strings are length-capped.
fn sanitize(detail: Value) -> BTreeMap<String, Value> {
    let prim = |v: Value| -> Value {
        match v {
            Value::String(s) => Value::String(cap(s)),
            Value::Number(n) if n.is_i64() || n.is_u64() => Value::Number(n),
            v @ (Value::Bool(_) | Value::Null) => v,
            other => Value::String(cap(other.to_string())),
        }
    };
    match detail {
        Value::Object(map) => map.into_iter().map(|(k, v)| (k, prim(v))).collect(),
        Value::Null => BTreeMap::new(),
        other => BTreeMap::from([("value".to_string(), prim(other))]),
    }
}

/// OpenSSH-style `SHA256:…` fingerprint of a public-key line, for logging a key
/// without its free-text comment. Falls back to a marker if the line won't parse.
pub fn key_fingerprint(public_line: &str) -> String {
    russh::keys::PublicKey::from_openssh(public_line.trim())
        .map(|k| k.fingerprint(russh::keys::HashAlg::Sha256).to_string())
        .unwrap_or_else(|_| "unparseable-key".to_string())
}

/* ------------------------------------------------------------------ anchor */

/// What reading the sealed head produced. The four cases are kept apart because
/// they mean very different things for integrity.
#[derive(Debug, Clone, PartialEq)]
enum SealRead {
    /// No seal has ever been written (or it was removed).
    Absent,
    /// The vault could not be read right now (locked, no backend, …).
    Unavailable,
    /// Something is stored there but it is not a head we wrote.
    Malformed,
    Present(u64, String),
    /// A startup check failed earlier and the anchor was frozen with this
    /// reason. Permanent until the log is archived: restoring the original file
    /// later must not turn a failed log back into a verified one.
    Frozen(String),
}

/// Where the chain head is sealed. The keychain in the app; an in-memory stand-in
/// in tests, so the production append / verify / restart paths can be exercised.
trait Anchor: Send + Sync {
    fn read(&self) -> SealRead;
    fn write(&self, seq: u64, hash: &str) -> Result<(), String>;
    /// Replace the head with a permanent "integrity failed" marker.
    fn freeze(&self, reason: &str) -> Result<(), String>;
    fn clear(&self) -> Result<(), String>;
}

fn seal_payload(seq: u64, hash: &str) -> String {
    format!("{{\"seq\":{seq},\"hash\":\"{hash}\"}}")
}

fn frozen_payload(reason: &str) -> String {
    serde_json::json!({ "frozen": cap(reason.to_string()) }).to_string()
}

fn parse_seal(raw: &str) -> SealRead {
    let Ok(v) = serde_json::from_str::<Value>(raw) else {
        return SealRead::Malformed;
    };
    if let Some(r) = v.get("frozen").and_then(Value::as_str) {
        return SealRead::Frozen(r.to_string());
    }
    match (
        v.get("seq").and_then(Value::as_u64),
        v.get("hash").and_then(Value::as_str),
    ) {
        (Some(seq), Some(h)) if h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()) => {
            SealRead::Present(seq, h.to_string())
        }
        _ => SealRead::Malformed,
    }
}

struct Keychain;

impl Anchor for Keychain {
    fn read(&self) -> SealRead {
        use crate::credentials::{read_secret, CredError};
        match read_secret(SEAL_ID) {
            Ok(raw) => parse_seal(raw.as_str()),
            Err(CredError::NotFound(_)) => SealRead::Absent,
            Err(_) => SealRead::Unavailable,
        }
    }
    fn write(&self, seq: u64, hash: &str) -> Result<(), String> {
        crate::credentials::write_secret(SEAL_ID, "audit", &seal_payload(seq, hash))
            .map_err(|e| e.to_string())
    }
    fn freeze(&self, reason: &str) -> Result<(), String> {
        crate::credentials::write_secret(SEAL_ID, "audit", &frozen_payload(reason))
            .map_err(|e| e.to_string())
    }
    fn clear(&self) -> Result<(), String> {
        use crate::credentials::{delete_secret, CredError};
        match delete_secret(SEAL_ID) {
            Ok(()) | Err(CredError::NotFound(_)) => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }
}

/* ------------------------------------------------------------ chain + seal */

/// The result of walking the file: either every record's hash in order, or the
/// first break.
struct Chain {
    /// `hashes[i]` is the hash of record seq `i + 1`. Only valid up to a break.
    hashes: Vec<String>,
    /// The first problem, as (1-based line, sentence), if the chain is broken.
    broken: Option<(u64, String)>,
    /// `audit.unanchored` / `audit.torn` / `audit.integrity_failed` records seen.
    notes: Vec<String>,
    /// The last parseable record, for continuing a log that is already broken.
    last: Option<(u64, String)>,
}

impl Chain {
    fn tip(&self) -> (u64, &str) {
        match self.hashes.last() {
            Some(h) => (self.hashes.len() as u64, h.as_str()),
            None => (0, GENESIS),
        }
    }
}

/// Recompute every hash and check contiguity and links.
fn walk(rows: &[Result<AuditEntry, usize>]) -> Chain {
    let mut c = Chain {
        hashes: Vec::new(),
        broken: None,
        notes: Vec::new(),
        last: None,
    };
    let mut prev = GENESIS.to_string();
    for (idx, row) in rows.iter().enumerate() {
        let line = (idx + 1) as u64;
        let e = match row {
            Ok(e) => e,
            Err(_) => {
                c.broken.get_or_insert((line, format!("Entry {line} is not a record as the app writes it — the log was edited or corrupted.")));
                continue;
            }
        };
        c.last = Some((e.seq, e.hash.clone()));
        if c.broken.is_some() {
            continue;
        }
        let expect = c.hashes.len() as u64 + 1;
        let problem = if e.seq != expect {
            Some(format!(
                "Entry {line} has sequence {} but {expect} was expected — an entry was inserted or removed.",
                e.seq
            ))
        } else if e.prev != prev {
            Some(format!("Entry {line} does not link to the previous entry — the chain was broken here."))
        } else if hash_entry(e) != e.hash {
            Some(format!("Entry {line} was modified after it was written — its contents no longer match its hash."))
        } else {
            None
        };
        if let Some(p) = problem {
            c.broken = Some((line, p));
            continue;
        }
        if matches!(e.event.as_str(), EV_UNANCHORED | EV_TORN | EV_INTEGRITY) {
            c.notes.push(e.summary.clone());
        }
        prev = e.hash.clone();
        c.hashes.push(e.hash.clone());
    }
    c
}

/// How the file stands against the seal. Shared by the writer (deciding whether
/// it may anchor) and by verify (deciding what to report), so the two can never
/// disagree.
#[derive(Debug, PartialEq)]
enum Decision {
    /// File head is exactly the sealed head (or both are empty).
    Anchored,
    /// The sealed head is an earlier record of this same chain, or there is no
    /// seal at all: records `from..=to` exist but were never anchored.
    Unanchored { from: u64, to: u64, why: &'static str },
    /// File and seal disagree, the chain is broken, or the seal is junk. The
    /// writer must never re-seal over this.
    Mismatch(String),
    /// The seal could not be read; nothing can be concluded yet.
    Unknown,
}

fn reconcile(chain: &Chain, seal: &SealRead) -> Decision {
    if let Some((_, msg)) = &chain.broken {
        return Decision::Mismatch(msg.clone());
    }
    let (n, tip) = chain.tip();
    match seal {
        SealRead::Unavailable => Decision::Unknown,
        SealRead::Frozen(r) => Decision::Mismatch(format!(
            "an earlier integrity check failed ({r}); this log stays failed until it is archived"
        )),
        SealRead::Malformed => {
            Decision::Mismatch("the keychain anchor holds data the app did not write".to_string())
        }
        SealRead::Absent if n == 0 => Decision::Anchored,
        SealRead::Absent => Decision::Unanchored {
            from: 1,
            to: n,
            why: "there was no keychain anchor",
        },
        SealRead::Present(s, h) => {
            let s = *s;
            if s == n && h == tip {
                Decision::Anchored
            } else if s > n {
                Decision::Mismatch(format!(
                    "the keychain anchor is ahead of the file (sealed up to entry {s}, file ends at {n}) — entries were deleted from the end"
                ))
            } else if s >= 1 && chain.hashes[(s - 1) as usize] == *h {
                Decision::Unanchored {
                    from: s + 1,
                    to: n,
                    why: "they were written after the last anchored entry (an interrupted shutdown or a failed keychain write)",
                }
            } else {
                Decision::Mismatch(
                    "the file does not match the keychain anchor — the log was rewritten".to_string(),
                )
            }
        }
    }
}

/* ------------------------------------------------------------------ writer */

/// Whether this process may move the anchor forward.
#[derive(Debug, Clone, PartialEq)]
enum Mode {
    /// The on-disk chain was reconciled with the seal; every record since was
    /// written by us. Each append re-seals (and retries after a failed seal).
    Trusted,
    /// The startup check failed. Keep recording, never seal.
    Frozen,
    /// The seal could not be read at startup. Re-check before each append; do
    /// not seal until the check resolves.
    Pending,
}

struct Session {
    seq: u64,
    hash: String,
    mode: Mode,
    /// The chain as loaded at startup, for resolving a `Pending` check later.
    loaded: Option<Chain>,
    last_warn: Option<Instant>,
    /// A freeze marker that still has to reach the keychain (retried per append).
    freeze_pending: Option<String>,
}

struct Log<A: Anchor> {
    path: PathBuf,
    anchor: A,
    session: Mutex<Option<Session>>,
}

/// Read and parse every line. Missing file → empty. A line that does not parse,
/// or is not byte-for-byte what the app would have written for that record, is
/// kept as its 1-based line number so verify can point at it. The exact-bytes
/// rule matters: extra fields or duplicate keys parse fine but sit outside the
/// hash, so raw-file readers (grep, a SIEM) could be shown unverified text.
fn parse_text(text: &str) -> Vec<Result<AuditEntry, usize>> {
    text.lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty())
        .map(|(i, l)| {
            serde_json::from_str::<AuditEntry>(l)
                .ok()
                .filter(|e| serde_json::to_string(e).is_ok_and(|canon| canon == l))
                .ok_or(i + 1)
        })
        .collect()
}

fn io_err(path: &Path) -> impl FnOnce(std::io::Error) -> KnownHostsError + '_ {
    move |source| KnownHostsError::Io {
        path: path.to_path_buf(),
        source,
    }
}

impl<A: Anchor> Log<A> {
    fn new(path: PathBuf, anchor: A) -> Self {
        Self {
            path,
            anchor,
            session: Mutex::new(None),
        }
    }

    fn read_text(&self) -> Result<String, KnownHostsError> {
        match std::fs::read_to_string(&self.path) {
            Ok(t) => Ok(t),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
            Err(e) => Err(io_err(&self.path)(e)),
        }
    }

    /// Text minus an incomplete final line (no trailing newline, won't parse).
    /// Returns the kept text and whether a torn tail was found.
    fn split_torn(text: &str) -> (&str, bool) {
        if text.is_empty() || text.ends_with('\n') {
            return (text, false);
        }
        let cut = text.rfind('\n').map_or(0, |i| i + 1);
        if serde_json::from_str::<AuditEntry>(&text[cut..]).is_ok() {
            (text, false) // complete record, only its newline is missing
        } else {
            (&text[..cut], true)
        }
    }

    /// Append one line (newline included) in a single write, then fsync. On a
    /// failed write, roll the file back to its previous length.
    fn append_line(&self, line: &str) -> Result<(), KnownHostsError> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).map_err(io_err(dir))?;
            super::platform::restrict_perms(dir, 0o700);
        }
        let mut opts = OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&self.path).map_err(io_err(&self.path))?;
        super::platform::restrict_perms(&self.path, 0o600);

        let before = file.metadata().map(|m| m.len()).ok();
        let mut buf = String::with_capacity(line.len() + 1);
        buf.push_str(line);
        buf.push('\n');
        if let Err(e) = file.write_all(buf.as_bytes()) {
            if let Some(len) = before {
                let _ = file.set_len(len);
            }
            return Err(io_err(&self.path)(e));
        }
        file.sync_data().map_err(io_err(&self.path))
    }

    /// Replace the log's contents via a synced temp file + rename, so a crash
    /// mid-rewrite leaves either the old file or the new one, never a stub.
    fn replace_atomically(&self, text: &str) -> Result<(), KnownHostsError> {
        let tmp = self.path.with_extension("jsonl.tmp");
        let mut opts = OpenOptions::new();
        opts.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp).map_err(io_err(&tmp))?;
        f.write_all(text.as_bytes())
            .and_then(|_| f.sync_all())
            .map_err(io_err(&tmp))?;
        std::fs::rename(&tmp, &self.path).map_err(io_err(&self.path))
    }

    /// Load and reconcile the chain for the first append of the session. May
    /// rewrite the file once, to drop a torn tail, and may append notes.
    fn open_session(&self) -> Result<Session, KnownHostsError> {
        let text = self.read_text()?;
        let (kept, torn) = Self::split_torn(&text);
        if torn {
            self.replace_atomically(kept)?;
        } else if !text.is_empty() && !text.ends_with('\n') {
            // A complete record missing only its newline: finish the line.
            self.append_line("").ok();
        }
        let chain = walk(&parse_text(kept));
        let (seq, hash) = match (&chain.broken, chain.last.clone()) {
            (None, _) => {
                let (n, h) = chain.tip();
                (n, h.to_string())
            }
            (Some(_), Some(last)) => last,
            (Some(_), None) => (0, GENESIS.to_string()),
        };
        let mut s = Session {
            seq,
            hash,
            mode: Mode::Pending,
            loaded: None,
            last_warn: None,
            freeze_pending: None,
        };
        if torn {
            self.write_record(
                &mut s,
                EV_TORN,
                "an incomplete trailing entry left by an interrupted write was discarded",
                BTreeMap::new(),
            )?;
        }
        s.loaded = Some(chain);
        self.resolve(&mut s)?;
        Ok(s)
    }

    /// Settle a `Pending` session against the seal: trust it (writing an
    /// `audit.unanchored` note first if needed), freeze it, or leave it pending.
    fn resolve(&self, s: &mut Session) -> Result<(), KnownHostsError> {
        let Some(chain) = s.loaded.as_ref() else {
            return Ok(());
        };
        let seal = self.anchor.read();
        match reconcile(chain, &seal) {
            Decision::Unknown => return Ok(()),
            Decision::Anchored => s.mode = Mode::Trusted,
            Decision::Unanchored { from, to, why } => {
                let mut d = BTreeMap::new();
                d.insert("from".to_string(), Value::from(from));
                d.insert("to".to_string(), Value::from(to));
                let summary = if from == to {
                    format!("entry {from} cannot be vouched for: {why}")
                } else {
                    format!("entries {from}–{to} cannot be vouched for: {why}")
                };
                s.mode = Mode::Trusted;
                self.write_record(s, EV_UNANCHORED, &summary, d)?;
            }
            Decision::Mismatch(why) => {
                s.mode = Mode::Frozen;
                // Make the failure stick in the keychain (unless it already
                // is), so a later restore of the "right" file cannot verify.
                if !matches!(seal, SealRead::Frozen(_)) {
                    s.freeze_pending = Some(why.clone());
                }
                let mut d = BTreeMap::new();
                d.insert("reason".to_string(), Value::String(cap(why.clone())));
                self.write_record(
                    s,
                    EV_INTEGRITY,
                    &format!("startup integrity check failed: {why}; anchoring is disabled for this log"),
                    d,
                )?;
            }
        }
        s.loaded = None;
        Ok(())
    }

    /// Write one record at the session head, then seal it if trusted. The head
    /// only advances once the bytes are durably on disk.
    fn write_record(
        &self,
        s: &mut Session,
        event: &str,
        summary: &str,
        detail: BTreeMap<String, Value>,
    ) -> Result<(), KnownHostsError> {
        let mut e = AuditEntry {
            seq: s.seq + 1,
            ts: now_secs(),
            event: event.to_string(),
            summary: cap(summary.to_string()),
            detail,
            prev: s.hash.clone(),
            hash: String::new(),
        };
        e.hash = hash_entry(&e);
        // One line: serde_json never emits interior newlines for this shape.
        let line = serde_json::to_string(&e).unwrap_or_default();
        self.append_line(&line)?;
        s.seq = e.seq;
        s.hash = e.hash;

        if let Some(reason) = s.freeze_pending.as_deref() {
            if self.anchor.freeze(reason).is_ok() {
                s.freeze_pending = None;
            }
        }
        if s.mode == Mode::Trusted {
            if let Err(err) = self.anchor.write(s.seq, &s.hash) {
                // Retry on the next append; just don't spam stderr meanwhile.
                // (Not `is_none_or`: that needs Rust 1.82; MSRV is 1.77.)
                let due = !matches!(s.last_warn, Some(t) if t.elapsed() <= Duration::from_secs(60));
                if due {
                    s.last_warn = Some(Instant::now());
                    eprintln!("hawser: audit head could not be sealed to the keychain ({err}); will retry on the next entry");
                }
            }
        }
        Ok(())
    }

    fn record(&self, event: &str, summary: &str, detail: Value) -> Result<(), String> {
        let mut guard = self.session.lock().map_err(|_| "audit lock poisoned".to_string())?;
        if guard.is_none() {
            *guard = Some(self.open_session().map_err(|e| e.to_string())?);
        }
        let s = guard.as_mut().expect("session set above");
        if s.mode == Mode::Pending {
            self.resolve(s).map_err(|e| e.to_string())?;
        }
        self.write_record(s, event, summary, sanitize(detail))
            .map_err(|e| e.to_string())
    }

    fn list(&self, limit: usize) -> Result<Vec<AuditView>, KnownHostsError> {
        let text = self.read_text()?;
        let mut out: Vec<AuditView> = parse_text(&text)
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

    /// Walk the chain and compare it with the seal. Holds the writer lock, so it
    /// never sees the file and the seal at different stages of one append.
    fn verify(&self) -> Result<VerifyReport, KnownHostsError> {
        let _guard = self.session.lock().map_err(|_| KnownHostsError::Io {
            path: self.path.clone(),
            source: std::io::Error::other("audit lock poisoned"),
        })?;
        self.verify_locked()
    }

    /// The previous log this one was archived from, if its fingerprint no longer
    /// matches what the (anchored) opening `audit.archived` record pinned.
    fn archived_log_problem(&self, rows: &[Result<AuditEntry, usize>]) -> Option<String> {
        let Some(Ok(first)) = rows.first() else { return None };
        if first.event != EV_ARCHIVED {
            return None;
        }
        let name = first.detail.get("archivedAs")?.as_str()?;
        let want = first.detail.get("archivedSha256")?.as_str()?;
        // Only a bare file name beside the log: a crafted record cannot point
        // the check elsewhere (it is hashed and anchored, but be strict anyway).
        if name.contains(['/', '\\', ':']) || name.starts_with('.') {
            return Some(format!("the archive name {name:?} is not a plain file name"));
        }
        match std::fs::read(self.path.with_file_name(name)) {
            Ok(bytes) if hex(&Sha256::digest(&bytes)) == want => None,
            Ok(_) => Some(format!("the archived previous log {name} was modified after it was archived")),
            Err(_) => Some(format!("the archived previous log {name} is missing or unreadable")),
        }
    }

    fn verify_locked(&self) -> Result<VerifyReport, KnownHostsError> {
        let text = self.read_text()?;
        let (kept, torn) = Self::split_torn(&text);
        let rows = parse_text(kept);
        let count = rows.len() as u64;
        let chain = walk(&rows);
        let seal = self.anchor.read();
        let mut decision = reconcile(&chain, &seal);
        if matches!(decision, Decision::Anchored) {
            if let Some(why) = self.archived_log_problem(&rows) {
                decision = Decision::Mismatch(why);
            }
        }
        let entries = |n: u64| format!("{n} entr{}", if n == 1 { "y" } else { "ies" });

        let (status, message, broken_at) = match decision {
            Decision::Mismatch(why) => (
                Status::Failed,
                match &chain.broken {
                    Some(_) => why,
                    None => format!("Chain hashes are consistent, but {why}."),
                },
                chain.broken.as_ref().map(|(l, _)| *l),
            ),
            Decision::Unknown => (
                Status::Warning,
                format!(
                    "{} chain correctly, but the keychain anchor could not be read, so truncation or a full rewrite cannot be ruled out.",
                    entries(count)
                ),
                None,
            ),
            Decision::Unanchored { from, to, why } => (
                Status::Warning,
                format!(
                    "The chain is intact, but {} not covered by the keychain anchor ({why}).",
                    if from == to { format!("entry {from} is") } else { format!("entries {from}–{to} are") }
                ),
                None,
            ),
            Decision::Anchored if count == 0 => (
                Status::Empty,
                "The audit log is empty. (If an earlier log and its anchor were both deleted, that cannot be detected locally.)".to_string(),
                None,
            ),
            Decision::Anchored if torn || !chain.notes.is_empty() => {
                let mut why = chain.notes.clone();
                if torn {
                    why.push("an incomplete trailing line is present".to_string());
                }
                (
                    Status::Warning,
                    format!(
                        "Verified {} against the keychain anchor, with earlier gaps recorded in the log: {}. Archive the log to start a fully verified one.",
                        entries(count),
                        why.join("; ")
                    ),
                    None,
                )
            }
            Decision::Anchored => (
                Status::Verified,
                format!(
                    "Verified {} — the chain is intact and matches the keychain anchor.",
                    entries(count)
                ),
                None,
            ),
        };
        let seal_status = match seal {
            SealRead::Absent => "absent",
            SealRead::Unavailable => "unavailable",
            SealRead::Malformed => "malformed",
            SealRead::Present(..) => "present",
            SealRead::Frozen(_) => "frozen",
        };
        Ok(VerifyReport {
            ok: status == Status::Verified,
            status,
            count,
            message,
            broken_at,
            seal_status: seal_status.to_string(),
        })
    }

    /// Move the current log aside (kept, never deleted) and start a fresh one.
    /// The new log's first record — anchored like any other — pins the archived
    /// file by SHA-256 together with its last head and the verdict it had, so
    /// the archive stays tamper-evident after its own anchor is gone. Returns
    /// the archive's file name.
    fn archive(&self) -> Result<String, String> {
        let mut guard = self.session.lock().map_err(|_| "audit lock poisoned".to_string())?;
        let prior = self.verify_locked().map_err(|e| e.to_string())?;
        let bytes = match std::fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(format!("could not read the audit log: {e}")),
        };
        let last = parse_text(&String::from_utf8_lossy(&bytes))
            .into_iter()
            .rev()
            .find_map(Result::ok);

        // A name that is not already taken: two archives in the same second (or
        // after a clock change) must never overwrite an earlier one.
        let ts = now_secs();
        let (name, dest) = (0u32..)
            .map(|n| {
                let name = if n == 0 {
                    format!("audit-{ts}.archived.jsonl")
                } else {
                    format!("audit-{ts}-{n}.archived.jsonl")
                };
                let dest = self.path.with_file_name(&name);
                (name, dest)
            })
            .find(|(_, d)| std::fs::symlink_metadata(d).is_err())
            .expect("an unused archive name exists");
        if !bytes.is_empty() {
            std::fs::rename(&self.path, &dest)
                .map_err(|e| format!("could not archive the audit log: {e}"))?;
        }
        // Best effort: the first seal of the new log overwrites it anyway.
        let _ = self.anchor.clear();

        let mut s = Session {
            seq: 0,
            hash: GENESIS.to_string(),
            mode: Mode::Trusted,
            loaded: None,
            last_warn: None,
            freeze_pending: None,
        };
        let mut d = BTreeMap::new();
        let status = serde_json::to_value(prior.status).unwrap_or(Value::Null);
        d.insert("priorStatus".to_string(), status);
        d.insert("priorMessage".to_string(), Value::String(cap(prior.message)));
        d.insert("priorSeal".to_string(), Value::String(prior.seal_status));
        let summary = if bytes.is_empty() {
            "started a new log (the previous one was empty)".to_string()
        } else {
            d.insert("archivedAs".to_string(), Value::String(name.clone()));
            d.insert("archivedSha256".to_string(), Value::String(hex(&Sha256::digest(&bytes))));
            d.insert("archivedBytes".to_string(), Value::from(bytes.len() as u64));
            if let Some(e) = last {
                d.insert("archivedLastSeq".to_string(), Value::from(e.seq));
                d.insert("archivedLastHash".to_string(), Value::String(e.hash));
            }
            format!("started a new log; the previous one was kept as {name}")
        };
        self.write_record(&mut s, EV_ARCHIVED, &summary, d)
            .map_err(|e| e.to_string())?;
        *guard = Some(s);
        Ok(name)
    }
}

/* ------------------------------------------------------------------ public */

fn global() -> Result<&'static Log<Keychain>, String> {
    static LOG: OnceLock<Result<Log<Keychain>, String>> = OnceLock::new();
    LOG.get_or_init(|| {
        let store = store_path().map_err(|e| e.to_string())?;
        let dir = store.parent().ok_or("no app data directory")?;
        Ok(Log::new(dir.join(AUDIT_FILE), Keychain))
    })
    .as_ref()
    .map_err(Clone::clone)
}

/// Append one record. Fire-and-forget: errors are logged to stderr and
/// swallowed, so auditing can never break a working operation. Pass `detail`
/// from `serde_json::json!`; it is flattened by [`sanitize`]. Never pass a
/// password, key, command text, or command output.
pub fn record(event: &str, summary: impl Into<String>, detail: Value) {
    let summary = summary.into();
    if let Err(e) = global().and_then(|log| log.record(event, &summary, detail)) {
        eprintln!("hawser: audit append failed ({event}): {e}");
    }
}

/// A record as handed to the UI (the chain fields are not interesting there).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditView {
    pub seq: u64,
    pub ts: u64,
    pub event: String,
    pub summary: String,
    pub detail: BTreeMap<String, Value>,
}

/// Most recent `limit` records, newest first.
pub fn list(limit: usize) -> Result<Vec<AuditView>, String> {
    global()?.list(limit).map_err(|e| e.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Status {
    /// Intact chain, matching anchor, no recorded gaps.
    Verified,
    /// Intact chain, but something cannot be vouched for (see message).
    Warning,
    /// Broken chain, or file and anchor disagree.
    Failed,
    /// No records and no anchor.
    Empty,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyReport {
    /// True only for [`Status::Verified`].
    pub ok: bool,
    pub status: Status,
    pub count: u64,
    pub message: String,
    /// 1-based line of the first broken entry, when the chain itself is broken.
    pub broken_at: Option<u64>,
    /// Raw anchor state: "present", "absent", "unavailable", or "malformed".
    pub seal_status: String,
}

pub fn verify() -> Result<VerifyReport, String> {
    global()?.verify().map_err(|e| e.to_string())
}

pub fn archive() -> Result<String, String> {
    global()?.archive()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    /// In-memory seal. `fail_writes` simulates a locked keychain; `unavailable`
    /// makes reads fail too.
    #[derive(Default, Clone)]
    struct Mem {
        seal: Arc<Mutex<Option<String>>>,
        fail_writes: Arc<AtomicBool>,
        unavailable: Arc<AtomicBool>,
    }

    impl Mem {
        fn frozen(&self) -> bool {
            matches!(self.read(), SealRead::Frozen(_))
        }
        fn get(&self) -> Option<(u64, String)> {
            match parse_seal(self.seal.lock().unwrap().as_deref()?) {
                SealRead::Present(s, h) => Some((s, h)),
                _ => None,
            }
        }
    }

    impl Anchor for Mem {
        fn read(&self) -> SealRead {
            if self.unavailable.load(Ordering::SeqCst) {
                return SealRead::Unavailable;
            }
            match self.seal.lock().unwrap().as_deref() {
                None => SealRead::Absent,
                Some(raw) => parse_seal(raw),
            }
        }
        fn write(&self, seq: u64, hash: &str) -> Result<(), String> {
            if self.fail_writes.load(Ordering::SeqCst) || self.unavailable.load(Ordering::SeqCst) {
                return Err("locked".into());
            }
            *self.seal.lock().unwrap() = Some(seal_payload(seq, hash));
            Ok(())
        }
        fn freeze(&self, reason: &str) -> Result<(), String> {
            if self.fail_writes.load(Ordering::SeqCst) || self.unavailable.load(Ordering::SeqCst) {
                return Err("locked".into());
            }
            *self.seal.lock().unwrap() = Some(frozen_payload(reason));
            Ok(())
        }
        fn clear(&self) -> Result<(), String> {
            *self.seal.lock().unwrap() = None;
            Ok(())
        }
    }

    static DIRS: AtomicUsize = AtomicUsize::new(0);

    fn tmp() -> PathBuf {
        let n = DIRS.fetch_add(1, Ordering::SeqCst);
        let d = std::env::temp_dir().join(format!("hawser-audit-test-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.join(AUDIT_FILE)
    }

    /// A fresh Log over the same file + seal = an app restart.
    fn restart(path: &Path, mem: &Mem) -> Log<Mem> {
        Log::new(path.to_path_buf(), mem.clone())
    }

    fn rec(log: &Log<Mem>, n: usize) {
        for i in 0..n {
            log.record("connect", &format!("event {i}"), json!({"host": "fw1", "n": i}))
                .unwrap();
        }
    }

    fn status(log: &Log<Mem>) -> Status {
        log.verify().unwrap().status
    }

    fn lines(path: &Path) -> Vec<String> {
        std::fs::read_to_string(path).unwrap().lines().map(String::from).collect()
    }

    #[test]
    fn fresh_log_verifies() {
        let (p, m) = (tmp(), Mem::default());
        let log = restart(&p, &m);
        assert_eq!(status(&log), Status::Empty);
        rec(&log, 3);
        let r = log.verify().unwrap();
        assert_eq!(r.status, Status::Verified, "{}", r.message);
        assert!(r.ok);
        assert_eq!(m.get().unwrap().0, 3);
        // Still verified after a restart and more appends.
        rec(&restart(&p, &m), 2);
        assert_eq!(status(&restart(&p, &m)), Status::Verified);
    }

    #[test]
    fn truncation_is_not_laundered_by_the_next_append() {
        let (p, m) = (tmp(), Mem::default());
        rec(&restart(&p, &m), 4);
        let sealed = m.get().unwrap();
        // App closed; attacker keeps a valid prefix.
        let keep = lines(&p)[..2].join("\n") + "\n";
        std::fs::write(&p, keep).unwrap();
        // Restart, one legitimate event.
        let log = restart(&p, &m);
        rec(&log, 1);
        assert!(m.frozen(), "a mismatch must freeze the anchor, never re-seal it");
        assert_eq!(status(&log), Status::Failed);
        // ...and it stays failed across further restarts and appends.
        rec(&restart(&p, &m), 5);
        assert_eq!(status(&restart(&p, &m)), Status::Failed);
        assert!(m.frozen());
        let _ = sealed;
    }

    #[test]
    fn full_rewrite_is_not_laundered_by_the_next_append() {
        let (p, m) = (tmp(), Mem::default());
        rec(&restart(&p, &m), 3);
        let sealed = m.get().unwrap();
        // Attacker forges a different, internally consistent 3-entry chain.
        let forged_dir = tmp();
        rec(&restart(&forged_dir, &Mem::default()), 3);
        let mut prev = GENESIS.to_string();
        let mut out = String::new();
        for (i, l) in lines(&forged_dir).iter().enumerate() {
            let mut e: AuditEntry = serde_json::from_str(l).unwrap();
            e.summary = format!("forged {i}");
            e.prev = prev.clone();
            e.hash = hash_entry(&e);
            prev = e.hash.clone();
            out.push_str(&serde_json::to_string(&e).unwrap());
            out.push('\n');
        }
        std::fs::write(&p, out).unwrap();
        let log = restart(&p, &m);
        rec(&log, 1);
        assert!(m.frozen());
        let _ = sealed;
        assert_eq!(status(&log), Status::Failed);
    }

    #[test]
    fn missing_seal_on_a_nonempty_log_is_a_warning_not_a_pass() {
        let (p, m) = (tmp(), Mem::default());
        rec(&restart(&p, &m), 3);
        m.clear().unwrap();
        let r = restart(&p, &m).verify().unwrap();
        assert_eq!(r.status, Status::Warning);
        assert!(!r.ok);
        // Anchoring resumes, but the gap is written into the chain for good.
        let log = restart(&p, &m);
        rec(&log, 1);
        let r = log.verify().unwrap();
        assert_eq!(r.status, Status::Warning, "{}", r.message);
        assert!(lines(&p).iter().any(|l| l.contains(EV_UNANCHORED)));
    }

    #[test]
    fn unreadable_seal_is_a_warning_and_never_sealed_over() {
        let (p, m) = (tmp(), Mem::default());
        rec(&restart(&p, &m), 2);
        let sealed = m.get().unwrap();
        m.unavailable.store(true, Ordering::SeqCst);
        let log = restart(&p, &m);
        assert_eq!(status(&log), Status::Warning);
        rec(&log, 2); // pending: appends, cannot seal
        m.unavailable.store(false, Ordering::SeqCst);
        assert_eq!(m.get().unwrap(), sealed);
        // Once readable, the pending check resolves against the chain as it was
        // loaded. It matches, so the entries this session wrote meanwhile are
        // ours and sealing resumes over them.
        rec(&log, 1);
        assert_eq!(status(&log), Status::Verified);
        assert_eq!(m.get().unwrap().0, 5);
    }

    #[test]
    fn malformed_seal_fails() {
        let (p, m) = (tmp(), Mem::default());
        rec(&restart(&p, &m), 2);
        *m.seal.lock().unwrap() = Some("not a head".into());
        let log = restart(&p, &m);
        assert_eq!(status(&log), Status::Failed);
        rec(&log, 1);
        assert_eq!(status(&log), Status::Failed);
        assert!(m.frozen());
    }

    #[test]
    fn deleted_log_with_a_seal_fails() {
        let (p, m) = (tmp(), Mem::default());
        rec(&restart(&p, &m), 2);
        std::fs::remove_file(&p).unwrap();
        assert_eq!(status(&restart(&p, &m)), Status::Failed);
    }

    #[test]
    fn transient_seal_failure_retries_within_the_session() {
        let (p, m) = (tmp(), Mem::default());
        let log = restart(&p, &m);
        rec(&log, 1);
        m.fail_writes.store(true, Ordering::SeqCst);
        rec(&log, 1);
        m.fail_writes.store(false, Ordering::SeqCst);
        rec(&log, 1);
        assert_eq!(m.get().unwrap().0, 3, "sealing must resume after a failure");
        assert_eq!(status(&log), Status::Verified);
    }

    #[test]
    fn crash_between_write_and_seal_is_noted_on_restart() {
        let (p, m) = (tmp(), Mem::default());
        let log = restart(&p, &m);
        rec(&log, 2);
        m.fail_writes.store(true, Ordering::SeqCst);
        rec(&log, 1); // on disk, not sealed; then the app "crashes"
        m.fail_writes.store(false, Ordering::SeqCst);
        let log = restart(&p, &m);
        assert_eq!(status(&log), Status::Warning);
        rec(&log, 1);
        let r = log.verify().unwrap();
        assert_eq!(r.status, Status::Warning);
        assert!(r.message.contains("entry 3"), "{}", r.message);
    }

    #[test]
    fn torn_tail_is_dropped_and_recorded() {
        let (p, m) = (tmp(), Mem::default());
        rec(&restart(&p, &m), 2);
        let mut f = OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(b"{\"seq\":3,\"ts\":1,\"ev").unwrap();
        drop(f);
        let log = restart(&p, &m);
        rec(&log, 1);
        let ls = lines(&p);
        assert!(ls.iter().all(|l| serde_json::from_str::<AuditEntry>(l).is_ok()));
        assert!(ls.iter().any(|l| l.contains(EV_TORN)));
        assert_eq!(status(&log), Status::Warning);
    }

    #[test]
    fn archive_starts_a_verified_log_and_keeps_the_old_one() {
        let (p, m) = (tmp(), Mem::default());
        rec(&restart(&p, &m), 3);
        std::fs::write(&p, lines(&p)[..1].join("\n") + "\n").unwrap();
        let log = restart(&p, &m);
        assert_eq!(status(&log), Status::Failed);
        let name = log.archive().unwrap();
        assert!(p.with_file_name(&name).exists());
        assert_eq!(status(&log), Status::Verified);
        rec(&log, 2);
        assert_eq!(status(&restart(&p, &m)), Status::Verified);
        assert!(lines(&p)[0].contains(EV_ARCHIVED));
    }

    #[test]
    fn edits_inserts_reorders_and_deletes_are_located() {
        let (p, m) = (tmp(), Mem::default());
        rec(&restart(&p, &m), 4);
        let orig = lines(&p);
        let check = |ls: Vec<String>, at: u64| {
            std::fs::write(&p, ls.join("\n") + "\n").unwrap();
            let r = restart(&p, &m).verify().unwrap();
            assert_eq!((r.status, r.broken_at), (Status::Failed, Some(at)), "{}", r.message);
        };
        let mut edited = orig.clone();
        edited[1] = edited[1].replace("event 1", "event 9");
        check(edited, 2);
        let mut deleted = orig.clone();
        deleted.remove(1);
        check(deleted, 2);
        let mut swapped = orig.clone();
        swapped.swap(1, 2);
        check(swapped, 2);
        let mut junk = orig.clone();
        junk.insert(2, "garbage".into());
        check(junk, 3);
    }

    #[test]
    fn verify_is_consistent_under_concurrent_appends() {
        let (p, m) = (tmp(), Mem::default());
        let log = Arc::new(restart(&p, &m));
        let writers: Vec<_> = (0..4)
            .map(|_| {
                let log = log.clone();
                std::thread::spawn(move || rec(&log, 25))
            })
            .collect();
        for _ in 0..40 {
            assert_ne!(status(&log), Status::Failed);
        }
        for w in writers {
            w.join().unwrap();
        }
        let r = log.verify().unwrap();
        assert_eq!((r.status, r.count), (Status::Verified, 100));
    }

    #[test]
    fn restoring_the_original_file_after_a_freeze_still_fails() {
        let (p, m) = (tmp(), Mem::default());
        rec(&restart(&p, &m), 3);
        let original = std::fs::read_to_string(&p).unwrap();
        std::fs::write(&p, lines(&p)[..2].join("\n") + "\n").unwrap();
        rec(&restart(&p, &m), 5); // frozen session: note + 5 unsealed records
        std::fs::write(&p, &original).unwrap(); // attacker puts the old file back
        let r = restart(&p, &m).verify().unwrap();
        assert_eq!(r.status, Status::Failed, "{}", r.message);
        assert_eq!(r.seal_status, "frozen");
    }

    #[test]
    fn freeze_is_retried_if_the_keychain_refuses_it() {
        let (p, m) = (tmp(), Mem::default());
        rec(&restart(&p, &m), 3);
        std::fs::write(&p, lines(&p)[..1].join("\n") + "\n").unwrap();
        m.fail_writes.store(true, Ordering::SeqCst);
        let log = restart(&p, &m);
        rec(&log, 1);
        assert!(!m.frozen());
        m.fail_writes.store(false, Ordering::SeqCst);
        rec(&log, 1);
        assert!(m.frozen());
    }

    #[test]
    fn archives_never_overwrite_each_other() {
        let (p, m) = (tmp(), Mem::default());
        let log = restart(&p, &m);
        rec(&log, 2);
        let a = log.archive().unwrap();
        rec(&log, 1);
        let b = log.archive().unwrap();
        assert_ne!(a, b);
        assert!(p.with_file_name(&a).exists() && p.with_file_name(&b).exists());
    }

    #[test]
    fn archived_log_is_pinned_by_the_new_anchored_log() {
        let (p, m) = (tmp(), Mem::default());
        let log = restart(&p, &m);
        rec(&log, 3);
        let name = log.archive().unwrap();
        assert_eq!(status(&log), Status::Verified);
        let first: AuditEntry = serde_json::from_str(&lines(&p)[0]).unwrap();
        assert_eq!(first.detail["priorStatus"], json!("verified"));
        assert_eq!(first.detail["archivedLastSeq"], json!(3));
        // Tamper with the archive: the new log's verify catches it.
        let arch = p.with_file_name(&name);
        let edited = std::fs::read_to_string(&arch).unwrap().replace("event 0", "event 7");
        std::fs::write(&arch, edited).unwrap();
        assert_eq!(status(&log), Status::Failed);
        std::fs::remove_file(&arch).unwrap();
        assert_eq!(status(&log), Status::Failed);
    }

    #[test]
    fn extra_or_duplicate_fields_outside_the_hash_are_rejected() {
        let (p, m) = (tmp(), Mem::default());
        rec(&restart(&p, &m), 2);
        let mut ls = lines(&p);
        ls[0] = ls[0].replacen('{', "{\"note\":\"attacker text\",", 1);
        std::fs::write(&p, ls.join("\n") + "\n").unwrap();
        let r = restart(&p, &m).verify().unwrap();
        assert_eq!((r.status, r.broken_at), (Status::Failed, Some(1)));

        let (p, m) = (tmp(), Mem::default());
        rec(&restart(&p, &m), 2);
        let mut ls = lines(&p);
        ls[0] = ls[0].replacen("\"detail\":{", "\"detail\":{\"host\":\"evil.example\",", 1);
        std::fs::write(&p, ls.join("\n") + "\n").unwrap();
        assert_eq!(status(&restart(&p, &m)), Status::Failed);
    }

    #[test]
    fn canonical_hash_survives_round_trip_and_ignores_key_order() {
        let d1 = sanitize(json!({
            "path": "/tmp/ünïcødé \"quoted\" \\ back\nslash\t✓ 🚀",
            "max": u64::MAX, "min": i64::MIN, "zero": 0, "ok": true, "none": null,
        }));
        let d2 = sanitize(json!({
            "none": null, "ok": true, "zero": 0, "min": i64::MIN, "max": u64::MAX,
            "path": "/tmp/ünïcødé \"quoted\" \\ back\nslash\t✓ 🚀",
        }));
        let mk = |d: BTreeMap<String, Value>| {
            let mut e = AuditEntry {
                seq: 1,
                ts: 1_789_646_400,
                event: "sftp.put".into(),
                summary: "s ✓".into(),
                detail: d,
                prev: GENESIS.into(),
                hash: String::new(),
            };
            e.hash = hash_entry(&e);
            e
        };
        let (a, b) = (mk(d1), mk(d2));
        assert_eq!(a.hash, b.hash);
        let line = serde_json::to_string(&a).unwrap();
        assert!(!line.contains('\n'));
        let back: AuditEntry = serde_json::from_str(&line).unwrap();
        assert_eq!(hash_entry(&back), a.hash);
    }

    #[test]
    fn sanitize_flattens_and_caps() {
        let d = sanitize(json!({
            "f": 1.5, "arr": [1, 2], "obj": {"x": 1}, "long": "x".repeat(2000),
        }));
        assert_eq!(d["f"], json!("1.5"));
        assert_eq!(d["arr"], json!("[1,2]"));
        assert_eq!(d["obj"], json!("{\"x\":1}"));
        assert!(d["long"].as_str().unwrap().len() <= MAX_FIELD + '…'.len_utf8());
        assert_eq!(sanitize(json!("bare"))["value"], json!("bare"));
    }

    #[test]
    fn key_fingerprint_drops_the_comment() {
        let line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl secret-comment@corp";
        let fp = key_fingerprint(line);
        assert!(fp.starts_with("SHA256:"), "{fp}");
        assert!(!fp.contains("secret-comment"));
        assert_eq!(key_fingerprint("not a key"), "unparseable-key");
    }
}
