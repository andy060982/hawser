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
//! - If an archive was interrupted after its commit and the keychain is then
//!   unreadable, records are refused (and lost, with a stderr line) until the
//!   keychain can be read, because it is unknown which file is live.
//! - One instance runs at a time (the app enforces it), and every append,
//!   verify and archive also holds a cross-process lock on `audit.jsonl.lock`
//!   and re-reads the head if the file grew under it, so even a forced second
//!   process cannot fork the chain.
//! - Appends are queued to one writer thread, which syncs the file and seals
//!   the keychain; an audited command never waits on either. A keychain that
//!   prompts delays the *writer*: records queue meanwhile, and if the queue
//!   fills, the overflow is dropped and an `audit.dropped` record says how many.
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
//! write is rolled back to the previous length where the platform allows it.
//! The file is read as bytes and streamed (memory stays bounded however long
//! the log grows): a final line that is incomplete or not valid UTF-8 — a crash
//! mid-append, or a stray byte — is a torn tail. It is moved aside as evidence
//! (`audit.jsonl.torn-<time>`), dropped from the log by a synced rewrite, and
//! that is recorded (`audit.torn`). An invalid line anywhere else is a broken
//! chain that verify reports, never an error that stops the log. Auditing
//! never fails the operation being audited: errors go to stderr and are
//! swallowed.
//!
//! On Unix the file is created 0600 and its directory restricted to 0700. On
//! Windows both inherit the per-user `%APPDATA%` ACL; no extra ACL is applied.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
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

/// Longest line the app could have written. Anything longer is not one of its
/// records, and is never buffered whole (a file-only attacker could otherwise
/// make every read allocate the whole file).
const MAX_LINE: usize = 1 << 20;

/// Largest staged rotation file that can hold the single opening record.
const MAX_STAGED: u64 = 64 * 1024;

/// At most this many gap notes are quoted in a verify message; the rest are
/// counted.
const MAX_NOTES: usize = 8;

/// Event tag of the record noting entries that were written without an anchor.
const EV_UNANCHORED: &str = "audit.unanchored";
/// Event tag of the record noting a discarded incomplete trailing line.
const EV_TORN: &str = "audit.torn";
/// Event tag recorded when the startup check found the log does not match its anchor.
const EV_INTEGRITY: &str = "audit.integrity_failed";
/// Event tag that opens a fresh log after the old one was archived.
const EV_ARCHIVED: &str = "audit.archived";
/// Event tag noting records the writer had to drop (its queue was full).
const EV_DROPPED: &str = "audit.dropped";
/// Records accepted before an exit that could not write them in time, spilled
/// to `audit.pending-*.jsonl` and recorded at the next start.
const EV_RECOVERED: &str = "audit.recovered";
/// Detail key of the unique id every accepted record carries (spill dedupe).
const RID: &str = "rid";
/// Prefix / suffix of spilled-record files beside the log.
const PENDING_PREFIX: &str = "audit.pending-";
const PENDING_SUFFIX: &str = ".jsonl";

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
        Value::Object(map) => map.into_iter().map(|(k, v)| (cap(k), prim(v))).collect(),
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
}

/* ------------------------------------------------------------ reading lines */

/// One line of the log as the reader classifies it.
enum Row {
    /// Empty or whitespace-only: skipped, as `str::lines` + trim did.
    Blank,
    /// Exactly what the app writes for this record.
    Record(AuditEntry),
    /// Anything else: too long, not UTF-8, not a record, or a record with
    /// bytes outside the hash (extra fields, duplicate keys, other spacing).
    Bad,
}

/// Classify one line's bytes (without its `\n`). The exact-bytes rule matters:
/// extra fields or duplicate keys parse fine but sit outside the hash, so
/// raw-file readers (grep, a SIEM) could be shown unverified text.
fn classify(line: Option<&[u8]>) -> Row {
    let Some(mut line) = line else { return Row::Bad };
    if let Some(stripped) = line.strip_suffix(b"\r") {
        line = stripped;
    }
    let Ok(text) = std::str::from_utf8(line) else { return Row::Bad };
    if text.trim().is_empty() {
        return Row::Blank;
    }
    match serde_json::from_str::<AuditEntry>(text) {
        Ok(e) if serde_json::to_string(&e).is_ok_and(|canon| canon == text) => Row::Record(e),
        _ => Row::Bad,
    }
}

/// Feed every line of `r` to `f` without ever buffering more than
/// [`MAX_LINE`] bytes of one: a longer line arrives as `None`. A final line
/// without a newline is delivered too. Memory stays bounded however large the
/// file is.
fn for_each_line(r: impl Read, mut f: impl FnMut(Option<&[u8]>)) -> std::io::Result<()> {
    let mut reader = BufReader::with_capacity(64 * 1024, r);
    let mut line: Vec<u8> = Vec::new();
    let mut overlong = false;
    let mut pending = false;
    loop {
        let avail = match reader.fill_buf() {
            Ok(a) => a,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if avail.is_empty() {
            if pending {
                f(if overlong { None } else { Some(&line) });
            }
            return Ok(());
        }
        let (chunk, used, ends) = match avail.iter().position(|&b| b == b'\n') {
            Some(i) => (&avail[..i], i + 1, true),
            None => (avail, avail.len(), false),
        };
        pending = true;
        if !overlong {
            if line.len() + chunk.len() > MAX_LINE {
                overlong = true;
                line = Vec::new();
            } else {
                line.extend_from_slice(chunk);
            }
        }
        reader.consume(used);
        if ends {
            f(if overlong { None } else { Some(&line) });
            line.clear();
            overlong = false;
            pending = false;
        }
    }
}

/* ------------------------------------------------------------ chain + seal */

/// The result of walking the file, kept to a bounded size: the tip, the
/// hashes the caller asked for, the first break, and the notes.
#[derive(Clone)]
struct Chain {
    /// Number of contiguous valid records before any break.
    n: u64,
    /// Hash of record `n` (GENESIS when n is 0).
    tip: String,
    /// `at[s]` is the hash of record seq `s`, for each seq that was asked for
    /// (and exists before any break).
    at: BTreeMap<u64, String>,
    /// The first problem, as (1-based row, sentence), if the chain is broken.
    broken: Option<(u64, String)>,
    /// `audit.unanchored` / `audit.torn` / `audit.integrity_failed` /
    /// `audit.dropped` records seen (at most MAX_NOTES kept; `more` counts the rest).
    notes: Vec<String>,
    more_notes: usize,
    /// The last parseable record, for continuing a log that is already broken.
    last: Option<(u64, String)>,
    /// Rows seen (records plus bad lines; blank lines excluded).
    rows: u64,
    /// The first row, when it is a record (for following archive pins).
    first: Option<AuditEntry>,
}

impl Chain {
    fn tip(&self) -> (u64, &str) {
        (self.n, self.tip.as_str())
    }
    fn hash_at(&self, seq: u64) -> Option<&str> {
        if seq == self.n {
            return Some(self.tip.as_str());
        }
        self.at.get(&seq).map(String::as_str)
    }
}

/// Recompute every hash and check contiguity and links, one row at a time.
struct Walker {
    c: Chain,
    prev: String,
    want: Vec<u64>,
}

impl Walker {
    fn new(want: &[u64]) -> Self {
        Self {
            c: Chain {
                n: 0,
                tip: GENESIS.to_string(),
                at: BTreeMap::new(),
                broken: None,
                notes: Vec::new(),
                more_notes: 0,
                last: None,
                rows: 0,
                first: None,
            },
            prev: GENESIS.to_string(),
            want: want.to_vec(),
        }
    }

    fn push(&mut self, row: Row) {
        let e = match row {
            Row::Blank => return,
            Row::Bad => {
                self.c.rows += 1;
                let line = self.c.rows;
                self.c.broken.get_or_insert((line, format!("Entry {line} is not a record as the app writes it — the log was edited or corrupted.")));
                return;
            }
            Row::Record(e) => e,
        };
        self.c.rows += 1;
        let line = self.c.rows;
        if line == 1 {
            self.c.first = Some(e.clone());
        }
        self.c.last = Some((e.seq, e.hash.clone()));
        if self.c.broken.is_some() {
            return;
        }
        let expect = self.c.n + 1;
        let problem = if e.seq != expect {
            Some(format!(
                "Entry {line} has sequence {} but {expect} was expected — an entry was inserted or removed.",
                e.seq
            ))
        } else if e.prev != self.prev {
            Some(format!("Entry {line} does not link to the previous entry — the chain was broken here."))
        } else if hash_entry(&e) != e.hash {
            Some(format!("Entry {line} was modified after it was written — its contents no longer match its hash."))
        } else {
            None
        };
        if let Some(p) = problem {
            self.c.broken = Some((line, p));
            return;
        }
        if matches!(e.event.as_str(), EV_UNANCHORED | EV_TORN | EV_INTEGRITY | EV_DROPPED) {
            if self.c.notes.len() < MAX_NOTES {
                self.c.notes.push(e.summary.clone());
            } else {
                self.c.more_notes += 1;
            }
        }
        self.c.n = e.seq;
        if self.want.contains(&e.seq) {
            self.c.at.insert(e.seq, e.hash.clone());
        }
        self.prev = e.hash.clone();
        self.c.tip = e.hash;
    }

    fn finish(self) -> Chain {
        self.c
    }
}

/// Walk the first `limit` bytes of `r` (the whole of it when `None`).
fn walk_reader(r: impl Read, limit: Option<u64>, want: &[u64]) -> std::io::Result<Chain> {
    let mut w = Walker::new(want);
    match limit {
        Some(n) => for_each_line(r.take(n), |l| w.push(classify(l)))?,
        None => for_each_line(r, |l| w.push(classify(l)))?,
    }
    Ok(w.finish())
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
            } else if s >= 1 && chain.hash_at(s) == Some(h.as_str()) {
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

/// The seq whose hash `reconcile` will need for this seal.
fn wanted(seal: &SealRead) -> Vec<u64> {
    match seal {
        SealRead::Present(s, _) => vec![*s],
        _ => Vec::new(),
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

/// What a `Pending` session still has to reconcile: the chain head as it was
/// loaded, before this session appended anything.
#[derive(Clone)]
struct Loaded {
    n: u64,
    tip: String,
    broken: Option<(u64, String)>,
}

struct Session {
    seq: u64,
    hash: String,
    mode: Mode,
    loaded: Option<Loaded>,
    last_warn: Option<Instant>,
    /// A freeze marker that still has to reach the keychain (retried per append).
    freeze_pending: Option<String>,
    /// The file's length after this session's last write. Anything else on
    /// disk means another writer (a second instance) appended, and the session
    /// must be re-read before chaining from its cached head.
    len: u64,
}

struct Log<A: Anchor> {
    path: PathBuf,
    anchor: A,
    session: Mutex<Option<Session>>,
    /// Test-only fault injection: fail the next fsync / stop an archive after
    /// step N / make the commit's seal write land but report failure.
    #[cfg(test)]
    faults: Faults,
}

#[cfg(test)]
#[derive(Default)]
struct Faults {
    fail_sync: std::sync::atomic::AtomicBool,
    crash_archive_after: std::sync::atomic::AtomicU8,
    fail_newline_repair: std::sync::atomic::AtomicBool,
    /// A verify waits here (outside every lock) until the test releases it.
    verify_gate: Mutex<Option<mpsc::Receiver<()>>>,
}

fn io_err(path: &Path) -> impl FnOnce(std::io::Error) -> KnownHostsError + '_ {
    move |source| KnownHostsError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// A cross-process exclusive lock on `<log>.lock`, held for one transaction
/// (reconcile + append + seal, a verify, an archive). The OS releases it if the
/// holder dies, so a stale lock file is harmless. One instance is the norm (the
/// app enforces it), but a forced second process must still never interleave
/// its appends with ours.
struct FileLock(#[allow(dead_code)] File);

impl FileLock {
    fn acquire(log: &Path) -> Result<Self, KnownHostsError> {
        let path = log.with_extension("jsonl.lock");
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(io_err(dir))?;
            super::platform::restrict_perms(dir, 0o700);
        }
        let mut opts = OpenOptions::new();
        opts.create(true).read(true).write(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let f = opts.open(&path).map_err(io_err(&path))?;
        f.lock().map_err(io_err(&path))?;
        Ok(Self(f))
    }
}

/// Current length of `path`, 0 when it does not exist.
fn file_len(path: &Path) -> Result<u64, KnownHostsError> {
    match std::fs::metadata(path) {
        Ok(m) => Ok(m.len()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(io_err(path)(e)),
    }
}

/// Where the last line of `path` starts, and whether that line is a torn
/// tail: no final newline and not a complete record. Returns (file length,
/// length to keep, torn). Reads only the tail.
fn split_torn(path: &Path) -> Result<(u64, u64, bool), KnownHostsError> {
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((0, 0, false)),
        Err(e) => return Err(io_err(path)(e)),
    };
    split_torn_in(&mut f, path)
}

/// `split_torn` on an open handle (`path` only names it in errors).
fn split_torn_in(f: &mut File, path: &Path) -> Result<(u64, u64, bool), KnownHostsError> {
    let len = f.metadata().map_err(io_err(path))?.len();
    if len == 0 {
        return Ok((0, 0, false));
    }
    // Find the last newline, scanning backwards in chunks.
    let mut pos = len;
    let mut buf = vec![0u8; 64 * 1024];
    let mut last_nl: Option<u64> = None;
    let mut first = true;
    while pos > 0 {
        let take = (pos.min(buf.len() as u64)) as usize;
        pos -= take as u64;
        f.seek(SeekFrom::Start(pos)).map_err(io_err(path))?;
        f.read_exact(&mut buf[..take]).map_err(io_err(path))?;
        if first {
            first = false;
            if buf[take - 1] == b'\n' {
                return Ok((len, len, false));
            }
        }
        if let Some(i) = buf[..take].iter().rposition(|&b| b == b'\n') {
            last_nl = Some(pos + i as u64);
            break;
        }
    }
    let cut = last_nl.map_or(0, |i| i + 1);
    let tail_len = len - cut;
    if tail_len as usize <= MAX_LINE {
        let mut tail = vec![0u8; tail_len as usize];
        f.seek(SeekFrom::Start(cut)).map_err(io_err(path))?;
        f.read_exact(&mut tail).map_err(io_err(path))?;
        // Complete record, only its newline missing.
        if let Row::Record(_) = classify(Some(&tail)) {
            return Ok((len, len, false));
        }
    }
    Ok((len, cut, true))
}

/// A name beside `base` that does not exist yet: `<base>-<ts>`, then
/// `<base>-<ts>-1`, … .
fn unused_sibling(dir_of: &Path, base: &str) -> PathBuf {
    let ts = now_secs();
    (0u32..)
        .map(|n| match n {
            0 => dir_of.with_file_name(format!("{base}-{ts}")),
            n => dir_of.with_file_name(format!("{base}-{ts}-{n}")),
        })
        .find(|p| std::fs::symlink_metadata(p).is_err())
        .expect("an unused name exists")
}

/// SHA-256 of a file, streamed, plus its first line classified (for following
/// archive pins). Memory stays bounded.
fn hash_file(path: &Path) -> std::io::Result<(String, Option<AuditEntry>)> {
    hash_reader(File::open(path)?)
}

/// `hash_file` over any reader (a snapshot's handle, cut at its length).
fn hash_reader(f: impl Read) -> std::io::Result<(String, Option<AuditEntry>)> {
    let mut hasher = Sha256::new();
    let mut first: Option<Option<AuditEntry>> = None;
    let mut line: Vec<u8> = Vec::new();
    let mut reader = BufReader::with_capacity(64 * 1024, f);
    loop {
        let avail = reader.fill_buf()?;
        if avail.is_empty() {
            break;
        }
        hasher.update(avail);
        if first.is_none() {
            match avail.iter().position(|&b| b == b'\n') {
                Some(i) if line.len() + i <= MAX_LINE => {
                    line.extend_from_slice(&avail[..i]);
                    first = Some(match classify(Some(&line)) {
                        Row::Record(e) => Some(e),
                        _ => None,
                    });
                }
                Some(_) => first = Some(None),
                None if line.len() + avail.len() <= MAX_LINE => line.extend_from_slice(avail),
                None => first = Some(None),
            }
        }
        let n = avail.len();
        reader.consume(n);
    }
    if first.is_none() && !line.is_empty() {
        first = Some(match classify(Some(&line)) {
            Row::Record(e) => Some(e),
            _ => None,
        });
    }
    Ok((hex(&hasher.finalize()), first.flatten()))
}

/// A problem with the archive pins, and whether it fails the log or only
/// warns.
struct PinProblem {
    fatal: bool,
    message: String,
}

/// Which file is at the log's path, and how long it is: changes on any
/// append, torn-tail rewrite or rotation (a new file).
#[derive(Debug, Clone, PartialEq)]
struct Stamp {
    len: u64,
    modified: Option<std::time::SystemTime>,
    #[cfg(unix)]
    ino: (u64, u64),
}

fn stamp(path: &Path) -> Option<Stamp> {
    let m = std::fs::metadata(path).ok()?;
    Some(Stamp {
        len: m.len(),
        modified: m.modified().ok(),
        #[cfg(unix)]
        ino: {
            use std::os::unix::fs::MetadataExt;
            (m.dev(), m.ino())
        },
    })
}

/// A consistent view of the log for a verify or an archive: the open file,
/// its torn-tail split and the seal, all taken together under the locks, then
/// read WITHOUT them, so appends never wait behind a long verify. The log is
/// append-only between locks: bytes before `keep` cannot change, and a
/// rewrite or rotation replaces the file at the path, never this handle's.
struct Snapshot {
    file: Option<File>,
    len: u64,
    keep: u64,
    torn: bool,
    seal: SealRead,
    stamp: Option<Stamp>,
}

/// An archive's verdict and pin, computed from a snapshot outside the locks.
/// Used at commit only if the file is still exactly the one snapshotted.
struct Prepared {
    stamp: Option<Stamp>,
    prior: VerifyReport,
    last: Option<(u64, String)>,
    sha: Option<String>,
    len: u64,
}

impl<A: Anchor> Log<A> {
    fn new(path: PathBuf, anchor: A) -> Self {
        Self {
            path,
            anchor,
            session: Mutex::new(None),
            #[cfg(test)]
            faults: Faults::default(),
        }
    }

    fn walk_file(&self, limit: Option<u64>, want: &[u64]) -> Result<Chain, KnownHostsError> {
        match File::open(&self.path) {
            Ok(f) => walk_reader(f, limit, want).map_err(io_err(&self.path)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                walk_reader(std::io::empty(), None, want).map_err(io_err(&self.path))
            }
            Err(e) => Err(io_err(&self.path)(e)),
        }
    }

    /// Append one line (newline included) in a single write, then fsync. On a
    /// failed write, roll the file back to its previous length. Returns the
    /// file's length afterwards.
    fn append_line(&self, line: &str) -> Result<u64, KnownHostsError> {
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
        let res = file.write_all(buf.as_bytes()).and_then(|_| {
            #[cfg(test)]
            if self.faults.fail_sync.swap(false, std::sync::atomic::Ordering::SeqCst) {
                return Err(std::io::Error::other("injected fsync failure"));
            }
            file.sync_data()
        });
        if let Err(e) = res {
            // Undo the line so the file matches the head we still hold. If even
            // that fails, the caller drops its cached head and the next append
            // re-reads the file, where an unsealed tail is noted, not reused.
            if let Some(len) = before {
                // Through a separate non-append handle: on Windows an append
                // handle has no FILE_WRITE_DATA, so it cannot truncate.
                drop(file);
                let _ = OpenOptions::new()
                    .write(true)
                    .open(&self.path)
                    .and_then(|f| f.set_len(len).and_then(|_| f.sync_data()));
            }
            return Err(io_err(&self.path)(e));
        }
        file.metadata().map(|m| m.len()).map_err(io_err(&self.path))
    }

    /// Drop a torn tail: the bytes past `keep` are first saved as evidence
    /// (`audit.jsonl.torn-<ts>`, never deleted), then the log is rewritten to
    /// its first `keep` bytes via a synced temp file + rename + directory
    /// sync, so a crash mid-rewrite leaves either the old file or the new one.
    fn drop_torn_tail(&self, keep: u64) -> Result<(), KnownHostsError> {
        let mut src = File::open(&self.path).map_err(io_err(&self.path))?;
        let create = |p: &Path| {
            let mut opts = OpenOptions::new();
            opts.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            opts.open(p)
        };
        // Evidence first: a tampered last line must not simply vanish.
        let evidence = unused_sibling(&self.path, "audit.jsonl.torn");
        let mut ev = create(&evidence).map_err(io_err(&evidence))?;
        src.seek(SeekFrom::Start(keep)).map_err(io_err(&self.path))?;
        std::io::copy(&mut src, &mut ev)
            .and_then(|_| ev.sync_all())
            .map_err(io_err(&evidence))?;
        drop(ev);

        let tmp = self.path.with_extension("jsonl.tmp");
        let _ = std::fs::remove_file(&tmp);
        let mut out = create(&tmp).map_err(io_err(&tmp))?;
        src.seek(SeekFrom::Start(0)).map_err(io_err(&self.path))?;
        let copied = std::io::copy(&mut (&mut src).take(keep), &mut out)
            .and_then(|n| out.sync_all().map(|_| n))
            .map_err(io_err(&tmp))?;
        drop((src, out));
        if copied != keep {
            let _ = std::fs::remove_file(&tmp);
            return Err(KnownHostsError::Parse(
                "the audit log shrank while its torn tail was being dropped".into(),
            ));
        }
        std::fs::rename(&tmp, &self.path).map_err(io_err(&self.path))?;
        sync_dir(&self.path).map_err(io_err(&self.path))
    }

    /// Finish the last line when it is a complete record missing only its
    /// newline. Its failure is an error: the next record would otherwise be
    /// glued onto that line.
    fn repair_newline(&self) -> Result<(), KnownHostsError> {
        #[cfg(test)]
        if self.faults.fail_newline_repair.swap(false, std::sync::atomic::Ordering::SeqCst) {
            return Err(KnownHostsError::Parse("injected newline repair failure".into()));
        }
        // An empty line: append_line adds the newline.
        self.append_line("").map(|_| ())
    }

    /// Load and reconcile the chain for the first append of the session. May
    /// rewrite the file once, to drop a torn tail, and may append notes.
    fn open_session(&self) -> Result<Session, KnownHostsError> {
        let (len, keep, torn) = split_torn(&self.path)?;
        if torn {
            self.drop_torn_tail(keep)?;
        } else if len > 0 && !self.ends_with_newline()? {
            self.repair_newline()?;
        }
        let seal = self.anchor.read();
        let chain = self.walk_file(None, &wanted(&seal))?;
        let (seq, hash) = match (&chain.broken, chain.last.clone()) {
            (None, _) => (chain.n, chain.tip.clone()),
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
            len: file_len(&self.path)?,
        };
        if torn {
            self.write_record(
                &mut s,
                EV_TORN,
                "an incomplete trailing entry left by an interrupted write was discarded (kept beside the log as audit.jsonl.torn-*)",
                BTreeMap::new(),
            )?;
        }
        let decision = reconcile(&chain, &seal);
        if decision == Decision::Unknown {
            s.loaded = Some(Loaded {
                n: chain.n,
                tip: chain.tip.clone(),
                broken: chain.broken.clone(),
            });
            return Ok(s);
        }
        self.apply(&mut s, decision, &seal)?;
        Ok(s)
    }

    fn ends_with_newline(&self) -> Result<bool, KnownHostsError> {
        let mut f = File::open(&self.path).map_err(io_err(&self.path))?;
        let len = f.metadata().map_err(io_err(&self.path))?.len();
        if len == 0 {
            return Ok(true);
        }
        let mut b = [0u8; 1];
        f.seek(SeekFrom::Start(len - 1)).map_err(io_err(&self.path))?;
        f.read_exact(&mut b).map_err(io_err(&self.path))?;
        Ok(b[0] == b'\n')
    }

    /// Settle a `Pending` session against the seal: trust it (writing an
    /// `audit.unanchored` note first if needed), freeze it, or leave it pending.
    ///
    /// The file is re-walked rather than the startup chain kept in memory
    /// (memory stays bounded). The records this session appended while pending
    /// must still end at its head, and the prefix that was loaded must be
    /// unchanged; otherwise the file changed under it and it is a mismatch.
    fn resolve(&self, s: &mut Session) -> Result<(), KnownHostsError> {
        let Some(loaded) = s.loaded.clone() else {
            return Ok(());
        };
        let seal = self.anchor.read();
        if seal == SealRead::Unavailable {
            return Ok(());
        }
        let mut want = wanted(&seal);
        want.push(loaded.n);
        let walked = self.walk_file(None, &want)?;
        let chain = if loaded.broken.is_some() {
            Chain { broken: loaded.broken.clone(), ..walked }
        } else if walked.broken.is_some() {
            walked
        } else if walked.hash_at(loaded.n).unwrap_or(GENESIS) != loaded.tip
            || (walked.n, walked.tip.as_str()) != (s.seq, s.hash.as_str())
        {
            Chain {
                broken: Some((0, "the log changed on disk while its keychain check was pending".into())),
                ..walked
            }
        } else {
            // The chain as it was loaded, with the hashes asked for.
            Chain { n: loaded.n, tip: loaded.tip.clone(), ..walked }
        };
        let decision = reconcile(&chain, &seal);
        self.apply(s, decision, &seal)
    }

    fn apply(&self, s: &mut Session, decision: Decision, seal: &SealRead) -> Result<(), KnownHostsError> {
        match decision {
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
        s.len = self.append_line(&line)?;
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
        let res = (|| {
            let _lock = FileLock::acquire(&self.path)?;
            // Another process (a forced second instance) may have appended
            // since our last write: never chain from a head it moved past.
            // Or it may have staged a rotation and moved the seal, then died
            // before renaming: the live file is unchanged, but appending to it
            // would seal the OLD chain over a committed stage, which the next
            // recovery would then discard. One stat per append catches it:
            // any staged file sends us through recovery (which completes a
            // committed stage) and a fresh session.
            if guard.as_ref().is_some_and(|s| {
                file_len(&self.path).ok() != Some(s.len) || std::fs::symlink_metadata(self.rotating_path()).is_ok()
            }) {
                *guard = None;
            }
            if guard.is_none() {
                if self.recover_rotation()? == Rotation::Pending {
                    return Err(KnownHostsError::Parse(ROTATION_PENDING.to_string()));
                }
                *guard = Some(self.open_session()?);
            }
            let s = guard.as_mut().expect("session set above");
            if s.mode == Mode::Pending {
                self.resolve(s)?;
            }
            self.write_record(s, event, summary, sanitize(detail))
        })();
        if res.is_err() {
            // The file may no longer match the cached head (a write whose
            // rollback failed, a half-applied note). Never chain from a head the
            // disk might disagree with: re-read and reconcile on the next append.
            *guard = None;
        }
        res.map_err(|e| e.to_string())
    }

    /// Which of `want` (record ids) the live log already holds. Streams the
    /// whole file, keeping only matches, under the file lock and after any
    /// interrupted rotation is settled (so the file scanned is the one the
    /// next append goes to).
    fn ids_present(
        &self,
        want: &std::collections::HashSet<String>,
    ) -> Result<std::collections::HashSet<String>, KnownHostsError> {
        #[derive(Deserialize)]
        struct Line {
            #[serde(default)]
            detail: Ids,
        }
        #[derive(Deserialize, Default)]
        struct Ids {
            #[serde(default)]
            rid: Option<String>,
        }
        let mut found = std::collections::HashSet::new();
        let _lock = FileLock::acquire(&self.path)?;
        if self.recover_rotation()? == Rotation::Pending {
            return Err(KnownHostsError::Parse(ROTATION_PENDING.to_string()));
        }
        let f = match File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(found),
            Err(e) => return Err(io_err(&self.path)(e)),
        };
        for_each_line(f, |line| {
            if let Some(rid) = line.and_then(|l| serde_json::from_slice::<Line>(l).ok()).and_then(|l| l.detail.rid) {
                if want.contains(&rid) {
                    found.insert(rid);
                }
            }
        })
        .map_err(io_err(&self.path))?;
        Ok(found)
    }

    /// The newest `limit` records, newest first, from a tail window of the
    /// file (never the whole history): records are read backwards until
    /// `limit` lines are in hand or 32 MiB has been read.
    fn list(&self, limit: usize) -> Result<Vec<AuditView>, KnownHostsError> {
        const MAX_WINDOW: u64 = 32 * 1024 * 1024;
        let mut f = match File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(io_err(&self.path)(e)),
        };
        let len = f.metadata().map_err(io_err(&self.path))?.len();
        let mut start = len;
        let mut window: Vec<u8> = Vec::new();
        let chunk = 256 * 1024u64;
        while start > 0 && (len - start) < MAX_WINDOW {
            let take = start.min(chunk);
            start -= take;
            let mut buf = vec![0u8; take as usize];
            f.seek(SeekFrom::Start(start)).map_err(io_err(&self.path))?;
            f.read_exact(&mut buf).map_err(io_err(&self.path))?;
            buf.extend_from_slice(&window);
            window = buf;
            if window.iter().filter(|&&b| b == b'\n').count() > limit {
                break;
            }
        }
        // Unless the window reaches the start of the file, its first line may
        // be cut: skip it.
        let body: &[u8] = if start > 0 {
            match window.iter().position(|&b| b == b'\n') {
                Some(i) => &window[i + 1..],
                None => &[],
            }
        } else {
            &window
        };
        let mut out: Vec<AuditView> = Vec::new();
        for_each_line(body, |l| {
            if let Row::Record(e) = classify(l) {
                out.push(AuditView {
                    seq: e.seq,
                    ts: e.ts,
                    event: e.event,
                    summary: e.summary,
                    detail: e.detail,
                });
            }
        })
        .map_err(io_err(&self.path))?;
        out.sort_by(|a, b| b.seq.cmp(&a.seq));
        out.truncate(limit);
        Ok(out)
    }

    /// Walk the chain and compare it with the seal. The file handle, its
    /// length and the seal are taken together under the writer and
    /// cross-process locks, so they never show different stages of one
    /// append; the walk itself runs without them. (The writer thread runs the
    /// two halves on different threads.)
    #[cfg(test)]
    fn verify(&self) -> Result<VerifyReport, KnownHostsError> {
        match self.locked_snapshot()? {
            Ok(mut snap) => self.verify_snapshot(&mut snap).map(|(r, _)| r),
            Err(pending) => Ok(pending),
        }
    }

    /// Take a [`Snapshot`] under the session and cross-process locks (held
    /// only for this: a recovery check, a tail read, a seal read). `Err` is
    /// the report for a rotation still pending on the keychain.
    fn locked_snapshot(&self) -> Result<Result<Snapshot, VerifyReport>, KnownHostsError> {
        let _guard = self.session.lock().map_err(|_| KnownHostsError::Io {
            path: self.path.clone(),
            source: std::io::Error::other("audit lock poisoned"),
        })?;
        let _lock = FileLock::acquire(&self.path)?;
        if self.recover_rotation()? == Rotation::Pending {
            return Ok(Err(VerifyReport {
                ok: false,
                status: Status::Warning,
                count: 0,
                message: format!("Cannot verify yet: {ROTATION_PENDING}."),
                broken_at: None,
                seal_status: "unavailable".to_string(),
            }));
        }
        self.take_snapshot().map(Ok)
    }

    /// The snapshot itself; the caller holds the locks.
    fn take_snapshot(&self) -> Result<Snapshot, KnownHostsError> {
        let mut file = match File::open(&self.path) {
            Ok(f) => Some(f),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(io_err(&self.path)(e)),
        };
        let (len, keep, torn) = match file.as_mut() {
            Some(f) => split_torn_in(f, &self.path)?,
            None => (0, 0, false),
        };
        Ok(Snapshot { file, len, keep, torn, seal: self.anchor.read(), stamp: stamp(&self.path) })
    }

    /// Walk the archive pins back through the generations: the current log's
    /// opening `audit.archived` record pins its predecessor by SHA-256, whose
    /// own opening record pins the one before, and so on.
    ///
    /// The immediate predecessor must be present and intact (fatal otherwise).
    /// An older archive that is missing is only a warning: deleting old logs to
    /// free space is ordinary, and making it fatal would leave a log that no
    /// archive could ever clear. An archive that is present but modified fails
    /// at any depth (delete it to downgrade that to the warning).
    fn archived_log_problem(&self, first: Option<&AuditEntry>) -> Option<PinProblem> {
        let mut first = first?.clone();
        let mut seen = std::collections::HashSet::new();
        let mut depth = 0u32;
        while first.event == EV_ARCHIVED {
            let (Some(name), Some(want)) = (
                first.detail.get("archivedAs").and_then(Value::as_str),
                first.detail.get("archivedSha256").and_then(Value::as_str),
            ) else {
                return None; // the log before this one was empty: nothing pinned
            };
            let fatal = |message: String| Some(PinProblem { fatal: true, message });
            // Only a bare file name beside the log: a crafted record cannot point
            // the check elsewhere (it is hashed and anchored, but be strict anyway).
            if name.contains(['/', '\\', ':', '\0']) || name.starts_with('.') {
                return fatal(format!("the archive name {name:?} is not a plain file name"));
            }
            if !seen.insert(name.to_string()) {
                return fatal(format!("the archive chain loops back to {name}"));
            }
            let path = self.path.with_file_name(name);
            let (sha, opening) = match std::fs::symlink_metadata(&path) {
                Ok(m) if m.is_file() => match hash_file(&path) {
                    Ok(r) => r,
                    Err(_) => return fatal(format!("the archived log {name} is unreadable")),
                },
                Ok(_) => return fatal(format!("the archived log {name} is not a regular file")),
                Err(_) if depth == 0 => {
                    return fatal(format!("the archived log {name} (the previous log) is missing"))
                }
                Err(_) => {
                    return Some(PinProblem {
                        fatal: false,
                        message: format!("an older archived log, {name}, has been deleted, so the history before it can no longer be checked"),
                    })
                }
            };
            if sha != want {
                return fatal(format!("the archived log {name} was modified after it was archived"));
            }
            // The archiving record pinned the predecessor's verdict too. If that
            // was not a clean pass, its problems (an older archive deleted or
            // modified, gaps) were already judged and sealed into this record:
            // archiving is the documented way past them, so stop here.
            if !matches!(first.detail.get("priorStatus").and_then(Value::as_str), Some("verified" | "empty")) {
                return None;
            }
            // Pinned and intact: its own first record is now trusted, so follow it.
            match opening {
                Some(e) => first = e,
                None => return None,
            }
            depth += 1;
        }
        None
    }

    /// The report, plus the last parseable record (for an archive's pin).
    fn verify_locked(&self) -> Result<(VerifyReport, Option<(u64, String)>), KnownHostsError> {
        let mut snap = self.take_snapshot()?;
        self.verify_snapshot(&mut snap)
    }

    /// Verify a snapshot. Needs no lock: it reads only the snapshot's handle
    /// (up to `keep`) and the immutable archives.
    fn verify_snapshot(&self, snap: &mut Snapshot) -> Result<(VerifyReport, Option<(u64, String)>), KnownHostsError> {
        #[cfg(test)]
        if let Some(gate) = self.faults.verify_gate.lock().unwrap().take() {
            let _ = gate.recv();
        }
        let (keep, torn) = (snap.keep, snap.torn);
        let seal = snap.seal.clone();
        let chain = match snap.file.as_mut() {
            Some(f) => {
                f.seek(SeekFrom::Start(0)).map_err(io_err(&self.path))?;
                walk_reader(&*f, Some(keep), &wanted(&seal)).map_err(io_err(&self.path))?
            }
            None => walk_reader(std::io::empty(), None, &wanted(&seal)).map_err(io_err(&self.path))?,
        };
        let count = chain.rows;
        let mut decision = reconcile(&chain, &seal);
        let pin = self.archived_log_problem(chain.first.as_ref());
        if let Some(p) = pin.as_ref().filter(|p| p.fatal) {
            if !matches!(decision, Decision::Mismatch(_)) {
                decision = Decision::Mismatch(p.message.clone());
            }
        }
        let entries = |n: u64| format!("{n} entr{}", if n == 1 { "y" } else { "ies" });
        let mut notes = chain.notes.clone();
        if chain.more_notes > 0 {
            notes.push(format!("and {} more", chain.more_notes));
        }

        let (status, mut message, broken_at) = match decision {
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
            Decision::Anchored if torn || !notes.is_empty() || pin.is_some() => {
                let mut why = notes.clone();
                if torn {
                    why.push("an incomplete trailing line is present".to_string());
                }
                if let Some(p) = &pin {
                    why.push(p.message.clone());
                }
                (
                    Status::Warning,
                    format!(
                        "Verified {} against the keychain anchor, with gaps: {}. Archive the log to start a fully verified one.",
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
        // Whatever the verdict, an archive problem is never hidden behind it.
        if let Some(p) = &pin {
            if !message.contains(&p.message) {
                message.push_str(&format!(" Also: {}.", p.message));
            }
        }
        let seal_status = match seal {
            SealRead::Absent => "absent",
            SealRead::Unavailable => "unavailable",
            SealRead::Malformed => "malformed",
            SealRead::Present(..) => "present",
            SealRead::Frozen(_) => "frozen",
        };
        Ok((
            VerifyReport {
                ok: status == Status::Verified,
                status,
                count,
                message,
                broken_at,
                seal_status: seal_status.to_string(),
            },
            chain.last,
        ))
    }

    /// Where an archive's replacement log is staged until the rotation commits.
    fn rotating_path(&self) -> PathBuf {
        self.path.with_extension("jsonl.rotating")
    }

    /// Move a staged file that can never commit out of the way, kept as
    /// evidence. Best effort: such a file cannot commit anyway (only a valid
    /// opening record can match the seal), so failing to move it must not
    /// block the log.
    fn quarantine(&self, staged: &Path, why: &str) {
        let dest = unused_sibling(staged, "audit.jsonl.rotating.bad");
        if let Err(e) = std::fs::rename(staged, &dest) {
            eprintln!("hawser: could not set aside the unusable staged audit log ({why}): {e}");
        } else {
            eprintln!("hawser: set aside an unusable staged audit log ({why}) as {}", dest.display());
        }
    }

    /// Finish or discard an archive interrupted by a crash or an I/O error.
    ///
    /// Rotation is a small transaction whose commit point is the seal:
    ///   1. the new log's opening record is written, synced, to `.rotating`;
    ///   2. the seal is moved to that record (commit);
    ///   3. the old log is renamed to its archive name;
    ///   4. `.rotating` becomes the live log.
    /// If the seal already names the staged record, the rotation committed and
    /// steps 3–4 are completed here. Otherwise it never committed: the staged
    /// file is discarded and the old log, still sealed, carries on unchanged.
    /// A forged `.rotating` cannot commit itself, because only the app can
    /// write the seal.
    ///
    /// A staged file that is not exactly one valid opening record (torn by a
    /// crash during step 1, not UTF-8, a directory, junk) cannot have
    /// committed, whatever the keychain says, so it is set aside without
    /// consulting the keychain.
    ///
    /// Returns [`Rotation::Pending`] while a valid staged record exists and the
    /// seal is unreadable: it is unknown whether the old or the staged file is
    /// the live one, so nothing may open or append to the log.
    fn recover_rotation(&self) -> Result<Rotation, KnownHostsError> {
        let staged = self.rotating_path();
        let meta = match std::fs::symlink_metadata(&staged) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Rotation::Clear),
            Err(_) => {
                self.quarantine(&staged, "unreadable");
                return Ok(Rotation::Clear);
            }
        };
        if !meta.is_file() || meta.len() > MAX_STAGED {
            self.quarantine(&staged, "not a staged record");
            return Ok(Rotation::Clear);
        }
        let bytes = match std::fs::read(&staged) {
            Ok(b) => b,
            Err(_) => {
                self.quarantine(&staged, "unreadable");
                return Ok(Rotation::Clear);
            }
        };
        let mut rows = Vec::new();
        let _ = for_each_line(&bytes[..], |l| match classify(l) {
            Row::Blank => {}
            r => rows.push(r),
        });
        let opening = match rows.as_slice() {
            [Row::Record(e)] if e.seq == 1 && e.event == EV_ARCHIVED && hash_entry(e) == e.hash => e,
            _ => {
                self.quarantine(&staged, "not one valid opening record");
                return Ok(Rotation::Clear);
            }
        };
        let committed = match self.anchor.read() {
            SealRead::Present(1, h) => h == opening.hash,
            SealRead::Unavailable => return Ok(Rotation::Pending),
            _ => false,
        };
        if !committed {
            std::fs::remove_file(&staged).map_err(io_err(&staged))?;
            return Ok(Rotation::Clear);
        }
        if let Some(name) = opening.detail.get("archivedAs").and_then(Value::as_str) {
            let dest = self.path.with_file_name(name);
            if self.path.exists() && std::fs::symlink_metadata(&dest).is_err() {
                std::fs::rename(&self.path, &dest).map_err(io_err(&dest))?;
            }
        }
        std::fs::rename(&staged, &self.path).map_err(io_err(&self.path))?;
        sync_dir(&self.path).map_err(io_err(&self.path))?;
        Ok(Rotation::Clear)
    }

    #[cfg(test)]
    fn crash_point(&self, step: u8) -> Result<(), String> {
        let at = self.faults.crash_archive_after.load(std::sync::atomic::Ordering::SeqCst);
        if at == step {
            return Err(format!("injected crash after archive step {step}"));
        }
        Ok(())
    }

    /// Move the current log aside (kept, never deleted) and start a fresh one.
    /// The new log's first record, anchored like any other, pins the archived
    /// file by SHA-256 together with its last head and the verdict it had, so
    /// the archive stays tamper-evident after the seal moves on. See
    /// [`Self::recover_rotation`] for the crash-safe ordering. Returns the
    /// archive's file name.
    /// Everything under the locks (the writer uses `archive_prepared`).
    #[cfg(test)]
    fn archive(&self) -> Result<String, String> {
        self.archive_with(None)
    }

    /// Archive with the slow part (verifying and hashing the whole log) done
    /// on a snapshot OUTSIDE the locks, so appends carry on meanwhile. The
    /// commit then takes the locks and uses that work only if the file is
    /// still exactly the one snapshotted; otherwise (records were appended
    /// meanwhile) it is redone under the locks, so nothing is ever archived
    /// without being pinned.
    fn archive_prepared(&self) -> Result<String, String> {
        let prepared = self.prepare_archive()?;
        self.archive_with(Some(prepared))
    }

    /// The unlocked half of `archive_prepared`.
    fn prepare_archive(&self) -> Result<Prepared, String> {
        Ok(match self.locked_snapshot().map_err(|e| e.to_string())? {
            Err(_) => return Err(ROTATION_PENDING.to_string()),
            Ok(mut snap) => {
                let (prior, last) = self.verify_snapshot(&mut snap).map_err(|e| e.to_string())?;
                let sha = match snap.file.as_mut() {
                    Some(f) if snap.len > 0 => {
                        f.seek(SeekFrom::Start(0)).map_err(|e| format!("could not read the audit log: {e}"))?;
                        Some(hash_reader((&*f).take(snap.len)).map_err(|e| format!("could not read the audit log: {e}"))?.0)
                    }
                    _ => None,
                };
                Prepared { stamp: snap.stamp, prior, last, sha, len: snap.len }
            }
        })
    }

    fn archive_with(&self, prepared: Option<Prepared>) -> Result<String, String> {
        let mut guard = self.session.lock().map_err(|_| "audit lock poisoned".to_string())?;
        // Whatever happens below, the next append re-reads the disk.
        *guard = None;
        let _lock = FileLock::acquire(&self.path).map_err(|e| e.to_string())?;
        if self.recover_rotation().map_err(|e| e.to_string())? == Rotation::Pending {
            return Err(ROTATION_PENDING.to_string());
        }
        if matches!(self.anchor.read(), SealRead::Unavailable) {
            return Err("the keychain is unavailable; cannot archive without moving the anchor".into());
        }
        let now = stamp(&self.path);
        let (prior, last, sha, bytes_len) = match prepared.filter(|p| p.stamp == now) {
            Some(p) => (p.prior, p.last, p.sha, p.len),
            None => {
                let (prior, last) = self.verify_locked().map_err(|e| e.to_string())?;
                let bytes_len = file_len(&self.path).map_err(|e| e.to_string())?;
                let sha = if bytes_len > 0 {
                    Some(hash_file(&self.path).map_err(|e| format!("could not read the audit log: {e}"))?.0)
                } else {
                    None
                };
                (prior, last, sha, bytes_len)
            }
        };

        // A name never used before: the timestamp plus the archived file's
        // hash, so a deleted archive's name is never handed to a different
        // file (a pin naming it must keep meaning that file), and two archives
        // in the same second cannot collide.
        let ts = now_secs();
        let tag = sha.as_deref().map_or("empty".to_string(), |s| s[..12].to_string());
        let name = (0u32..)
            .map(|n| match n {
                0 => format!("audit-{ts}-{tag}.archived.jsonl"),
                n => format!("audit-{ts}-{tag}-{n}.archived.jsonl"),
            })
            .find(|name| std::fs::symlink_metadata(self.path.with_file_name(name)).is_err())
            .expect("an unused archive name exists");

        let mut d = BTreeMap::new();
        let status = serde_json::to_value(prior.status).unwrap_or(Value::Null);
        d.insert("priorStatus".to_string(), status);
        d.insert("priorMessage".to_string(), Value::String(cap(prior.message)));
        d.insert("priorSeal".to_string(), Value::String(prior.seal_status));
        let summary = match &sha {
            None => "started a new log (the previous one was empty)".to_string(),
            Some(sha) => {
                d.insert("archivedAs".to_string(), Value::String(name.clone()));
                d.insert("archivedSha256".to_string(), Value::String(sha.clone()));
                d.insert("archivedBytes".to_string(), Value::from(bytes_len));
                if let Some((seq, hash)) = last {
                    d.insert("archivedLastSeq".to_string(), Value::from(seq));
                    d.insert("archivedLastHash".to_string(), Value::String(hash));
                }
                format!("started a new log; the previous one was kept as {name}")
            }
        };
        let mut e = AuditEntry {
            seq: 1,
            ts: now_secs(),
            event: EV_ARCHIVED.to_string(),
            summary: cap(summary),
            detail: d,
            prev: GENESIS.to_string(),
            hash: String::new(),
        };
        e.hash = hash_entry(&e);
        let line = serde_json::to_string(&e).unwrap_or_default() + "\n";

        // 1. Stage the opening record durably.
        let staged = self.rotating_path();
        let stage = || -> std::io::Result<()> {
            let mut opts = OpenOptions::new();
            opts.create(true).write(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts.open(&staged)?;
            f.write_all(line.as_bytes())?;
            f.sync_all()
        };
        // The staged file's directory entry must be durable before the commit:
        // a seal pointing at a file that power loss erased could never recover.
        stage().and_then(|_| sync_dir(&staged)).map_err(|err| {
            let _ = std::fs::remove_file(&staged);
            format!("could not stage the new audit log: {err}")
        })?;
        #[cfg(test)]
        self.crash_point(1)?;

        // 2. Commit: move the seal to the staged record. An error does not
        // prove the write did not land (a keychain call can time out after it
        // stored the item), so the seal decides: if it names the staged record
        // the rotation committed and is finished; if it plainly does not, the
        // staged file is discarded; if it cannot be read, the staged file stays
        // for `recover_rotation` to decide later. Deleting it unconditionally
        // destroyed the only copy of the record a landed seal named, and the
        // old log then read as rewritten.
        if let Err(err) = self.anchor.write(1, &e.hash) {
            match self.anchor.read() {
                SealRead::Present(1, h) if h == e.hash => {}
                SealRead::Unavailable => {
                    return Err(format!(
                        "could not move the keychain anchor ({err}); the archive finishes or is discarded once the keychain can be read"
                    ))
                }
                _ => {
                    let _ = std::fs::remove_file(&staged);
                    return Err(format!("could not move the keychain anchor: {err}"));
                }
            }
        }
        #[cfg(test)]
        self.crash_point(2)?;

        // 3–4. Committed: finish the renames (also what recovery would do).
        if sha.is_some() {
            std::fs::rename(&self.path, self.path.with_file_name(&name))
                .map_err(|err| format!("could not archive the audit log: {err}"))?;
        }
        #[cfg(test)]
        self.crash_point(3)?;
        std::fs::rename(&staged, &self.path)
            .map_err(|err| format!("could not activate the new audit log: {err}"))?;
        // Committed already; a failure here is reported, and recovery (or the
        // journal) completes what the renames did not make durable.
        sync_dir(&self.path).map_err(|err| format!("archived, but syncing the directory failed: {err}"))?;
        Ok(name)
    }
}

/// Whether an interrupted archive still blocks the log (see `recover_rotation`).
#[derive(Debug, PartialEq)]
enum Rotation {
    Clear,
    Pending,
}

const ROTATION_PENDING: &str = "an interrupted archive is waiting for the keychain to become readable; nothing can be recorded or verified until then";

/// fsync the directory holding `path`, so a file created or renamed in it
/// survives power loss. Errors propagate on Unix. Windows has no directory
/// handle to sync; NTFS journals the metadata itself.
fn sync_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        std::fs::File::open(dir)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/* ------------------------------------------------------------ writer thread */

/// Work for the writer thread. One thread owns the log and handles these in
/// the order they were queued, so a verify sees every record queued before it.
/// A verify or an archive only takes its snapshot there; the long part runs
/// on its own thread, so appends never wait behind it.
enum Job {
    Record { id: u64, event: String, summary: String, detail: Value },
    Verify(mpsc::Sender<Result<VerifyReport, String>>),
    Archive(mpsc::Sender<Result<String, String>>),
    Flush(mpsc::Sender<()>),
}

/// Records may queue up while the keychain shows a prompt (each seal waits on
/// it). Beyond this many the newest are dropped, counted, and the count is
/// itself recorded once the writer catches up, so a drop is never silent.
const QUEUE: usize = 16 * 1024;
/// Accepted-but-unwritten records kept for a spill (queued plus failed).
const MAX_PENDING: usize = 2 * QUEUE;

/// A record accepted by `record` and not yet durably written. Kept until the
/// append succeeds, so an exit that cannot wait for the writer (or an append
/// that failed) spills it instead of losing it.
struct PendingRec {
    event: String,
    summary: String,
    detail: Value,
    accepted: u64,
    /// The writer has started on it: at a spill it may or may not have landed.
    in_progress: bool,
}

#[derive(Default)]
struct Pending {
    next: u64,
    recs: BTreeMap<u64, PendingRec>,
    /// Set by the exit spill, in the same critical section that takes `recs`:
    /// admission is closed, and a record accepted after it is spilled on its
    /// own, straight into this folder, rather than left in a map nobody
    /// will spill again.
    closed: Option<PathBuf>,
}

type SharedPending = std::sync::Arc<Mutex<Pending>>;

fn lock_pending(p: &SharedPending) -> std::sync::MutexGuard<'_, Pending> {
    p.lock().unwrap_or_else(|e| e.into_inner())
}

struct Writer {
    tx: SyncSender<Job>,
    dropped: std::sync::Arc<AtomicU64>,
    pending: SharedPending,
}

impl Writer {
    /// `open` runs on the writer thread (resolving the path may copy files).
    fn spawn<A: Anchor + 'static>(
        open: impl FnOnce() -> Result<Log<A>, String> + Send + 'static,
    ) -> std::io::Result<Self> {
        let (tx, rx) = mpsc::sync_channel::<Job>(QUEUE);
        let dropped = std::sync::Arc::new(AtomicU64::new(0));
        let lost = std::sync::Arc::clone(&dropped);
        let pending: SharedPending = Default::default();
        let shared = std::sync::Arc::clone(&pending);
        std::thread::Builder::new()
            .name("hawser-audit".into())
            .spawn(move || serve(open().map(std::sync::Arc::new), rx, &lost, &shared))?;
        Ok(Self { tx, dropped, pending })
    }

    fn record(&self, event: &str, summary: String, detail: Value) {
        // Every accepted record carries a unique id from here on, in its
        // detail (so in the hashed entry): spill recovery skips any id the
        // log already holds, whatever else the record says.
        let detail = with_rid(detail, &super::artifacts::random_hex(16));
        let id = {
            let mut p = lock_pending(&self.pending);
            if let Some(dir) = p.closed.clone() {
                drop(p);
                let rec = PendingRec { event: event.to_string(), summary, detail, accepted: now_secs(), in_progress: false };
                if let Err(e) = write_spill(&dir, &spill_text([&rec].into_iter(), 0)) {
                    eprintln!("hawser: could not keep an audit record accepted during exit ({event}): {e}");
                }
                return;
            }
            if p.recs.len() >= MAX_PENDING {
                drop(p);
                if self.dropped.fetch_add(1, Ordering::SeqCst) == 0 {
                    eprintln!("hawser: audit backlog full; dropping records until the writer catches up ({event})");
                }
                return;
            }
            let id = p.next;
            p.next += 1;
            p.recs.insert(
                id,
                PendingRec { event: event.to_string(), summary: summary.clone(), detail: detail.clone(), accepted: now_secs(), in_progress: false },
            );
            id
        };
        let job = Job::Record { id, event: event.to_string(), summary, detail };
        match self.tx.try_send(job) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                lock_pending(&self.pending).recs.remove(&id);
                if self.dropped.fetch_add(1, Ordering::SeqCst) == 0 {
                    eprintln!("hawser: audit queue full; dropping records until the writer catches up ({event})");
                }
            }
            Err(TrySendError::Disconnected(_)) => {
                // Kept in `pending`: spilled at exit, recorded next start.
                eprintln!("hawser: audit writer is gone; ({event}) is kept for the next start");
            }
        }
    }

    fn ask<T>(&self, make: impl FnOnce(mpsc::Sender<T>) -> Job) -> Option<T> {
        let (tx, rx) = mpsc::channel();
        self.tx.send(make(tx)).ok()?;
        rx.recv().ok()
    }

    /// Wait up to `timeout` for everything queued so far to be handled.
    /// True when the writer answered in time.
    fn flush(&self, timeout: Duration) -> bool {
        let (tx, rx) = mpsc::channel();
        // std's SyncSender has no send_timeout: retry try_send until the deadline.
        let deadline = Instant::now() + timeout;
        let mut job = Job::Flush(tx);
        loop {
            match self.tx.try_send(job) {
                Ok(()) => break,
                Err(TrySendError::Disconnected(_)) => return false,
                Err(TrySendError::Full(j)) => {
                    if Instant::now() >= deadline {
                        return false;
                    }
                    job = j;
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }
        rx.recv_timeout(deadline.saturating_duration_since(Instant::now())).is_ok()
    }

    /// Move every accepted-but-unwritten record into `dir/audit.pending-<ts>.jsonl`
    /// (0600), one JSON object per line, and close admission: a record accepted
    /// after this is spilled to a file of its own (see `record`). The writer
    /// skips any record it has not started yet once it is spilled; one it had
    /// started may still land, and is skipped at ingest by its id. Returns
    /// the file.
    fn spill(&self, dir: &Path) -> std::io::Result<Option<PathBuf>> {
        let recs = {
            let mut p = lock_pending(&self.pending);
            p.closed = Some(dir.to_path_buf());
            std::mem::take(&mut p.recs)
        };
        let lost = self.dropped.swap(0, Ordering::SeqCst);
        if recs.is_empty() && lost == 0 {
            return Ok(None);
        }
        write_spill(dir, &spill_text(recs.values(), lost)).map(Some)
    }
}

/// `detail` with the record id `rid` added (a non-object detail is wrapped as
/// `value`, exactly as `sanitize` would store it).
fn with_rid(detail: Value, rid: &str) -> Value {
    let mut map = match detail {
        Value::Object(m) => m,
        Value::Null => serde_json::Map::new(),
        other => serde_json::Map::from_iter([("value".to_string(), other)]),
    };
    map.insert(RID.into(), Value::String(rid.to_string()));
    Value::Object(map)
}

/// The record id stored in a detail object, if any.
fn rid_of(detail: &Value) -> Option<&str> {
    detail.get(RID).and_then(Value::as_str)
}

/// Spill-file text: one JSON object per record, plus a dropped-count note.
fn spill_text<'a>(recs: impl Iterator<Item = &'a PendingRec>, lost: u64) -> String {
    let mut text = String::new();
    for r in recs {
        let line = serde_json::json!({
            "event": r.event, "summary": r.summary, "detail": r.detail,
            "accepted": r.accepted, "uncertain": r.in_progress,
        });
        text.push_str(&line.to_string());
        text.push('\n');
    }
    if lost > 0 {
        let line = serde_json::json!({
            "event": EV_DROPPED,
            "summary": format!("{lost} audit entr{} could not be recorded: the writer was blocked and its queue was full", if lost == 1 { "y" } else { "ies" }),
            "detail": with_rid(serde_json::json!({ "count": lost }), &super::artifacts::random_hex(16)),
            "accepted": now_secs(), "uncertain": false,
        });
        text.push_str(&line.to_string());
        text.push('\n');
    }
    text
}

/// Write `text` to a new `dir/audit.pending-<ts>[-n].jsonl` (0600, synced).
fn write_spill(dir: &Path, text: &str) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let ts = now_secs();
    for n in 0..1000u32 {
        let name = match n {
            0 => format!("{PENDING_PREFIX}{ts}{PENDING_SUFFIX}"),
            n => format!("{PENDING_PREFIX}{ts}-{n}{PENDING_SUFFIX}"),
        };
        let path = dir.join(name);
        let mut opts = OpenOptions::new();
        opts.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        match opts.open(&path) {
            Ok(mut f) => {
                f.write_all(text.as_bytes())?;
                f.sync_all()?;
                let _ = sync_dir(&path);
                return Ok(path);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::other("no free audit.pending file name"))
}

fn serve<A: Anchor + 'static>(
    log: Result<std::sync::Arc<Log<A>>, String>,
    rx: Receiver<Job>,
    dropped: &AtomicU64,
    pending: &SharedPending,
) {
    if let Ok(l) = &log {
        ingest_pending(l);
    }
    for job in rx {
        let log = match &log {
            Ok(l) => l,
            Err(e) => {
                match job {
                    // Kept in `pending` for a spill at exit.
                    Job::Record { event, .. } => eprintln!("hawser: audit append failed ({event}): {e}"),
                    Job::Verify(r) => drop(r.send(Err(e.clone()))),
                    Job::Archive(r) => drop(r.send(Err(e.clone()))),
                    Job::Flush(r) => drop(r.send(())),
                }
                continue;
            }
        };
        let lost = dropped.swap(0, Ordering::SeqCst);
        if lost > 0 {
            let res = log.record(
                EV_DROPPED,
                &format!("{lost} audit entr{} could not be recorded: the writer was blocked (a keychain prompt?) and its queue was full", if lost == 1 { "y" } else { "ies" }),
                serde_json::json!({ "count": lost }),
            );
            if let Err(e) = res {
                eprintln!("hawser: audit append failed ({EV_DROPPED}): {e}");
            }
        }
        match job {
            Job::Record { id, event, summary, detail } => {
                // Claim it; a record already spilled (exit) is not written.
                let claimed = match lock_pending(pending).recs.get_mut(&id) {
                    Some(r) => {
                        r.in_progress = true;
                        true
                    }
                    None => false,
                };
                if !claimed {
                    continue;
                }
                let res = log.record(&event, &summary, detail);
                let mut p = lock_pending(pending);
                match res {
                    Ok(()) => {
                        p.recs.remove(&id);
                    }
                    Err(e) => {
                        // Kept: a spill at exit carries it to the next start.
                        if let Some(r) = p.recs.get_mut(&id) {
                            r.in_progress = false;
                        }
                        eprintln!("hawser: audit append failed ({event}): {e}; kept for the next start");
                    }
                }
            }
            Job::Verify(r) => match log.locked_snapshot() {
                Ok(Ok(mut snap)) => {
                    let l = std::sync::Arc::clone(log);
                    let spawned = std::thread::Builder::new().name("hawser-audit-verify".into()).spawn(move || {
                        drop(r.send(l.verify_snapshot(&mut snap).map(|(v, _)| v).map_err(|e| e.to_string())))
                    });
                    if let Err(e) = spawned {
                        eprintln!("hawser: could not start an audit verify: {e}");
                    }
                }
                Ok(Err(report)) => drop(r.send(Ok(report))),
                Err(e) => drop(r.send(Err(e.to_string()))),
            },
            Job::Archive(r) => {
                let l = std::sync::Arc::clone(log);
                let spawned = std::thread::Builder::new()
                    .name("hawser-audit-archive".into())
                    .spawn(move || drop(r.send(l.archive_prepared())));
                if let Err(e) = spawned {
                    eprintln!("hawser: could not start an audit archive: {e}");
                }
            }
            Job::Flush(r) => drop(r.send(())),
        }
    }
}

/// Record what an earlier exit spilled (`audit.pending-*.jsonl` beside the
/// log): an `audit.recovered` note per file, then each record, with the time
/// it was originally accepted.
///
/// Idempotent, by record id: every spilled record carries the id it was given
/// when it was accepted, and the note gets one derived from the file. Before
/// a file is replayed the whole live log is scanned (streaming) for those
/// ids, and any already present is skipped: one the writer did land after
/// all, and everything a crash mid-recovery already wrote. A file is removed
/// only once all of it is recorded; a removal that fails just repeats the
/// (now empty) pass next time. Spill files from builds before record ids fall
/// back to matching an uncertain record against the log's recent tail.
fn ingest_pending<A: Anchor>(log: &Log<A>) {
    let Some(dir) = log.path.parent() else { return };
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    let mut files: Vec<PathBuf> = rd
        .flatten()
        .filter(|e| {
            let n = e.file_name().to_string_lossy().to_string();
            n.starts_with(PENDING_PREFIX) && n.ends_with(PENDING_SUFFIX) && e.file_type().is_ok_and(|t| t.is_file())
        })
        .map(|e| e.path())
        .collect();
    files.sort();
    for file in files {
        let Ok(bytes) = std::fs::read(&file) else { continue };
        let mut rows: Vec<Value> = Vec::new();
        let mut bad = 0u64;
        let _ = for_each_line(&bytes[..], |l| match l.map(serde_json::from_slice::<Value>) {
            Some(Ok(v)) if v.get("event").and_then(Value::as_str).is_some() => rows.push(v),
            Some(_) => bad += 1,
            None => bad += 1,
        });
        let name = file.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        let note_rid = format!("recovered-{}", &hex(&Sha256::digest([name.as_bytes(), b"\0", &bytes].concat()))[..32]);
        let mut want: std::collections::HashSet<String> =
            rows.iter().filter_map(|v| v.get("detail").and_then(rid_of)).map(str::to_string).collect();
        want.insert(note_rid.clone());
        let present = match log.ids_present(&want) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("hawser: could not record spilled audit entries yet ({e}); kept {name}");
                return;
            }
        };
        if !present.contains(&note_rid) {
            let note = log.record(
                EV_RECOVERED,
                &format!(
                    "{} audit entr{} accepted before the previous exit, which could not wait for them, are recorded below (from {name}){}",
                    rows.len(),
                    if rows.len() == 1 { "y" } else { "ies" },
                    if bad > 0 { format!("; {bad} unreadable line(s) skipped") } else { String::new() }
                ),
                serde_json::json!({ "count": rows.len(), "file": name, "unreadable": bad, RID: note_rid }),
            );
            if let Err(e) = note {
                eprintln!("hawser: could not record spilled audit entries yet ({e}); kept {name}");
                return;
            }
        }
        let mut recent: Option<Vec<AuditView>> = None;
        for v in rows {
            let event = v.get("event").and_then(Value::as_str).unwrap_or_default().to_string();
            let summary = v.get("summary").and_then(Value::as_str).unwrap_or_default().to_string();
            let mut detail = v.get("detail").cloned().unwrap_or(Value::Null);
            match rid_of(&detail) {
                Some(r) if present.contains(r) => continue,
                Some(_) => {}
                // A pre-id spill: the old best-effort tail match.
                None if v.get("uncertain").and_then(Value::as_bool) == Some(true) => {
                    let want = sanitize(detail.clone());
                    let tail = recent.get_or_insert_with(|| log.list(256).unwrap_or_default());
                    if tail.iter().any(|r| r.event == event && r.summary == summary && r.detail == want) {
                        continue;
                    }
                }
                None => {}
            }
            if !detail.is_object() {
                detail = serde_json::json!({ "value": detail });
            }
            if let Some(o) = detail.as_object_mut() {
                o.insert("acceptedAt".into(), v.get("accepted").cloned().unwrap_or(Value::Null));
                o.insert("recovered".into(), Value::Bool(true));
            }
            if let Err(e) = log.record(&event, &summary, detail) {
                eprintln!("hawser: could not record spilled audit entries yet ({e}); kept {name}");
                return;
            }
        }
        if let Err(e) = std::fs::remove_file(&file) {
            eprintln!("hawser: recorded but could not remove {name}: {e}");
        }
    }
}

/* ------------------------------------------------------------------ public */

/// Where the live log is. Beside hosts.json, except on Windows, where that is
/// the ROAMING profile while the keychain seal (CRED_PERSIST_LOCAL_MACHINE)
/// is per machine: a roaming log would be checked against another machine's
/// seal. There it lives under %LOCALAPPDATA%, copied once from the roaming
/// folder (archives included, so their pins still resolve).
fn audit_path() -> Result<PathBuf, String> {
    static PATH: OnceLock<Result<PathBuf, String>> = OnceLock::new();
    PATH.get_or_init(resolve_audit_path).clone()
}

fn resolve_audit_path() -> Result<PathBuf, String> {
    let store = store_path().map_err(|e| e.to_string())?;
    let roaming = store.parent().ok_or("no app data directory")?.to_path_buf();
    #[cfg(windows)]
    {
        if let Some(local) = std::env::var_os("LOCALAPPDATA").filter(|v| !v.is_empty()) {
            let local = PathBuf::from(local).join("hawser");
            if local != roaming {
                if let Err(e) = migrate_audit_files(&roaming, &local) {
                    eprintln!("hawser: could not move the audit log to the local profile: {e}");
                    return Ok(roaming.join(AUDIT_FILE));
                }
            }
            return Ok(local.join(AUDIT_FILE));
        }
    }
    Ok(roaming.join(AUDIT_FILE))
}

/// Copy the audit files (`audit.jsonl`, its archives, torn evidence and a
/// staged rotation) from `from` into `to`. The originals are left in place,
/// since a roaming profile shares them with other machines.
///
/// Crash-safe and retried until it completes: each file is copied to a temp
/// name, synced, and only then renamed into place, and `audit.migrated` is
/// written LAST. Without the marker the migration runs again; a destination
/// that is a strict prefix of its source (a copy an older build cut short) is
/// replaced, while one that is complete or has grown past its source (this
/// machine appended to it) is kept.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
fn migrate_audit_files(from: &Path, to: &Path) -> std::io::Result<()> {
    let marker = to.join("audit.migrated");
    if marker.exists() {
        return Ok(());
    }
    std::fs::create_dir_all(to)?;
    super::platform::restrict_perms(to, 0o700);
    // Every error below propagates, so the marker is written only once every
    // source file was read and copied. A missing source folder has nothing to
    // copy; any other failure to list it is an error, never "nothing there".
    match std::fs::read_dir(from) {
        Ok(dir) => {
            for entry in dir {
                let entry = entry?;
                let name = entry.file_name();
                let name = name.to_string_lossy();
                let ours = name == AUDIT_FILE
                    || (name.starts_with("audit-") && name.ends_with(".archived.jsonl"))
                    || name.starts_with("audit.jsonl.");
                if !ours || name.ends_with(".lock") || !entry.file_type()?.is_file() {
                    continue;
                }
                let dest = to.join(&*name);
                if !migration_needs_copy(&entry.path(), &dest)? {
                    continue;
                }
                let tmp = to.join(format!(".migrating-{name}"));
                let _ = std::fs::remove_file(&tmp);
                copy_synced(&mut File::open(entry.path())?, &tmp)?;
                std::fs::rename(&tmp, &dest)?;
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    sync_dir(&marker)?;
    let tmp = to.join(".migrating-audit.migrated");
    let _ = std::fs::remove_file(&tmp);
    copy_synced(&mut &b"1\n"[..], &tmp)?;
    std::fs::rename(&tmp, &marker)?;
    sync_dir(&marker)
}

/// Copy `src` into a new file at `dest` and sync it through the SAME write
/// handle before closing it. (Windows FlushFileBuffers needs write access: a
/// sync through a handle reopened read-only fails with access denied.)
fn copy_synced(src: &mut impl Read, dest: &Path) -> std::io::Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut out = opts.open(dest)?;
    std::io::copy(src, &mut out)?;
    out.sync_all()
}

/// Whether `dest` still needs `src` copied over it: missing, or a strict
/// prefix of `src` (an interrupted copy). Anything else is kept.
fn migration_needs_copy(src: &Path, dest: &Path) -> std::io::Result<bool> {
    let dlen = match std::fs::metadata(dest) {
        Ok(m) => m.len(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(e) => return Err(e),
    };
    let slen = std::fs::metadata(src)?.len();
    if dlen >= slen {
        return Ok(false);
    }
    let (mut a, mut b) = (BufReader::new(File::open(src)?), BufReader::new(File::open(dest)?));
    let (mut x, mut y) = (vec![0u8; 64 * 1024], vec![0u8; 64 * 1024]);
    let mut left = dlen;
    while left > 0 {
        let n = (left.min(x.len() as u64)) as usize;
        a.read_exact(&mut x[..n])?;
        b.read_exact(&mut y[..n])?;
        if x[..n] != y[..n] {
            return Ok(false);
        }
        left -= n as u64;
    }
    Ok(true)
}

fn writer() -> Option<&'static Writer> {
    static W: OnceLock<Option<Writer>> = OnceLock::new();
    W.get_or_init(|| {
        match Writer::spawn(|| audit_path().map(|p| Log::new(p, Keychain))) {
            Ok(w) => Some(w),
            Err(e) => {
                eprintln!("hawser: could not start the audit writer: {e}");
                None
            }
        }
    })
    .as_ref()
}

/// Start the writer thread now (at app startup) rather than on the first
/// record. Never blocks on the file or the keychain.
pub fn start() {
    let _ = writer();
}

/// Append one record. Fire-and-forget and non-blocking: the record is queued
/// for the writer thread, which does the file sync and the keychain seal, so
/// an audited command never waits on either (a keychain prompt included).
/// Errors are logged to stderr. Pass `detail` from `serde_json::json!`; it is
/// flattened by [`sanitize`]. Never pass a password, key, command text, or
/// command output.
pub fn record(event: &str, summary: impl Into<String>, detail: Value) {
    match writer() {
        Some(w) => w.record(event, summary.into(), detail),
        None => eprintln!("hawser: audit append failed ({event}): no audit writer"),
    }
}

/// At exit: wait (up to `timeout`) for every record queued so far to be
/// written, then spill whatever is still unwritten — records the writer could
/// not reach in time (a long keychain prompt, another process holding the
/// log), and records whose append failed — to `audit.pending-<ts>.jsonl`
/// beside the log. The next start records them (`audit.recovered`). So an
/// accepted record is never lost silently with the process.
pub fn shutdown(timeout: Duration) {
    let Some(w) = writer() else { return };
    if !w.flush(timeout) {
        eprintln!("hawser: the audit writer did not finish within {}s; spilling what is left", timeout.as_secs());
    }
    let dir = match audit_path() {
        Ok(p) => p.parent().map(Path::to_path_buf),
        Err(_) => None,
    };
    let Some(dir) = dir else {
        eprintln!("hawser: no audit folder; unwritten audit records are lost");
        return;
    };
    match w.spill(&dir) {
        Ok(Some(p)) => eprintln!("hawser: unwritten audit records kept in {} for the next start", p.display()),
        Ok(None) => {}
        Err(e) => eprintln!("hawser: could not keep unwritten audit records: {e}"),
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

/// Most recent `limit` records, newest first. Reads only a tail window of the
/// file; blocking, so call it off the async runtime.
pub fn list(limit: usize) -> Result<Vec<AuditView>, String> {
    let path = audit_path()?;
    Log::new(path, Keychain).list(limit).map_err(|e| e.to_string())
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

/// Verify on the writer thread, after every record queued before it. Blocking.
pub fn verify() -> Result<VerifyReport, String> {
    writer()
        .ok_or("no audit writer")?
        .ask(Job::Verify)
        .unwrap_or_else(|| Err("the audit writer stopped".into()))
}

/// Archive on the writer thread. Blocking.
pub fn archive() -> Result<String, String> {
    writer()
        .ok_or("no audit writer")?
        .ask(Job::Archive)
        .unwrap_or_else(|| Err("the audit writer stopped".into()))
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
        /// The next write lands, then reports failure (a keychain call that
        /// timed out after storing the item).
        land_then_fail: Arc<AtomicBool>,
    }

    impl Mem {
        fn clear(&self) -> Result<(), String> {
            *self.seal.lock().unwrap() = None;
            Ok(())
        }
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
            if self.land_then_fail.swap(false, Ordering::SeqCst) {
                return Err("timed out".into());
            }
            Ok(())
        }
        fn freeze(&self, reason: &str) -> Result<(), String> {
            if self.fail_writes.load(Ordering::SeqCst) || self.unavailable.load(Ordering::SeqCst) {
                return Err("locked".into());
            }
            *self.seal.lock().unwrap() = Some(frozen_payload(reason));
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
    fn fsync_failure_never_reuses_a_sequence_number() {
        let (p, m) = (tmp(), Mem::default());
        let log = restart(&p, &m);
        rec(&log, 2);
        log.faults.fail_sync.store(true, Ordering::SeqCst);
        assert!(log.record("connect", "lost", json!({})).is_err());
        rec(&log, 2);
        let r = log.verify().unwrap();
        assert_eq!((r.status, r.count), (Status::Verified, 4), "{}", r.message);
        let seqs: Vec<u64> = lines(&p)
            .iter()
            .map(|l| serde_json::from_str::<AuditEntry>(l).unwrap().seq)
            .collect();
        assert_eq!(seqs, [1, 2, 3, 4]);
    }

    #[test]
    fn every_archive_generation_stays_pinned() {
        let (p, m) = (tmp(), Mem::default());
        let log = restart(&p, &m);
        rec(&log, 2);
        let a = log.archive().unwrap();
        rec(&log, 2);
        let b = log.archive().unwrap();
        rec(&log, 1);
        assert_eq!(status(&log), Status::Verified);
        // Tamper with the OLDER archive only; B (its pin holder) is untouched.
        let pa = p.with_file_name(&a);
        let t = std::fs::read_to_string(&pa).unwrap().replace("event 1", "event 8");
        std::fs::write(&pa, t).unwrap();
        let r = log.verify().unwrap();
        assert_eq!(r.status, Status::Failed, "{}", r.message);
        assert!(r.message.contains(&a), "{}", r.message);
        // Deleting an OLDER archive (to free space) is only a warning, and the
        // message names it; archiving once more clears it.
        std::fs::remove_file(&pa).unwrap();
        let r = log.verify().unwrap();
        assert_eq!(r.status, Status::Warning, "{}", r.message);
        assert!(r.message.contains(&a), "{}", r.message);
        log.archive().unwrap();
        rec(&log, 1);
        let r = log.verify().unwrap();
        assert_eq!(r.status, Status::Verified, "{}", r.message);
        let _ = b;
    }

    #[test]
    fn archive_interrupted_at_any_step_recovers() {
        for step in 1..=3u8 {
            let (p, m) = (tmp(), Mem::default());
            let log = restart(&p, &m);
            rec(&log, 3);
            log.faults.crash_archive_after.store(step, Ordering::SeqCst);
            assert!(log.archive().is_err(), "step {step}");
            // "Restart" and carry on.
            let log = restart(&p, &m);
            rec(&log, 1);
            let r = log.verify().unwrap();
            assert_eq!(r.status, Status::Verified, "step {step}: {}", r.message);
            assert!(!log.rotating_path().exists(), "step {step}");
            let first: AuditEntry = serde_json::from_str(&lines(&p)[0]).unwrap();
            if step == 1 {
                // Never committed: the old log carries on, nothing archived.
                assert_eq!((first.event.as_str(), r.count), ("connect", 4), "step {step}");
            } else {
                // Committed: rotation completed, the old log is pinned.
                assert_eq!((first.event.as_str(), r.count), (EV_ARCHIVED, 2), "step {step}");
                let name = first.detail["archivedAs"].as_str().unwrap();
                assert!(p.with_file_name(name).exists(), "step {step}");
            }
        }
    }

    #[test]
    fn interrupted_archive_blocks_appends_while_the_keychain_is_locked() {
        for step in 2..=3u8 {
            let (p, m) = (tmp(), Mem::default());
            let log = restart(&p, &m);
            rec(&log, 3);
            log.faults.crash_archive_after.store(step, Ordering::SeqCst);
            assert!(log.archive().is_err());
            let snapshot = |p: &Path| {
                let mut v: Vec<_> = std::fs::read_dir(p.parent().unwrap())
                    .unwrap()
                    .flatten()
                    .map(|e| (e.file_name(), std::fs::read(e.path()).unwrap()))
                    .collect();
                v.sort();
                v
            };
            let before = snapshot(&p);

            // Restart with the keychain locked: nothing may be written anywhere.
            m.unavailable.store(true, Ordering::SeqCst);
            let log = restart(&p, &m);
            assert!(log.record("connect", "x", json!({})).is_err(), "step {step}");
            assert!(log.record("connect", "y", json!({})).is_err(), "step {step}");
            assert_eq!(status(&log), Status::Warning, "step {step}");
            assert_eq!(snapshot(&p), before, "step {step}: files changed while pending");

            // Keychain back: the rotation completes and the log verifies.
            m.unavailable.store(false, Ordering::SeqCst);
            rec(&log, 1);
            let r = log.verify().unwrap();
            assert_eq!((r.status, r.count), (Status::Verified, 2), "step {step}: {}", r.message);
            assert!(lines(&p)[0].contains(EV_ARCHIVED));
        }
    }

    #[test]
    fn a_forged_staged_rotation_cannot_commit() {
        let (p, m) = (tmp(), Mem::default());
        rec(&restart(&p, &m), 2);
        // A file-only attacker stages an "archived" opening record of their own.
        let mut e = AuditEntry {
            seq: 1,
            ts: 1,
            event: EV_ARCHIVED.into(),
            summary: "started a new log".into(),
            detail: BTreeMap::new(),
            prev: GENESIS.into(),
            hash: String::new(),
        };
        e.hash = hash_entry(&e);
        let log = restart(&p, &m);
        std::fs::write(log.rotating_path(), serde_json::to_string(&e).unwrap() + "\n").unwrap();
        assert_eq!(status(&log), Status::Verified);
        assert!(!log.rotating_path().exists());
        assert_eq!(lines(&p).len(), 2);
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

    /* ---------------------------------------------------------- W4 regressions */

    fn append_raw(p: &Path, bytes: &[u8]) {
        let mut f = OpenOptions::new().append(true).open(p).unwrap();
        f.write_all(bytes).unwrap();
    }

    fn siblings(p: &Path, prefix: &str) -> Vec<PathBuf> {
        std::fs::read_dir(p.parent().unwrap())
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(prefix))
            .map(|e| e.path())
            .collect()
    }

    #[test]
    fn invalid_utf8_tail_is_torn_and_kept_as_evidence() {
        // A crash cut an append inside a multibyte character, or an attacker
        // appended one 0xFF byte: either way, a torn tail, not a dead log.
        for tail in [&b"{\"seq\":3,\"summary\":\"caf\xc3"[..], &b"\xff"[..]] {
            let (p, m) = (tmp(), Mem::default());
            rec(&restart(&p, &m), 2);
            append_raw(&p, tail);
            let log = restart(&p, &m);
            assert_eq!(status(&log), Status::Warning);
            rec(&log, 1);
            let ls = lines(&p);
            assert!(ls.iter().all(|l| serde_json::from_str::<AuditEntry>(l).is_ok()));
            assert!(ls.iter().any(|l| l.contains(EV_TORN)));
            let ev = siblings(&p, "audit.jsonl.torn-");
            assert_eq!(ev.len(), 1);
            assert_eq!(std::fs::read(&ev[0]).unwrap(), tail, "the dropped bytes are kept");
            let r = log.verify().unwrap();
            assert_eq!((r.status, r.count), (Status::Warning, 4), "{}", r.message);
            assert_eq!(log.list(10).unwrap().len(), 4);
        }
    }

    #[test]
    fn invalid_utf8_inside_the_log_is_a_failed_verify_not_an_error() {
        let (p, m) = (tmp(), Mem::default());
        rec(&restart(&p, &m), 3);
        let mut ls: Vec<Vec<u8>> = lines(&p).into_iter().map(String::into_bytes).collect();
        ls[1] = b"\xff\xfe not text".to_vec();
        let mut body = ls.join(&b'\n');
        body.push(b'\n');
        std::fs::write(&p, body).unwrap();
        let log = restart(&p, &m);
        let r = log.verify().expect("a report, never an error");
        assert_eq!((r.status, r.broken_at), (Status::Failed, Some(2)), "{}", r.message);
        // Listing and recording keep working; archiving is the way out.
        assert_eq!(log.list(10).unwrap().len(), 2);
        rec(&log, 1);
        log.archive().unwrap();
        rec(&log, 1);
        assert_eq!(status(&log), Status::Verified);
    }

    #[test]
    fn unusable_staged_rotation_is_quarantined_even_with_the_keychain_locked() {
        for kind in 0..3 {
            let (p, m) = (tmp(), Mem::default());
            rec(&restart(&p, &m), 2);
            let log = restart(&p, &m);
            let staged = log.rotating_path();
            match kind {
                0 => std::fs::write(&staged, b"\xff").unwrap(),
                1 => std::fs::create_dir(&staged).unwrap(),
                _ => std::fs::write(&staged, b"{\"seq\":1,\"ev").unwrap(),
            }
            // A junk file can never have committed: the keychain need not be
            // read, so a locked keychain does not block the log either.
            m.unavailable.store(true, Ordering::SeqCst);
            assert!(log.record("connect", "while locked", json!({})).is_ok(), "kind {kind}");
            m.unavailable.store(false, Ordering::SeqCst);
            assert!(!staged.exists(), "kind {kind}");
            assert_eq!(siblings(&p, "audit.jsonl.rotating.bad-").len(), 1, "kind {kind}");
            rec(&log, 1);
            assert_eq!(status(&log), Status::Verified, "kind {kind}");
        }
    }

    #[test]
    fn a_seal_that_landed_despite_an_error_completes_the_archive() {
        let (p, m) = (tmp(), Mem::default());
        let log = restart(&p, &m);
        rec(&log, 3);
        m.land_then_fail.store(true, Ordering::SeqCst);
        let name = log.archive().expect("the seal names the staged record: committed");
        assert!(p.with_file_name(&name).exists());
        rec(&log, 1);
        let r = restart(&p, &m).verify().unwrap();
        assert_eq!((r.status, r.count), (Status::Verified, 2), "{}", r.message);
    }

    #[test]
    fn a_seal_write_that_did_not_land_discards_the_staged_log() {
        let (p, m) = (tmp(), Mem::default());
        let log = restart(&p, &m);
        rec(&log, 3);
        m.fail_writes.store(true, Ordering::SeqCst);
        assert!(log.archive().is_err());
        m.fail_writes.store(false, Ordering::SeqCst);
        assert!(!log.rotating_path().exists());
        rec(&log, 1);
        let r = log.verify().unwrap();
        assert_eq!((r.status, r.count), (Status::Verified, 4), "{}", r.message);
    }

    #[test]
    fn archive_names_carry_the_archived_hash_and_are_never_reused() {
        let (p, m) = (tmp(), Mem::default());
        let log = restart(&p, &m);
        rec(&log, 2);
        let a = log.archive().unwrap();
        let first: AuditEntry = serde_json::from_str(&lines(&p)[0]).unwrap();
        let sha = first.detail["archivedSha256"].as_str().unwrap();
        assert!(a.contains(&sha[..12]), "{a}");
        rec(&log, 2);
        let b = log.archive().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn a_second_process_appending_never_forks_the_chain() {
        // Two Logs over one file and one seal = two app instances.
        let (p, m) = (tmp(), Mem::default());
        let a = restart(&p, &m);
        let b = restart(&p, &m);
        for i in 0..10 {
            let w = if i % 2 == 0 { &a } else { &b };
            w.record("connect", &format!("event {i}"), json!({})).unwrap();
        }
        // Concurrently too (the cross-process lock serialises the appends).
        let (a, b) = (Arc::new(a), Arc::new(b));
        let ts: Vec<_> = [Arc::clone(&a), Arc::clone(&b)]
            .into_iter()
            .map(|l| std::thread::spawn(move || rec(&l, 20)))
            .collect();
        for t in ts {
            t.join().unwrap();
        }
        let r = restart(&p, &m).verify().unwrap();
        assert_eq!((r.status, r.count), (Status::Verified, 50), "{}", r.message);
        assert!(!m.frozen());
    }

    #[test]
    fn a_failed_newline_repair_never_glues_two_records() {
        let (p, m) = (tmp(), Mem::default());
        rec(&restart(&p, &m), 2);
        // Strip the final newline: a complete record missing only that.
        let text = std::fs::read_to_string(&p).unwrap();
        std::fs::write(&p, text.trim_end_matches('\n')).unwrap();
        let log = restart(&p, &m);
        log.faults.fail_newline_repair.store(true, Ordering::SeqCst);
        assert!(log.record("connect", "x", json!({})).is_err(), "the session does not open");
        rec(&log, 1);
        let r = log.verify().unwrap();
        assert_eq!((r.status, r.count), (Status::Verified, 3), "{}", r.message);
    }

    #[test]
    fn list_reads_a_tail_window_newest_first() {
        let (p, m) = (tmp(), Mem::default());
        let log = restart(&p, &m);
        rec(&log, 60);
        let l = log.list(10).unwrap();
        assert_eq!(l.iter().map(|v| v.seq).collect::<Vec<_>>(), (51..=60).rev().collect::<Vec<_>>());
        assert_eq!(log.list(1000).unwrap().len(), 60);
        assert!(restart(&tmp(), &m).list(5).unwrap().is_empty());
    }

    #[test]
    fn overlong_lines_are_bad_rows_not_allocations() {
        let (p, m) = (tmp(), Mem::default());
        rec(&restart(&p, &m), 1);
        append_raw(&p, &vec![b'x'; MAX_LINE + 10]);
        append_raw(&p, b"\n");
        let r = restart(&p, &m).verify().unwrap();
        assert_eq!((r.status, r.broken_at), (Status::Failed, Some(2)), "{}", r.message);
    }

    #[test]
    fn the_writer_thread_keeps_order_and_answers_verify() {
        let (p, m) = (tmp(), Mem::default());
        let log = restart(&p, &m);
        let w = Writer::spawn(move || Ok(log)).unwrap();
        for i in 0..20 {
            w.record("connect", format!("event {i}"), json!({ "n": i }));
        }
        // Queued after the records, so it sees all of them.
        let r = w.ask(Job::Verify).unwrap().unwrap();
        assert_eq!((r.status, r.count), (Status::Verified, 20), "{}", r.message);
        let seqs: Vec<u64> = lines(&p)
            .iter()
            .map(|l| serde_json::from_str::<AuditEntry>(l).unwrap().seq)
            .collect();
        assert_eq!(seqs, (1..=20).collect::<Vec<_>>());
        // Dropped records (a full queue) are themselves recorded.
        w.dropped.store(3, Ordering::SeqCst);
        w.record("connect", "after".into(), json!({}));
        let r = w.ask(Job::Verify).unwrap().unwrap();
        assert_eq!((r.status, r.count), (Status::Warning, 22), "{}", r.message);
        assert!(lines(&p).iter().any(|l| l.contains(EV_DROPPED)));
        assert!(w.ask(Job::Flush).is_some());
    }

    #[test]
    fn a_pending_session_seals_only_an_unchanged_file() {
        let (p, m) = (tmp(), Mem::default());
        rec(&restart(&p, &m), 2);
        m.unavailable.store(true, Ordering::SeqCst);
        let log = restart(&p, &m);
        rec(&log, 2); // pending: written, not sealed
        m.unavailable.store(false, Ordering::SeqCst);
        rec(&log, 1); // resolves: anchored at 2, seals 5
        let r = log.verify().unwrap();
        assert_eq!((r.status, r.count), (Status::Verified, 5), "{}", r.message);
        assert_eq!(m.get().unwrap().0, 5);
    }

    #[test]
    fn audit_files_migrate_once_and_originals_stay() {
        let from = tmp().parent().unwrap().to_path_buf();
        let to = tmp().parent().unwrap().join("local");
        std::fs::write(from.join(AUDIT_FILE), b"log\n").unwrap();
        std::fs::write(from.join("audit-1-abc.archived.jsonl"), b"old\n").unwrap();
        std::fs::write(from.join("hosts.json"), b"[]").unwrap();
        migrate_audit_files(&from, &to).unwrap();
        assert_eq!(std::fs::read(to.join(AUDIT_FILE)).unwrap(), b"log\n");
        assert!(to.join("audit-1-abc.archived.jsonl").exists());
        assert!(!to.join("hosts.json").exists());
        assert!(from.join(AUDIT_FILE).exists());
        // Once: a later run never overwrites the local log.
        std::fs::write(to.join(AUDIT_FILE), b"newer\n").unwrap();
        std::fs::write(from.join(AUDIT_FILE), b"roamed\n").unwrap();
        migrate_audit_files(&from, &to).unwrap();
        assert_eq!(std::fs::read(to.join(AUDIT_FILE)).unwrap(), b"newer\n");
    }

    /// W4b: process B stages a rotation, moves the seal (commit) and dies
    /// before the renames. Process A, holding a cached head whose file length
    /// still matches, must complete B's committed rotation, not append to the
    /// old chain and seal it (which made the next recovery discard the stage).
    #[test]
    fn a_rotation_committed_by_another_process_is_completed_not_discarded() {
        let (p, m) = (tmp(), Mem::default());
        let a = restart(&p, &m);
        rec(&a, 3); // A has a cached session
        let b = restart(&p, &m);
        b.faults.crash_archive_after.store(2, Ordering::SeqCst);
        assert!(b.archive().is_err(), "B dies after the commit");
        drop(b);
        assert!(a.rotating_path().exists());
        a.record("connect", "after B", json!({})).unwrap();
        assert!(!a.rotating_path().exists(), "the committed stage was completed");
        let first: AuditEntry = serde_json::from_str(&lines(&p)[0]).unwrap();
        assert_eq!(first.event, EV_ARCHIVED, "A appended to the NEW log");
        let r = restart(&p, &m).verify().unwrap();
        assert_eq!((r.status, r.count), (Status::Verified, 2), "{}", r.message);
        assert!(!m.frozen());
    }

    /// W4b: a verify runs outside the writer and the log locks, so appends
    /// (and a flush) complete while it is still running.
    #[test]
    fn appends_never_wait_behind_a_verify() {
        let (p, m) = (tmp(), Mem::default());
        let log = restart(&p, &m);
        let (release, gate) = mpsc::channel();
        *log.faults.verify_gate.lock().unwrap() = Some(gate);
        let w = Writer::spawn(move || Ok(log)).unwrap();
        w.record("connect", "before".into(), json!({}));
        // Queued before the records below (the verify's place in the order).
        let (tx, verify) = mpsc::channel();
        w.tx.send(Job::Verify(tx)).unwrap();
        for i in 0..5 {
            w.record("connect", format!("during {i}"), json!({}));
        }
        assert!(w.flush(Duration::from_secs(5)), "appends finished while the verify was blocked");
        assert_eq!(lines(&p).len(), 6);
        release.send(()).unwrap();
        let r = verify.recv().unwrap().unwrap();
        // The verify saw the log as of its place in the queue.
        assert_eq!((r.status, r.count), (Status::Verified, 1), "{}", r.message);
        assert_eq!(restart(&p, &m).verify().unwrap().count, 6);
    }

    /// W4b: records the writer could not reach before exit are spilled, and
    /// the next start records them after an `audit.recovered` note.
    #[test]
    fn records_left_at_exit_are_spilled_and_recovered_next_start() {
        let (p, m) = (tmp(), Mem::default());
        rec(&restart(&p, &m), 1);
        // A writer stuck before it can write anything (a keychain prompt).
        let (release, stuck) = mpsc::channel::<()>();
        let (p2, m2) = (p.clone(), m.clone());
        let w = Writer::spawn(move || {
            let _ = stuck.recv();
            Ok(restart(&p2, &m2))
        })
        .unwrap();
        for i in 0..3 {
            w.record("sftp.put", format!("upload {i}"), json!({ "n": i }));
        }
        assert!(!w.flush(Duration::from_millis(200)), "the writer is stuck");
        // Spilled aside first, so the stuck writer's own startup ingest does
        // not pick it up in this test.
        let aside = p.parent().unwrap().join("aside");
        let spilled = w.spill(&aside).unwrap().expect("a pending file");
        assert!(spilled.file_name().unwrap().to_string_lossy().starts_with(PENDING_PREFIX));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&spilled).unwrap().permissions().mode() & 0o777, 0o600);
        }
        // The stuck writer wakes up: spilled records are not written twice.
        release.send(()).unwrap();
        assert!(w.flush(Duration::from_secs(5)));
        assert_eq!(lines(&p).len(), 1, "spilled records were not also written");
        drop(w);
        let spilled = {
            let dest = p.with_file_name(spilled.file_name().unwrap());
            std::fs::rename(&spilled, &dest).unwrap();
            dest
        };

        // Next start: ingested, in order, after a note; the file is gone.
        let w = Writer::spawn({
            let (p, m) = (p.clone(), m.clone());
            move || Ok(restart(&p, &m))
        })
        .unwrap();
        let r = w.ask(Job::Verify).unwrap().unwrap();
        assert_eq!((r.status, r.count), (Status::Verified, 5), "{}", r.message);
        assert!(!spilled.exists());
        let all = lines(&p);
        assert!(all[1].contains(EV_RECOVERED), "{}", all[1]);
        for (i, l) in all[2..].iter().enumerate() {
            let e: AuditEntry = serde_json::from_str(l).unwrap();
            assert_eq!(e.summary, format!("upload {i}"));
            assert_eq!(e.detail.get("recovered"), Some(&Value::Bool(true)));
        }
    }

    /// An uncertain spilled record (the writer had started on it) that did
    /// land is not recorded twice.
    #[test]
    fn an_uncertain_spilled_record_that_landed_is_not_duplicated() {
        let (p, m) = (tmp(), Mem::default());
        let log = restart(&p, &m);
        log.record("connect", "landed", json!({ "host": "fw1" })).unwrap();
        let line = json!({ "event": "connect", "summary": "landed", "detail": { "host": "fw1" }, "accepted": 1, "uncertain": true });
        std::fs::write(p.with_file_name(format!("{PENDING_PREFIX}1{PENDING_SUFFIX}")), format!("{line}\n")).unwrap();
        ingest_pending(&log);
        let all = lines(&p);
        assert_eq!(all.len(), 2, "only the recovered note was added: {all:?}");
    }

    fn spill_line(rid: &str, summary: &str, uncertain: bool) -> String {
        json!({ "event": "connect", "summary": summary, "detail": { "host": "fw1", "rid": rid }, "accepted": 1, "uncertain": uncertain })
            .to_string()
    }

    fn summaries(p: &Path) -> Vec<String> {
        lines(p).iter().map(|l| serde_json::from_str::<AuditEntry>(l).unwrap().summary).collect()
    }

    /// W4c: dedupe is by record id, never by content. A record that did not
    /// land is recorded even when an identical-looking one is in the log; one
    /// that did land is skipped wherever it is in the file.
    #[test]
    fn spill_recovery_dedupes_by_record_id_not_by_content() {
        let (p, m) = (tmp(), Mem::default());
        let log = restart(&p, &m);
        log.record("connect", "same", json!({ "host": "fw1", "rid": "a1" })).unwrap();
        rec(&log, 300); // pushes it far outside any tail window
        let spill = p.with_file_name(format!("{PENDING_PREFIX}1{PENDING_SUFFIX}"));
        let text = [spill_line("a1", "same", true), spill_line("b2", "same", true)].join("\n");
        std::fs::write(&spill, format!("{text}\n")).unwrap();
        ingest_pending(&log);
        let got = summaries(&p);
        assert_eq!(got.len(), 301 + 2, "the note and b2 only");
        assert!(got[301].contains("recorded below"));
        assert_eq!(got[302], "same");
        let last: AuditEntry = serde_json::from_str(lines(&p).last().unwrap()).unwrap();
        assert_eq!(last.detail.get(RID), Some(&json!("b2")));
        assert!(!spill.exists());
        assert_eq!(status(&restart(&p, &m)), Status::Verified);
    }

    /// W4c: a crash part-way through recovery (or a spill that could not be
    /// removed) never duplicates on the next pass, note included.
    #[test]
    fn interrupted_spill_recovery_is_idempotent() {
        let (p, m) = (tmp(), Mem::default());
        let log = restart(&p, &m);
        let spill = p.with_file_name(format!("{PENDING_PREFIX}1{PENDING_SUFFIX}"));
        let text = [spill_line("r1", "one", false), spill_line("r2", "two", false), spill_line("r3", "three", false)].join("\n");
        std::fs::write(&spill, format!("{text}\n")).unwrap();
        let keep = std::fs::read(&spill).unwrap();
        ingest_pending(&log);
        assert_eq!(summaries(&p).len(), 4);
        // As if the first pass had died before removing the file.
        std::fs::write(&spill, &keep).unwrap();
        ingest_pending(&restart(&p, &m));
        assert_eq!(summaries(&p).len(), 4, "nothing replayed");
        assert!(!spill.exists());
        // As if it had died after the note and the first record only.
        let (p2, m2) = (tmp(), Mem::default());
        let log2 = restart(&p2, &m2);
        let spill2 = p2.with_file_name(spill.file_name().unwrap());
        std::fs::write(&spill2, &keep).unwrap();
        ingest_pending(&log2);
        let full = lines(&p2);
        std::fs::write(&p2, format!("{}\n{}\n", full[0], full[1])).unwrap();
        let (p3, m3) = (p2.clone(), Mem::default()); // a fresh seal: the cut is not what is tested here
        std::fs::write(&spill2, &keep).unwrap();
        ingest_pending(&restart(&p3, &m3));
        let got = summaries(&p3);
        assert_eq!(got.iter().filter(|s| s.contains("recorded below")).count(), 1, "{got:?}");
        assert_eq!(got.iter().filter(|s| *s == "one").count(), 1, "{got:?}");
        assert!(got.contains(&"two".to_string()) && got.contains(&"three".to_string()), "{got:?}");
    }

    /// W4c: every accepted record gets an id, and a record accepted after the
    /// exit spill closed admission is spilled on its own, not lost.
    #[test]
    fn records_accepted_after_the_exit_spill_are_kept() {
        let (p, m) = (tmp(), Mem::default());
        let (release, stuck) = mpsc::channel::<()>();
        let (p2, m2) = (p.clone(), m.clone());
        let w = Writer::spawn(move || {
            let _ = stuck.recv();
            Ok(restart(&p2, &m2))
        })
        .unwrap();
        w.record("connect", "before".into(), json!({ "n": 1 }));
        let aside = p.parent().unwrap().join("aside");
        let first = w.spill(&aside).unwrap().expect("spilled");
        w.record("disconnect", "after".into(), json!("plain"));
        let files: Vec<PathBuf> = std::fs::read_dir(&aside).unwrap().flatten().map(|e| e.path()).collect();
        assert_eq!(files.len(), 2, "the late record has its own spill file: {files:?}");
        let mut rids = Vec::new();
        for f in &files {
            let v: Value = serde_json::from_str(std::fs::read_to_string(f).unwrap().lines().next().unwrap()).unwrap();
            let rid = v["detail"][RID].as_str().unwrap().to_string();
            assert_eq!(rid.len(), 32, "128-bit id");
            rids.push(rid);
        }
        assert_ne!(rids[0], rids[1]);
        let late = files.iter().find(|f| **f != first).unwrap();
        assert!(std::fs::read_to_string(late).unwrap().contains("\"value\":\"plain\""));
        release.send(()).unwrap();
        assert!(w.flush(Duration::from_secs(5)));
        assert!(!p.exists() || lines(&p).is_empty(), "nothing spilled was also written");
    }

    /// W4c (item 5): a source folder that cannot be listed is an error, and
    /// no completion marker is written.
    #[cfg(unix)]
    #[test]
    fn a_migration_source_that_cannot_be_read_never_writes_the_marker() {
        let root = tmp().parent().unwrap().to_path_buf();
        let (from, to) = (root.join("roaming-file"), root.join("local"));
        std::fs::write(&from, b"not a folder").unwrap();
        assert!(migrate_audit_files(&from, &to).is_err());
        assert!(!to.join("audit.migrated").exists());
        // A missing source folder simply has nothing to copy.
        migrate_audit_files(&root.join("absent"), &to).unwrap();
        assert!(to.join("audit.migrated").exists());
    }

    /// W4b: an archive verified and hashed outside the locks is used only if
    /// the file is still the one it saw; appends since then are redone under
    /// the lock, so the pin always covers every archived record.
    #[test]
    fn a_prepared_archive_is_redone_when_records_were_appended_meanwhile() {
        let (p, m) = (tmp(), Mem::default());
        let log = restart(&p, &m);
        rec(&log, 2);
        let stale = log.prepare_archive().unwrap();
        rec(&log, 2); // appended while the archive was being prepared
        let name = log.archive_with(Some(stale)).unwrap();
        let first: AuditEntry = serde_json::from_str(&lines(&p)[0]).unwrap();
        assert_eq!(first.detail["archivedSha256"].as_str().unwrap(), hash_file(&p.with_file_name(&name)).unwrap().0);
        assert_eq!(first.detail["archivedLastSeq"], json!(4));
        rec(&log, 1);
        let r = log.verify().unwrap();
        assert_eq!(r.status, Status::Verified, "{}", r.message);
        // And an unchanged file uses the prepared work as is.
        let fresh = log.prepare_archive().unwrap();
        log.archive_with(Some(fresh)).unwrap();
        assert_eq!(log.verify().unwrap().status, Status::Verified);
    }

    /// W4b: a migration cut short is retried (no marker yet), completing a
    /// partial copy; a local log that grew past its source is never replaced.
    #[test]
    fn an_interrupted_migration_is_retried_until_its_marker_is_written() {
        let from = tmp().parent().unwrap().to_path_buf();
        let to = tmp().parent().unwrap().join("local");
        std::fs::write(from.join(AUDIT_FILE), b"line one\nline two\n").unwrap();
        std::fs::write(from.join("audit-1-abc.archived.jsonl"), b"old\n").unwrap();
        // An older build copied half the live log and died: no archive, no marker.
        std::fs::create_dir_all(&to).unwrap();
        std::fs::write(to.join(AUDIT_FILE), b"line one\n").unwrap();
        migrate_audit_files(&from, &to).unwrap();
        assert_eq!(std::fs::read(to.join(AUDIT_FILE)).unwrap(), b"line one\nline two\n");
        assert!(to.join("audit-1-abc.archived.jsonl").exists());
        assert!(to.join("audit.migrated").exists());
        let temps = std::fs::read_dir(&to).unwrap().flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(".migrating-"))
            .count();
        assert_eq!(temps, 0);
        // Without a marker, a local log that has grown past its source is kept.
        std::fs::remove_file(to.join("audit.migrated")).unwrap();
        std::fs::write(to.join(AUDIT_FILE), b"line one\nline two\nlocal three\n").unwrap();
        migrate_audit_files(&from, &to).unwrap();
        assert_eq!(std::fs::read(to.join(AUDIT_FILE)).unwrap(), b"line one\nline two\nlocal three\n");
        // A divergent shorter one is kept too (not a prefix: not ours to replace).
        std::fs::remove_file(to.join("audit.migrated")).unwrap();
        std::fs::write(to.join(AUDIT_FILE), b"other\n").unwrap();
        migrate_audit_files(&from, &to).unwrap();
        assert_eq!(std::fs::read(to.join(AUDIT_FILE)).unwrap(), b"other\n");
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
