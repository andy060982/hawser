//! OpenSSH-compatible `known_hosts` storage.
//!
//! # What is stored, and what is not
//!
//! This file records the server's **full public key**, not its fingerprint.
//! That distinction is load-bearing: a fingerprint is a one-way SHA256 hash, so
//! a file of fingerprints could never be read by `ssh`, `ssh-keygen -F`, or any
//! other OpenSSH tool, and could not be used to verify a key by any means other
//! than re-hashing. The fingerprint is a *human comparison aid* and belongs in
//! the UI; the key itself belongs on disk.
//!
//! Format is therefore the standard one line per host:
//!
//! ```text
//! hostname ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...
//! [hostname]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...
//! ```
//!
//! with the bracketed form used whenever the port is not 22, exactly as
//! OpenSSH writes it. The resulting file can be concatenated onto
//! `~/.ssh/known_hosts` or consumed by `ssh` directly.
//!
//! # Why not russh's default path
//!
//! `russh::keys::known_hosts::check_known_hosts` resolves to
//! `%USERPROFILE%\ssh\known_hosts` on Windows — note the missing dot, which is
//! not where OpenSSH for Windows actually looks. Owning the path explicitly
//! avoids that quirk and keeps Hawser's trust store separate from the system
//! one, so a mistake here can never corrupt the file `ssh` itself depends on.
//!
//! Parsing and serialisation are delegated to russh's implementation rather
//! than hand-rolled: known_hosts has more edge cases than it looks (hashed
//! hostnames, `@revoked` and `@cert-authority` markers, comma-separated host
//! lists, CRLF), and a subtly wrong parser here is a security bug, not a
//! cosmetic one.

use std::path::{Path, PathBuf};

use russh::keys::known_hosts::{
    check_known_hosts_path, known_host_keys_path, learn_known_hosts_path,
};
use russh::keys::ssh_key::PublicKey;

#[derive(Debug, thiserror::Error)]
pub enum KnownHostsError {
    #[error("could not locate the application data directory")]
    NoAppDataDir,
    #[error("known_hosts store at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("known_hosts store is malformed: {0}")]
    Parse(String),
    /// The store's lock stayed taken for the whole bounded wait (see
    /// `TRUST_LOCK_WAIT`). Nothing was trusted.
    #[error(
        "another Hawser instance is updating known hosts; the key was not trusted. Try again \
         in a moment"
    )]
    Busy,
}

/// Result of checking a presented host key against the store.
///
/// Three states, not two. Collapsing `Unknown` and `Changed` into a single
/// "not trusted" is the mistake that leads to prompting on a changed key, which
/// is precisely the case where a prompt must never appear.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKeyStatus {
    /// Recorded, and the presented key matches.
    Trusted,
    /// No entry for this host — a first connection.
    Unknown,
    /// An entry exists with a *different* key (any algorithm) for this host, or
    /// no stored key matches. Either the server was rebuilt or the connection is
    /// being intercepted — refuse, never prompt.
    Changed { line: usize },
    /// The presented key is explicitly revoked (`@revoked` line). Refuse
    /// unconditionally — this beats any matching trust entry.
    Revoked { line: usize },
}

/// `%APPDATA%\hawser\known_hosts` on Windows.
///
/// Roaming rather than Local on purpose: host trust is a user decision that
/// should follow the user to another domain-joined machine, unlike the
/// credentials in the vault, which are deliberately machine-local.
#[cfg(target_os = "windows")]
pub fn store_path() -> Result<PathBuf, KnownHostsError> {
    let appdata = std::env::var_os("APPDATA").ok_or(KnownHostsError::NoAppDataDir)?;
    Ok(PathBuf::from(appdata).join("hawser").join("known_hosts"))
}

#[cfg(not(target_os = "windows"))]
pub fn store_path() -> Result<PathBuf, KnownHostsError> {
    let home = std::env::var_os("HOME").ok_or(KnownHostsError::NoAppDataDir)?;
    Ok(PathBuf::from(home)
        .join(".config")
        .join("hawser")
        .join("known_hosts"))
}

/// Create the directory and an empty file if either is missing, and return the
/// path. Safe to call repeatedly; never truncates an existing store.
pub fn ensure_store() -> Result<PathBuf, KnownHostsError> {
    let path = store_path()?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| KnownHostsError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    if !path.exists() {
        // create_new rather than File::create: if two sessions race to first
        // connection, the loser must not truncate the winner's file.
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(source) => {
                return Err(KnownHostsError::Io {
                    path: path.clone(),
                    source,
                })
            }
        }
    }

    Ok(path)
}

/// Key algorithms already pinned for `host:port`, in file order, deduplicated.
///
/// Offered to the server first during negotiation, as OpenSSH does: a host
/// pinned as ECDSA that later also offers Ed25519 must keep signing with the
/// pinned ECDSA key, or the classification below sees "no matching key" and
/// refuses it as CHANGED although the pinned key is still valid. An unreadable
/// store yields an empty list; the check itself then fails closed.
pub fn pinned_algorithms(host: &str, port: u16) -> Vec<russh::keys::Algorithm> {
    match store_path() {
        Ok(path) if path.exists() => pinned_algorithms_at(host, port, &path),
        _ => Vec::new(),
    }
}

pub(crate) fn pinned_algorithms_at(host: &str, port: u16, path: &Path) -> Vec<russh::keys::Algorithm> {
    let mut out: Vec<russh::keys::Algorithm> = Vec::new();
    let mut push = |k: &PublicKey| {
        let alg = k.algorithm();
        if !out.contains(&alg) {
            out.push(alg);
        }
    };
    if let Ok(entries) = host_entries(host, port, path) {
        for k in entries.iter().filter(|e| e.trust_entry).filter_map(|e| e.key.as_ref()) {
            push(k);
        }
    }
    if let Ok(hashed) = known_host_keys_path(&host.to_ascii_lowercase(), port, path) {
        for (_, k) in &hashed {
            push(k);
        }
    }
    out
}

/// Check a presented key against the store at `path` (from `ensure_store`, so
/// a first run's empty file reads as `Unknown`). A store that exists but cannot
/// be read or parsed is an error, never `Unknown`.
pub(crate) fn classify(
    host: &str,
    port: u16,
    key: &PublicKey,
    path: &Path,
) -> Result<HostKeyStatus, KnownHostsError> {
    // Revocation wins over everything: an explicitly `@revoked` key is refused
    // even if the same key also appears as a normal trust entry.
    if let Some(line) = revoked_line(key, path)? {
        return Ok(HostKeyStatus::Revoked { line });
    }

    match check_known_hosts_path(host, port, key, path) {
        Ok(true) => Ok(HostKeyStatus::Trusted),
        Ok(false) => {
            // russh found no key on file matching the presented one. That is
            // NOT automatically "unknown host": russh only reports KeyChanged
            // for a *same-algorithm* mismatch, so a host we already trust that
            // presents a different-algorithm key (a classic downgrade/
            // interception move) also lands here. Distinguish:
            //   - host has no entry at all   -> genuinely first use -> prompt
            //   - host IS on file, key isn't -> treat as Changed -> refuse,
            //     never a silent trust prompt. Recovery is explicit: remove the
            //     host's known_hosts line, then reconnect to re-trust.
            //
            // russh matches host names case-SENSITIVELY, but DNS names are not:
            // a host pinned as `FW01.corp` and dialled as `fw01.corp` with the
            // SAME key is trusted, not "changed".
            let entries = host_entries(host, port, path)?;
            if entries.iter().any(|e| e.trust_entry && e.key.as_ref().is_some_and(|k| k.key_data() == key.key_data())) {
                return Ok(HostKeyStatus::Trusted);
            }
            if let Some(first) = entries.first() {
                return Ok(HostKeyStatus::Changed { line: first.line });
            }
            // Hashed `|1|…` entries (pasted from an OpenSSH known_hosts) can only
            // be matched by russh. OpenSSH lowercases names before hashing.
            let lower = host.to_ascii_lowercase();
            let hashed = known_host_keys_path(&lower, port, path).map_err(|e| {
                KnownHostsError::Parse(format!(
                    "could not verify {host}:{port} against the known_hosts store: {e}"
                ))
            })?;
            if hashed.iter().any(|(_, k)| k.key_data() == key.key_data()) {
                return Ok(HostKeyStatus::Trusted);
            }
            match hashed.first() {
                Some((line, _)) => Ok(HostKeyStatus::Changed { line: physical_line(path, *line) }),
                None => Ok(HostKeyStatus::Unknown),
            }
        }
        // russh's line counter skips `#` comment lines; report the real line so
        // "remove line N by hand" points at the right entry.
        Err(russh::keys::Error::KeyChanged { line }) => Ok(HostKeyStatus::Changed {
            line: physical_line(path, line),
        }),
        // Any OTHER error — an unreadable or corrupt store, a malformed line —
        // is propagated, NOT downgraded to a trust prompt. The store exists by
        // this point (ensure_store created it), so a read/parse failure here is
        // a real problem: fail closed and make the user fix the file rather than
        // let a parse error masquerade as a first-use connection.
        Err(e) => Err(KnownHostsError::Parse(format!(
            "could not verify {host}:{port} against the known_hosts store: {e}"
        ))),
    }
}

/// The 1-based line of a `@revoked` entry whose key matches the presented one,
/// if any.
///
/// Matching is by KEY MATERIAL, not by host pattern. A `@revoked` line's host
/// field can be a literal name, `[host]:port`, a comma list, a `*`/`?` wildcard,
/// a negation, or an HMAC-hashed `|1|…` entry — and getting that matching subtly
/// wrong is exactly how a revoked key slips back through to a trust prompt.
/// Comparing key bytes instead is simpler and strictly safer: if the exact key
/// the server just presented is marked `@revoked` anywhere in the store, refuse
/// it. This is a deliberate conservative over-approximation (a key revoked for
/// one host is treated as revoked everywhere) — the right instinct for what is,
/// by definition, a key someone marked as compromised.
///
/// A store read failure propagates (fail closed). A `@revoked` line whose key
/// field is unparseable cannot match any real key and is skipped — it could not
/// have revoked a specific key by content in the first place.
fn revoked_line(key: &PublicKey, path: &Path) -> Result<Option<usize>, KnownHostsError> {
    let text = std::fs::read_to_string(path).map_err(|source| KnownHostsError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        if !matches!(fields.next(), Some(m) if m.eq_ignore_ascii_case("@revoked")) {
            continue;
        }
        // Everything after the marker is `<hostpattern> <keytype> <base64>
        // [comment]`. Rather than interpret the host pattern, scan the remaining
        // fields for any adjacent `<type> <base64>` pair that parses to a key,
        // and compare its material — robust to the host field's form.
        let rest: Vec<&str> = fields.collect();
        for pair in rest.windows(2) {
            if let Ok(revoked) = PublicKey::from_openssh(&format!("{} {}", pair[0], pair[1])) {
                if revoked.key_data() == key.key_data() {
                    return Ok(Some(i + 1));
                }
            }
        }
    }
    Ok(None)
}

/// Map russh's line number — which does not count lines starting with `#` —
/// to the physical 1-based line in the file. Falls back to russh's number if the
/// file cannot be re-read.
fn physical_line(path: &Path, russh_line: usize) -> usize {
    let Ok(text) = std::fs::read_to_string(path) else {
        return russh_line;
    };
    let mut counted = 0usize;
    for (i, line) in text.lines().enumerate() {
        if line.as_bytes().first() == Some(&b'#') {
            continue;
        }
        counted += 1;
        if counted == russh_line {
            return i + 1;
        }
    }
    russh_line
}

/// One plaintext known_hosts line naming a host.
struct HostEntry {
    /// 1-based physical line number.
    line: usize,
    /// The recorded key, when it parses.
    key: Option<PublicKey>,
    /// A plain trust line — not `@revoked` / `@cert-authority`, whose key is
    /// not this host's key and must never make it trusted.
    trust_entry: bool,
}

/// Every known_hosts entry naming this host, plaintext host fields only,
/// matched case-insensitively (hashed `|1|…` entries can't be matched by name;
/// see `classify`).
fn host_entries(host: &str, port: u16, path: &Path) -> Result<Vec<HostEntry>, KnownHostsError> {
    let needle = if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    };
    // Propagate a read failure rather than swallowing it: a store that exists
    // but can't be read must fail the check closed, not report "host absent"
    // (which routes to a trust prompt).
    let text = std::fs::read_to_string(path).map_err(|source| KnownHostsError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let Some(mut first) = fields.next() else { continue };
        // Skip an @revoked / @cert-authority marker to reach the host field.
        let marker = first.starts_with('@');
        if marker {
            first = match fields.next() {
                Some(f) => f,
                None => continue,
            };
        }
        // Host field may be a comma-separated list of patterns.
        if first.split(',').any(|h| h.eq_ignore_ascii_case(&needle)) {
            let key = match (fields.next(), fields.next()) {
                (Some(kind), Some(b64)) => PublicKey::from_openssh(&format!("{kind} {b64}")).ok(),
                _ => None,
            };
            out.push(HostEntry { line: i + 1, key, trust_entry: !marker });
        }
    }
    Ok(out)
}

/// How long `trust_at` waits for the store's locks before failing closed.
pub(crate) const TRUST_LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(5);
/// Poll interval while those locks are taken.
const TRUST_LOCK_POLL: std::time::Duration = std::time::Duration::from_millis(25);

/// Serialises trust decisions inside this process. The re-classification and
/// the append must be one step: two sessions approving different unknown keys
/// for the same host could otherwise both see `Unknown` and both append, and
/// russh then refuses BOTH keys (it reports any same-algorithm mismatch as
/// KeyChanged, even when another line matches), locking the user out.
static TRUST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Append a host's public key to the store at `path`. Called only after a
/// human has accepted the fingerprint.
///
/// Refuses to append over a *changed* key: re-recording one would leave two
/// conflicting entries and make every later check ambiguous. Replacing a
/// changed key is a deliberate, manual act. A key that is already trusted
/// (another session pinned the same key while this prompt was open) is a
/// no-op, not a duplicate line. The re-check and the append run under one
/// lock, so two sessions approving different keys pin exactly one.
///
/// Blocking: run it off the async runtime. The locks are taken with a bounded
/// wait (`TRUST_LOCK_WAIT`) and never blocked on: a suspended second instance
/// holding the file lock must not strand an SSH task, nor (by blocking while
/// holding the process lock) every other approval in this process. On timeout
/// it fails closed with `Busy`.
pub(crate) fn trust_at(
    host: &str,
    port: u16,
    key: &PublicKey,
    path: &Path,
) -> Result<(), KnownHostsError> {
    trust_at_within(host, port, key, path, TRUST_LOCK_WAIT)
}

pub(crate) fn trust_at_within(
    host: &str,
    port: u16,
    key: &PublicKey,
    path: &Path,
    wait: std::time::Duration,
) -> Result<(), KnownHostsError> {
    // Another Hawser instance shares the store, so the process lock alone is
    // not enough. A sidecar file rather than the store itself: Windows locks are
    // mandatory, and the append below goes through a separate handle.
    let lock_path = path.with_file_name("known_hosts.lock");
    let lock_file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .map_err(|source| KnownHostsError::Io { path: lock_path.clone(), source })?;
    let deadline = std::time::Instant::now() + wait;
    // Both locks are only ever TRIED: whichever is taken, release what we hold
    // and retry until the deadline, so nothing here blocks while holding the
    // process lock.
    let _guard = loop {
        let process = match TRUST_LOCK.try_lock() {
            Ok(g) => Some(g),
            Err(std::sync::TryLockError::Poisoned(p)) => Some(p.into_inner()),
            Err(std::sync::TryLockError::WouldBlock) => None,
        };
        if let Some(g) = process {
            match lock_file.try_lock() {
                Ok(()) => break g,
                Err(std::fs::TryLockError::WouldBlock) => drop(g),
                Err(std::fs::TryLockError::Error(source)) => {
                    return Err(KnownHostsError::Io { path: lock_path, source })
                }
            }
        }
        if std::time::Instant::now() >= deadline {
            return Err(KnownHostsError::Busy);
        }
        std::thread::sleep(TRUST_LOCK_POLL);
    };

    match classify(host, port, key, path)? {
        HostKeyStatus::Changed { line } => {
            return Err(KnownHostsError::Parse(format!(
                "{host}:{port} already has a different key on line {line}; \
                 remove it by hand before trusting a new one"
            )))
        }
        HostKeyStatus::Revoked { line } => {
            return Err(KnownHostsError::Parse(format!(
                "{host}:{port} presented a key that is revoked on line {line}; \
                 refusing to trust it"
            )))
        }
        HostKeyStatus::Trusted => return Ok(()),
        HostKeyStatus::Unknown => {}
    }

    // russh handles the details that are easy to get wrong: appending a leading
    // newline when the file does not end in one, and the [host]:port form for
    // non-default ports.
    learn_known_hosts_path(host, port, key, path).map_err(|e| match e {
        russh::keys::Error::IO(source) => KnownHostsError::Io {
            path: path.to_path_buf(),
            source,
        },
        other => KnownHostsError::Parse(other.to_string()),
    })
    // Both locks are released on return (`_guard`, then `lock_file`).
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_path_is_under_appdata() {
        // Only asserts shape; the directory need not exist.
        let p = store_path().expect("path resolves");
        assert!(p.ends_with("hawser/known_hosts") || p.ends_with(r"hawser\known_hosts"));
    }

    #[test]
    fn ensure_store_is_idempotent() {
        let a = ensure_store().expect("first call");
        let b = ensure_store().expect("second call");
        assert_eq!(a, b);
        assert!(a.exists());
    }

    // Revocation must be caught regardless of the @revoked line's host-pattern
    // form (wildcard, hashed, comma list), because it is matched by KEY, not
    // host. A different key on the same lines must NOT be reported revoked.
    #[test]
    fn revoked_matches_by_key_across_host_pattern_forms() {
        const KEY1: &str =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ1EeRn1nUZ6oQiaSmrlPONbjg1FxJtr35MXzTndFYIe revtest";
        const KEY2: &str =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHveLo5tgiTjyNgc98zwmigaaw1vJ/1IN9KDWqa0Z43a other";
        let k1 = PublicKey::from_openssh(KEY1).expect("k1 parses");
        let k2 = PublicKey::from_openssh(KEY2).expect("k2 parses");
        let k1_body = KEY1.trim_start_matches("ssh-ed25519 ").trim_end_matches(" revtest");

        let dir = std::env::temp_dir().join(format!("hawser-revtest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("known_hosts");
        // A wildcard-host @revoked line and a hashed-host one, both for KEY1.
        std::fs::write(
            &path,
            format!(
                "# comment\n\
                 host.example ssh-ed25519 {k1_body}\n\
                 @revoked *.wild ssh-ed25519 {k1_body}\n\
                 @revoked |1|c2FsdA==|aGFzaA== ssh-ed25519 {k1_body}\n",
            ),
        )
        .unwrap();

        // KEY1 is revoked (matched despite wildcard/hashed host fields).
        assert!(revoked_line(&k1, &path).unwrap().is_some());
        // KEY2 is not on any @revoked line → not revoked.
        assert!(revoked_line(&k2, &path).unwrap().is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    // Host names compare case-insensitively (DNS does), and a changed key is
    // reported at its PHYSICAL line even when comment lines precede it.
    #[test]
    fn case_insensitive_trust_and_physical_changed_line() {
        const KEY1: &str =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ1EeRn1nUZ6oQiaSmrlPONbjg1FxJtr35MXzTndFYIe";
        const KEY2: &str =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHveLo5tgiTjyNgc98zwmigaaw1vJ/1IN9KDWqa0Z43a";
        let k1 = PublicKey::from_openssh(KEY1).expect("k1 parses");
        let k2 = PublicKey::from_openssh(KEY2).expect("k2 parses");

        let dir = std::env::temp_dir().join(format!("hawser-casetest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("known_hosts");
        std::fs::write(
            &path,
            format!("# notes\n# more notes\nFW01.corp {KEY1}\nhostb.corp {KEY1}\n"),
        )
        .unwrap();

        // Same key, different letter case: trusted, not changed.
        assert_eq!(classify("fw01.corp", 22, &k1, &path).unwrap(), HostKeyStatus::Trusted);
        // Different key, case-insensitive name match: changed at line 3.
        assert_eq!(
            classify("fw01.corp", 22, &k2, &path).unwrap(),
            HostKeyStatus::Changed { line: 3 }
        );
        // Exact-name same-algorithm mismatch (russh's KeyChanged path): line 4,
        // not russh's comment-skipping count of 2.
        assert_eq!(
            classify("hostb.corp", 22, &k2, &path).unwrap(),
            HostKeyStatus::Changed { line: 4 }
        );
        // Absent host: unknown.
        assert_eq!(classify("other.corp", 22, &k1, &path).unwrap(), HostKeyStatus::Unknown);

        let _ = std::fs::remove_dir_all(&dir);
    }

    const ED_A: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ1EeRn1nUZ6oQiaSmrlPONbjg1FxJtr35MXzTndFYIe";
    const ED_B: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHveLo5tgiTjyNgc98zwmigaaw1vJ/1IN9KDWqa0Z43a";

    fn temp_store(tag: &str) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "hawser-kh-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("known_hosts");
        std::fs::write(&path, "").unwrap();
        (dir, path)
    }

    fn lines_for(path: &Path, needle: &str) -> usize {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .filter(|l| l.split_whitespace().next() == Some(needle))
            .count()
    }

    // Two sessions approving DIFFERENT unknown keys for one host at the same
    // moment must end with exactly one pinned key: the loser sees the winner's
    // line on its re-check and is refused as changed.
    #[test]
    fn concurrent_trusts_of_different_keys_pin_one() {
        let (dir, path) = temp_store("race");
        let ka = PublicKey::from_openssh(ED_A).unwrap();
        let kb = PublicKey::from_openssh(ED_B).unwrap();
        for _ in 0..20 {
            std::fs::write(&path, "").unwrap();
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            let spawn = |k: PublicKey| {
                let (b, p) = (std::sync::Arc::clone(&barrier), path.clone());
                std::thread::spawn(move || {
                    b.wait();
                    trust_at("race.example", 22, &k, &p).is_ok()
                })
            };
            let (a, b) = (spawn(ka.clone()), spawn(kb.clone()));
            let oks = [a.join().unwrap(), b.join().unwrap()];
            assert_eq!(oks.iter().filter(|o| **o).count(), 1, "exactly one trust wins");
            assert_eq!(lines_for(&path, "race.example"), 1, "exactly one key pinned");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    // Trusting a key that is already pinned (a second tab approved the same
    // fingerprint) is a no-op, not a duplicate line.
    #[test]
    fn trusting_an_already_trusted_key_is_a_noop() {
        let (dir, path) = temp_store("noop");
        let ka = PublicKey::from_openssh(ED_A).unwrap();
        trust_at("dup.example", 2222, &ka, &path).unwrap();
        trust_at("dup.example", 2222, &ka, &path).unwrap();
        assert_eq!(lines_for(&path, "[dup.example]:2222"), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pinned_algorithms_lists_trust_entries_only() {
        let (dir, path) = temp_store("algs");
        const ECDSA: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBI/gPg4KkOG52SzCdcnggcQk7DG6z1OLSfSAi2LTGk4OFnDnYrkNsxVIWtt/KArpW70Gac7c1im2IEx4u8Bs0MI=";
        let ka = PublicKey::from_openssh(ED_A).unwrap();
        std::fs::write(
            &path,
            format!("fw01 {ECDSA}\n@revoked fw01 {ED_A}\nother {ED_A}\n"),
        )
        .unwrap();
        let algs = pinned_algorithms_at("FW01", 22, &path);
        assert_eq!(algs, vec![PublicKey::from_openssh(ECDSA).unwrap().algorithm()]);
        assert!(pinned_algorithms_at("nobody", 22, &path).is_empty());
        assert_ne!(algs[0], ka.algorithm());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // Another instance holding the store lock (suspended, say) must not strand
    // the approving task: the wait is bounded and fails closed, nothing is
    // pinned, and this process's lock is not held while waiting — another
    // store's trust in this process goes through meanwhile.
    #[test]
    fn trust_fails_closed_while_another_instance_holds_the_lock() {
        let (dir, path) = temp_store("busy");
        let (dir2, path2) = temp_store("busy-other");
        let ka = PublicKey::from_openssh(ED_A).unwrap();
        let other_instance = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(path.with_file_name("known_hosts.lock"))
            .unwrap();
        other_instance.lock().unwrap();

        let waiting = {
            let (k, p) = (ka.clone(), path.clone());
            std::thread::spawn(move || {
                let t = std::time::Instant::now();
                let r = trust_at_within("busy.example", 22, &k, &p, std::time::Duration::from_millis(600));
                (r, t.elapsed())
            })
        };
        std::thread::sleep(std::time::Duration::from_millis(100));
        let t = std::time::Instant::now();
        trust_at("free.example", 22, &ka, &path2).unwrap();
        assert!(t.elapsed() < std::time::Duration::from_millis(400), "blocked on the process lock");

        let (r, took) = waiting.join().unwrap();
        assert!(matches!(r, Err(KnownHostsError::Busy)), "{r:?}");
        assert!(took < std::time::Duration::from_secs(2));
        assert!(r.unwrap_err().to_string().contains("another Hawser instance"));
        assert_eq!(lines_for(&path, "busy.example"), 0);

        // Released: the same trust now succeeds.
        drop(other_instance);
        trust_at("busy.example", 22, &ka, &path).unwrap();
        assert_eq!(lines_for(&path, "busy.example"), 1);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&dir2);
    }
}
