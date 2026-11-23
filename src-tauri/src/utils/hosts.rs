//! Persistence for the saved-host catalogue.
//!
//! The tree is stored as opaque JSON. Rust deliberately does **not** model
//! `HostNode`: the shape is a recursive folder/host union owned by the
//! frontend, and duplicating it here would mean every UI-side field addition
//! becomes a two-language change plus a migration. Nothing in the backend needs
//! to interpret the tree — `ssh_connect` receives the individual fields it
//! needs as arguments — so persisting it verbatim is both simpler and harder to
//! get out of sync.
//!
//! Secrets are never in this file. Passwords live in the Credential Manager,
//! keyed by host id; this holds names, addresses, ports, usernames, and auth
//! *method*. That separation is why this file can be plain, readable JSON.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use serde_json::{json, Value};

use super::known_hosts::KnownHostsError;
use super::vault_item::{self, Destination, Envelope};

/// Serialises every catalogue/settings write so two concurrent saves can neither
/// interleave on a shared scratch file nor race on the final replace.
static WRITE_LOCK: Mutex<()> = Mutex::new(());
/// Makes each temp filename unique even within a burst of same-process saves.
static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Create the app data directory (and parents) if needed, owner-only (0700)
/// on Unix. Every file written below it is created 0600.
pub fn ensure_dir(dir: &Path) -> Result<(), KnownHostsError> {
    std::fs::create_dir_all(dir).map_err(|source| KnownHostsError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    super::platform::restrict_perms(dir, 0o700);
    Ok(())
}

/// Create `path` for writing, failing if it exists (no clobber, and it never
/// follows a planted symlink: O_EXCL refuses one), owner-only on Unix.
pub fn create_private(path: &Path) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// fsync the directory holding `path` (Unix; NTFS journals its own metadata).
fn sync_parent(path: &Path) {
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        let _ = std::fs::File::open(dir).and_then(|d| d.sync_all());
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Write `contents` to `path` as atomically as the platform allows.
///
/// A unique temp sibling is created exclusively (0600 on Unix), written in
/// full and fsynced, then rename-replaced over the destination, and the
/// directory is synced. `std::fs::rename` is an atomic replace on Unix and on
/// modern Windows. Only if that direct replace fails do we take the fallback —
/// and the fallback never *deletes* the original: it moves it aside to a
/// backup first, so at no instant is the destination gone, and if the second
/// rename fails the original is restored. A crash in the tiny window leaves
/// either the new file in place or the original recoverable at its `.bak`
/// sibling — never nothing. The whole operation is serialised process-wide.
pub(crate) fn write_atomic(path: &Path, contents: &str) -> Result<(), KnownHostsError> {
    use std::io::Write;
    let _guard = WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(dir) = path.parent() {
        ensure_dir(dir)?;
    }

    let n = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = path.with_extension(format!("tmp.{}.{}", std::process::id(), n));
    let io = |path: &Path| {
        let path = path.to_path_buf();
        move |source| KnownHostsError::Io { path, source }
    };
    let _ = std::fs::remove_file(&tmp); // a leftover from a crashed run with our pid
    let written = create_private(&tmp).and_then(|mut f| {
        f.write_all(contents.as_bytes())?;
        f.sync_all()
    });
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(io(&tmp)(e));
    }

    if std::fs::rename(&tmp, path).is_err() {
        // Move the original ASIDE (not delete) before putting the new file in
        // place, so a crash between the two renames cannot lose the catalogue.
        let bak = path.with_extension(format!("bak.{}.{}", std::process::id(), n));
        let had_original = path.exists();
        if had_original {
            std::fs::rename(path, &bak).map_err(|source| {
                let _ = std::fs::remove_file(&tmp);
                KnownHostsError::Io {
                    path: path.to_path_buf(),
                    source,
                }
            })?;
        }
        match std::fs::rename(&tmp, path) {
            Ok(()) => {
                if had_original {
                    let _ = std::fs::remove_file(&bak);
                }
            }
            Err(source) => {
                // Put the original back rather than leave the destination empty.
                if had_original {
                    let _ = std::fs::rename(&bak, path);
                }
                let _ = std::fs::remove_file(&tmp);
                return Err(KnownHostsError::Io {
                    path: path.to_path_buf(),
                    source,
                });
            }
        }
    }
    sync_parent(path);
    Ok(())
}

/// Decode a JSON settings file's bytes: UTF-8 (a leading BOM is dropped, as
/// Notepad's "UTF-8 with BOM" writes it) or UTF-16 with a BOM (PowerShell 5's
/// `Out-File` / `>`). Anything else is an error, never a lossy guess.
fn decode_text(bytes: &[u8]) -> Result<String, String> {
    if let Some(rest) = bytes.strip_prefix(b"\xef\xbb\xbf") {
        return String::from_utf8(rest.to_vec()).map_err(|_| "it is not valid UTF-8".to_string());
    }
    let utf16 = |rest: &[u8], le: bool| -> Result<String, String> {
        if rest.len() % 2 != 0 {
            return Err("it is not valid UTF-16 (odd length)".into());
        }
        let units: Vec<u16> = rest
            .chunks_exact(2)
            .map(|c| if le { u16::from_le_bytes([c[0], c[1]]) } else { u16::from_be_bytes([c[0], c[1]]) })
            .collect();
        String::from_utf16(&units).map_err(|_| "it is not valid UTF-16".to_string())
    };
    if let Some(rest) = bytes.strip_prefix(b"\xff\xfe") {
        return utf16(rest, true);
    }
    if let Some(rest) = bytes.strip_prefix(b"\xfe\xff") {
        return utf16(rest, false);
    }
    String::from_utf8(bytes.to_vec()).map_err(|_| {
        "it is not valid UTF-8 (save it as UTF-8, or UTF-16 with a byte-order mark)".to_string()
    })
}

/// Keep the bytes of a file that could not be loaded, as
/// `<name>.corrupt-<unix time>` beside it, so the next save can never destroy
/// the only copy. A backup with identical bytes already there is reused
/// (repeated launches do not pile up copies). Returns the backup's path.
fn keep_backup(path: &Path, bytes: &[u8]) -> Option<PathBuf> {
    let name = path.file_name()?.to_string_lossy().to_string();
    let prefix = format!("{name}.corrupt-");
    if let Some(dir) = path.parent() {
        if let Ok(rd) = std::fs::read_dir(dir) {
            for e in rd.flatten() {
                if e.file_name().to_string_lossy().starts_with(&prefix)
                    && std::fs::read(e.path()).is_ok_and(|b| b == bytes)
                {
                    return Some(e.path());
                }
            }
        }
    }
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    for n in 0..1000u32 {
        let candidate = match n {
            0 => path.with_file_name(format!("{prefix}{ts}")),
            n => path.with_file_name(format!("{prefix}{ts}-{n}")),
        };
        match create_private(&candidate) {
            Ok(mut f) => {
                use std::io::Write;
                if f.write_all(bytes).and_then(|_| f.sync_all()).is_ok() {
                    return Some(candidate);
                }
                let _ = std::fs::remove_file(&candidate);
                return None;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return None,
        }
    }
    None
}

/// Read and parse a JSON file the frontend owns. `Ok(None)`: no file. A file
/// that exists but cannot be decoded or parsed is backed up (see
/// `keep_backup`) and reported as an error naming the backup.
fn read_json(path: &Path) -> Result<Option<Value>, KnownHostsError> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(KnownHostsError::Io {
                path: path.to_path_buf(),
                source,
            })
        }
    };
    let parsed = decode_text(&bytes).and_then(|t| {
        serde_json::from_str::<Value>(&t).map_err(|e| format!("it is not valid JSON ({e})"))
    });
    match parsed {
        Ok(v) => Ok(Some(v)),
        Err(why) => {
            let backup = keep_backup(path, &bytes);
            Err(KnownHostsError::Parse(match backup {
                Some(b) => format!(
                    "{} could not be read: {why}. It was left in place and a copy kept at {}.",
                    path.display(),
                    b.display()
                ),
                None => format!("{} could not be read: {why}. It was left in place.", path.display()),
            }))
        }
    }
}

/// `%APPDATA%\hawser\hosts.json`, beside known_hosts.
fn hosts_path() -> Result<PathBuf, KnownHostsError> {
    let store = super::known_hosts::store_path()?;
    Ok(store
        .parent()
        .ok_or(KnownHostsError::NoAppDataDir)?
        .join("hosts.json"))
}

/// Read the catalogue. Returns `None` only when no file exists yet, which
/// the frontend treats as "seed from defaults". A file that exists but cannot
/// be read, decoded (a UTF-8 BOM and UTF-16 with a BOM are accepted) or parsed,
/// or whose root is not a list, is an ERROR — never `None`: answering "absent"
/// made the frontend write its demo catalogue over the user's real one. The
/// file is left in place and a timestamped copy is kept beside it.
pub fn load() -> Result<Option<Value>, KnownHostsError> {
    let path = hosts_path()?;
    let value = read_json(&path)?;
    match value {
        Some(v) if !v.is_array() => {
            let backup = std::fs::read(&path).ok().and_then(|b| keep_backup(&path, &b));
            Err(KnownHostsError::Parse(format!(
                "{} is not a host list (its top level must be a JSON array). It was left in place{}.",
                path.display(),
                backup.map(|b| format!(" and a copy kept at {}", b.display())).unwrap_or_default()
            )))
        }
        v => Ok(v),
    }
}

fn catalogue_text(tree: &Value) -> Result<String, KnownHostsError> {
    if !tree.is_array() {
        return Err(KnownHostsError::Parse("the host catalogue must be a list".into()));
    }
    serde_json::to_string_pretty(tree).map_err(|e| KnownHostsError::Parse(e.to_string()))
}

/// Write the catalogue atomically. Losing the host list to a mid-write crash
/// would be a real data-loss bug, so this goes through `write_atomic`
/// (unique temp, rename-replace, process-wide serialisation). Published only
/// through `save_and_narrow`, which orders saves.
fn save_at(path: &Path, tree: &Value) -> Result<(), KnownHostsError> {
    write_atomic(path, &catalogue_text(tree)?)
}

/// The first-run seed: create the catalogue only if NO file exists, never
/// replacing one (a file restored between the "missing" read and this write
/// is kept). Written to a private temp file, synced, then published with a
/// no-replace rename. `Ok(false)`: a file was already there; nothing written.
pub fn save_new(tree: &Value) -> Result<bool, KnownHostsError> {
    save_new_at(&hosts_path()?, tree)
}

fn save_new_at(path: &Path, tree: &Value) -> Result<bool, KnownHostsError> {
    use std::io::Write;
    let text = catalogue_text(tree)?;
    let _guard = WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(dir) = path.parent() {
        ensure_dir(dir)?;
    }
    let n = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = path.with_extension(format!("tmp.{}.{}", std::process::id(), n));
    let _ = std::fs::remove_file(&tmp);
    let io = |p: &Path| {
        let p = p.to_path_buf();
        move |source| KnownHostsError::Io { path: p, source }
    };
    if let Err(e) = create_private(&tmp).and_then(|mut f| {
        f.write_all(text.as_bytes())?;
        f.sync_all()
    }) {
        let _ = std::fs::remove_file(&tmp);
        return Err(io(&tmp)(e));
    }
    let published = super::artifacts::rename_noreplace(&tmp, path);
    let _ = std::fs::remove_file(&tmp);
    match published {
        Ok(()) => {
            sync_parent(path);
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(io(path)(e)),
    }
}

/// Keep a `.corrupt-<ts>` copy of hosts.json as it is now, for a file the
/// FRONTEND found unusable (malformed nodes the backend's JSON check passes).
/// Returns the backup's path; `None` when there is no file.
pub fn keep_catalogue_backup() -> Result<Option<PathBuf>, KnownHostsError> {
    let path = hosts_path()?;
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(KnownHostsError::Io { path, source }),
    };
    keep_backup(&path, &bytes)
        .map(Some)
        .ok_or_else(|| KnownHostsError::Parse(format!("could not keep a copy of {}", path.display())))
}

/// Serialises catalogue publication (and the narrowing that goes with it),
/// holding the generation of the last tree published this run.
static CATALOGUE_LOCK: Mutex<u64> = Mutex::new(0);

/// Prefix of the error a stale save gets (the frontend recognises it).
pub const STALE_SAVE: &str = "stale catalogue save";

/// Save the catalogue AND revoke, for each vault id in `narrow`, every bound
/// destination that no host in `tree` uses any more — as one operation, under
/// one lock that also orders publication.
///
/// `generation`: the frontend numbers its saves; one that is not newer than
/// the last tree published is refused (`STALE_SAVE`), so an older tree can
/// never replace a newer one however the IPC calls are scheduled. `None` (an
/// older caller) is unordered.
///
/// Narrowing runs FIRST, and a narrowing failure saves nothing: the edit is
/// reported as not saved (the frontend keeps it and retries with the next
/// save). The other order could leave the catalogue edited while the old
/// destination still receives the password. A narrowing that did succeed
/// before a later one failed stays applied: narrowing only ever removes
/// destinations, so that is safe, and the retry repeats it as a no-op.
/// Destinations are derived here, from `tree`, with the vault's own id rule
/// (`binding_key`); a frontend-supplied tree can revoke but never authorize.
pub fn save_and_narrow(tree: &Value, narrow: &[String], generation: Option<u64>) -> Result<(), String> {
    let hosts = hosts_path().map_err(|e| e.to_string())?;
    let bindings = bindings_path().map_err(|e| e.to_string())?;
    save_and_narrow_with(&OsVault, &hosts, &bindings, tree, narrow, generation)
}

fn save_and_narrow_with(
    vault: &impl VaultOps,
    hosts: &Path,
    bindings: &Path,
    tree: &Value,
    narrow: &[String],
    generation: Option<u64>,
) -> Result<(), String> {
    if !tree.is_array() {
        return Err("the host catalogue must be a list".into());
    }
    let mut last = CATALOGUE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(g) = generation {
        if g <= *last {
            return Err(format!("{STALE_SAVE} (generation {g}; last saved {})", *last));
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut failed = Vec::new();
    for id in narrow {
        if check_host_cred_id(id).is_err() || !seen.insert(binding_key(id)) {
            continue;
        }
        if let Err(e) = narrow_binding_with(vault, bindings, id, &catalogue_dests(tree, id)) {
            failed.push(format!("{id}: {e}"));
        }
    }
    if !failed.is_empty() {
        return Err(format!(
            "the change was not saved, because a saved password could not be withdrawn from the destinations it no longer serves ({})",
            failed.join("; ")
        ));
    }
    save_at(hosts, tree).map_err(|e| e.to_string())?;
    if let Some(g) = generation {
        *last = g;
    }
    Ok(())
}

/// Destinations in `tree` whose effective vault entry (`credentialId`, else
/// the host's own id) is `cred_id`, compared with the vault's case rule.
fn catalogue_dests(tree: &Value, cred_id: &str) -> Vec<Dest> {
    let mut out: Vec<Dest> = Vec::new();
    walk_hosts(tree, &mut |node| {
        let id = node.get("id").and_then(Value::as_str);
        let effective = node.get("credentialId").and_then(Value::as_str).or(id);
        if !effective.is_some_and(|e| same_cred(e, cred_id)) {
            return;
        }
        if let (Some(h), Some(p), Some(u)) = (
            node.get("hostname").and_then(Value::as_str),
            node.get("port").and_then(Value::as_u64).and_then(|p| u16::try_from(p).ok()),
            node.get("username").and_then(Value::as_str),
        ) {
            let d = Dest { host: h.into(), port: p, username: u.into() };
            if !out.contains(&d) {
                out.push(d);
            }
        }
    });
    out
}

/* -------------------------------------------------------------------------- */

// -------------------------------------------------------------------------
// Backend-owned credential→destination authorization.
//
// `ssh_connect` must not decide "may this saved password go to this host?" by
// reading the FRONTEND-owned catalogue (hosts.json): a compromised webview can
// rewrite that file via `hosts_save`, add an attacker destination that borrows
// a victim's `credentialId`, then connect — and the backend would treat it as
// authorized. So the authorization is backend-owned, written only when the
// human saves the secret, and only ever narrowed afterwards. Repointing it
// therefore requires `credential_save`, which overwrites the secret itself —
// an attacker cannot keep a victim's password while redirecting it.
//
// It is held in two places that must agree:
// - `credential_bindings.json` (0600, atomic replace): `cred_id -> [
//   {host,port,username}, … ]`, the destination list;
// - the secret's own vault item (utils::vault_item): the secret plus
//   `dest_digest`, SHA-256 of that list's canonical set.
// A secret is sent only to a destination in a list whose digest equals the one
// stored WITH the secret. Every disagreement — a crash between the two writes,
// a failed rollback, an edited or restored file — fails closed and the user
// re-enters the password; nothing can pair a secret with a list it was not
// saved (or narrowed) with. The vault item stays small however many hosts
// share the password (Windows Credential Manager caps a blob at 2,560 bytes).
//
// No earlier format is read: no Hawser build has been released (see
// utils::vault_item), so there is no plain-secret, journal or backfill path.
// -------------------------------------------------------------------------

fn bindings_path() -> Result<PathBuf, KnownHostsError> {
    let store = super::known_hosts::store_path()?;
    Ok(store
        .parent()
        .ok_or(KnownHostsError::NoAppDataDir)?
        .join("credential_bindings.json"))
}

/// Held across every load→modify→write of the bindings file, so two concurrent
/// saves (parallel credential_save commands, two tabs saving typed passwords)
/// cannot drop each other's entry.
static BINDINGS_LOCK: Mutex<()> = Mutex::new(());

/// Bindings are keyed with exactly the case rule the OS vault uses, so a
/// binding and the secret it guards can never disagree about identity:
/// - Windows Credential Manager resolves target names case-insensitively, so
///   `H-ABC` and `h-abc` are ONE secret and must share one binding (else a
///   differently-cased id looks "unbound" and can be re-bound elsewhere).
/// - macOS Keychain / Secret Service are case-sensitive: they are TWO secrets,
///   and folding there would let a throwaway `h-abc` binding authorize sending
///   the real `H-ABC` secret.
///
/// The rule itself is `credentials::vault_id_key`, the one the frontend is
/// told about too (`vault_id_rule`), so every side compares ids alike.
fn binding_key(cred_id: &str) -> String {
    crate::credentials::vault_id_key(cred_id)
}

/// Whether two credential ids name the same vault entry (see `binding_key`).
fn same_cred(a: &str, b: &str) -> bool {
    binding_key(a) == binding_key(b)
}

/// Re-key a bindings map loaded from disk with `binding_key`. This build
/// writes only normalised keys, so this matters only for a file edited by
/// hand (or copied from another OS): spellings that fold together but
/// disagree are BOTH dropped (fail closed: the user re-saves the password)
/// rather than merged, since one of them may have been planted.
fn normalize_keys(map: Value) -> Value {
    let Value::Object(obj) = map else { return map };
    let mut out = serde_json::Map::new();
    let mut conflicted = std::collections::BTreeSet::new();
    for (k, v) in obj {
        let key = binding_key(&k);
        if conflicted.contains(&key) {
            continue;
        }
        match out.get(&key) {
            Some(existing) if existing != &v => {
                out.remove(&key);
                conflicted.insert(key);
            }
            Some(_) => {}
            None => {
                out.insert(key, v);
            }
        }
    }
    Value::Object(out)
}

/// The bindings map, distinguishing a missing file (`Ok({})` — nothing bound
/// yet) from an unreadable or corrupt one (`Err`), which must fail closed.
fn read_bindings_at(path: &Path) -> Result<Value, ()> {
    match std::fs::read_to_string(path) {
        Ok(t) => match serde_json::from_str::<Value>(&t) {
            Ok(v) if v.is_object() => Ok(normalize_keys(v)),
            _ => Err(()),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(json!({})),
        Err(_) => Err(()),
    }
}

/// `cred_id`'s destination list. `Ok(None)`: no entry. `Err`: the file, or
/// this entry, cannot be read (fail closed).
fn read_entry_at(path: &Path, cred_id: &str) -> Result<Option<Vec<Dest>>, ()> {
    let map = read_bindings_at(path)?;
    match map.get(binding_key(cred_id)) {
        None => Ok(None),
        Some(v) => serde_json::from_value::<Vec<Dest>>(v.clone()).map(Some).map_err(|_| ()),
    }
}

/// Same unique-temp, serialised, never-delete-the-original replace as the
/// catalogue (`write_atomic`, 0600). Callers hold BINDINGS_LOCK.
fn write_bindings_at(path: &Path, map: &Value) -> Result<(), KnownHostsError> {
    // Test hook: a bindings file under a "fail-writes" directory cannot be written.
    #[cfg(test)]
    if path.to_string_lossy().contains("fail-writes") || FAIL_BINDING_WRITES.with(|c| c.get()) {
        return Err(KnownHostsError::Parse("injected binding write failure".into()));
    }
    let text =
        serde_json::to_string_pretty(map).map_err(|e| KnownHostsError::Parse(e.to_string()))?;
    write_atomic(path, &text)
}

#[cfg(test)]
thread_local! {
    static FAIL_BINDING_WRITES: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_ROLLBACK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Catalogue destinations that legitimately use vault entry `cred_id`: the owner
/// record (`id == cred_id`) and any borrower (`credentialId == cred_id`), each
/// contributing its own `hostname`/`port`/`username`.
fn dests_for_cred(cred_id: &str) -> Vec<Dest> {
    match load() {
        Ok(Some(tree)) => catalogue_users(&tree, cred_id),
        _ => Vec::new(),
    }
}

fn catalogue_users(tree: &Value, cred_id: &str) -> Vec<Dest> {
    let mut out: Vec<Dest> = Vec::new();
    walk_hosts(tree, &mut |node| {
        let id = node.get("id").and_then(Value::as_str);
        let borrows = node.get("credentialId").and_then(Value::as_str);
        let uses = |x: Option<&str>| x.is_some_and(|x| same_cred(x, cred_id));
        if !uses(id) && !uses(borrows) {
            return;
        }
        if let (Some(h), Some(p), Some(u)) = (
            node.get("hostname").and_then(Value::as_str),
            node.get("port").and_then(Value::as_u64).and_then(|p| u16::try_from(p).ok()),
            node.get("username").and_then(Value::as_str),
        ) {
            let d = Dest { host: h.into(), port: p, username: u.into() };
            if !out.contains(&d) {
                out.push(d);
            }
        }
    });
    out
}

/// One approved destination for a saved secret.
#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct Dest {
    pub host: String,
    pub port: u16,
    pub username: String,
}

impl Dest {
    fn to_json(&self) -> Value {
        json!({ "host": self.host, "port": u64::from(self.port), "username": self.username })
    }

    fn tuple(&self) -> Destination {
        (self.host.clone(), self.port, self.username.clone())
    }
}

/// The digest a vault item for `cred_id` holds for the list `dests`.
fn digest_of(cred_id: &str, dests: &[Dest]) -> String {
    let tuples: Vec<Destination> = dests.iter().map(Dest::tuple).collect();
    vault_item::dest_digest(&binding_key(cred_id), &tuples)
}

/// The destinations a save binds. `exact`: the set the caller approved (the
/// editor's view of the catalogue AFTER the edit), which REPLACES the binding,
/// so an edited host's old address is revoked. `None` keeps the older rule
/// (the catalogue's current users plus the owner), for paths that have no
/// such view. The owner is always included.
fn binding_dests(cred_id: &str, owner: &Dest, exact: Option<&[Dest]>) -> Result<Vec<Dest>, KnownHostsError> {
    if crate::credentials::is_reserved_id(cred_id) {
        return Err(KnownHostsError::Parse(format!(
            "'{cred_id}' is a reserved id and cannot be bound to a host"
        )));
    }
    crate::credentials::validate_id(cred_id).map_err(KnownHostsError::Parse)?;
    let mut dests: Vec<Dest> = match exact {
        Some(list) => list.to_vec(),
        None => dests_for_cred(cred_id),
    };
    if !dests.contains(owner) {
        dests.push(owner.clone());
    }
    let mut unique: Vec<Dest> = Vec::with_capacity(dests.len());
    for d in dests {
        if !unique.contains(&d) {
            unique.push(d);
        }
    }
    Ok(unique)
}

/// Set (`Some`) or remove (`None`) `cred_id`'s entry in the bindings file.
/// A corrupt file is replaced rather than merged into: every other entry in
/// it then has no list matching its vault digest, so it fails closed.
fn set_entry_at(path: &Path, cred_id: &str, entry: Option<Value>) -> Result<(), KnownHostsError> {
    let _guard = BINDINGS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut map = match read_bindings_at(path) {
        Ok(m) => m,
        // Nothing to remove from a file that authorizes nothing.
        Err(()) if entry.is_none() => return Ok(()),
        Err(()) => json!({}),
    };
    let key = binding_key(cred_id);
    if let Some(obj) = map.as_object_mut() {
        match entry {
            Some(v) => {
                if obj.get(&key) == Some(&v) {
                    return Ok(());
                }
                obj.insert(key, v);
            }
            None => {
                if obj.remove(&key).is_none() {
                    return Ok(());
                }
            }
        }
    }
    write_bindings_at(path, &map)
}

fn list_json(dests: &[Dest]) -> Value {
    Value::Array(dests.iter().map(Dest::to_json).collect())
}

/* ------------------------------------------ vault item: secret + digest */

/// Serialises every vault-item transaction (save, narrow, delete, and the
/// connect-time read), so a read never sees one half of a save. Taken before
/// BINDINGS_LOCK (and after CATALOGUE_LOCK).
static VAULT_LOCK: Mutex<()> = Mutex::new(());

fn vault_lock() -> std::sync::MutexGuard<'static, ()> {
    VAULT_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// The OS vault, behind a seam so the transactions are testable.
pub trait VaultOps {
    fn read(&self, id: &str) -> Result<zeroize::Zeroizing<String>, crate::credentials::CredError>;
    fn write(&self, id: &str, user: &str, secret: &str) -> Result<(), crate::credentials::CredError>;
    fn delete(&self, id: &str) -> Result<(), crate::credentials::CredError>;
    /// Whether an item exists, without decrypting it (no unlock prompt).
    fn exists(&self, id: &str) -> bool;
}

pub struct OsVault;

impl VaultOps for OsVault {
    fn read(&self, id: &str) -> Result<zeroize::Zeroizing<String>, crate::credentials::CredError> {
        crate::credentials::read_secret(id)
    }
    fn write(&self, id: &str, user: &str, secret: &str) -> Result<(), crate::credentials::CredError> {
        crate::credentials::write_secret(id, user, secret)
    }
    fn delete(&self, id: &str) -> Result<(), crate::credentials::CredError> {
        crate::credentials::delete_secret(id)
    }
    fn exists(&self, id: &str) -> bool {
        crate::credentials::has_secret(id)
    }
}

fn check_host_cred_id(cred_id: &str) -> Result<(), String> {
    if crate::credentials::is_reserved_id(cred_id) {
        return Err(format!("'{cred_id}' is a reserved vault id, not a host"));
    }
    crate::credentials::validate_id(cred_id)
}

/// Save a secret together with the destinations it may be sent to. `exact`:
/// see `binding_dests`.
pub fn save_credential(
    cred_id: &str,
    username: &str,
    secret: &str,
    owner: &Dest,
    exact: Option<&[Dest]>,
) -> Result<(), String> {
    let path = bindings_path().map_err(|e| e.to_string())?;
    save_credential_with(&OsVault, &path, cred_id, username, secret, owner, exact)
}

/// Order: the file entry with the NEW destinations first, then the vault item
/// with the matching digest. Between the two (a crash, a failed vault write
/// whose rollback also fails) the old secret's digest does not match the new
/// list and the new list has no secret: nothing is sent anywhere until the
/// password is saved again. A failed vault write restores the previous entry,
/// so the previous secret keeps working.
fn save_credential_with(
    vault: &impl VaultOps,
    path: &Path,
    cred_id: &str,
    username: &str,
    secret: &str,
    owner: &Dest,
    exact: Option<&[Dest]>,
) -> Result<(), String> {
    check_host_cred_id(cred_id)?;
    let dests = binding_dests(cred_id, owner, exact).map_err(|e| e.to_string())?;
    // Encoded before anything is written, so a refusal (size) changes nothing.
    let item = vault_item::encode(&Envelope {
        user: username.to_string(),
        secret: zeroize::Zeroizing::new(secret.to_string()),
        dest_digest: Some(digest_of(cred_id, &dests)),
        origin_digest: None,
    })?;
    let _vault = vault_lock();
    let previous = read_bindings_at(path).ok().and_then(|m| m.get(binding_key(cred_id)).cloned());
    set_entry_at(path, cred_id, Some(list_json(&dests)))
        .map_err(|e| format!("could not record where the password may be sent: {e}"))?;
    if let Err(e) = vault.write(cred_id, username, &item) {
        // Best effort: if this fails too, the old secret's digest does not
        // match the file and it fails closed.
        #[cfg(test)]
        if FAIL_ROLLBACK.with(|c| c.get()) {
            return Err(e.to_string());
        }
        let _ = set_entry_at(path, cred_id, previous);
        return Err(e.to_string());
    }
    Ok(())
}

/// Delete a secret and, once it is gone, its destination list. A vault error
/// keeps both (the secret is still there) and is returned.
pub fn delete_credential(cred_id: &str) -> Result<(), String> {
    let path = bindings_path().map_err(|e| e.to_string())?;
    delete_credential_with(&OsVault, &path, cred_id)
}

fn delete_credential_with(vault: &impl VaultOps, path: &Path, cred_id: &str) -> Result<(), String> {
    use crate::credentials::CredError;
    check_host_cred_id(cred_id)?;
    let _vault = vault_lock();
    match vault.delete(cred_id) {
        Ok(()) | Err(CredError::NotFound(_)) => {
            // Without the secret a list authorizes nothing; a failure to drop
            // it is harmless (a later save replaces it).
            let _ = set_entry_at(path, cred_id, None);
            Ok(())
        }
        Err(e) => Err(e.to_string()),
    }
}

/// Shrink a credential's destinations to those in `keep` (never adds one:
/// widening needs the secret re-typed, i.e. a save). For revoking a host's old
/// address when it is edited, deleted, or stops borrowing the credential.
pub fn narrow_binding(cred_id: &str, keep: &[Dest]) -> Result<(), String> {
    let path = bindings_path().map_err(|e| e.to_string())?;
    narrow_binding_with(&OsVault, &path, cred_id, keep)
}

/// Order: the vault item with the narrowed digest first, then the file. If
/// the file write fails the two disagree and the secret fails closed; the
/// retry (the frontend's NarrowQueue) finds the vault digest equal to the
/// digest of the narrowed list and completes the file write. If the vault
/// write fails nothing has changed and the error is returned.
///
/// Only ever shrinks what is authorized: the vault digest is only rewritten to
/// a subset of a list that matched it, and the file is only rewritten to a
/// subset of itself.
fn narrow_binding_with(vault: &impl VaultOps, path: &Path, cred_id: &str, keep: &[Dest]) -> Result<(), String> {
    use crate::credentials::CredError;
    check_host_cred_id(cred_id)?;
    let _vault = vault_lock();
    let map = read_bindings_at(path).map_err(|_| "the credential bindings file is unreadable".to_string())?;
    let list = match map.get(binding_key(cred_id)).map(|v| serde_json::from_value::<Vec<Dest>>(v.clone())) {
        // No list: the secret (if any) is authorized nowhere.
        None => return Ok(()),
        Some(Ok(list)) => list,
        // A damaged entry authorizes nothing; dropping it keeps it that way.
        Some(Err(_)) => return set_entry_at(path, cred_id, None).map_err(|e| e.to_string()),
    };
    let narrowed: Vec<Dest> = list.iter().filter(|d| keep.contains(d)).cloned().collect();
    let shrink_file = || {
        if narrowed.len() == list.len() {
            return Ok(());
        }
        set_entry_at(path, cred_id, Some(list_json(&narrowed))).map_err(|e| e.to_string())
    };
    // Nothing saved (asked without decrypting, so no unlock prompt): only the
    // stale list is left to shrink.
    if !vault.exists(cred_id) {
        return shrink_file();
    }
    let raw = match vault.read(cred_id) {
        Ok(raw) => raw,
        Err(CredError::NotFound(_)) => return shrink_file(),
        Err(e) => return Err(format!("could not read the saved password to withdraw it: {e}")),
    };
    let Ok(env) = vault_item::decode(raw) else {
        // An item this build cannot read authorizes nothing.
        return shrink_file();
    };
    let Some(stored) = env.dest_digest.as_deref() else {
        // Not a host item (an AI key's): authorizes no host.
        return shrink_file();
    };
    let want = digest_of(cred_id, &narrowed);
    if stored == want {
        // Already narrowed in the vault (possibly by an attempt whose file
        // write failed): finish the file.
        return shrink_file();
    }
    if stored != digest_of(cred_id, &list) {
        // Already disagreeing, so authorized nowhere; shrinking the file
        // keeps it that way.
        return shrink_file();
    }
    if narrowed.len() == list.len() {
        return Ok(());
    }
    let user = env.user.clone();
    let item = vault_item::encode(&Envelope { dest_digest: Some(want), ..env })?;
    vault.write(cred_id, &user, &item).map_err(|e| e.to_string())?;
    shrink_file()
}

/// What the vault holds for a connect, read together with its destinations.
pub enum StoredSecret {
    /// Nothing saved under this id.
    None,
    /// The secret, authorized for the destination asked about (or not
    /// needing a binding).
    Authorized(zeroize::Zeroizing<String>),
    /// A secret exists, its list is intact, and this destination is not in it.
    Unbound,
    /// A secret exists but cannot be used: its item is not one this build
    /// reads, or its destination list does not match the digest stored with
    /// it (an interrupted save, a damaged or edited file). The user saves the
    /// password again.
    Poisoned,
}

/// Read `cred_id`'s item and check this destination against its destination
/// list, which must match the digest stored in the item. `check_binding`:
/// false for a key passphrase (used locally, never sent).
pub fn read_authorized(
    cred_id: &str,
    dest: &Dest,
    check_binding: bool,
) -> Result<StoredSecret, crate::credentials::CredError> {
    let path = bindings_path().ok();
    read_authorized_with(&OsVault, path.as_deref(), cred_id, dest, check_binding)
}

fn read_authorized_with(
    vault: &impl VaultOps,
    path: Option<&Path>,
    cred_id: &str,
    dest: &Dest,
    check_binding: bool,
) -> Result<StoredSecret, crate::credentials::CredError> {
    use crate::credentials::CredError;
    let _vault = vault_lock();
    let raw = match vault.read(cred_id) {
        Err(CredError::NotFound(_)) => return Ok(StoredSecret::None),
        Err(e) => return Err(e),
        Ok(s) => s,
    };
    let Ok(env) = vault_item::decode(raw) else {
        return Ok(StoredSecret::Poisoned);
    };
    let Some(stored) = env.dest_digest.as_deref() else {
        // An AI key item under a host id: never a host secret.
        return Ok(StoredSecret::Poisoned);
    };
    if !check_binding {
        return Ok(StoredSecret::Authorized(env.secret));
    }
    let list = match path.map(|p| read_entry_at(p, cred_id)) {
        Some(Ok(Some(list))) => list,
        _ => return Ok(StoredSecret::Poisoned),
    };
    if digest_of(cred_id, &list) != stored {
        return Ok(StoredSecret::Poisoned);
    }
    Ok(if list.contains(dest) { StoredSecret::Authorized(env.secret) } else { StoredSecret::Unbound })
}

/// Write `tree` (pretty JSON) into `dir` as `hawser-hosts.json`, or
/// `hawser-hosts-2.json`, … when that exists: never overwriting a file and
/// never following a symlink planted at the name. The content is written to an
/// exclusive temp file, synced, then published with a hard link (atomic, and
/// fails if the name is taken); where hard links are unsupported (FAT, some
/// network shares) the synced temp file is renamed onto the name with a
/// no-replace rename, so the final name is never written in place and never
/// holds a partial export. Owner-only (0600) on Unix. Returns the path written.
pub fn export_to(dir: &Path, tree: &Value) -> Result<PathBuf, String> {
    use std::io::Write;
    let text = serde_json::to_string_pretty(tree).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let n = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = dir.join(format!(".hawser-hosts.{}.{n}.tmp", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    create_private(&tmp)
        .and_then(|mut f| f.write_all(text.as_bytes()).and_then(|_| f.sync_all()))
        .map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            format!("{}: {e}", tmp.display())
        })?;
    let result = (1..=1000u32)
        .map(|i| match i {
            1 => dir.join("hawser-hosts.json"),
            i => dir.join(format!("hawser-hosts-{i}.json")),
        })
        .find_map(|dest| match link_export(&tmp, &dest) {
            Ok(()) => Some(Ok(dest)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => None,
            // No hard links here: move the complete, synced temp file onto
            // the name with a no-replace rename. The final name never holds
            // a partial file.
            Err(_) => match super::artifacts::rename_noreplace(&tmp, &dest) {
                Ok(()) => Some(Ok(dest)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => None,
                Err(e) => Some(Err(format!("{}: {e}", dest.display()))),
            },
        })
        .unwrap_or_else(|| Err("no free export file name (hawser-hosts-N.json) in the folder".into()));
    let _ = std::fs::remove_file(&tmp);
    if let Ok(dest) = &result {
        sync_parent(dest);
    }
    result
}

/// Publish an export by hard link. Tests can make it fail as on a filesystem
/// without hard links (FAT, some network shares).
fn link_export(tmp: &Path, dest: &Path) -> std::io::Result<()> {
    #[cfg(test)]
    if NO_HARD_LINKS.with(|c| c.get()) {
        return Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "no hard links (test)"));
    }
    std::fs::hard_link(tmp, dest)
}

#[cfg(test)]
thread_local! {
    static NO_HARD_LINKS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Visit every `kind: "host"` object in the opaque catalogue tree, descending
/// folders and an array root. Reads only the shape the security binding needs.
fn walk_hosts(node: &Value, visit: &mut impl FnMut(&Value)) {
    if let Some(arr) = node.as_array() {
        for child in arr {
            walk_hosts(child, visit);
        }
        return;
    }
    match node.get("kind").and_then(Value::as_str) {
        Some("host") => visit(node),
        Some("folder") => {
            if let Some(children) = node.get("children").and_then(Value::as_array) {
                for child in children {
                    walk_hosts(child, visit);
                }
            }
        }
        _ => {}
    }
}

/* -------------------------------------------------------------------------- */

/// `%APPDATA%\hawser\sessions.json` — which hosts were open when the app last
/// closed.
///
/// Only host ids and view mode are recorded. A TCP connection cannot be
/// serialised, so "restore" means *reconnect*, and anything that was running
/// remotely is gone unless it lived inside tmux or screen.
fn sessions_path() -> Result<PathBuf, KnownHostsError> {
    let store = super::known_hosts::store_path()?;
    Ok(store
        .parent()
        .ok_or(KnownHostsError::NoAppDataDir)?
        .join("sessions.json"))
}

/// The open-tabs list. `None` only when there is no file. An unreadable or
/// corrupt one is an error (after a copy of it is kept), exactly like an
/// unreadable file: reading it as absent let the next ordinary save replace
/// it without the user ever hearing about it. The frontend reports the error
/// and saves again only once the user says so.
pub fn load_sessions() -> Result<Option<Value>, KnownHostsError> {
    read_json(&sessions_path()?)
}

pub fn save_sessions(list: &Value) -> Result<(), KnownHostsError> {
    let path = sessions_path()?;
    let text = serde_json::to_string_pretty(list)
        .map_err(|e| KnownHostsError::Parse(e.to_string()))?;
    write_atomic(&path, &text)
}

/* -------------------------------------------------------------------------- */

/// Generic sibling-file persistence in the hawser data dir, for small settings
/// files (ai.json, settings.json). `None` only when there is no file. A
/// corrupt file is an error, the same as an unreadable one, after a
/// `.corrupt-<ts>` copy of it is kept: it used to read as absent, so the next
/// ordinary settings edit wrote defaults over it with no warning. The
/// frontend surfaces the error and saves only once the user confirms.
pub fn load_named(name: &str) -> Result<Option<Value>, KnownHostsError> {
    load_named_in(&named_dir()?, name)
}

fn named_dir() -> Result<PathBuf, KnownHostsError> {
    let store = super::known_hosts::store_path()?;
    Ok(store.parent().ok_or(KnownHostsError::NoAppDataDir)?.to_path_buf())
}

fn load_named_in(dir: &Path, name: &str) -> Result<Option<Value>, KnownHostsError> {
    read_json(&dir.join(name))
}

pub fn save_named(name: &str, value: &Value) -> Result<(), KnownHostsError> {
    let store = super::known_hosts::store_path()?;
    let dir = store.parent().ok_or(KnownHostsError::NoAppDataDir)?;
    let path = dir.join(name);
    let text =
        serde_json::to_string_pretty(value).map_err(|e| KnownHostsError::Parse(e.to_string()))?;
    write_atomic(&path, &text)
}

#[cfg(test)]
mod tests {
    use super::{binding_key, normalize_keys, walk_hosts};
    use super::*;
    use crate::credentials::CredError;
    use serde_json::{json, Value};
    use std::collections::HashMap;

    /// In-memory vault with failure switches.
    #[derive(Default)]
    struct FakeVault {
        items: Mutex<HashMap<String, String>>,
        fail_write: std::sync::atomic::AtomicUsize, // fail the Nth write from now (1 = next)
        fail_delete: std::sync::atomic::AtomicBool,
        fail_read: std::sync::atomic::AtomicBool,
    }

    impl VaultOps for FakeVault {
        fn read(&self, id: &str) -> Result<zeroize::Zeroizing<String>, CredError> {
            if self.fail_read.load(Ordering::SeqCst) {
                return Err(CredError::Malformed(id.into()));
            }
            self.items.lock().unwrap().get(id).cloned().map(zeroize::Zeroizing::new).ok_or(CredError::NotFound(id.into()))
        }
        fn write(&self, id: &str, _user: &str, secret: &str) -> Result<(), CredError> {
            let n = self.fail_write.load(Ordering::SeqCst);
            if n > 0 {
                self.fail_write.store(n - 1, Ordering::SeqCst);
                if n == 1 {
                    return Err(CredError::Malformed(id.into()));
                }
            }
            self.items.lock().unwrap().insert(id.into(), secret.into());
            Ok(())
        }
        fn delete(&self, id: &str) -> Result<(), CredError> {
            if self.fail_delete.load(Ordering::SeqCst) {
                return Err(CredError::Malformed(id.into()));
            }
            self.items.lock().unwrap().remove(id).map(|_| ()).ok_or(CredError::NotFound(id.into()))
        }
        fn exists(&self, id: &str) -> bool {
            self.items.lock().unwrap().contains_key(id)
        }
    }

    fn bindings_in(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "hawser-bind-{}-{}-{}",
            tag,
            std::process::id(),
            TMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.join("credential_bindings.json")
    }

    fn dest(h: &str, port: u16, u: &str) -> Dest {
        Dest { host: h.into(), port, username: u.into() }
    }

    /// The secret stored for `id`, decoded from its item.
    fn secret_of(v: &FakeVault, id: &str) -> Option<String> {
        let raw = v.items.lock().unwrap().get(id).cloned()?;
        Some(vault_item::decode(zeroize::Zeroizing::new(raw)).unwrap().secret.to_string())
    }

    fn stored_digest(v: &FakeVault, id: &str) -> Option<String> {
        let raw = v.items.lock().unwrap().get(id).cloned()?;
        vault_item::decode(zeroize::Zeroizing::new(raw)).unwrap().dest_digest
    }

    fn file_list(p: &Path, id: &str) -> Option<Vec<Dest>> {
        read_entry_at(p, id).unwrap()
    }

    fn read(v: &FakeVault, p: &Path, id: &str, d: &Dest) -> StoredSecret {
        read_authorized_with(v, Some(p), id, d, true).unwrap()
    }

    fn authorized(v: &FakeVault, p: &Path, id: &str, d: &Dest) -> Option<String> {
        match read(v, p, id, d) {
            StoredSecret::Authorized(s) => Some(s.to_string()),
            _ => None,
        }
    }

    fn poisoned(v: &FakeVault, p: &Path, id: &str, d: &Dest) -> bool {
        matches!(read(v, p, id, d), StoredSecret::Poisoned)
    }

    /// W4d: the vault item holds the secret and a digest; the destination
    /// list is in the bindings file, and the two must agree.
    #[test]
    fn a_secret_and_its_destinations_round_trip() {
        let v = FakeVault::default();
        let p = bindings_in("ok");
        let (a, b) = (dest("10.0.0.1", 22, "admin"), dest("10.0.0.2", 2222, "root"));
        save_credential_with(&v, &p, "h-rt", "admin", "s3cr\"et", &a, Some(&[a.clone(), b.clone()])).unwrap();
        let raw = v.items.lock().unwrap().get("h-rt").cloned().unwrap();
        assert!(raw.starts_with("hawser-vault:2:{"), "a marked item");
        assert!(!raw.contains("10.0.0.1"), "the destinations are not in the vault item");
        assert_eq!(file_list(&p, "h-rt"), Some(vec![a.clone(), b.clone()]));
        assert_eq!(stored_digest(&v, "h-rt"), Some(digest_of("h-rt", &[b.clone(), a.clone()])));
        assert_eq!(authorized(&v, &p, "h-rt", &a).as_deref(), Some("s3cr\"et"));
        assert_eq!(authorized(&v, &p, "h-rt", &b).as_deref(), Some("s3cr\"et"));
        assert!(matches!(read(&v, &p, "h-rt", &dest("evil", 22, "admin")), StoredSecret::Unbound));
        // A key passphrase is not bound (used locally, never sent).
        assert!(matches!(
            read_authorized_with(&v, Some(&p), "h-rt", &dest("evil", 22, "x"), false).unwrap(),
            StoredSecret::Authorized(_)
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    /// W4d: any disagreement between the list and the digest stored with the
    /// secret fails closed (the user re-enters the password).
    #[test]
    fn a_list_that_does_not_match_its_digest_fails_closed() {
        let v = FakeVault::default();
        let p = bindings_in("ok");
        let (a, evil) = (dest("a", 22, "u"), dest("evil", 22, "u"));
        save_credential_with(&v, &p, "h-dg", "u", "pw", &a, None).unwrap();
        // The file edited to add a destination.
        set_entry_at(&p, "h-dg", Some(list_json(&[a.clone(), evil.clone()]))).unwrap();
        assert!(poisoned(&v, &p, "h-dg", &evil));
        assert!(poisoned(&v, &p, "h-dg", &a), "not even the original destination");
        // ... to replace one.
        set_entry_at(&p, "h-dg", Some(list_json(&[evil.clone()]))).unwrap();
        assert!(poisoned(&v, &p, "h-dg", &evil));
        // Another id's (valid) list copied over it.
        save_credential_with(&v, &p, "h-other", "u", "pw2", &evil, None).unwrap();
        let other = read_bindings_at(&p).unwrap().get(binding_key("h-other")).cloned();
        set_entry_at(&p, "h-dg", other).unwrap();
        assert!(poisoned(&v, &p, "h-dg", &evil), "a digest is bound to its id");
        // Missing, damaged, or an unreadable file.
        set_entry_at(&p, "h-dg", None).unwrap();
        assert!(poisoned(&v, &p, "h-dg", &a));
        set_entry_at(&p, "h-dg", Some(json!("nonsense"))).unwrap();
        assert!(poisoned(&v, &p, "h-dg", &a));
        std::fs::write(&p, b"{ not json").unwrap();
        assert!(poisoned(&v, &p, "h-other", &evil));
        // Order does not matter: the digest is over the set.
        save_credential_with(&v, &p, "h-dg", "u", "pw", &a, Some(&[a.clone(), evil.clone()])).unwrap();
        set_entry_at(&p, "h-dg", Some(list_json(&[evil.clone(), a.clone()]))).unwrap();
        assert_eq!(authorized(&v, &p, "h-dg", &a).as_deref(), Some("pw"));
        // Saving again repairs a mismatch.
        set_entry_at(&p, "h-dg", Some(list_json(&[evil.clone()]))).unwrap();
        save_credential_with(&v, &p, "h-dg", "u", "pw", &a, Some(&[a.clone()])).unwrap();
        assert_eq!(authorized(&v, &p, "h-dg", &a).as_deref(), Some("pw"));
    }

    #[test]
    fn a_failed_vault_write_leaves_the_previous_secret_with_its_own_destinations() {
        let v = FakeVault::default();
        let p = bindings_in("ok");
        let (a, b) = (dest("10.0.0.1", 22, "admin"), dest("10.0.0.2", 22, "admin"));
        save_credential_with(&v, &p, "h-tx1", "admin", "old", &a, None).unwrap();
        v.fail_write.store(1, Ordering::SeqCst);
        assert!(save_credential_with(&v, &p, "h-tx1", "admin", "new", &b, Some(&[b.clone()])).is_err());
        assert_eq!(authorized(&v, &p, "h-tx1", &a).as_deref(), Some("old"), "the list was rolled back");
        assert!(authorized(&v, &p, "h-tx1", &b).is_none());
        // A first save that fails leaves nothing (no list either).
        v.fail_write.store(1, Ordering::SeqCst);
        assert!(save_credential_with(&v, &p, "h-tx2", "u", "pw", &a, None).is_err());
        assert_eq!(secret_of(&v, "h-tx2"), None);
        assert_eq!(file_list(&p, "h-tx2"), None);
    }

    /// W4d crash points of a save: (1) before anything, (2) after the file
    /// entry and before the vault item, (3) after both. None of them can send
    /// a secret anywhere it was not saved for.
    #[test]
    fn a_save_interrupted_at_any_step_never_sends_a_secret_to_the_wrong_place() {
        let v = FakeVault::default();
        let p = bindings_in("ok");
        let (old, new) = (dest("old.h", 22, "u"), dest("new.h", 22, "u"));
        save_credential_with(&v, &p, "h-c", "u", "pw-old", &old, Some(&[old.clone()])).unwrap();

        // (1) The file write fails: nothing changed.
        FAIL_BINDING_WRITES.with(|c| c.set(true));
        let r = save_credential_with(&v, &p, "h-c", "u", "pw-new", &new, Some(&[new.clone()]));
        FAIL_BINDING_WRITES.with(|c| c.set(false));
        assert!(r.is_err());
        assert_eq!(authorized(&v, &p, "h-c", &old).as_deref(), Some("pw-old"));
        assert!(!poisoned(&v, &p, "h-c", &new) && authorized(&v, &p, "h-c", &new).is_none());

        // (2) Crash after the file entry: the new list, the old item.
        set_entry_at(&p, "h-c", Some(list_json(&[new.clone()]))).unwrap();
        assert!(poisoned(&v, &p, "h-c", &new), "the old password never reaches the new host");
        assert!(poisoned(&v, &p, "h-c", &old), "nor, any longer, the old one");
        // A vault write that fails AND a rollback that fails end the same way.
        save_credential_with(&v, &p, "h-c", "u", "pw-old", &old, Some(&[old.clone()])).unwrap();
        v.fail_write.store(1, Ordering::SeqCst);
        FAIL_ROLLBACK.with(|c| c.set(true));
        let r = save_credential_with(&v, &p, "h-c", "u", "pw-new", &new, Some(&[new.clone()]));
        FAIL_ROLLBACK.with(|c| c.set(false));
        assert!(r.is_err());
        assert!(poisoned(&v, &p, "h-c", &new) && poisoned(&v, &p, "h-c", &old));

        // (3) Both written: the new pair.
        save_credential_with(&v, &p, "h-c", "u", "pw-new", &new, Some(&[new.clone()])).unwrap();
        assert_eq!(authorized(&v, &p, "h-c", &new).as_deref(), Some("pw-new"));
        assert!(matches!(read(&v, &p, "h-c", &old), StoredSecret::Unbound));
    }

    /// W4d: anything in the vault without the item marker (a plain value an
    /// unreleased development build wrote, or anything else) fails closed;
    /// there is no released earlier format to read.
    #[test]
    fn an_unmarked_damaged_or_future_vault_item_fails_closed() {
        let v = FakeVault::default();
        let p = bindings_in("ok");
        let a = dest("a", 22, "u");
        let d = digest_of("h-bad", &[a.clone()]);
        let ai = format!("hawser-vault:2:{{\"user\":\"u\",\"secret\":\"pw\",\"origin_digest\":\"{d}\"}}");
        for raw in [
            "plain-dev-build-password",
            "{\"v\":2,\"user\":\"u\",\"secret\":\"pw\",\"destinations\":[[\"a\",22,\"u\"]]}",
            "hawser-vault:2:{\"user\":\"u\",\"secret\":\"pw\"",
            "hawser-vault:9:{}",
            &ai,
        ] {
            v.items.lock().unwrap().insert("h-bad".into(), raw.into());
            set_entry_at(&p, "h-bad", Some(list_json(&[a.clone()]))).unwrap();
            assert!(poisoned(&v, &p, "h-bad", &a), "{raw}");
            assert!(matches!(
                read_authorized_with(&v, Some(&p), "h-bad", &a, false).unwrap(),
                StoredSecret::Poisoned
            ), "{raw}: not even as a passphrase");
            // Narrowing it is possible (it authorizes nothing) and only shrinks the list.
            narrow_binding_with(&v, &p, "h-bad", &[]).unwrap();
            assert_eq!(file_list(&p, "h-bad"), Some(vec![]), "{raw}");
        }
    }

    #[test]
    fn an_exact_destination_set_revokes_the_old_address() {
        let v = FakeVault::default();
        let p = bindings_in("ok");
        let old = dest("10.0.0.1", 22, "admin");
        let new = dest("10.0.0.9", 22, "admin");
        save_credential_with(&v, &p, "h-tx5", "admin", "pw", &old, None).unwrap();
        save_credential_with(&v, &p, "h-tx5", "admin", "pw", &new, Some(&[new.clone()])).unwrap();
        assert!(authorized(&v, &p, "h-tx5", &old).is_none());
        assert!(authorized(&v, &p, "h-tx5", &new).is_some());
    }

    #[test]
    fn narrowing_only_ever_removes_destinations() {
        let v = FakeVault::default();
        let p = bindings_in("ok");
        let (a, b, c) = (dest("a", 22, "u"), dest("b", 22, "u"), dest("c", 22, "u"));
        save_credential_with(&v, &p, "h-tx6", "u", "pw", &a, Some(&[a.clone(), b.clone()])).unwrap();
        // A failed vault write changes nothing.
        v.fail_write.store(1, Ordering::SeqCst);
        assert!(narrow_binding_with(&v, &p, "h-tx6", &[a.clone()]).is_err());
        assert!(authorized(&v, &p, "h-tx6", &b).is_some(), "the old pair stands");
        narrow_binding_with(&v, &p, "h-tx6", &[a.clone(), c.clone()]).unwrap();
        assert!(authorized(&v, &p, "h-tx6", &a).is_some());
        assert!(authorized(&v, &p, "h-tx6", &b).is_none(), "revoked");
        assert!(authorized(&v, &p, "h-tx6", &c).is_none(), "never added");
        assert_eq!(file_list(&p, "h-tx6"), Some(vec![a.clone()]));
        assert_eq!(secret_of(&v, "h-tx6").as_deref(), Some("pw"), "the secret is kept");
        // Narrowing an id with no saved secret reads nothing from the vault.
        v.fail_read.store(true, Ordering::SeqCst);
        narrow_binding_with(&v, &p, "h-unbound", &[a.clone()]).unwrap();
        v.fail_read.store(false, Ordering::SeqCst);
        // An unreadable bindings file is an error (the frontend retries).
        let q = bindings_in("ok");
        save_credential_with(&v, &q, "h-q", "u", "pw", &a, None).unwrap();
        std::fs::write(&q, b"{").unwrap();
        assert!(narrow_binding_with(&v, &q, "h-q", &[]).is_err());
    }

    /// W4d crash points of a narrowing: after the vault digest and before the
    /// file, the secret fails closed, and the retry completes the narrowing.
    #[test]
    fn a_narrowing_interrupted_between_its_writes_fails_closed_and_the_retry_completes_it() {
        let v = FakeVault::default();
        let p = bindings_in("ok");
        let (a, b) = (dest("a", 22, "u"), dest("b", 22, "u"));
        save_credential_with(&v, &p, "h-n", "u", "pw", &a, Some(&[a.clone(), b.clone()])).unwrap();
        FAIL_BINDING_WRITES.with(|c| c.set(true));
        let r = narrow_binding_with(&v, &p, "h-n", &[a.clone()]);
        FAIL_BINDING_WRITES.with(|c| c.set(false));
        assert!(r.is_err());
        assert_eq!(stored_digest(&v, "h-n"), Some(digest_of("h-n", &[a.clone()])), "the vault was narrowed");
        assert!(poisoned(&v, &p, "h-n", &b), "b is never sent the password");
        assert!(poisoned(&v, &p, "h-n", &a));
        // The retry (same request) finishes the file.
        narrow_binding_with(&v, &p, "h-n", &[a.clone()]).unwrap();
        assert_eq!(file_list(&p, "h-n"), Some(vec![a.clone()]));
        assert_eq!(authorized(&v, &p, "h-n", &a).as_deref(), Some("pw"));
        assert!(matches!(read(&v, &p, "h-n", &b), StoredSecret::Unbound));
        // A retry that keeps MORE than was narrowed cannot widen anything.
        let st = bindings_in("ok");
        save_credential_with(&v, &st, "h-m", "u", "pw", &a, Some(&[a.clone(), b.clone()])).unwrap();
        FAIL_BINDING_WRITES.with(|c| c.set(true));
        let _ = narrow_binding_with(&v, &st, "h-m", &[]);
        FAIL_BINDING_WRITES.with(|c| c.set(false));
        narrow_binding_with(&v, &st, "h-m", &[a.clone(), b.clone()]).unwrap();
        assert!(poisoned(&v, &st, "h-m", &a) && poisoned(&v, &st, "h-m", &b));
    }

    /// W4d: 500 destinations share one password; the vault item is no larger
    /// than for one, so Windows Credential Manager's limit is never reached.
    #[test]
    fn five_hundred_destinations_share_one_small_vault_item() {
        let v = FakeVault::default();
        let p = bindings_in("ok");
        let many: Vec<Dest> = (0..500).map(|i| dest(&format!("host-{i}.example.internal"), 22, "administrator")).collect();
        save_credential_with(&v, &p, "h-500", "administrator", "pw", &many[0], Some(&many)).unwrap();
        let big = v.items.lock().unwrap().get("h-500").cloned().unwrap();
        save_credential_with(&v, &p, "h-1", "administrator", "pw", &many[0], Some(&many[..1])).unwrap();
        let one = v.items.lock().unwrap().get("h-1").cloned().unwrap();
        assert_eq!(big.len(), one.len());
        assert!(big.encode_utf16().count() * 2 <= 2560);
        for d in [&many[0], &many[250], &many[499]] {
            assert_eq!(authorized(&v, &p, "h-500", d).as_deref(), Some("pw"));
        }
        narrow_binding_with(&v, &p, "h-500", &many[..10]).unwrap();
        assert!(authorized(&v, &p, "h-500", &many[9]).is_some());
        assert!(authorized(&v, &p, "h-500", &many[10]).is_none());
    }

    #[test]
    fn delete_keeps_the_secret_when_the_vault_refuses() {
        let v = FakeVault::default();
        let p = bindings_in("ok");
        let a = dest("a", 22, "u");
        save_credential_with(&v, &p, "h-tx7", "u", "pw", &a, None).unwrap();
        v.fail_delete.store(true, Ordering::SeqCst);
        assert!(delete_credential_with(&v, &p, "h-tx7").is_err());
        v.fail_delete.store(false, Ordering::SeqCst);
        assert!(authorized(&v, &p, "h-tx7", &a).is_some(), "secret and destinations both kept");
        delete_credential_with(&v, &p, "h-tx7").unwrap();
        assert!(matches!(read_authorized_with(&v, Some(&p), "h-tx7", &a, true).unwrap(), StoredSecret::None));
        assert_eq!(file_list(&p, "h-tx7"), None);
    }

    #[test]
    fn nul_and_control_ids_are_refused_everywhere() {
        let v = FakeVault::default();
        let p = bindings_in("ok");
        let a = dest("a", 22, "u");
        assert!(save_credential_with(&v, &p, "h-1\0x", "u", "pw", &a, None).is_err());
        assert!(delete_credential_with(&v, &p, "h-1\nx").is_err());
        assert!(narrow_binding_with(&v, &p, "h\0", &[]).is_err());
        assert!(v.items.lock().unwrap().is_empty());
        assert!(!p.exists());
    }

    #[test]
    fn text_decoding_accepts_boms_and_utf16_and_refuses_the_rest() {
        assert_eq!(decode_text(b"[1]").unwrap(), "[1]");
        assert_eq!(decode_text(b"\xef\xbb\xbf[1]").unwrap(), "[1]");
        let le: Vec<u8> = [0xff, 0xfe].into_iter().chain("[\"\u{e9}\"]".encode_utf16().flat_map(u16::to_le_bytes)).collect();
        assert_eq!(decode_text(&le).unwrap(), "[\"\u{e9}\"]");
        let be: Vec<u8> = [0xfe, 0xff].into_iter().chain("[2]".encode_utf16().flat_map(u16::to_be_bytes)).collect();
        assert_eq!(decode_text(&be).unwrap(), "[2]");
        assert!(decode_text(b"[\"caf\xe9\"]").is_err(), "cp1252 is not guessed");
        assert!(decode_text(b"\xff\xfe[").is_err(), "odd UTF-16");
    }

    #[test]
    fn an_unparseable_file_is_an_error_with_one_backup() {
        let d = bindings_in("json").parent().unwrap().to_path_buf();
        let f = d.join("hosts.json");
        std::fs::write(&f, b"[{ not json").unwrap();
        let e = read_json(&f).unwrap_err().to_string();
        assert!(e.contains("corrupt-"), "{e}");
        // The original stays; a second failure reuses the identical backup.
        assert_eq!(std::fs::read(&f).unwrap(), b"[{ not json");
        let _ = read_json(&f);
        let backups = std::fs::read_dir(&d).unwrap().flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with("hosts.json.corrupt-"))
            .count();
        assert_eq!(backups, 1);
        assert!(read_json(&d.join("absent.json")).unwrap().is_none());
        std::fs::write(&f, b"\xef\xbb\xbf[]").unwrap();
        assert_eq!(read_json(&f).unwrap(), Some(json!([])));
    }

    #[test]
    fn a_corrupt_settings_file_is_an_error_not_defaults() {
        let d = bindings_in("named").parent().unwrap().to_path_buf();
        for name in ["settings.json", "ai.json"] {
            let f = d.join(name);
            std::fs::write(&f, b"{ \"theme\": ").unwrap();
            let e = load_named_in(&d, name).unwrap_err().to_string();
            assert!(e.contains(&format!("{name}.corrupt-")), "{e}");
            assert_eq!(std::fs::read(&f).unwrap(), b"{ \"theme\": ", "left in place");
            let backups = std::fs::read_dir(&d).unwrap().flatten()
                .filter(|e| e.file_name().to_string_lossy().starts_with(&format!("{name}.corrupt-")))
                .count();
            assert_eq!(backups, 1);
            assert!(load_named_in(&d, &format!("absent-{name}")).unwrap().is_none());
        }
    }

    #[cfg(unix)]
    #[test]
    fn atomic_writes_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let d = bindings_in("perm").parent().unwrap().join("data");
        let f = d.join("settings.json");
        write_atomic(&f, "{}").unwrap();
        assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(&d).unwrap().permissions().mode() & 0o777, 0o700);
        // Replacing a world-readable file leaves an owner-only one.
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_atomic(&f, "{\"a\":1}").unwrap();
        assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "{\"a\":1}");
    }

    #[test]
    fn export_never_clobbers_and_never_follows_a_link() {
        let d = bindings_in("export").parent().unwrap().to_path_buf();
        let first = export_to(&d, &json!([{"kind":"host"}])).unwrap();
        assert_eq!(first, d.join("hawser-hosts.json"));
        let second = export_to(&d, &json!([])).unwrap();
        assert_eq!(second, d.join("hawser-hosts-2.json"));
        assert!(std::fs::read_to_string(&first).unwrap().contains("host"), "first export untouched");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let victim = d.join("victim.txt");
            std::fs::write(&victim, b"keep").unwrap();
            std::os::unix::fs::symlink(&victim, d.join("hawser-hosts-3.json")).unwrap();
            let third = export_to(&d, &json!([])).unwrap();
            assert_eq!(third, d.join("hawser-hosts-4.json"));
            assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
            assert_eq!(std::fs::metadata(&third).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let leftovers = std::fs::read_dir(&d).unwrap().flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .count();
        assert_eq!(leftovers, 0);
    }

    #[test]
    fn saving_the_catalogue_narrows_first_and_saves_nothing_if_that_fails() {
        let v = FakeVault::default();
        let ok = bindings_in("ok");
        let hosts = ok.with_file_name("hosts.json");
        let (a, b) = (dest("a.h", 22, "u"), dest("b.h", 22, "u"));
        save_credential_with(&v, &ok, "lender", "u", "pw", &a, Some(&[a.clone(), b.clone()])).unwrap();
        // The borrower on b.h is removed from the catalogue.
        let tree = json!([{ "kind": "host", "id": "lender", "hostname": "a.h", "port": 22, "username": "u" }]);
        v.fail_write.store(1, Ordering::SeqCst);
        let err = save_and_narrow_with(&v, &hosts, &ok, &tree, &["lender".into()], None).unwrap_err();
        assert!(err.contains("not saved"), "{err}");
        assert!(!hosts.exists(), "the catalogue was not written");
        assert!(authorized(&v, &ok, "lender", &b).is_some(), "the old envelope stands");
        // The vault works again: narrowed and saved together.
        save_and_narrow_with(&v, &hosts, &ok, &tree, &["lender".into()], None).unwrap();
        assert!(hosts.exists());
        assert!(authorized(&v, &ok, "lender", &b).is_none(), "revoked");
        assert!(authorized(&v, &ok, "lender", &a).is_some());
    }

    /// W4c: saves are numbered; an older tree can never publish after a newer
    /// one, whatever order the calls arrive in.
    #[test]
    fn an_older_catalogue_tree_never_publishes_after_a_newer_one() {
        let v = FakeVault::default();
        let p = bindings_in("ok");
        let hosts = p.with_file_name("hosts.json");
        let base = *CATALOGUE_LOCK.lock().unwrap_or_else(|e| e.into_inner()) + 1_000_000;
        let older = json!([{ "kind": "host", "id": "borrower", "hostname": "b.h", "port": 22, "username": "u" }]);
        let newer = json!([]);
        save_and_narrow_with(&v, &hosts, &p, &newer, &[], Some(base + 2)).unwrap();
        let err = save_and_narrow_with(&v, &hosts, &p, &older, &[], Some(base + 1)).unwrap_err();
        assert!(err.starts_with(STALE_SAVE), "{err}");
        let err = save_and_narrow_with(&v, &hosts, &p, &older, &[], Some(base + 2)).unwrap_err();
        assert!(err.starts_with(STALE_SAVE), "an equal generation is not newer: {err}");
        assert_eq!(read_json(&hosts).unwrap(), Some(newer));
        save_and_narrow_with(&v, &hosts, &p, &older, &[], Some(base + 3)).unwrap();
        assert_eq!(read_json(&hosts).unwrap(), Some(older));
        // A refused (failed) save does not advance the generation.
        save_credential_with(&v, &p, "x", "u", "pw", &dest("x.h", 22, "u"), None).unwrap();
        v.fail_read.store(true, Ordering::SeqCst);
        assert!(save_and_narrow_with(&v, &hosts, &p, &json!([]), &["x".into()], Some(base + 10)).is_err());
        v.fail_read.store(false, Ordering::SeqCst);
        save_and_narrow_with(&v, &hosts, &p, &json!([]), &[], Some(base + 4)).unwrap();
    }

    #[test]
    fn catalogue_destinations_use_the_vault_case_rule() {
        let tree = json!([
            { "kind": "host", "id": "h-1", "hostname": "a", "port": 22, "username": "u" },
            { "kind": "host", "id": "b", "hostname": "b", "port": 22, "username": "u", "credentialId": "H-1" },
            // Borrows someone else: its own id is not its credential.
            { "kind": "host", "id": "h-2", "hostname": "c", "port": 22, "username": "u", "credentialId": "x" },
        ]);
        let got: Vec<String> = catalogue_dests(&tree, "h-1").into_iter().map(|d| d.host).collect();
        if cfg!(windows) {
            assert_eq!(got, ["a", "b"]);
        } else {
            assert_eq!(got, ["a"]);
        }
        assert!(catalogue_dests(&tree, "h-2").is_empty());
    }

    #[test]
    fn the_first_run_seed_never_replaces_an_existing_catalogue() {
        let d = bindings_in("seed").parent().unwrap().to_path_buf();
        let f = d.join("hosts.json");
        assert!(save_new_at(&f, &json!([{ "seed": 1 }])).unwrap());
        // A file restored meanwhile (or a second seed) is kept as is.
        std::fs::write(&f, b"[\"mine\"]").unwrap();
        assert!(!save_new_at(&f, &json!([{ "seed": 2 }])).unwrap());
        assert_eq!(std::fs::read(&f).unwrap(), b"[\"mine\"]");
        let tmp_left = std::fs::read_dir(&d).unwrap().flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .count();
        assert_eq!(tmp_left, 0);
    }

    #[test]
    fn export_without_hard_links_never_writes_the_final_name_in_place() {
        let d = bindings_in("export-nolink").parent().unwrap().to_path_buf();
        NO_HARD_LINKS.with(|c| c.set(true));
        std::fs::write(d.join("hawser-hosts.json"), b"theirs").unwrap();
        let got = export_to(&d, &json!([{ "kind": "host" }]));
        NO_HARD_LINKS.with(|c| c.set(false));
        let got = got.unwrap();
        assert_eq!(got, d.join("hawser-hosts-2.json"));
        assert_eq!(std::fs::read(d.join("hawser-hosts.json")).unwrap(), b"theirs");
        assert!(std::fs::read_to_string(&got).unwrap().contains("host"));
        let leftovers = std::fs::read_dir(&d).unwrap().flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .count();
        assert_eq!(leftovers, 0);
    }

    // The audit anchor lives in the vault beside host secrets; it must never be
    // savable, readable or narrowable as a host credential, in any letter case.
    #[test]
    fn audit_seal_id_cannot_be_bound_or_authorized() {
        let v = FakeVault::default();
        let p = bindings_in("ok");
        let a = dest("fw1", 22, "admin");
        for id in [crate::utils::audit::SEAL_ID, "HAWSER:AUDIT-HEAD"] {
            assert!(save_credential_with(&v, &p, id, "admin", "pw", &a, None).is_err());
            assert!(narrow_binding_with(&v, &p, id, &[]).is_err());
        }
        assert!(v.items.lock().unwrap().is_empty() && !p.exists());
    }

    // Binding keys follow the vault's case rule: folded on Windows (one
    // Credential Manager entry), exact elsewhere (two Keychain items).
    #[test]
    fn binding_keys_follow_vault_case_rule() {
        assert_ne!(binding_key("h-abc"), binding_key("h-abd"));
        if cfg!(windows) {
            assert_eq!(binding_key("H-AbC"), binding_key("h-abc"));
        } else {
            assert_ne!(binding_key("H-AbC"), binding_key("h-abc"));
        }
    }

    // Spellings that fold together but disagree are both dropped (fail
    // closed); agreeing ones collapse to one entry.
    #[test]
    fn normalize_keys_drops_conflicting_spellings() {
        let a = json!([{ "host": "a", "port": 22u64, "username": "u" }]);
        let b = json!([{ "host": "evil", "port": 22u64, "username": "u" }]);
        let m = normalize_keys(json!({ "H-X": a.clone(), "h-x": b, "h-y": a.clone() }));
        assert_eq!(m.get(binding_key("h-y")), Some(&a));
        if cfg!(windows) {
            assert!(m.get(binding_key("h-x")).is_none());
        } else {
            assert!(m.get("H-X").is_some() && m.get("h-x").is_some());
        }
    }

    // walk_hosts must reach hosts nested inside folders and an array root, since
    // that is how snapshot/migration enumerate borrowers.
    #[test]
    fn walk_hosts_descends_folders_and_array_root() {
        let tree = json!([
            { "kind": "host", "id": "a", "hostname": "a.h", "port": 22, "username": "u" },
            { "kind": "folder", "id": "f", "name": "F", "children": [
                { "kind": "host", "id": "b", "hostname": "b.h", "port": 22, "username": "u",
                  "credentialId": "a" }
            ]}
        ]);
        let mut ids: Vec<String> = Vec::new();
        walk_hosts(&tree, &mut |n: &Value| {
            if let Some(id) = n.get("id").and_then(Value::as_str) {
                ids.push(id.to_string());
            }
        });
        assert_eq!(ids, vec!["a".to_string(), "b".to_string()]);
    }
}
