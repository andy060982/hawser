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

/// Write the catalogue atomically. Losing the host list to a mid-write crash
/// would be a real data-loss bug, so this goes through `write_atomic`
/// (unique temp, rename-replace, process-wide serialisation).
pub fn save(tree: &Value) -> Result<(), KnownHostsError> {
    save_at(&hosts_path()?, tree)
}

fn catalogue_text(tree: &Value) -> Result<String, KnownHostsError> {
    if !tree.is_array() {
        return Err(KnownHostsError::Parse("the host catalogue must be a list".into()));
    }
    serde_json::to_string_pretty(tree).map_err(|e| KnownHostsError::Parse(e.to_string()))
}

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

/// Save the catalogue AND revoke, for each vault id in `narrow`, every bound
/// destination that no host in `tree` uses any more — as one operation.
///
/// Narrowing runs FIRST, and a narrowing failure saves nothing: the edit is
/// reported as not saved (the frontend keeps it and retries with the next
/// save). The other order could leave the catalogue edited while the old
/// destination still receives the password. Destinations are derived here,
/// from `tree`, with the vault's own id rule (`binding_key`); narrowing only
/// ever removes, so a frontend-supplied tree can revoke but never authorize.
pub fn save_and_narrow(tree: &Value, narrow: &[String]) -> Result<(), String> {
    let hosts = hosts_path().map_err(|e| e.to_string())?;
    let bindings = bindings_path().map_err(|e| e.to_string())?;
    save_and_narrow_at(&hosts, &bindings, tree, narrow)
}

fn save_and_narrow_at(hosts: &Path, bindings: &Path, tree: &Value, narrow: &[String]) -> Result<(), String> {
    if !tree.is_array() {
        return Err("the host catalogue must be a list".into());
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut failed = Vec::new();
    for id in narrow {
        if check_host_cred_id(id).is_err() || !seen.insert(binding_key(id)) {
            continue;
        }
        if let Err(e) = narrow_binding_at(bindings, id, &catalogue_dests(tree, id)) {
            failed.push(format!("{id}: {e}"));
        }
    }
    if !failed.is_empty() {
        return Err(format!(
            "the change was not saved, because a saved password could not be withdrawn from the destinations it no longer serves ({})",
            failed.join("; ")
        ));
    }
    save_at(hosts, tree).map_err(|e| e.to_string())
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
// Backend-owned credential→destination bindings.
//
// `ssh_connect` must not decide "may this saved password go to this host?" by
// reading the FRONTEND-owned catalogue (hosts.json): a compromised webview can
// rewrite that file via `hosts_save`, add an attacker destination that borrows
// a victim's `credentialId`, then connect — and the backend would treat it as
// authorized. So the authorization lives in a file only the backend writes:
// `credential_bindings.json`, mapping `cred_id -> [ {host,port,username}, … ]`.
//
// It is written ONLY at credential-save time (the human is present and just
// typed the secret) and, once, at startup migration (from the on-disk catalogue
// BEFORE the webview loads). Repointing a binding therefore requires calling
// `credential_save`, which overwrites the secret itself — so an attacker cannot
// keep a victim's password while redirecting it. Later edits to hosts.json have
// no effect on what is authorized.
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

/// Sidecar file recording that the one-time startup backfill has run. Kept
/// OUTSIDE the bindings map: an in-map marker shares the credential-id
/// namespace, so `credential_delete("<marker>")` from a compromised webview
/// could erase it and re-arm the catalogue-derived backfill on next launch.
fn migrated_marker_path() -> Result<PathBuf, KnownHostsError> {
    Ok(bindings_path()?.with_file_name("credential_bindings.migrated"))
}

fn migration_done() -> bool {
    migrated_marker_path().is_ok_and(|p| p.exists())
}

fn mark_migration_done() {
    if let Ok(p) = migrated_marker_path() {
        let _ = write_atomic(&p, "1\n");
    }
}

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

/// Re-key a bindings map loaded from disk with `binding_key`. Older builds
/// stored ids verbatim; on Windows two spellings of one id would otherwise be
/// unreachable or ambiguous. Spellings that fold together but disagree are
/// BOTH dropped (fail closed: the user re-saves the password) rather than
/// merged, since one of them may have been planted.
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
/// yet) from an unreadable or corrupt one (`Err`), which must fail closed and
/// must not be mistaken for "never migrated".
fn read_bindings() -> Result<Value, ()> {
    read_bindings_at(&bindings_path().map_err(|_| ())?)
}

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

/// Same unique-temp, serialised, never-delete-the-original replace as the
/// catalogue (`write_atomic`). Callers hold BINDINGS_LOCK.
fn write_bindings_at(path: &Path, map: &Value) -> Result<(), KnownHostsError> {
    // Test hook: a bindings file under a "fail-writes" directory cannot be written.
    #[cfg(test)]
    if path.to_string_lossy().contains("fail-writes") {
        return Err(KnownHostsError::Parse("injected binding write failure".into()));
    }
    let text =
        serde_json::to_string_pretty(map).map_err(|e| KnownHostsError::Parse(e.to_string()))?;
    write_atomic(path, &text)
}


/// Catalogue destinations that legitimately use vault entry `cred_id`: the owner
/// record (`id == cred_id`) and any borrower (`credentialId == cred_id`), each
/// contributing its own `hostname`/`port`/`username`.
fn dests_for_cred(cred_id: &str) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::new();
    if let Ok(Some(tree)) = load() {
        walk_hosts(&tree, &mut |node| {
            let id = node.get("id").and_then(Value::as_str);
            let borrows = node.get("credentialId").and_then(Value::as_str);
            let uses = |x: Option<&str>| x.is_some_and(|x| same_cred(x, cred_id));
            if !uses(id) && !uses(borrows) {
                return;
            }
            if let (Some(h), Some(p), Some(u)) = (
                node.get("hostname").and_then(Value::as_str),
                node.get("port").and_then(Value::as_u64),
                node.get("username").and_then(Value::as_str),
            ) {
                let d = json!({ "host": h, "port": p, "username": u });
                if !out.contains(&d) {
                    out.push(d);
                }
            }
        });
    }
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
}

/// Record the destinations `cred_id` may be sent to, in backend-owned state.
/// The owner's own (host, port, username) is passed explicitly (authoritative,
/// and free of any hosts.json write-ordering dependency); catalogue borrowers of
/// `cred_id` present at this moment are included too.
pub fn snapshot_binding(
    cred_id: &str,
    host: &str,
    port: u16,
    username: &str,
) -> Result<(), KnownHostsError> {
    let path = bindings_path()?;
    snapshot_binding_at(&path, cred_id, &Dest { host: host.into(), port, username: username.into() }, None)
}

/// `exact`: the destination set the caller approved (the editor's view of the
/// catalogue AFTER the edit), which REPLACES the binding, so an edited host's
/// old address is revoked. `None` keeps the older rule (the catalogue's current
/// users plus the owner), for paths that have no such view.
fn snapshot_binding_at(
    path: &Path,
    cred_id: &str,
    owner: &Dest,
    exact: Option<&[Dest]>,
) -> Result<(), KnownHostsError> {
    let dests = binding_dests(cred_id, owner, exact)?;
    put_binding_at(path, cred_id, dests)
}

/// The destination list a save binds (see `snapshot_binding_at`).
fn binding_dests(cred_id: &str, owner: &Dest, exact: Option<&[Dest]>) -> Result<Vec<Value>, KnownHostsError> {
    if crate::credentials::is_reserved_id(cred_id) {
        return Err(KnownHostsError::Parse(format!(
            "'{cred_id}' is a reserved id and cannot be bound to a host"
        )));
    }
    crate::credentials::validate_id(cred_id).map_err(KnownHostsError::Parse)?;
    let mut dests: Vec<Value> = match exact {
        Some(list) => list.iter().map(Dest::to_json).collect(),
        None => dests_for_cred(cred_id),
    };
    let owner = owner.to_json();
    if !dests.contains(&owner) {
        dests.push(owner);
    }
    dests.dedup();
    Ok(dests)
}

/// Replace `cred_id`'s binding with `dests`.
fn put_binding_at(path: &Path, cred_id: &str, dests: Vec<Value>) -> Result<(), KnownHostsError> {
    let _guard = BINDINGS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // A corrupt file is replaced rather than merged into.
    let mut map = read_bindings_at(path).unwrap_or_else(|_| json!({}));
    if let Some(obj) = map.as_object_mut() {
        obj.insert(binding_key(cred_id), Value::Array(dests));
    }
    write_bindings_at(path, &map)
}

/// Drop a credential's bindings (called when its secret is deleted).
fn remove_binding_at(path: &Path, cred_id: &str) -> Result<(), KnownHostsError> {
    let _guard = BINDINGS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // An unreadable file has nothing to remove; leave it for inspection.
    let Ok(mut map) = read_bindings_at(path) else {
        return Ok(());
    };
    if let Some(obj) = map.as_object_mut() {
        if obj.remove(&binding_key(cred_id)).is_some() {
            return write_bindings_at(path, &map);
        }
    }
    Ok(())
}

/// Authorize sending the vault secret keyed by `cred_id` to `host:port` as
/// `username`, consulting ONLY the backend-owned binding file — never the
/// frontend-writable catalogue. Unknown credential, unreadable bindings, or an
/// unmatched destination returns false (fail closed).
fn binding_is_authorized_at(path: &Path, cred_id: &str, host: &str, port: u16, username: &str) -> bool {
    if crate::credentials::is_reserved_id(cred_id) || crate::credentials::validate_id(cred_id).is_err() {
        return false;
    }
    let map = read_bindings_at(path).unwrap_or_else(|_| json!({}));
    let Some(list) = map.get(binding_key(cred_id)).and_then(Value::as_array) else {
        return false;
    };
    dest_authorized_in(list, host, port, username)
}

/* ------------------------------------------------- vault + binding as a unit */

// A saved secret and its binding live in two stores (the OS vault and
// credential_bindings.json) that cannot be written atomically together. Every
// operation on the pair — save, delete, narrowing, and the connect-time read —
// runs under VAULT_LOCK, so a connect sees the pair entirely before or entirely
// after a save, never the new secret against the old binding. A save whose
// binding cannot be written puts the previous secret back; if even that fails
// the secret is removed, and if THAT fails the id is "poisoned": refused for
// sending until a save or delete of it succeeds (or the app restarts, by which
// point the user has been told to re-save it).

/// Serialises every vault+binding transaction. Taken before BINDINGS_LOCK.
static VAULT_LOCK: Mutex<()> = Mutex::new(());

fn vault_lock() -> std::sync::MutexGuard<'static, ()> {
    VAULT_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Ids whose secret may not match their binding (see above), by binding key.
static POISONED: Mutex<std::collections::BTreeSet<String>> = Mutex::new(std::collections::BTreeSet::new());

fn poison(cred_id: &str, on: bool) {
    let mut set = POISONED.lock().unwrap_or_else(|e| e.into_inner());
    if on {
        set.insert(binding_key(cred_id));
    } else {
        set.remove(&binding_key(cred_id));
    }
}

fn is_poisoned(cred_id: &str) -> bool {
    POISONED.lock().unwrap_or_else(|e| e.into_inner()).contains(&binding_key(cred_id))
}

/// The OS vault, behind a seam so the transactions are testable.
pub trait VaultOps {
    fn read(&self, id: &str) -> Result<zeroize::Zeroizing<String>, crate::credentials::CredError>;
    fn write(&self, id: &str, user: &str, secret: &str) -> Result<(), crate::credentials::CredError>;
    fn delete(&self, id: &str) -> Result<(), crate::credentials::CredError>;
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
}

fn check_host_cred_id(cred_id: &str) -> Result<(), String> {
    if crate::credentials::is_reserved_id(cred_id) {
        return Err(format!("'{cred_id}' is a reserved vault id, not a host"));
    }
    crate::credentials::validate_id(cred_id)
}

/// Save a secret and bind it, as one unit. `exact`: see `snapshot_binding_at`.
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

fn save_credential_with(
    vault: &impl VaultOps,
    path: &Path,
    cred_id: &str,
    username: &str,
    secret: &str,
    owner: &Dest,
    exact: Option<&[Dest]>,
) -> Result<(), String> {
    use crate::credentials::CredError;
    check_host_cred_id(cred_id)?;
    let _vault = vault_lock();
    // The previous value, to put back if the binding cannot be written. A
    // vault that cannot be read now would make the save unrecoverable, so it
    // is refused rather than attempted.
    let previous = match vault.read(cred_id) {
        Ok(old) => Some(old),
        Err(CredError::NotFound(_)) => None,
        Err(e) => return Err(format!("could not read the saved credential to replace it safely: {e}")),
    };
    let dests = binding_dests(cred_id, owner, exact).map_err(|e| e.to_string())?;

    // Journal the transaction before the vault changes (see `Intent`), so a
    // crash at any later point is repaired at the next start.
    let journal = intent_path_for(path);
    let mut intent = Intent {
        id: cred_id.to_string(),
        old_binding_hash: binding_hash(current_binding(path).as_ref()),
        new_binding: dests.clone(),
        phase: Phase::Staged,
    };
    write_intent(&journal, &intent).map_err(|e| format!("could not record the save before making it ({e}); nothing was changed"))?;
    if crashed(1) {
        return Err(INJECTED_CRASH.into());
    }
    if let Err(e) = vault.write(cred_id, username, secret) {
        clear_intent(&journal);
        return Err(e.to_string());
    }
    if crashed(2) {
        return Err(INJECTED_CRASH.into());
    }
    // The vault now holds the new secret. If this note cannot be written the
    // journal still says Staged, which a repair treats as ambiguous (the
    // secret is removed): safe, only less convenient.
    intent.phase = Phase::Written;
    let _ = write_intent(&journal, &intent);
    if crashed(3) {
        return Err(INJECTED_CRASH.into());
    }
    let Err(bind_err) = put_binding_at(path, cred_id, dests) else {
        if crashed(4) {
            return Err(INJECTED_CRASH.into());
        }
        clear_intent(&journal);
        poison(cred_id, false);
        return Ok(());
    };
    // From here the vault may hold either secret while a rollback runs: a
    // crash anywhere below must end with the secret removed.
    intent.phase = Phase::Ambiguous;
    let _ = write_intent(&journal, &intent);
    if crashed(5) {
        return Err(INJECTED_CRASH.into());
    }
    // The binding still names the OLD destinations: restore the old secret
    // (or no secret) so the pair stays consistent.
    let restored = match &previous {
        Some(old) => vault.write(cred_id, username, old),
        None => match vault.delete(cred_id) {
            Err(CredError::NotFound(_)) => Ok(()),
            r => r,
        },
    };
    if crashed(6) {
        return Err(INJECTED_CRASH.into());
    }
    match restored {
        Ok(()) => {
            clear_intent(&journal);
            Err(format!("could not record where the password may be sent ({bind_err}); nothing was changed"))
        }
        Err(rollback) => match vault.delete(cred_id) {
            Ok(()) | Err(CredError::NotFound(_)) => {
                let _ = remove_binding_at(path, cred_id);
                clear_intent(&journal);
                poison(cred_id, false);
                Err(format!(
                    "could not record where the password may be sent ({bind_err}) or restore the previous one ({rollback}); the saved password was removed, save it again"
                ))
            }
            Err(del) => {
                // The journal stays (Ambiguous): the next start removes it.
                poison(cred_id, true);
                Err(format!(
                    "could not record where the password may be sent ({bind_err}), restore the previous one ({rollback}) or remove it ({del}); it will not be used until it is saved again"
                ))
            }
        },
    }
}

/* ------------------------------------------------------ vault intent journal */

// The vault and the bindings file cannot be written atomically together, and
// the in-memory poison latch does not survive a crash. So a save journals its
// intent in `vault.intent` (0600, beside the bindings) BEFORE touching the
// vault, notes when the vault write has landed, and clears the journal once
// the binding is written. At startup, before the webview loads,
// `repair_vault_intent` settles a journal left behind:
// - the binding already names the new destinations: just clear it;
// - the vault write is known to have landed and the binding is still the old
//   one: finish writing the binding (the new secret gets its new binding);
// - anything else (the vault write may or may not have landed, a rollback was
//   interrupted, the binding changed under it): delete the secret and its
//   binding — the user saves the password again.
// So a crash at any point leaves the secret either paired with the binding
// it was saved for, or deleted; never a new secret behind an old binding.

#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
enum Phase {
    /// Journaled; the vault write may or may not have happened.
    Staged,
    /// The vault holds the new secret; the binding may still be the old one.
    Written,
    /// A rollback is in progress: which secret the vault holds is unknown.
    Ambiguous,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct Intent {
    id: String,
    /// SHA-256 of the binding as it was before the save (see `binding_hash`).
    old_binding_hash: String,
    /// The destinations the new secret is to be bound to.
    new_binding: Vec<Value>,
    phase: Phase,
}

const INJECTED_CRASH: &str = "injected crash";

// Test hook: the save "dies" right after step N (no cleanup at all).
#[cfg(test)]
thread_local! {
    static CRASH_AT: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
}

fn crashed(step: u8) -> bool {
    #[cfg(test)]
    {
        CRASH_AT.with(|c| c.get() == step)
    }
    #[cfg(not(test))]
    {
        let _ = step;
        false
    }
}

fn intent_path_for(bindings: &Path) -> PathBuf {
    bindings.with_file_name("vault.intent")
}

/// The whole bindings map as it is now (an unreadable file reads as a marker
/// string, which never matches a recorded hash of a real map).
fn current_binding(path: &Path) -> Option<Value> {
    let _guard = BINDINGS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    match read_bindings_at(path) {
        Ok(map) => Some(map),
        Err(()) => Some(Value::String("<unreadable>".into())),
    }
}

/// Hash of the whole bindings map, as text. The whole map, not one entry, so
/// any later change to the file (a narrowing, another id's save) shows.
fn binding_hash(map: Option<&Value>) -> String {
    use sha2::{Digest, Sha256};
    let text = serde_json::to_string(map.unwrap_or(&Value::Null)).unwrap_or_default();
    Sha256::digest(text.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

fn write_intent(path: &Path, intent: &Intent) -> Result<(), KnownHostsError> {
    let text = serde_json::to_string(intent).map_err(|e| KnownHostsError::Parse(e.to_string()))?;
    write_atomic(path, &text)
}

fn clear_intent(path: &Path) {
    let _ = std::fs::remove_file(path);
    sync_parent(path);
}

/// What a startup repair did.
#[derive(Debug, PartialEq)]
pub enum Repair {
    /// The save had completed; only the journal was left.
    Completed(String),
    /// The secret had landed; its binding was finished.
    BindingFinished(String),
    /// Which secret the vault held was unknown: it was removed.
    SecretRemoved(String),
}

/// Settle a save interrupted by a crash (see above). Call at startup, before
/// the webview can invoke anything.
pub fn repair_vault_intent() -> Result<Option<Repair>, String> {
    let path = bindings_path().map_err(|e| e.to_string())?;
    repair_vault_intent_with(&OsVault, &path)
}

fn repair_vault_intent_with(vault: &impl VaultOps, path: &Path) -> Result<Option<Repair>, String> {
    use crate::credentials::CredError;
    let journal = intent_path_for(path);
    let _vault = vault_lock();
    let text = match std::fs::read_to_string(&journal) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", journal.display())),
    };
    let Ok(intent) = serde_json::from_str::<Intent>(&text) else {
        // Only this app writes it, atomically; junk names no id to repair.
        clear_intent(&journal);
        return Err(format!("{} was not a valid journal and was removed", journal.display()));
    };
    let id = intent.id.clone();
    if check_host_cred_id(&id).is_err() {
        clear_intent(&journal);
        return Err(format!("the journal named an invalid vault id '{id}' and was removed"));
    }
    let map = current_binding(path);
    let bound_now = map.as_ref().and_then(|m| m.get(binding_key(&id))).and_then(Value::as_array);
    if intent.phase != Phase::Ambiguous && bound_now == Some(&intent.new_binding) {
        clear_intent(&journal);
        return Ok(Some(Repair::Completed(id)));
    }
    if intent.phase == Phase::Written && binding_hash(map.as_ref()) == intent.old_binding_hash {
        if put_binding_at(path, &id, intent.new_binding.clone()).is_ok() {
            clear_intent(&journal);
            poison(&id, false);
            return Ok(Some(Repair::BindingFinished(id)));
        }
    }
    match vault.delete(&id) {
        Ok(()) | Err(CredError::NotFound(_)) => {
            let _ = remove_binding_at(path, &id);
            clear_intent(&journal);
            poison(&id, false);
            Ok(Some(Repair::SecretRemoved(id)))
        }
        Err(e) => {
            // Keep the journal for the next start; refuse to send it now.
            poison(&id, true);
            Err(format!("an interrupted password save for '{id}' could not be repaired ({e}); it will not be used until it is saved again"))
        }
    }
}

/// Delete a secret and, once it is gone, its binding. A vault error keeps the
/// binding (the secret is still there) and is returned.
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
            poison(cred_id, false);
            // Without the secret the binding authorizes nothing; a failure to
            // drop it is harmless (a later save rewrites it).
            let _ = remove_binding_at(path, cred_id);
            // A journal left by an interrupted save of this id is settled too.
            let journal = intent_path_for(path);
            if std::fs::read_to_string(&journal)
                .ok()
                .and_then(|t| serde_json::from_str::<Intent>(&t).ok())
                .is_some_and(|i| same_cred(&i.id, cred_id))
            {
                clear_intent(&journal);
            }
            Ok(())
        }
        Err(e) => Err(e.to_string()),
    }
}

/// Shrink a binding to the destinations in `keep` (never adds one: widening
/// needs the secret re-typed, i.e. a save). For revoking a host's old address
/// when it is edited, deleted, or stops borrowing the credential.
pub fn narrow_binding(cred_id: &str, keep: &[Dest]) -> Result<(), String> {
    let path = bindings_path().map_err(|e| e.to_string())?;
    narrow_binding_at(&path, cred_id, keep)
}

fn narrow_binding_at(path: &Path, cred_id: &str, keep: &[Dest]) -> Result<(), String> {
    check_host_cred_id(cred_id)?;
    let _vault = vault_lock();
    let _guard = BINDINGS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut map = read_bindings_at(path).map_err(|_| "the credential bindings file is unreadable".to_string())?;
    let key = binding_key(cred_id);
    let Some(list) = map.get(&key).and_then(Value::as_array).cloned() else {
        return Ok(());
    };
    let keep: Vec<Value> = keep.iter().map(Dest::to_json).collect();
    let narrowed: Vec<Value> = list.into_iter().filter(|d| keep.contains(d)).collect();
    if let Some(obj) = map.as_object_mut() {
        if narrowed.len() == obj.get(&key).and_then(Value::as_array).map_or(0, Vec::len) {
            return Ok(());
        }
        obj.insert(key, Value::Array(narrowed));
    }
    write_bindings_at(path, &map).map_err(|e| e.to_string())
}

/// What the vault holds for a connect, read together with its binding.
pub enum StoredSecret {
    /// Nothing saved under this id.
    None,
    /// The secret, authorized for the destination asked about (or not
    /// needing a binding).
    Authorized(zeroize::Zeroizing<String>),
    /// A secret exists but this destination is not bound to it.
    Unbound,
    /// The secret may not match its binding (a failed save); refused.
    Poisoned,
}

/// Read `cred_id`'s secret and check its binding for this destination in one
/// critical section. `check_binding`: false for a key passphrase (used
/// locally, never sent).
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
    if check_binding && is_poisoned(cred_id) {
        return Ok(StoredSecret::Poisoned);
    }
    let secret = match vault.read(cred_id) {
        Err(CredError::NotFound(_)) => return Ok(StoredSecret::None),
        Err(e) => return Err(e),
        Ok(s) => s,
    };
    if !check_binding {
        return Ok(StoredSecret::Authorized(secret));
    }
    let ok = path.is_some_and(|p| binding_is_authorized_at(p, cred_id, &dest.host, dest.port, &dest.username));
    Ok(if ok { StoredSecret::Authorized(secret) } else { StoredSecret::Unbound })
}

/// Remove secrets saved under quick-connect ids (`qc-…`): a quick-connect host
/// is never in the catalogue, so no UI could ever delete them. Older builds
/// could save one from a reconnect's password prompt. Found through their
/// bindings (every such save was bound). An id that a real catalogue host
/// uses is left alone. Returns how many were removed.
pub fn purge_quick_connect_secrets() -> usize {
    let Ok(path) = bindings_path() else { return 0 };
    let Ok(map) = read_bindings_at(&path) else { return 0 };
    let catalogue: std::collections::BTreeSet<String> = match load() {
        Ok(Some(tree)) => {
            let mut ids = std::collections::BTreeSet::new();
            walk_hosts(&tree, &mut |n| {
                for k in ["id", "credentialId"] {
                    if let Some(id) = n.get(k).and_then(Value::as_str) {
                        ids.insert(binding_key(id));
                    }
                }
            });
            ids
        }
        Ok(None) => Default::default(),
        // Unknown catalogue: do not guess which ids are in use.
        Err(_) => return 0,
    };
    let mut removed = 0;
    for id in quick_connect_ids(&map, &catalogue) {
        if delete_credential(&id).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// Binding keys that are quick-connect ids no catalogue host uses.
fn quick_connect_ids(map: &Value, catalogue: &std::collections::BTreeSet<String>) -> Vec<String> {
    map.as_object()
        .map(|o| {
            o.keys()
                .filter(|k| k.starts_with("qc-") && !catalogue.contains(*k))
                .cloned()
                .collect()
        })
        .unwrap_or_default()
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

/// Pure membership check, split out so the authorization rule is testable
/// without touching disk.
fn dest_authorized_in(list: &[Value], host: &str, port: u16, username: &str) -> bool {
    let want = json!({ "host": host, "port": u64::from(port), "username": username });
    list.iter().any(|d| d == &want)
}

/// One-time backfill: for every catalogue host that has a saved secret but no
/// binding yet, snapshot it now. Called at STARTUP, before the webview loads —
/// so the catalogue it reads is last session's on-disk file, not something a
/// compromised frontend could have poisoned this run.
///
/// Genuinely one-shot: a sidecar marker file is written after the first run. Re-running on
/// every launch would trust whatever hosts.json the PREVIOUS session's webview
/// wrote, letting a planted node bind an unbound secret to an attacker
/// destination. Reserved vault ids (the AI key at `ai:…`) are never bound.
pub fn migrate_bindings() {
    let _vault = vault_lock();
    let Ok(existing) = read_bindings() else {
        // Unreadable bindings: fail closed, and do not rebuild them from the
        // frontend-writable catalogue.
        return;
    };
    if migration_done() {
        return;
    }
    // A bindings file that already holds entries was written by a build that
    // ran this backfill (v0.4.0 ran it on every launch; `ab938ed` kept an
    // in-map marker). Record that and stop, rather than trusting this launch's
    // catalogue once more. This also keeps a sidecar that cannot be written
    // from re-arming the backfill on every launch once anything is bound.
    if existing.as_object().is_some_and(|o| !o.is_empty()) {
        mark_migration_done();
        return;
    }
    let Ok(Some(tree)) = load() else {
        mark_migration_done();
        return;
    };
    let mut done: std::collections::BTreeSet<String> = existing
        .as_object()
        .map(|o| o.keys().map(|k| binding_key(k)).collect())
        .unwrap_or_default();

    // Collect (cred_id, host, port, username) for every host first, so we are
    // not holding the tree borrow across the vault reads / writes below.
    let mut rows: Vec<(String, String, u64, String)> = Vec::new();
    walk_hosts(&tree, &mut |node| {
        let id = node.get("id").and_then(Value::as_str);
        // The vault key is credentialId when borrowing, else the host's own id.
        let cred = node.get("credentialId").and_then(Value::as_str).or(id);
        if let (Some(cred), Some(h), Some(p), Some(u)) = (
            cred,
            node.get("hostname").and_then(Value::as_str),
            node.get("port").and_then(Value::as_u64),
            node.get("username").and_then(Value::as_str),
        ) {
            rows.push((cred.to_string(), h.to_string(), p, u.to_string()));
        }
    });

    for (cred, h, p, u) in rows {
        if done.contains(&binding_key(&cred)) || crate::credentials::is_reserved_id(&cred) {
            continue;
        }
        if crate::credentials::has_secret(&cred) {
            // Best-effort backfill: a write failure here just leaves this cred
            // unbound, so ssh_connect fails closed and the user re-saves — safe.
            let _ = snapshot_binding(&cred, &h, p as u16, &u);
            done.insert(binding_key(&cred));
        }
    }
    mark_migration_done();
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

/// The open-tabs list. Unreadable or corrupt reads as absent (nothing to
/// restore), after a copy of it is kept.
pub fn load_sessions() -> Result<Option<Value>, KnownHostsError> {
    let path = sessions_path()?;
    match read_json(&path) {
        Err(KnownHostsError::Parse(why)) => {
            eprintln!("hawser: {why}");
            Ok(None)
        }
        other => other,
    }
}

pub fn save_sessions(list: &Value) -> Result<(), KnownHostsError> {
    let path = sessions_path()?;
    let text = serde_json::to_string_pretty(list)
        .map_err(|e| KnownHostsError::Parse(e.to_string()))?;
    write_atomic(&path, &text)
}

/* -------------------------------------------------------------------------- */

/// Generic sibling-file persistence in the hawser data dir, for small settings
/// files (ai.json, settings.json). A corrupt file reads as absent (the app runs
/// on defaults), but only after a copy of it is kept, so the next save cannot
/// destroy the only one.
pub fn load_named(name: &str) -> Result<Option<Value>, KnownHostsError> {
    let store = super::known_hosts::store_path()?;
    let path = store
        .parent()
        .ok_or(KnownHostsError::NoAppDataDir)?
        .join(name);
    match read_json(&path) {
        Err(KnownHostsError::Parse(why)) => {
            eprintln!("hawser: {why}");
            Ok(None)
        }
        other => other,
    }
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
    use super::{binding_key, dest_authorized_in, normalize_keys, walk_hosts};
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

    fn secret_of(v: &FakeVault, id: &str) -> Option<String> {
        v.items.lock().unwrap().get(id).cloned()
    }

    fn authorized(v: &FakeVault, p: &Path, id: &str, d: &Dest) -> Option<String> {
        match read_authorized_with(v, Some(p), id, d, true).unwrap() {
            StoredSecret::Authorized(s) => Some(s.to_string()),
            _ => None,
        }
    }

    #[test]
    fn a_save_whose_binding_fails_restores_the_previous_secret() {
        let v = FakeVault::default();
        let ok = bindings_in("ok");
        let a = dest("10.0.0.1", 22, "admin");
        save_credential_with(&v, &ok, "h-tx1", "admin", "old", &a, None).unwrap();
        // The binding write fails: the old secret is back, still bound to A.
        let bad = bindings_in("fail-writes");
        std::fs::copy(&ok, &bad).unwrap();
        let b = dest("10.0.0.2", 22, "admin");
        assert!(save_credential_with(&v, &bad, "h-tx1", "admin", "new", &b, Some(&[b.clone()])).is_err());
        assert_eq!(secret_of(&v, "h-tx1").as_deref(), Some("old"));
        assert_eq!(authorized(&v, &bad, "h-tx1", &a).as_deref(), Some("old"));
        assert!(authorized(&v, &bad, "h-tx1", &b).is_none());
    }

    #[test]
    fn a_first_save_whose_binding_fails_leaves_no_secret() {
        let v = FakeVault::default();
        let bad = bindings_in("fail-writes");
        assert!(save_credential_with(&v, &bad, "h-tx2", "u", "pw", &dest("a", 22, "u"), None).is_err());
        assert_eq!(secret_of(&v, "h-tx2"), None);
    }

    #[test]
    fn an_unrecoverable_save_is_poisoned_until_saved_again() {
        let v = FakeVault::default();
        let ok = bindings_in("ok");
        let a = dest("10.0.0.1", 22, "admin");
        save_credential_with(&v, &ok, "h-tx3", "admin", "old", &a, None).unwrap();
        let bad = bindings_in("fail-writes");
        std::fs::copy(&ok, &bad).unwrap();
        // Binding fails, restoring the old secret fails (2nd write), and so
        // does removing the new one: the id is refused, not sent.
        v.fail_write.store(2, Ordering::SeqCst);
        v.fail_delete.store(true, Ordering::SeqCst);
        assert!(save_credential_with(&v, &bad, "h-tx3", "admin", "new", &a, None).is_err());
        assert_eq!(secret_of(&v, "h-tx3").as_deref(), Some("new"));
        assert!(matches!(read_authorized_with(&v, Some(&bad), "h-tx3", &a, true).unwrap(), StoredSecret::Poisoned));
        // A successful save clears it.
        v.fail_delete.store(false, Ordering::SeqCst);
        save_credential_with(&v, &ok, "h-tx3", "admin", "newer", &a, None).unwrap();
        assert_eq!(authorized(&v, &ok, "h-tx3", &a).as_deref(), Some("newer"));
    }

    #[test]
    fn an_unreadable_previous_secret_refuses_the_save() {
        let v = FakeVault::default();
        v.fail_read.store(true, Ordering::SeqCst);
        let ok = bindings_in("ok");
        assert!(save_credential_with(&v, &ok, "h-tx4", "u", "pw", &dest("a", 22, "u"), None).is_err());
        v.fail_read.store(false, Ordering::SeqCst);
        assert_eq!(secret_of(&v, "h-tx4"), None);
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
        narrow_binding_at(&p, "h-tx6", &[a.clone(), c.clone()]).unwrap();
        assert!(authorized(&v, &p, "h-tx6", &a).is_some());
        assert!(authorized(&v, &p, "h-tx6", &b).is_none(), "revoked");
        assert!(authorized(&v, &p, "h-tx6", &c).is_none(), "never added");
        // Narrowing an unbound id is a no-op.
        narrow_binding_at(&p, "h-unbound", &[a]).unwrap();
    }

    #[test]
    fn delete_keeps_the_binding_when_the_vault_refuses() {
        let v = FakeVault::default();
        let p = bindings_in("ok");
        let a = dest("a", 22, "u");
        save_credential_with(&v, &p, "h-tx7", "u", "pw", &a, None).unwrap();
        v.fail_delete.store(true, Ordering::SeqCst);
        assert!(delete_credential_with(&v, &p, "h-tx7").is_err());
        v.fail_delete.store(false, Ordering::SeqCst);
        assert!(authorized(&v, &p, "h-tx7", &a).is_some(), "secret and binding both kept");
        delete_credential_with(&v, &p, "h-tx7").unwrap();
        assert!(matches!(read_authorized_with(&v, Some(&p), "h-tx7", &a, true).unwrap(), StoredSecret::None));
        assert!(!binding_is_authorized_at(&p, "h-tx7", "a", 22, "u"));
    }

    #[test]
    fn nul_and_control_ids_are_refused_everywhere() {
        let v = FakeVault::default();
        let p = bindings_in("ok");
        let a = dest("a", 22, "u");
        assert!(save_credential_with(&v, &p, "h-1\0x", "u", "pw", &a, None).is_err());
        assert!(delete_credential_with(&v, &p, "h-1\nx").is_err());
        assert!(snapshot_binding_at(&p, "h\0", &a, None).is_err());
        assert!(!binding_is_authorized_at(&p, "h\0", "a", 22, "u"));
        assert!(v.items.lock().unwrap().is_empty());
    }

    #[test]
    fn quick_connect_ids_outside_the_catalogue_are_purged() {
        let map = json!({ "qc-abc": [], "qc-kept": [], "h-1": [] });
        let catalogue: std::collections::BTreeSet<String> = ["qc-kept".to_string()].into();
        assert_eq!(quick_connect_ids(&map, &catalogue), vec!["qc-abc".to_string()]);
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

    /// W4b: a save that dies after any step is repaired at the next start so
    /// that the secret is paired with the binding it was saved for, or gone.
    #[test]
    fn a_crash_at_any_step_of_a_save_is_repaired_consistently() {
        let (a, b) = (dest("10.0.0.1", 22, "admin"), dest("10.0.0.2", 22, "admin"));
        let bound = |p: &Path, id: &str| -> Option<Value> {
            read_bindings_at(p).unwrap().get(binding_key(id)).cloned()
        };
        // Steps 1-4: the normal path. 5-6: inside a rollback (binding write fails).
        for step in 1..=6u8 {
            let v = FakeVault::default();
            let ok = bindings_in("ok");
            let id = format!("h-crash{step}");
            save_credential_with(&v, &ok, &id, "admin", "old", &a, Some(&[a.clone()])).unwrap();
            let old_binding = bound(&ok, &id);
            let p = if step >= 5 {
                let bad = bindings_in("fail-writes");
                std::fs::copy(&ok, &bad).unwrap();
                bad
            } else {
                ok.clone()
            };
            CRASH_AT.with(|c| c.set(step));
            let r = save_credential_with(&v, &p, &id, "admin", "new", &b, Some(&[b.clone()]));
            CRASH_AT.with(|c| c.set(0));
            assert_eq!(r.unwrap_err(), INJECTED_CRASH, "step {step}");
            assert!(intent_path_for(&p).exists(), "step {step}: journal left behind");

            // "Restart": the in-memory poison latch is gone with the process.
            poison(&id, false);
            let repaired = repair_vault_intent_with(&v, &p).unwrap();
            assert!(repaired.is_some(), "step {step}");
            assert!(!intent_path_for(&p).exists(), "step {step}: journal cleared");
            let new_binding = Some(json!([b.to_json()]));
            match secret_of(&v, &id).as_deref() {
                Some("new") => assert_eq!(bound(&p, &id), new_binding, "step {step}: new secret, new binding"),
                Some("old") => assert_eq!(bound(&p, &id), old_binding, "step {step}: old secret, old binding"),
                None => {}
                other => panic!("step {step}: unexpected secret {other:?}"),
            }
            // The new secret is never sendable to the old destination.
            if secret_of(&v, &id).as_deref() == Some("new") {
                assert!(authorized(&v, &p, &id, &a).is_none(), "step {step}");
            }
            match step {
                1 | 2 | 5 | 6 => assert_eq!(repaired, Some(Repair::SecretRemoved(id.clone())), "step {step}"),
                3 => assert_eq!(repaired, Some(Repair::BindingFinished(id.clone()))),
                _ => assert_eq!(repaired, Some(Repair::Completed(id.clone()))),
            }
        }
    }

    #[test]
    fn a_completed_save_leaves_no_journal_and_repair_is_a_no_op() {
        let v = FakeVault::default();
        let p = bindings_in("ok");
        save_credential_with(&v, &p, "h-j1", "u", "pw", &dest("a", 22, "u"), None).unwrap();
        assert!(!intent_path_for(&p).exists());
        assert_eq!(repair_vault_intent_with(&v, &p).unwrap(), None);
        // A failed rollback that cannot remove the secret keeps the journal.
        let bad = bindings_in("fail-writes");
        std::fs::copy(&p, &bad).unwrap();
        v.fail_write.store(2, Ordering::SeqCst);
        v.fail_delete.store(true, Ordering::SeqCst);
        assert!(save_credential_with(&v, &bad, "h-j1", "u", "new", &dest("b", 22, "u"), None).is_err());
        assert!(intent_path_for(&bad).exists());
        assert!(repair_vault_intent_with(&v, &bad).is_err(), "the vault still refuses");
        assert!(intent_path_for(&bad).exists(), "kept for the next start");
        v.fail_delete.store(false, Ordering::SeqCst);
        assert_eq!(repair_vault_intent_with(&v, &bad).unwrap(), Some(Repair::SecretRemoved("h-j1".into())));
        assert_eq!(secret_of(&v, "h-j1"), None);
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
        let bad = bindings_in("fail-writes");
        std::fs::copy(&ok, &bad).unwrap();
        let err = save_and_narrow_at(&bad.with_file_name("hosts.json"), &bad, &tree, &["lender".into()]).unwrap_err();
        assert!(err.contains("not saved"), "{err}");
        assert!(!bad.with_file_name("hosts.json").exists(), "the catalogue was not written");
        assert!(authorized(&v, &bad, "lender", &b).is_some(), "binding unchanged");
        // Working bindings: narrowed and saved together.
        save_and_narrow_at(&hosts, &ok, &tree, &["lender".into()]).unwrap();
        assert!(hosts.exists());
        assert!(authorized(&v, &ok, "lender", &b).is_none(), "revoked");
        assert!(authorized(&v, &ok, "lender", &a).is_some());
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
    // bindable or usable as a host credential, in any letter case. Both checks
    // return before touching the bindings file.
    #[test]
    fn audit_seal_id_cannot_be_bound_or_authorized() {
        for id in [crate::utils::audit::SEAL_ID, "HAWSER:AUDIT-HEAD"] {
            assert!(super::snapshot_binding(id, "fw1", 22, "admin").is_err());
            let p = std::env::temp_dir().join("hawser-none").join("credential_bindings.json");
            assert!(!super::binding_is_authorized_at(&p, id, "fw1", 22, "admin"));
        }
    }

    // A recorded binding list is authorized only for the exact destinations in
    // it, whatever their host/port/user — matching the tuple, nothing looser.
    #[test]
    fn dest_membership_is_exact() {
        let list = vec![
            json!({ "host": "fw-01.corp", "port": 22u64, "username": "admin" }),
            json!({ "host": "fw-02.corp", "port": 2222u64, "username": "admin" }),
        ];
        assert!(dest_authorized_in(&list, "fw-01.corp", 22, "admin"));
        assert!(dest_authorized_in(&list, "fw-02.corp", 2222, "admin")); // a borrower dest
        assert!(!dest_authorized_in(&list, "attacker.example", 22, "admin"));
        assert!(!dest_authorized_in(&list, "fw-01.corp", 23, "admin")); // wrong port
        assert!(!dest_authorized_in(&list, "fw-01.corp", 22, "root")); // wrong user
        assert!(!dest_authorized_in(&[], "fw-01.corp", 22, "admin")); // no binding
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
