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

/// Write `contents` to `path` as atomically as the platform allows.
///
/// A unique temp sibling is written in full, then rename-replaced over the
/// destination. `std::fs::rename` is an atomic replace on Unix and on modern
/// Windows. Only if that direct replace fails do we take the fallback — and the
/// fallback never *deletes* the original: it moves it aside to a backup first,
/// so at no instant is the destination gone, and if the second rename fails the
/// original is restored. A crash in the tiny window leaves either the new file
/// in place or the original recoverable at its `.bak` sibling — never nothing.
/// The whole operation is serialised process-wide.
fn write_atomic(path: &Path, contents: &str) -> Result<(), KnownHostsError> {
    let _guard = WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let n = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = path.with_extension(format!("tmp.{}.{}", std::process::id(), n));
    std::fs::write(&tmp, contents).map_err(|source| KnownHostsError::Io {
        path: tmp.clone(),
        source,
    })?;

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
    Ok(())
}

/// `%APPDATA%\hawser\hosts.json`, beside known_hosts.
fn hosts_path() -> Result<PathBuf, KnownHostsError> {
    let store = super::known_hosts::store_path()?;
    Ok(store
        .parent()
        .ok_or(KnownHostsError::NoAppDataDir)?
        .join("hosts.json"))
}

/// Read the catalogue. Returns `None` when no file exists yet, which the
/// frontend treats as "seed from defaults" rather than as an error — a first
/// run must not look like a failure.
pub fn load() -> Result<Option<Value>, KnownHostsError> {
    let path = hosts_path()?;
    if !path.exists() {
        return Ok(None);
    }

    let text = std::fs::read_to_string(&path).map_err(|source| KnownHostsError::Io {
        path: path.clone(),
        source,
    })?;

    // A corrupt file must not brick the app. Report it as absent and let the
    // next save overwrite; the alternative is a user who cannot start the
    // program and cannot reach the UI that would fix it. Before treating it as
    // absent, preserve the original bytes to `hosts.json.corrupt` so a bad
    // hand-edit is recoverable rather than silently discarded on the next save.
    match serde_json::from_str(&text) {
        Ok(value) => Ok(Some(value)),
        Err(_) => {
            let backup = path.with_extension("json.corrupt");
            let _ = std::fs::write(&backup, &text);
            eprintln!(
                "hawser: hosts.json is not valid JSON; backed up to {} and starting from defaults",
                backup.display()
            );
            Ok(None)
        }
    }
}

/// Write the catalogue atomically. Losing the host list to a mid-write crash
/// would be a real data-loss bug, so this goes through `write_atomic`
/// (unique temp, rename-replace, process-wide serialisation).
pub fn save(tree: &Value) -> Result<(), KnownHostsError> {
    let path = hosts_path()?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| KnownHostsError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    let pretty = serde_json::to_string_pretty(tree)
        .map_err(|e| KnownHostsError::Parse(e.to_string()))?;
    write_atomic(&path, &pretty)
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
#[cfg(windows)]
fn binding_key(cred_id: &str) -> String {
    cred_id.to_ascii_lowercase()
}
#[cfg(not(windows))]
fn binding_key(cred_id: &str) -> String {
    cred_id.to_string()
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
    let path = bindings_path().map_err(|_| ())?;
    match std::fs::read_to_string(&path) {
        Ok(t) => match serde_json::from_str::<Value>(&t) {
            Ok(v) if v.is_object() => Ok(normalize_keys(v)),
            _ => Err(()),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(json!({})),
        Err(_) => Err(()),
    }
}

/// For authorization: any read problem is an empty map, i.e. nothing is bound
/// (fail closed).
fn load_bindings() -> Value {
    read_bindings().unwrap_or_else(|_| json!({}))
}

/// Same unique-temp, serialised, never-delete-the-original replace as the
/// catalogue (`write_atomic`). Callers hold BINDINGS_LOCK.
fn write_bindings(map: &Value) -> Result<(), KnownHostsError> {
    let path = bindings_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| KnownHostsError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let text =
        serde_json::to_string_pretty(map).map_err(|e| KnownHostsError::Parse(e.to_string()))?;
    write_atomic(&path, &text)
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
    if crate::credentials::is_reserved_id(cred_id) {
        return Err(KnownHostsError::Parse(format!(
            "'{cred_id}' is a reserved id and cannot be bound to a host"
        )));
    }
    let mut dests = dests_for_cred(cred_id);
    let owner = json!({ "host": host, "port": u64::from(port), "username": username });
    if !dests.contains(&owner) {
        dests.push(owner);
    }
    let _guard = BINDINGS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // A corrupt file is replaced rather than merged into.
    let mut map = read_bindings().unwrap_or_else(|_| json!({}));
    if let Some(obj) = map.as_object_mut() {
        obj.insert(binding_key(cred_id), Value::Array(dests));
    }
    // Propagate a write failure so credential_save can be atomic from the user's
    // point of view: a saved secret whose binding failed to persist would later
    // be refused by ssh_connect (fail-closed), which is safe but surprising.
    write_bindings(&map)
}

/// Drop a credential's bindings (called when its secret is deleted).
pub fn remove_binding(cred_id: &str) {
    let _guard = BINDINGS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // An unreadable file has nothing to remove; leave it for inspection.
    let Ok(mut map) = read_bindings() else {
        return;
    };
    if let Some(obj) = map.as_object_mut() {
        if obj.remove(&binding_key(cred_id)).is_some() {
            let _ = write_bindings(&map);
        }
    }
}

/// Authorize sending the vault secret keyed by `cred_id` to `host:port` as
/// `username`, consulting ONLY the backend-owned binding file — never the
/// frontend-writable catalogue. Unknown credential or unmatched destination
/// returns false (fail closed).
pub fn binding_is_authorized(cred_id: &str, host: &str, port: u16, username: &str) -> bool {
    if crate::credentials::is_reserved_id(cred_id) {
        return false;
    }
    let map = load_bindings();
    let Some(list) = map.get(binding_key(cred_id)).and_then(Value::as_array) else {
        return false;
    };
    dest_authorized_in(list, host, port, username)
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

pub fn load_sessions() -> Result<Option<Value>, KnownHostsError> {
    let path = sessions_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&path).map_err(|source| KnownHostsError::Io {
        path: path.clone(),
        source,
    })?;
    Ok(serde_json::from_str(&text).ok())
}

pub fn save_sessions(list: &Value) -> Result<(), KnownHostsError> {
    let path = sessions_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| KnownHostsError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let text = serde_json::to_string_pretty(list)
        .map_err(|e| KnownHostsError::Parse(e.to_string()))?;
    write_atomic(&path, &text)
}

/* -------------------------------------------------------------------------- */

/// Generic sibling-file persistence in the hawser data dir, for small settings
/// files (ai.json). Same corrupt-file-tolerant contract as the catalogue.
pub fn load_named(name: &str) -> Result<Option<Value>, KnownHostsError> {
    let store = super::known_hosts::store_path()?;
    let path = store
        .parent()
        .ok_or(KnownHostsError::NoAppDataDir)?
        .join(name);
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&path).map_err(|source| KnownHostsError::Io {
        path: path.clone(),
        source,
    })?;
    Ok(serde_json::from_str(&text).ok())
}

pub fn save_named(name: &str, value: &Value) -> Result<(), KnownHostsError> {
    let store = super::known_hosts::store_path()?;
    let dir = store.parent().ok_or(KnownHostsError::NoAppDataDir)?;
    std::fs::create_dir_all(dir).map_err(|source| KnownHostsError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    let path = dir.join(name);
    let text =
        serde_json::to_string_pretty(value).map_err(|e| KnownHostsError::Parse(e.to_string()))?;
    write_atomic(&path, &text)
}

#[cfg(test)]
mod tests {
    use super::{binding_key, dest_authorized_in, normalize_keys, walk_hosts};
    use serde_json::{json, Value};

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
