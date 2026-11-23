mod credentials;
mod local_shell;
mod utils;
mod ssh;

use std::time::UNIX_EPOCH;

use tauri::{AppHandle, Manager, State};

use ssh::{AuthPrompts, DirListing, FileEntry, HostKeyPrompts, Registry};
use std::sync::Arc;

/// Commands return `Result<_, String>`: Tauri needs a serialisable error, and a
/// rendered message is what the UI shows. Note what is *not* here — no command
/// accepts or returns a password.
type CmdResult<T> = Result<T, String>;

/// Run blocking work (file I/O, an OS keychain call that may show a prompt)
/// on the blocking pool, never on an async worker: a worker parked in a
/// keychain prompt or a slow network share stalls every SSH pump scheduled on
/// it.
async fn off<T: Send + 'static>(f: impl FnOnce() -> CmdResult<T> + Send + 'static) -> CmdResult<T> {
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|e| e.to_string())?
}

/* ------------------------------------------------------------------ session */

/// Connect a tab. Resolves to the endpoint identity the backend dialled (see
/// `utils::artifacts::dial_identity`), which the frontend uses for anything
/// keyed by this connection after the dial.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn ssh_connect(
    app: AppHandle,
    registry: State<'_, Registry>,
    prompts: State<'_, Arc<HostKeyPrompts>>,
    auth_prompts: State<'_, Arc<AuthPrompts>>,
    session_id: String,
    host_id: String,
    host: String,
    port: u16,
    username: String,
    cols: u32,
    rows: u32,
    startup_commands: Option<Vec<String>>,
    auth: Option<String>,
    key_path: Option<String>,
    jump: Option<ssh::JumpParams>,
    one_shot_password: Option<String>,
    endpoint: Option<String>,
    label: Option<String>,
    ephemeral: Option<bool>,
) -> CmdResult<String> {
    // Wrapped at once, so the IPC-owned buffer itself is wiped on drop.
    let one_shot_password = one_shot_password.map(zeroize::Zeroizing::new);
    let spec = ssh::ConnectSpec {
        session_id,
        host_id,
        host: host.clone(),
        port,
        username: username.clone(),
        cols,
        rows,
        startup_commands: startup_commands.unwrap_or_default(),
        auth: auth.unwrap_or_else(|| "password".into()),
        key_path,
        jump,
        one_shot_password,
        endpoint,
        label,
        ephemeral: ephemeral.unwrap_or(false),
    };
    let result = registry
        .connect(app, Arc::clone(&prompts), Arc::clone(&auth_prompts), spec)
        .await
        .map_err(|e| e.to_string());
    // Audit the authentication outcome. host/port/user are not secret; the error
    // string is an SSH/protocol message (e.g. "authentication failed"), never a
    // password. The connect result folds the host-key and auth steps together.
    match &result {
        Ok(_) => utils::audit::record(
            "connect",
            format!("connected {username}@{host}:{port}"),
            serde_json::json!({ "host": host, "port": port, "user": username, "ok": true }),
        ),
        Err(e) => utils::audit::record(
            "connect.fail",
            format!("connection to {username}@{host}:{port} failed"),
            serde_json::json!({ "host": host, "port": port, "user": username, "ok": false, "error": e }),
        ),
    }
    result
}

/// Answer a host-key prompt raised by the `ssh://host-key-prompt` event.
///
/// Accepting records the key in known_hosts, so this is the only path by which
/// a new host becomes trusted. There is deliberately no command to accept a
/// *changed* key: that requires editing known_hosts by hand.
#[tauri::command]
async fn host_key_respond(
    prompts: State<'_, Arc<HostKeyPrompts>>,
    request_id: String,
    accept: bool,
) -> CmdResult<()> {
    prompts.respond(&request_id, accept);
    Ok(())
}

/// Answer a keyboard-interactive challenge raised by `ssh://auth-prompt`.
///
/// `answers` are the user's typed responses, one per ECHO prompt shown (in
/// order). Hidden prompts are never surfaced and are answered with the stored
/// password in the backend, so no password is passed in here.
#[tauri::command]
async fn auth_prompt_respond(
    auth_prompts: State<'_, Arc<AuthPrompts>>,
    request_id: String,
    answers: Vec<String>,
    #[allow(non_snake_case)] save: Option<bool>,
) -> CmdResult<()> {
    // Each typed answer is wiped when the auth that consumes it is done.
    let answers = answers.into_iter().map(zeroize::Zeroizing::new).collect();
    auth_prompts.respond(&request_id, answers, save.unwrap_or(false));
    Ok(())
}

/// Cancel an interactive auth prompt: aborts authentication entirely rather than
/// answering. This is what the dialog's Cancel/Escape must call — responding
/// with an empty answer vector would still let the backend fill the HIDDEN
/// prompts with the stored password, i.e. authenticate despite "Cancel".
#[tauri::command]
async fn auth_prompt_cancel(
    auth_prompts: State<'_, Arc<AuthPrompts>>,
    request_id: String,
) -> CmdResult<()> {
    auth_prompts.cancel(&request_id);
    Ok(())
}

/// Keystrokes from the terminal grid.
///
/// `data` is already-encoded terminal input, not a key name: arrow keys arrive
/// as "\x1b[A", Ctrl+C as 0x03, a paste as one block. Write the bytes verbatim —
/// interpreting them here breaks every full-screen program (vim, less, top)
/// that relies on raw mode. Bytes rather than a String because a PTY carries
/// sequences that are not valid UTF-8, which a String round-trip would mangle.
#[tauri::command]
async fn ssh_write(
    registry: State<'_, Registry>,
    local: State<'_, Arc<local_shell::LocalShells>>,
    session_id: String,
    data: Vec<u8>,
) -> CmdResult<()> {
    // Local terminals share the session commands (see local_shell). A PTY
    // write can block while the shell isn't reading, so it runs off the
    // async runtime.
    if local.owns(&session_id) {
        let local = Arc::clone(&local);
        return tauri::async_runtime::spawn_blocking(move || local.write(&session_id, &data))
            .await
            .map_err(|e| e.to_string())?;
    }
    registry
        .write(&session_id, &data)
        .await
        .map_err(|e| e.to_string())
}

/// Window-size change from the frontend ResizeObserver, forwarded as a real SSH
/// `window-change` request. Without it the remote keeps drawing to the old
/// geometry and full-screen programs wrap at the wrong column.
#[tauri::command]
async fn ssh_resize(
    registry: State<'_, Registry>,
    local: State<'_, Arc<local_shell::LocalShells>>,
    session_id: String,
    cols: u32,
    rows: u32,
) -> CmdResult<()> {
    if local.owns(&session_id) {
        // Off the async runtime: the master lock can briefly wait on the exit
        // watcher closing the console.
        let local = Arc::clone(&local);
        return tauri::async_runtime::spawn_blocking(move || local.resize(&session_id, cols, rows))
            .await
            .map_err(|e| e.to_string())?;
    }
    registry
        .resize(&session_id, cols, rows)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn ssh_disconnect(
    app: AppHandle,
    registry: State<'_, Registry>,
    prompts: State<'_, Arc<HostKeyPrompts>>,
    auth_prompts: State<'_, Arc<AuthPrompts>>,
    local: State<'_, Arc<local_shell::LocalShells>>,
    session_id: String,
) -> CmdResult<()> {
    // A local terminal closes its shell (no-op for any other id). Off the
    // async runtime: the kill escalates with a short grace period.
    if local.owns(&session_id) {
        let local = Arc::clone(&local);
        let id = session_id.clone();
        let _ = tauri::async_runtime::spawn_blocking(move || local.close(&id)).await;
    }
    // Cancel an in-flight connect FIRST: once it is cancelled it cannot raise
    // a new prompt, so the sweep below cannot miss one registered behind it.
    registry.remove(&session_id).await;
    // A tab closed mid-connect may still have a host-key or password dialog up.
    // Drop those prompts and tell the UI to close them, rather than leave a
    // question nobody owns on screen.
    let closed = prompts
        .cancel_session(&session_id)
        .into_iter()
        .chain(auth_prompts.cancel_session(&session_id));
    for request_id in closed {
        ssh::emit_prompt_closed(&app, &request_id);
    }
    Ok(())
}

/* ------------------------------------------------------------ local shells */

/// Shells available on this machine for "New local terminal".
#[tauri::command]
async fn local_shell_profiles() -> CmdResult<Vec<local_shell::ShellProfile>> {
    off(|| Ok(local_shell::profiles())).await
}

/// Start a local shell in a PTY for `session_id`. `profile` is a profile id
/// from `local_shell_profiles`, never a program path. `record` keeps a
/// transcript like an SSH session does (Settings → Terminal).
#[tauri::command]
async fn local_shell_start(
    app: AppHandle,
    local: State<'_, Arc<local_shell::LocalShells>>,
    session_id: String,
    profile: String,
    cols: u32,
    rows: u32,
    record: bool,
) -> CmdResult<()> {
    let local = Arc::clone(&local);
    let started = tauri::async_runtime::spawn_blocking(move || {
        local.start(&app, &session_id, &profile, cols, rows, record)
    })
    .await
    .map_err(|e| e.to_string())?;
    // Audited like a connect (which shell, never what is typed). Recording is
    // queued to the audit writer, so the terminal never waits on its seal.
    let (event, summary, detail) = match &started {
        Ok(p) => (
            "local.open",
            format!("opened a local terminal ({})", p.label),
            serde_json::json!({ "profile": p.id, "ok": true }),
        ),
        Err(e) => (
            "local.open.fail",
            "a local terminal failed to start".to_string(),
            serde_json::json!({ "error": e, "ok": false }),
        ),
    };
    utils::audit::record(event, summary, detail);
    started.map(|_| ())
}

/* --------------------------------------------------------------------- sftp */

#[tauri::command]
async fn sftp_list(
    registry: State<'_, Registry>,
    session_id: String,
    path: String,
) -> CmdResult<DirListing> {
    registry
        .list_dir(&session_id, &path)
        .await
        .map_err(|e| e.to_string())
}

/// A transfer's id: the frontend's, or a fresh one for a caller that sends
/// none (it then cannot cancel, or match events to a row).
fn transfer_id_or_new(id: Option<String>) -> String {
    id.filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("t-{}", utils::artifacts::random_hex(8)))
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn sftp_get(
    app: AppHandle,
    registry: State<'_, Registry>,
    session_id: String,
    remote_path: String,
    local_path: String,
    transfer_id: Option<String>,
    overwrite: Option<String>,
) -> CmdResult<ssh::TransferOutcome> {
    let policy = ssh::Overwrite::parse(overwrite.as_deref())?;
    let transfer_id = transfer_id_or_new(transfer_id);
    let result = registry
        .download(&app, &session_id, &transfer_id, &remote_path, &local_path, policy)
        .await
        .map_err(|e| e.to_string());
    match &result {
        Ok(out) => utils::audit::record(
            "sftp.get",
            format!("downloaded {remote_path} ({} bytes)", out.bytes),
            serde_json::json!({ "remote": remote_path, "local": local_path, "bytes": out.bytes, "overwrite": overwrite, "ok": true }),
        ),
        Err(e) => utils::audit::record(
            "sftp.get.fail",
            format!("download of {remote_path} failed"),
            serde_json::json!({ "remote": remote_path, "local": local_path, "ok": false, "error": e }),
        ),
    }
    result
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn sftp_put(
    app: AppHandle,
    registry: State<'_, Registry>,
    session_id: String,
    local_path: String,
    remote_path: String,
    transfer_id: Option<String>,
    overwrite: Option<String>,
) -> CmdResult<ssh::TransferOutcome> {
    let policy = ssh::Overwrite::parse(overwrite.as_deref())?;
    let transfer_id = transfer_id_or_new(transfer_id);
    let result = registry
        .upload(&app, &session_id, &transfer_id, &local_path, &remote_path, policy)
        .await
        .map_err(|e| e.to_string());
    match &result {
        Ok(out) => utils::audit::record(
            "sftp.put",
            format!("uploaded {remote_path} ({} bytes)", out.bytes),
            serde_json::json!({ "local": local_path, "remote": remote_path, "bytes": out.bytes, "overwrite": overwrite, "ok": true }),
        ),
        Err(e) => utils::audit::record(
            "sftp.put.fail",
            format!("upload to {remote_path} failed"),
            serde_json::json!({ "local": local_path, "remote": remote_path, "ok": false, "error": e }),
        ),
    }
    result
}

/// Cancel a running `sftp_get`/`sftp_put` by the id it was started with. Its
/// staging files are removed on both sides; the destination is untouched.
#[tauri::command]
async fn sftp_cancel(registry: State<'_, Registry>, transfer_id: String) -> CmdResult<()> {
    registry.transfer_cancel(&transfer_id);
    Ok(())
}

/* ----------------------------------------------------------------- tunnels */

/// Start a local port-forward (`ssh -L`) over an open session.
#[tauri::command]
async fn forward_start(
    registry: State<'_, Registry>,
    session_id: String,
    local_port: u16,
    remote_host: String,
    remote_port: u16,
) -> CmdResult<ssh::ForwardInfo> {
    let result = registry
        .forward_start(&session_id, local_port, &remote_host, remote_port)
        .await
        .map_err(|e| e.to_string());
    // A local listener that tunnels into the remote network is security-
    // relevant: record where it points.
    match &result {
        Ok(info) => utils::audit::record(
            "tunnel.start",
            format!("forwarded localhost:{} to {remote_host}:{remote_port}", info.local_port),
            serde_json::json!({ "localPort": info.local_port, "remoteHost": remote_host, "remotePort": remote_port, "kind": "local", "ok": true }),
        ),
        Err(e) => utils::audit::record(
            "tunnel.start.fail",
            format!("forwarding localhost:{local_port} to {remote_host}:{remote_port} failed"),
            serde_json::json!({ "localPort": local_port, "remoteHost": remote_host, "remotePort": remote_port, "kind": "local", "ok": false, "error": e }),
        ),
    }
    result
}

/// Start a SOCKS5 dynamic proxy (`ssh -D`) over an open session.
#[tauri::command]
async fn forward_start_socks(
    registry: State<'_, Registry>,
    session_id: String,
    local_port: u16,
) -> CmdResult<ssh::ForwardInfo> {
    let result = registry
        .forward_start_socks(&session_id, local_port)
        .await
        .map_err(|e| e.to_string());
    match &result {
        Ok(info) => utils::audit::record(
            "tunnel.start",
            format!("opened a SOCKS proxy on localhost:{}", info.local_port),
            serde_json::json!({ "localPort": info.local_port, "kind": "socks", "ok": true }),
        ),
        Err(e) => utils::audit::record(
            "tunnel.start.fail",
            format!("opening a SOCKS proxy on localhost:{local_port} failed"),
            serde_json::json!({ "localPort": local_port, "kind": "socks", "ok": false, "error": e }),
        ),
    }
    result
}

#[tauri::command]
async fn forward_stop(registry: State<'_, Registry>, forward_id: String) -> CmdResult<()> {
    registry.forward_stop(&forward_id).await;
    utils::audit::record(
        "tunnel.stop",
        format!("stopped forward {forward_id}"),
        serde_json::json!({ "forwardId": forward_id, "ok": true }),
    );
    Ok(())
}

#[tauri::command]
async fn forwards_list(
    registry: State<'_, Registry>,
    session_id: Option<String>,
) -> CmdResult<Vec<ssh::ForwardInfo>> {
    Ok(registry.forwards_list(session_id.as_deref()))
}

/// Existence check for the overwrite guard. `remote` picks the side; local
/// checks need no session.
#[tauri::command]
async fn path_exists(
    registry: State<'_, Registry>,
    session_id: Option<String>,
    path: String,
    remote: bool,
) -> CmdResult<bool> {
    if remote {
        let sid = session_id.ok_or("session required for remote check")?;
        registry.sftp_exists(&sid, &path).await.map_err(|e| e.to_string())
    } else {
        // Without following links (a symlink at the destination is "there"),
        // and an error other than not-found is reported, not read as "free".
        off(move || match std::fs::symlink_metadata(&path) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(format!("{path}: {e}")),
        })
        .await
    }
}

#[tauri::command]
async fn sftp_rename(
    registry: State<'_, Registry>,
    session_id: String,
    from: String,
    to: String,
) -> CmdResult<()> {
    let result = registry.sftp_rename(&session_id, &from, &to).await.map_err(|e| e.to_string());
    match &result {
        Ok(()) => utils::audit::record(
            "sftp.rename",
            format!("renamed {from} to {to}"),
            serde_json::json!({ "from": from, "to": to, "ok": true }),
        ),
        Err(e) => utils::audit::record(
            "sftp.rename.fail",
            format!("rename of {from} failed"),
            serde_json::json!({ "from": from, "to": to, "ok": false, "error": e }),
        ),
    }
    result
}

#[tauri::command]
async fn sftp_delete(
    registry: State<'_, Registry>,
    session_id: String,
    path: String,
    is_dir: bool,
) -> CmdResult<()> {
    let result = registry.sftp_delete(&session_id, &path, is_dir).await.map_err(|e| e.to_string());
    match &result {
        Ok(()) => utils::audit::record(
            "sftp.delete",
            format!("deleted {}{path}", if is_dir { "directory " } else { "" }),
            serde_json::json!({ "path": path, "isDir": is_dir, "ok": true }),
        ),
        Err(e) => utils::audit::record(
            "sftp.delete.fail",
            format!("delete of {path} failed"),
            serde_json::json!({ "path": path, "isDir": is_dir, "ok": false, "error": e }),
        ),
    }
    result
}

#[tauri::command]
async fn sftp_mkdir(
    registry: State<'_, Registry>,
    session_id: String,
    path: String,
) -> CmdResult<()> {
    let result = registry.sftp_mkdir(&session_id, &path).await.map_err(|e| e.to_string());
    match &result {
        Ok(()) => utils::audit::record(
            "sftp.mkdir",
            format!("created directory {path}"),
            serde_json::json!({ "path": path, "ok": true }),
        ),
        Err(e) => utils::audit::record(
            "sftp.mkdir.fail",
            format!("creating directory {path} failed"),
            serde_json::json!({ "path": path, "ok": false, "error": e }),
        ),
    }
    result
}

/// Local-side mutations, mirroring the sftp_* trio so the two panes offer the
/// same menu. Delete is not recursive here either, for the same reason.
///
/// Rename never clobbers: std::fs::rename silently replaces an existing file
/// (and, on Unix, an empty directory), which a typo in the new name would turn
/// into data loss. The remote side's SFTP rename refuses too, so the panes agree.
#[tauri::command]
async fn local_rename(from: String, to: String) -> CmdResult<()> {
    off(move || local_rename_blocking(&from, &to)).await
}

fn local_rename_blocking(from: &str, to: &str) -> CmdResult<()> {
    // A case-only rename on a case-insensitive filesystem (macOS, Windows)
    // resolves `to` to `from` itself; that is not a collision.
    let same_entry = match (std::fs::canonicalize(from), std::fs::canonicalize(to)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    };
    if std::fs::symlink_metadata(to).is_ok() && !same_entry {
        return Err(format!("{to} already exists"));
    }
    std::fs::rename(from, to).map_err(|e| e.to_string())
}

#[tauri::command]
async fn local_delete(path: String, is_dir: bool) -> CmdResult<()> {
    off(move || {
        if is_dir {
            std::fs::remove_dir(&path).map_err(|e| e.to_string())
        } else {
            std::fs::remove_file(&path).map_err(|e| e.to_string())
        }
    })
    .await
}

#[tauri::command]
async fn local_mkdir(path: String) -> CmdResult<()> {
    off(move || std::fs::create_dir(&path).map_err(|e| e.to_string())).await
}

/* -------------------------------------------------------------------- local */

/// Where the local file pane starts: the root of the system drive on Windows
/// (`%SystemDrive%\`, which is not always C:), `/` elsewhere.
#[tauri::command]
async fn local_root() -> CmdResult<String> {
    Ok(local_root_from(std::env::var("SystemDrive").ok().as_deref()))
}

fn local_root_from(system_drive: Option<&str>) -> String {
    if !cfg!(windows) {
        return "/".into();
    }
    match system_drive.map(str::trim) {
        Some(d) if d.len() == 2 && d.as_bytes()[0].is_ascii_alphabetic() && d.ends_with(':') => format!("{d}\\"),
        _ => "C:\\".into(),
    }
}

/// Local half of the dual pane. Deliberately mirrors `sftp_list`'s shape so the
/// two panes are the same component with a different data source.
#[tauri::command]
async fn local_list(path: String) -> CmdResult<DirListing> {
    off(move || local_list_blocking(path)).await
}

fn local_list_blocking(path: String) -> CmdResult<DirListing> {
    let dir = std::path::Path::new(&path);
    let canonical = dir
        .canonicalize()
        .map(|p| {
            // Strip the \\?\ verbatim prefix Windows adds; it is correct but
            // renders badly in a path bar. A UNC path canonicalises to
            // \\?\UNC\server\share (which IS \\server\share) — strip that to its
            // real form rather than leaving the invalid "UNC\server\share".
            let s = p.to_string_lossy();
            if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
                format!(r"\\{rest}")
            } else if let Some(rest) = s.strip_prefix(r"\\?\") {
                rest.to_string()
            } else {
                s.to_string()
            }
        })
        .unwrap_or_else(|_| path.clone());

    let mut entries = vec![FileEntry {
        name: "..".into(),
        kind: "directory",
        size: 0,
        modified: None,
        mode: String::new(),
    }];

    let read = std::fs::read_dir(&canonical).map_err(|e| format!("{canonical}: {e}"))?;
    for item in read.flatten() {
        let meta = match item.metadata() {
            Ok(m) => m,
            // A file can vanish or be locked between listing and stat; skipping
            // one entry beats failing the whole directory.
            Err(_) => continue,
        };
        let kind = if meta.is_dir() {
            "directory"
        } else if meta.file_type().is_symlink() {
            "symlink"
        } else {
            "file"
        };
        entries.push(FileEntry {
            name: item.file_name().to_string_lossy().to_string(),
            kind,
            size: meta.len(),
            modified: meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as u32),
            mode: if meta.permissions().readonly() {
                "read-only".into()
            } else {
                String::new()
            },
        });
    }

    Ok(DirListing {
        path: canonical,
        entries,
        truncated: false,
    })
}

/* --------------------------------------------------------------- catalogue */

/// Load the saved-host tree. `None` means "no file yet" — a first run, not a
/// failure; the frontend seeds from its defaults in that case.
#[tauri::command]
async fn hosts_load() -> CmdResult<Option<serde_json::Value>> {
    off(|| utils::hosts::load().map_err(|e| e.to_string())).await
}

#[tauri::command]
async fn hosts_save(tree: serde_json::Value) -> CmdResult<()> {
    off(move || utils::hosts::save(&tree).map_err(|e| e.to_string())).await
}

/// Tabs open at last exit, so a restart can offer them again.
#[tauri::command]
async fn sessions_load() -> CmdResult<Option<serde_json::Value>> {
    off(|| utils::hosts::load_sessions().map_err(|e| e.to_string())).await
}

#[tauri::command]
async fn sessions_save(list: serde_json::Value) -> CmdResult<()> {
    off(move || utils::hosts::save_sessions(&list).map_err(|e| e.to_string())).await
}

/// Tail of the last transcript for an endpoint, for replay into a reconnected
/// tab and as AI context.
///
/// Endpoint-keyed rather than session-keyed: session ids are per-connection, and
/// the point is to bridge ACROSS connections. Not hostname-keyed either: two
/// entries sharing an address must never see each other's output.
/// The endpoint identity a lookup should use: the live session's own (derived
/// from what it dialled) whenever `session_id` names one, else the identity
/// the frontend computed for a host with no live session (the replay before a
/// dial, or the history of a host that is not connected).
fn lookup_endpoint(
    registry: &Registry,
    session_id: Option<String>,
    endpoint: Option<String>,
) -> CmdResult<String> {
    if let Some(ep) = session_id.as_deref().and_then(|sid| registry.endpoint_of(sid).ok()) {
        return Ok(ep);
    }
    endpoint.ok_or_else(|| "no live session and no endpoint identity given".to_string())
}

/// Refuse a live session's history when it dialled another endpoint than the
/// one its caller's policy check was made for.
fn check_same_endpoint(live: &str, claimed: &str) -> CmdResult<()> {
    if live == claimed {
        Ok(())
    } else {
        Err("This tab is still connected to the host's previous address, account or bastion (the host was edited after it connected), so its output is not shared. Reconnect the tab first.".into())
    }
}

/// The endpoint whose transcript `session_history` reads, from ONE resolution
/// of the live session (`live`) and the identity the caller's policy check was
/// made for (`claimed`): the live one when it matches the claim, a refusal
/// when it does not, and the claim when no session is live.
fn history_endpoint(live: Option<String>, claimed: Option<String>) -> CmdResult<String> {
    match (live, claimed) {
        (Some(live), Some(claimed)) => check_same_endpoint(&live, &claimed).map(|()| live),
        (Some(live), None) => Ok(live),
        (None, Some(claimed)) => Ok(claimed),
        (None, None) => Err("no live session and no endpoint identity given".to_string()),
    }
}

#[tauri::command]
async fn session_history(
    registry: State<'_, Registry>,
    session_id: Option<String>,
    endpoint: Option<String>,
    max_bytes: usize,
) -> CmdResult<Option<String>> {
    // `endpoint` is the identity whose AI policy the caller checked (the
    // catalogue entry as it stands now). If the live session dialled
    // something else (the entry or its bastion was edited after it
    // connected), its transcript comes from an endpoint that policy was never
    // evaluated for, so it is refused rather than returned.
    // The live session is resolved exactly once: the identity that passes the
    // comparison is the one whose transcript is read.
    let live = session_id.as_deref().and_then(|sid| registry.endpoint_of(sid).ok());
    let endpoint = history_endpoint(live, endpoint)?;
    tauri::async_runtime::spawn_blocking(move || {
        utils::session_log::latest_transcript(&endpoint, max_bytes)
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())
}

/// List past session transcripts (newest first) for the history browser.
#[tauri::command]
async fn logs_list() -> CmdResult<Vec<utils::session_log::LogEntry>> {
    off(|| utils::session_log::list().map_err(|e| e.to_string())).await
}

/// Open the transcript directory in Explorer.
///
/// Fixed target, not a parameter: an `open(path)` command reachable from the
/// webview is a shell-execute primitive for anything that ever gets script
/// injection. This one can open exactly one folder and nothing else.
#[tauri::command]
async fn open_logs_folder() -> CmdResult<()> {
    off(|| {
        let dir = utils::session_log::logs_dir().map_err(|e| e.to_string())?;
        utils::hosts::ensure_dir(&dir).map_err(|e| e.to_string())?;
        utils::platform::open_dir(&dir).map_err(|e| e.to_string())
    })
    .await
}

/// Read one page of a transcript by its bare filename: the newest page by
/// default, the page around `line` (a search hit), or the page before/after a
/// byte offset of a page already shown.
#[tauri::command]
async fn log_read(
    name: String,
    line: Option<u64>,
    before: Option<u64>,
    after: Option<u64>,
) -> CmdResult<utils::session_log::LogPage> {
    use utils::session_log::PageAt;
    let at = match (line, before, after) {
        (Some(l), _, _) => PageAt::Line(l),
        (_, Some(b), _) => PageAt::Before(b),
        (_, _, Some(a)) => PageAt::After(a),
        _ => PageAt::Tail,
    };
    tauri::async_runtime::spawn_blocking(move || utils::session_log::read_log(&name, at))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

/// Search every transcript for a line containing `query` (case-insensitive),
/// newest session first. Runs on the blocking pool: it reads every log file.
/// Starting a search supersedes any still running.
#[tauri::command]
async fn logs_search(query: String, limit: usize) -> CmdResult<utils::session_log::SearchResult> {
    let generation = utils::session_log::begin_search();
    tauri::async_runtime::spawn_blocking(move || utils::session_log::search(&query, limit, generation))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

/// Stop any running transcript search.
#[tauri::command]
async fn logs_search_cancel() -> CmdResult<()> {
    utils::session_log::cancel_searches();
    Ok(())
}

/// Most recent audit-log entries, newest first, for the Audit panel.
#[tauri::command]
async fn audit_list(limit: usize) -> CmdResult<Vec<utils::audit::AuditView>> {
    // Clamp so a bad/huge limit cannot ask the UI to render the entire history.
    off(move || utils::audit::list(limit.min(2000))).await
}

/// Walk the audit chain and report whether it is intact, where it broke, and
/// whether the file head matches the keychain anchor.
#[tauri::command]
async fn audit_verify() -> CmdResult<utils::audit::VerifyReport> {
    // On the audit writer thread (after every record queued before it); this
    // task only waits for the answer, off the async workers.
    off(utils::audit::verify).await
}

/// Set the current audit log aside (renamed, never deleted) and start a fresh,
/// anchored one whose first entry names the archive. The only way back to a
/// clean "verified" state after a failed or gapped check.
#[tauri::command]
async fn audit_archive() -> CmdResult<String> {
    off(utils::audit::archive).await
}

/// Export the host catalogue to the user's Documents folder and reveal it.
///
/// Topology only — names, addresses, folders, snippets. Passwords live in the
/// OS credential vault and are structurally absent from hosts.json, so an
/// export holds no password. It can still hold what users put into hosts.json
/// themselves (usernames, on-connect commands, snippets), so it is written
/// owner-only, and never over an existing file: `hawser-hosts.json`, else
/// `hawser-hosts-2.json`, … (see `utils::hosts::export_to`).
#[tauri::command]
async fn hosts_export() -> CmdResult<String> {
    let path = off(|| {
        let tree = utils::hosts::load()
            .map_err(|e| e.to_string())?
            .ok_or("no host catalogue to export")?;
        let docs = utils::platform::documents_dir().ok_or("cannot resolve Documents folder")?;
        let path = utils::hosts::export_to(&docs, &tree)?;
        // Reveal rather than open: the point is "here is the file to copy".
        let _ = utils::platform::reveal_file(&path);
        Ok(path)
    })
    .await?;
    utils::audit::record(
        "hosts.export",
        "exported the host catalogue",
        serde_json::json!({ "path": path.to_string_lossy(), "ok": true }),
    );
    Ok(path.to_string_lossy().to_string())
}

/* ---------------------------------------------------------------- network */

/// Start ping or traceroute against a target; output streams on `net://{run_id}`.
#[tauri::command]
async fn net_tool_start(
    app: AppHandle,
    tools: State<'_, utils::nettools::NetTools>,
    run_id: String,
    tool: String,
    target: String,
) -> CmdResult<()> {
    tools.start_process_tool(app, run_id, &tool, &target)
}

#[tauri::command]
async fn net_tool_cancel(
    tools: State<'_, utils::nettools::NetTools>,
    run_id: String,
) -> CmdResult<()> {
    tools.cancel(&run_id);
    Ok(())
}

/// TCP port check: OPEN / CLOSED (refused) / FILTERED (timeout).
#[tauri::command]
async fn net_port_check(target: String, port: u16) -> CmdResult<String> {
    utils::nettools::NetTools::port_check(&target, port, 3000).await
}

/// Resolve a name through the OS resolver.
#[tauri::command]
async fn net_dns_lookup(target: String) -> CmdResult<Vec<String>> {
    utils::nettools::NetTools::dns_lookup(&target).await
}

/// Probe many hosts' SSH ports concurrently (reachability sweep).
#[tauri::command]
async fn hosts_probe(
    targets: Vec<(String, String, u16)>,
) -> CmdResult<Vec<utils::nettools::ProbeResult>> {
    Ok(utils::nettools::probe_hosts(targets).await)
}

/* ---------------------------------------------------------------- configs */

/// Run blocking snapshot/diff file work off the async workers.
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, utils::known_hosts::KnownHostsError> + Send + 'static,
) -> CmdResult<T> {
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

/// An exec-capture error as audited: without the device's stderr, which
/// `exec_capture` appends after ": " (device output, like the command line,
/// stays out of the audit log).
fn exec_error_for_audit(e: &str) -> &str {
    e.split(": ").next().unwrap_or(e)
}

const NOTHING_CAPTURED: &str =
    "capture returned nothing — the device may not support exec-channel commands";

/// Capture a device's config over a fresh exec channel and store a snapshot.
///
/// The snapshot folder is keyed by the session's own endpoint identity (what
/// it dialled; see utils::artifacts); `host` is only the readable label.
#[tauri::command]
async fn config_snapshot(
    registry: State<'_, Registry>,
    session_id: String,
    host: String,
    command: String,
) -> CmdResult<utils::configs::SnapshotResult> {
    // The snapshot belongs to what this session actually dialled, never to a
    // key the webview supplies next to the session id.
    // One resolution: the identity and the capture come from the same
    // connection, even if a reconnect replaces the tab's session meanwhile.
    let audited_host = host.clone();
    let result: CmdResult<utils::configs::SnapshotResult> = async {
        let session = registry.session(&session_id).map_err(|e| e.to_string())?;
        // stdout only: stderr noise (a login-shell warning) is not config.
        let output = session.exec_capture(&command, 60).await.map_err(|e| e.to_string())?.stdout;
        let endpoint = session.endpoint().to_string();
        if output.trim().is_empty() {
            return Err(NOTHING_CAPTURED.to_string());
        }
        blocking(move || utils::configs::save_snapshot(&endpoint, &host, &output)).await
    }
    .await;
    // Like config_check: host and size (or the error) only — never the command
    // or config.
    match &result {
        Ok(saved) => utils::audit::record(
            "config.snapshot",
            format!("saved a config snapshot of {audited_host}"),
            serde_json::json!({ "host": audited_host, "lines": saved.lines, "ok": true }),
        ),
        Err(e) => utils::audit::record(
            "config.snapshot.fail",
            format!("config snapshot of {audited_host} failed"),
            serde_json::json!({ "host": audited_host, "ok": false, "error": exec_error_for_audit(e) }),
        ),
    }
    result
}

/// "What changed since my last visit": capture the config over a fresh exec
/// channel and compare it with the newest snapshot, saving only if it differs.
/// Run on connect for hosts that opt in (Host editor), never otherwise.
#[tauri::command]
async fn config_check(
    registry: State<'_, Registry>,
    session_id: String,
    host: String,
    command: String,
) -> CmdResult<utils::configs::ConfigCheck> {
    // One resolution: the identity and the capture come from the same
    // connection, even if a reconnect replaces the tab's session meanwhile.
    let audited_host = host.clone();
    let result: CmdResult<utils::configs::ConfigCheck> = async {
        let session = registry.session(&session_id).map_err(|e| e.to_string())?;
        // stdout only: stderr noise (a login-shell warning) is not config.
        let output = session.exec_capture(&command, 60).await.map_err(|e| e.to_string())?.stdout;
        let endpoint = session.endpoint().to_string();
        if output.trim().is_empty() {
            return Err(NOTHING_CAPTURED.to_string());
        }
        blocking(move || utils::configs::check_snapshot(&endpoint, &host, &output)).await
    }
    .await;
    // Like capture_output: host and outcome only — never the command or config.
    match &result {
        Ok(check) => utils::audit::record(
            "config.check",
            format!("checked the config on {audited_host}: {}", check.status),
            serde_json::json!({ "host": audited_host, "status": check.status, "added": check.added, "removed": check.removed, "ok": true }),
        ),
        Err(e) => utils::audit::record(
            "config.check.fail",
            format!("config check on {audited_host} failed"),
            serde_json::json!({ "host": audited_host, "ok": false, "error": exec_error_for_audit(e) }),
        ),
    }
    result
}

#[tauri::command]
async fn config_list(
    registry: State<'_, Registry>,
    session_id: Option<String>,
    endpoint: Option<String>,
    host: String,
) -> CmdResult<Vec<utils::configs::SnapshotInfo>> {
    let endpoint = lookup_endpoint(&registry, session_id, endpoint)?;
    blocking(move || utils::configs::list_snapshots(&endpoint, &host)).await
}

#[tauri::command]
async fn config_diff(
    registry: State<'_, Registry>,
    session_id: Option<String>,
    endpoint: Option<String>,
    host: String,
    older: String,
    newer: String,
) -> CmdResult<String> {
    let endpoint = lookup_endpoint(&registry, session_id, endpoint)?;
    blocking(move || utils::configs::diff_snapshots(&endpoint, &host, &older, &newer)).await
}

#[tauri::command]
async fn config_read(
    registry: State<'_, Registry>,
    session_id: Option<String>,
    endpoint: Option<String>,
    host: String,
    name: String,
) -> CmdResult<String> {
    let endpoint = lookup_endpoint(&registry, session_id, endpoint)?;
    blocking(move || utils::configs::read_snapshot(&endpoint, &host, &name)).await
}

/// Run one command over a fresh hidden exec channel and save its output to a
/// timestamped file under the endpoint's captures folder — "log just this
/// command's output" for a `show tech-support`-sized dump, without it scrolling
/// past in the terminal. Same exec-capture path (and 16 MiB cap) as a config
/// snapshot.
#[tauri::command]
async fn capture_output(
    registry: State<'_, Registry>,
    session_id: String,
    host: String,
    command: String,
) -> CmdResult<utils::captures::CaptureResult> {
    // One resolution: the identity and the capture come from the same
    // connection, even if a reconnect replaces the tab's session meanwhile.
    let result: CmdResult<utils::captures::CaptureResult> = async {
        let session = registry.session(&session_id).map_err(|e| e.to_string())?;
        // A human-read capture keeps stderr, labelled apart from stdout.
        let output = session.exec_capture(&command, 120).await.map_err(|e| e.to_string())?.labelled();
        let endpoint = session.endpoint().to_string();
        if output.trim().is_empty() {
            return Err(NOTHING_CAPTURED.to_string());
        }
        let label = host.clone();
        blocking(move || utils::captures::save_capture(&endpoint, &label, &output)).await
    }
    .await;
    // Neither the command nor its output is logged: a command line can carry
    // a token or password (`curl -H 'Authorization: …'`). Only the host and
    // the size of what was saved, or the error.
    match &result {
        Ok(cap) => utils::audit::record(
            "exec.capture",
            format!("captured command output on {host}"),
            serde_json::json!({ "host": host, "bytes": cap.bytes, "lines": cap.lines, "ok": true }),
        ),
        Err(e) => utils::audit::record(
            "exec.capture.fail",
            format!("command capture on {host} failed"),
            serde_json::json!({ "host": host, "ok": false, "error": exec_error_for_audit(e) }),
        ),
    }
    result
}

/// Generate an Ed25519 keypair into ~/.ssh, returning the private-key path
/// and the public key line to paste into a server's authorized_keys.
///
/// Ed25519 only, on purpose: it is the modern default, has no parameter
/// choices to get wrong, and every server worth reaching supports it. The
/// private key is written unencrypted (russh loads it without a prompt);
/// the file inherits the user-profile ACL, which on Windows is the same
/// protection ssh-keygen's output gets.
/// Install a public key on a host via a one-shot password connection
/// (ssh-copy-id). The password is used once, never stored.
#[tauri::command]
async fn ssh_copy_id(
    app: AppHandle,
    registry: State<'_, Registry>,
    prompts: State<'_, Arc<HostKeyPrompts>>,
    auth_prompts: State<'_, Arc<AuthPrompts>>,
    host: String,
    port: u16,
    username: String,
    password: String,
    public_key: String,
    op_id: Option<String>,
) -> CmdResult<()> {
    let password = zeroize::Zeroizing::new(password);
    let result = registry
        .copy_id_run(
            app,
            std::sync::Arc::clone(&prompts),
            std::sync::Arc::clone(&auth_prompts),
            op_id.as_deref(),
            &host,
            port,
            &username,
            password,
            &public_key,
        )
        .await
        .map_err(|e| e.to_string());
    // The key is logged by fingerprint (its comment is free text); the password
    // used for the one-shot login is never logged.
    match &result {
        Ok(()) => utils::audit::record(
            "key.install",
            format!("installed a public key for {username}@{host}:{port}"),
            serde_json::json!({ "host": host, "port": port, "user": username, "keyFingerprint": utils::audit::key_fingerprint(&public_key), "ok": true }),
        ),
        Err(_) => utils::audit::record(
            "key.install.fail",
            format!("key install for {username}@{host}:{port} failed"),
            // No error text: on failure it carries up to 200 chars of the remote
            // command's output, and command output is never logged.
            serde_json::json!({ "host": host, "port": port, "user": username, "ok": false }),
        ),
    }
    result
}

/// Abandon an in-flight `ssh_copy_id` started with the same `op_id` (the host
/// editor closed). Its connection is dropped and any prompt it raised closed.
#[tauri::command]
async fn ssh_copy_id_cancel(registry: State<'_, Registry>, op_id: String) -> CmdResult<()> {
    registry.copy_id_cancel(&op_id);
    Ok(())
}

/// Write a new keypair into `dir` as `hawser_ed25519[_N]` and `.pub`, never
/// clobbering anything: a keypair someone already deployed to twenty servers
/// is irreplaceable, and so is an unrelated `.pub` whose private half moved.
/// BOTH names are reserved with an exclusive create (O_EXCL), bumping the
/// suffix while either is taken. A failed write removes both files, so no
/// half-written key is left behind. Returns the private key's path.
fn write_keypair(
    dir: &std::path::Path,
    private_pem: &[u8],
    public_line: &str,
) -> std::io::Result<std::path::PathBuf> {
    use std::io::Write;
    let create = |p: &std::path::Path, mode: u32| {
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // Private key 0600 from the start (OpenSSH refuses group- or
            // world-readable keys); the public half 0644.
            o.mode(mode);
        }
        #[cfg(not(unix))]
        let _ = mode;
        o.open(p)
    };
    for n in 0..10_000u32 {
        let path = if n == 0 {
            dir.join("hawser_ed25519")
        } else {
            dir.join(format!("hawser_ed25519_{n}"))
        };
        let pub_path = path.with_extension("pub");
        let mut private = match create(&path, 0o600) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        };
        let mut public = match create(&pub_path, 0o644) {
            Ok(f) => f,
            Err(e) => {
                drop(private);
                let _ = std::fs::remove_file(&path);
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    continue;
                }
                return Err(e);
            }
        };
        let written = private
            .write_all(private_pem)
            .and_then(|_| private.sync_all())
            .and_then(|_| public.write_all(format!("{public_line}\n").as_bytes()));
        if let Err(e) = written {
            drop((private, public));
            let _ = std::fs::remove_file(&path);
            let _ = std::fs::remove_file(&pub_path);
            return Err(e);
        }
        return Ok(path);
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "no free hawser_ed25519 key name in ~/.ssh",
    ))
}

#[tauri::command]
async fn ssh_keygen(comment: String) -> CmdResult<serde_json::Value> {
    off(move || ssh_keygen_blocking(comment)).await
}

fn ssh_keygen_blocking(comment: String) -> CmdResult<serde_json::Value> {
    use russh::keys::ssh_key::{self, getrandom::SysRng, rand_core::UnwrapErr, LineEnding};

    // Cross-platform home via the shared helper (USERPROFILE on Windows, HOME
    // on macOS/Linux) — keeps the Windows-only assumption out of keygen.
    let home = utils::platform::home_dir().ok_or("could not determine home directory")?;
    let dir = home.join(".ssh");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

    // ssh-key's RNG is fallible (SysRng: TryCryptoRng); UnwrapErr adapts it to
    // the infallible CryptoRng that PrivateKey::random requires.
    let mut rng = UnwrapErr(SysRng);
    let mut key = ssh_key::PrivateKey::random(&mut rng, ssh_key::Algorithm::Ed25519)
        .map_err(|e| e.to_string())?;
    key.set_comment(comment);
    let pem = key.to_openssh(LineEnding::LF).map_err(|e| e.to_string())?;
    let public = key
        .public_key()
        .to_openssh()
        .map_err(|e| e.to_string())?;
    let path = write_keypair(&dir, pem.as_bytes(), &public).map_err(|e| e.to_string())?;

    utils::audit::record(
        "key.generate",
        format!("generated an Ed25519 key at {}", path.to_string_lossy()),
        serde_json::json!({ "privatePath": path.to_string_lossy(), "keyFingerprint": utils::audit::key_fingerprint(&public), "ok": true }),
    );

    Ok(serde_json::json!({
        "privatePath": path.to_string_lossy(),
        "publicKey": public,
    }))
}

/* --------------------------------------------------------------------- ai */

/// Start a streaming chat with the configured provider; deltas arrive on
/// `ai://{run_id}`. The webview supplies the visible context; the key comes
/// from the vault and never returns.
#[tauri::command]
async fn ai_chat(
    app: AppHandle,
    run_id: String,
    cfg: utils::ai::ProviderConfig,
    profile: String,
    system_context: String,
    messages: Vec<utils::ai::ChatMessage>,
) -> CmdResult<()> {
    utils::ai::start(app, run_id, cfg, profile, system_context, messages);
    Ok(())
}

/// Stop a running chat; its final `done` event reports "Cancelled.".
#[tauri::command]
async fn ai_cancel(run_id: String) -> CmdResult<bool> {
    Ok(utils::ai::cancel(&run_id))
}

#[tauri::command]
async fn ai_key_save(
    profile: String,
    key: String,
    kind: String,
    base_url: String,
) -> CmdResult<()> {
    let key = zeroize::Zeroizing::new(key);
    let (p, k) = (profile.clone(), kind.clone());
    let result = off(move || utils::ai::save_key(&p, &key, &k, &base_url)).await;
    if result.is_ok() {
        // The API key itself is never logged — only that a key was saved for this
        // provider profile.
        utils::audit::record(
            "aikey.save",
            format!("saved an AI provider key for profile '{profile}'"),
            serde_json::json!({ "profile": profile, "kind": kind, "ok": true }),
        );
    }
    result
}

#[tauri::command]
async fn ai_key_status(profile: String) -> CmdResult<bool> {
    off(move || Ok(utils::ai::key_exists(&profile))).await
}

/// Remove a profile's saved API key and its origin binding — the way out after
/// switching to a provider that needs no key (e.g. local Ollama).
#[tauri::command]
async fn ai_key_delete(profile: String) -> CmdResult<()> {
    let p = profile.clone();
    let result = off(move || utils::ai::delete_key(&p)).await;
    if result.is_ok() {
        utils::audit::record(
            "aikey.delete",
            format!("removed the AI provider key for profile '{profile}'"),
            serde_json::json!({ "profile": profile, "ok": true }),
        );
    }
    result
}

/// Provider settings (kind/baseUrl/model — never the key) as opaque JSON at
/// %APPDATA%\hawseri.json, same pattern as the host catalogue.
#[tauri::command]
async fn ai_config_load() -> CmdResult<Option<serde_json::Value>> {
    off(|| utils::hosts::load_named("ai.json").map_err(|e| e.to_string())).await
}

#[tauri::command]
async fn ai_config_save(config: serde_json::Value) -> CmdResult<()> {
    off(move || utils::hosts::save_named("ai.json", &config).map_err(|e| e.to_string())).await
}

/// App-wide settings (colour policies, device profiles, UI defaults).
/// %APPDATA%\hawser\settings.json — opaque JSON owned by the frontend, same
/// corrupt-tolerant contract as the host catalogue.
#[tauri::command]
async fn settings_load() -> CmdResult<Option<serde_json::Value>> {
    off(|| utils::hosts::load_named("settings.json").map_err(|e| e.to_string())).await
}

#[tauri::command]
async fn settings_save(settings: serde_json::Value) -> CmdResult<()> {
    off(move || utils::hosts::save_named("settings.json", &settings).map_err(|e| e.to_string())).await
}

/* -------------------------------------------------------------- credentials */

/// Save a password to the OS credential vault and bind it to its destinations.
///
/// This is the one command that accepts a secret, and only because the user
/// just typed it into the host editor. It goes straight into the OS vault and
/// is never echoed back: there is deliberately no `credential_read` command.
///
/// `destinations` is the exact set of (host, port, username) the editor
/// approved for this vault entry — the catalogue as it will be after the edit —
/// and REPLACES the binding, so an edited host's old address can no longer
/// receive the password. Without it (an older caller) the catalogue's current
/// users of the entry are bound, as before.
#[tauri::command]
async fn credential_save(
    host_id: String,
    username: String,
    password: String,
    host: String,
    port: u16,
    destinations: Option<Vec<utils::hosts::Dest>>,
) -> CmdResult<()> {
    let password = zeroize::Zeroizing::new(password);
    let owner = utils::hosts::Dest { host: host.clone(), port, username: username.clone() };
    let (id, user) = (host_id.clone(), username.clone());
    // Secret and binding as one unit, under the vault lock that connect's read
    // takes too; a failed binding write puts the previous secret back.
    off(move || {
        utils::hosts::save_credential(&id, &user, &password, &owner, destinations.as_deref())
    })
    .await?;
    // The password is never logged — only that a credential was saved and bound
    // to this destination.
    utils::audit::record(
        "credential.save",
        format!("saved a password for {username}@{host}:{port}"),
        serde_json::json!({ "hostId": host_id, "host": host, "port": port, "user": username, "ok": true }),
    );
    Ok(())
}

/// Whether a password is stored, without decrypting it — lets the UI show
/// "password saved" with no plaintext in the webview.
#[tauri::command]
async fn credential_status(host_id: String) -> CmdResult<bool> {
    off(move || {
        Ok(!credentials::is_reserved_id(&host_id)
            && credentials::validate_id(&host_id).is_ok()
            && credentials::has_secret(&host_id))
    })
    .await
}

#[tauri::command]
async fn credential_delete(host_id: String) -> CmdResult<()> {
    let id = host_id.clone();
    // The binding is dropped only once the secret is gone (or was never
    // there); a vault error keeps both and is reported.
    off(move || utils::hosts::delete_credential(&id)).await?;
    utils::audit::record(
        "credential.delete",
        format!("removed the saved password for host '{host_id}'"),
        serde_json::json!({ "hostId": host_id, "ok": true }),
    );
    Ok(())
}

/// Revoke destinations from a saved credential's binding: keep only those in
/// `destinations` (the catalogue's users of the entry after an edit or delete).
/// Never adds one — widening needs the password typed again.
#[tauri::command]
async fn credential_binding_narrow(
    host_id: String,
    destinations: Vec<utils::hosts::Dest>,
) -> CmdResult<()> {
    off(move || utils::hosts::narrow_binding(&host_id, &destinations)).await
}

/* --------------------------------------------------------------------- run */

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        // First, so a second launch hands over and exits before anything else
        // starts: two instances would race on the audit log and every other
        // data file. The running window is brought forward instead.
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.unminimize();
                let _ = w.show();
                let _ = w.set_focus();
            }
        }))
        .setup(|app| {
            app.manage(Registry::default());
            app.manage(Arc::new(local_shell::LocalShells::default()));
            app.manage(Arc::new(HostKeyPrompts::default()));
            app.manage(Arc::new(AuthPrompts::default()));
            app.manage(utils::nettools::NetTools::default());

            // The audit writer thread, before anything can be recorded.
            utils::audit::start();
            // The data directory is owner-only (0700) on Unix; files in it are
            // written 0600 (utils::hosts::write_atomic).
            if let Ok(store) = utils::known_hosts::store_path() {
                if let Some(dir) = store.parent() {
                    let _ = utils::hosts::ensure_dir(dir);
                }
            }

            // Backfill credential→destination and AI-origin bindings for
            // already-saved secrets, from the on-disk catalogue. This MUST run
            // synchronously here, before setup returns and the webview can
            // invoke any command: if it were spawned, a compromised frontend
            // could race it — poisoning hosts.json via hosts_save before the
            // migration reads it — and reintroduce the frontend-writable-source
            // bug. Run inline (small catalogue + a few vault reads); a panic is
            // contained so a migration hiccup never blocks startup.
            let _ = std::panic::catch_unwind(utils::hosts::migrate_bindings);
            let _ = std::panic::catch_unwind(utils::ai::migrate_ai_origins);

            // Prune old transcripts on launch. Defaults chosen to keep a useful
            // window of history without letting plaintext firewall logs pile up
            // indefinitely: 30 days, and at most 500 files. Runs off-thread so a
            // large logs directory never delays the window appearing.
            // Quick-connect hosts are never saved, so a password an older build
            // saved for one could never be deleted from the UI: remove them.
            // Off-thread: each removal is a keychain call.
            std::thread::spawn(|| {
                match std::panic::catch_unwind(utils::hosts::purge_quick_connect_secrets) {
                    Ok(n) if n > 0 => eprintln!("hawser: removed {n} saved quick-connect password(s)"),
                    Ok(_) => {}
                    Err(_) => eprintln!("hawser: quick-connect cleanup panicked"),
                }
            });
            std::thread::spawn(|| {
                // catch_unwind so a panic in pruning (e.g. the logs directory
                // vanishing mid-scan) is reported rather than silently swallowed
                // by a dead background thread.
                match std::panic::catch_unwind(|| utils::session_log::prune(30, 500)) {
                    Ok(n) if n > 0 => eprintln!("hawser: pruned {n} old session log(s)"),
                    Ok(_) => {}
                    Err(_) => eprintln!("hawser: session-log pruning thread panicked"),
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            ssh_connect,
            ssh_write,
            ssh_resize,
            ssh_disconnect,
            host_key_respond,
            auth_prompt_respond,
            auth_prompt_cancel,
            sftp_list,
            sftp_get,
            sftp_put,
            sftp_cancel,
            local_list,
            local_root,
            path_exists,
            sftp_rename,
            sftp_delete,
            sftp_mkdir,
            local_rename,
            local_delete,
            local_mkdir,
            forward_start,
            forward_start_socks,
            forward_stop,
            forwards_list,
            net_tool_start,
            net_tool_cancel,
            net_port_check,
            net_dns_lookup,
            hosts_probe,
            config_snapshot,
            config_check,
            capture_output,
            config_list,
            config_diff,
            config_read,
            ssh_keygen,
            ssh_copy_id,
            ssh_copy_id_cancel,
            ai_chat,
            ai_cancel,
            ai_key_save,
            ai_key_status,
            ai_key_delete,
            ai_config_load,
            ai_config_save,
            settings_load,
            settings_save,
            hosts_load,
            hosts_save,
            hosts_export,
            sessions_load,
            sessions_save,
            session_history,
            logs_list,
            open_logs_folder,
            log_read,
            logs_search,
            logs_search_cancel,
            audit_list,
            audit_verify,
            audit_archive,
            local_shell_profiles,
            local_shell_start,
            credential_save,
            credential_status,
            credential_delete,
            credential_binding_narrow,
        ])
        .build(tauri::generate_context!())
        .expect("error while running tauri application");
    app.run(|_app, event| {
        // Audit records are written by a background thread; give the queue a
        // moment to drain so the last actions of a session are not lost.
        if let tauri::RunEvent::Exit = event {
            utils::audit::flush(std::time::Duration::from_secs(3));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use utils::artifacts::dial_identity;

    /// A failed capture is audited without the device's stderr.
    #[test]
    fn audited_exec_errors_leave_out_device_output() {
        assert_eq!(
            exec_error_for_audit("capture command exited with status 1: token=abc123 rejected"),
            "capture command exited with status 1"
        );
        assert_eq!(exec_error_for_audit("capture timed out after 60s; output discarded"), "capture timed out after 60s; output discarded");
    }

    #[test]
    fn local_root_is_the_system_drive_on_windows_and_slash_elsewhere() {
        if cfg!(windows) {
            assert_eq!(local_root_from(Some("D:")), "D:\\");
            assert_eq!(local_root_from(Some("bogus")), "C:\\");
            assert_eq!(local_root_from(None), "C:\\");
        } else {
            assert_eq!(local_root_from(Some("D:")), "/");
        }
    }

    #[test]
    fn keygen_never_clobbers_an_orphan_public_key() {
        let d = std::env::temp_dir().join(format!("hawser-keygen-{}", utils::artifacts::random_hex(6)));
        std::fs::create_dir_all(&d).unwrap();
        // An unrelated .pub whose private half was moved away.
        std::fs::write(d.join("hawser_ed25519.pub"), "ssh-ed25519 KEEP me\n").unwrap();
        let p = write_keypair(&d, b"PRIVATE", "ssh-ed25519 NEW").unwrap();
        assert_eq!(p, d.join("hawser_ed25519_1"));
        assert_eq!(std::fs::read_to_string(d.join("hawser_ed25519.pub")).unwrap(), "ssh-ed25519 KEEP me\n");
        assert!(!d.join("hawser_ed25519").exists(), "the probe reservation must be released");
        assert_eq!(std::fs::read_to_string(d.join("hawser_ed25519_1.pub")).unwrap(), "ssh-ed25519 NEW\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        }
        // A second key takes the next free pair.
        assert_eq!(write_keypair(&d, b"P2", "ssh-ed25519 N2").unwrap(), d.join("hawser_ed25519_2"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn ai_context_is_refused_when_the_live_dial_is_not_the_policy_endpoint() {
        // The tab dialled 10.0.0.1; the entry was then repointed at 10.0.0.2
        // (and, say, AI enabled for it). The panel's policy is for the new
        // identity, the transcript comes from the old one.
        let live = dial_identity(Some("host:h-1"), ("admin", "10.0.0.1", 22), None);
        let now = dial_identity(Some("host:h-1"), ("admin", "10.0.0.2", 22), None);
        assert!(check_same_endpoint(&live, &now).is_err());
        assert!(check_same_endpoint(&live, &live).is_ok());
        // Editing the bastion's account counts the same way.
        let via = |user: &str| dial_identity(Some("host:h-1|via:host:b-1"), ("admin", "10.0.0.1", 22), Some((user, "bastion", 22)));
        assert!(check_same_endpoint(&via("ops"), &via("root")).is_err());
    }

    #[test]
    fn history_reads_the_endpoint_that_passed_the_check() {
        // One resolution feeds both the comparison and the read: the result is
        // the identity that was compared, never a second lookup's.
        let live = dial_identity(Some("host:h-1"), ("admin", "10.0.0.1", 22), None);
        let now = dial_identity(Some("host:h-1"), ("admin", "10.0.0.2", 22), None);
        assert_eq!(history_endpoint(Some(live.clone()), Some(live.clone())).unwrap(), live);
        assert!(history_endpoint(Some(live.clone()), Some(now.clone())).is_err());
        // No live session: the caller's identity (replay before a dial).
        assert_eq!(history_endpoint(None, Some(now.clone())).unwrap(), now);
        assert_eq!(history_endpoint(Some(live.clone()), None).unwrap(), live);
        assert!(history_endpoint(None, None).is_err());
    }
}
