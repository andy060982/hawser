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

/* ------------------------------------------------------------------ session */

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
) -> CmdResult<()> {
    let result = registry
        .connect(
            app,
            Arc::clone(&prompts),
            Arc::clone(&auth_prompts),
            &session_id,
            &host_id,
            &host,
            port,
            &username,
            cols,
            rows,
            &startup_commands.unwrap_or_default(),
            auth.as_deref().unwrap_or("password"),
            key_path.as_deref(),
            jump,
            one_shot_password.as_deref(),
        )
        .await
        .map_err(|e| e.to_string());
    // Audit the authentication outcome. host/port/user are not secret; the error
    // string is an SSH/protocol message (e.g. "authentication failed"), never a
    // password. The connect result folds the host-key and auth steps together.
    match &result {
        Ok(()) => utils::audit::record(
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
    // A local terminal closes its shell; no-op for any other id.
    local.close(&session_id);
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
    Ok(local_shell::profiles())
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
    // Audited like a connect (which shell, never what is typed), but off the
    // command's path: sealing writes the keychain, which can show a prompt, and
    // the terminal must not wait on it.
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
    tauri::async_runtime::spawn_blocking(move || utils::audit::record(event, summary, detail));
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

#[tauri::command]
async fn sftp_get(
    app: AppHandle,
    registry: State<'_, Registry>,
    session_id: String,
    remote_path: String,
    local_path: String,
) -> CmdResult<u64> {
    let result = registry
        .download(&app, &session_id, &remote_path, &local_path)
        .await
        .map_err(|e| e.to_string());
    match &result {
        Ok(bytes) => utils::audit::record(
            "sftp.get",
            format!("downloaded {remote_path} ({bytes} bytes)"),
            serde_json::json!({ "remote": remote_path, "local": local_path, "bytes": bytes, "ok": true }),
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
async fn sftp_put(
    app: AppHandle,
    registry: State<'_, Registry>,
    session_id: String,
    local_path: String,
    remote_path: String,
) -> CmdResult<u64> {
    let result = registry
        .upload(&app, &session_id, &local_path, &remote_path)
        .await
        .map_err(|e| e.to_string());
    match &result {
        Ok(bytes) => utils::audit::record(
            "sftp.put",
            format!("uploaded {remote_path} ({bytes} bytes)"),
            serde_json::json!({ "local": local_path, "remote": remote_path, "bytes": bytes, "ok": true }),
        ),
        Err(e) => utils::audit::record(
            "sftp.put.fail",
            format!("upload to {remote_path} failed"),
            serde_json::json!({ "local": local_path, "remote": remote_path, "ok": false, "error": e }),
        ),
    }
    result
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
    registry
        .forward_start(&session_id, local_port, &remote_host, remote_port)
        .await
        .map_err(|e| e.to_string())
}

/// Start a SOCKS5 dynamic proxy (`ssh -D`) over an open session.
#[tauri::command]
async fn forward_start_socks(
    registry: State<'_, Registry>,
    session_id: String,
    local_port: u16,
) -> CmdResult<ssh::ForwardInfo> {
    registry
        .forward_start_socks(&session_id, local_port)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn forward_stop(registry: State<'_, Registry>, forward_id: String) -> CmdResult<()> {
    registry.forward_stop(&forward_id);
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
        Ok(std::fs::metadata(&path).is_ok())
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
    if result.is_ok() {
        utils::audit::record(
            "sftp.rename",
            format!("renamed {from} to {to}"),
            serde_json::json!({ "from": from, "to": to, "ok": true }),
        );
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
    if result.is_ok() {
        utils::audit::record(
            "sftp.mkdir",
            format!("created directory {path}"),
            serde_json::json!({ "path": path, "ok": true }),
        );
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
    // A case-only rename on a case-insensitive filesystem (macOS, Windows)
    // resolves `to` to `from` itself; that is not a collision.
    let same_entry = match (std::fs::canonicalize(&from), std::fs::canonicalize(&to)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    };
    if std::fs::symlink_metadata(&to).is_ok() && !same_entry {
        return Err(format!("{to} already exists"));
    }
    std::fs::rename(&from, &to).map_err(|e| e.to_string())
}

#[tauri::command]
async fn local_delete(path: String, is_dir: bool) -> CmdResult<()> {
    if is_dir {
        std::fs::remove_dir(&path).map_err(|e| e.to_string())
    } else {
        std::fs::remove_file(&path).map_err(|e| e.to_string())
    }
}

#[tauri::command]
async fn local_mkdir(path: String) -> CmdResult<()> {
    std::fs::create_dir(&path).map_err(|e| e.to_string())
}

/* -------------------------------------------------------------------- local */

/// Local half of the dual pane. Deliberately mirrors `sftp_list`'s shape so the
/// two panes are the same component with a different data source.
#[tauri::command]
async fn local_list(path: String) -> CmdResult<DirListing> {
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
    })
}

/* --------------------------------------------------------------- catalogue */

/// Load the saved-host tree. `None` means "no file yet" — a first run, not a
/// failure; the frontend seeds from its defaults in that case.
#[tauri::command]
async fn hosts_load() -> CmdResult<Option<serde_json::Value>> {
    utils::hosts::load().map_err(|e| e.to_string())
}

#[tauri::command]
async fn hosts_save(tree: serde_json::Value) -> CmdResult<()> {
    utils::hosts::save(&tree).map_err(|e| e.to_string())
}

/// Tabs open at last exit, so a restart can offer them again.
#[tauri::command]
async fn sessions_load() -> CmdResult<Option<serde_json::Value>> {
    utils::hosts::load_sessions().map_err(|e| e.to_string())
}

#[tauri::command]
async fn sessions_save(list: serde_json::Value) -> CmdResult<()> {
    utils::hosts::save_sessions(&list).map_err(|e| e.to_string())
}

/// Tail of the last transcript for a host, for replay into a reconnected tab.
///
/// Host-keyed rather than session-keyed: session ids are per-connection, and the
/// point is to bridge ACROSS connections.
#[tauri::command]
async fn session_history(host: String, max_bytes: usize) -> CmdResult<Option<String>> {
    utils::session_log::latest_transcript(&host, max_bytes).map_err(|e| e.to_string())
}

/// List past session transcripts (newest first) for the history browser.
#[tauri::command]
async fn logs_list() -> CmdResult<Vec<utils::session_log::LogEntry>> {
    utils::session_log::list().map_err(|e| e.to_string())
}

/// Open the transcript directory in Explorer.
///
/// Fixed target, not a parameter: an `open(path)` command reachable from the
/// webview is a shell-execute primitive for anything that ever gets script
/// injection. This one can open exactly one folder and nothing else.
#[tauri::command]
async fn open_logs_folder() -> CmdResult<()> {
    let dir = utils::session_log::logs_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    utils::platform::open_dir(&dir).map_err(|e| e.to_string())?;
    Ok(())
}

/// Read one transcript by its bare filename.
#[tauri::command]
async fn log_read(name: String) -> CmdResult<String> {
    utils::session_log::read_log(&name).map_err(|e| e.to_string())
}

/// Search every transcript for a line containing `query` (case-insensitive),
/// newest session first. Runs on the blocking pool: it reads every log file.
#[tauri::command]
async fn logs_search(query: String, limit: usize) -> CmdResult<utils::session_log::SearchResult> {
    tauri::async_runtime::spawn_blocking(move || utils::session_log::search(&query, limit))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

/// Most recent audit-log entries, newest first, for the Audit panel.
#[tauri::command]
async fn audit_list(limit: usize) -> CmdResult<Vec<utils::audit::AuditView>> {
    // Clamp so a bad/huge limit cannot ask the UI to render the entire history.
    utils::audit::list(limit.min(2000))
}

/// Walk the audit chain and report whether it is intact, where it broke, and
/// whether the file head matches the keychain anchor.
#[tauri::command]
async fn audit_verify() -> CmdResult<utils::audit::VerifyReport> {
    utils::audit::verify()
}

/// Set the current audit log aside (renamed, never deleted) and start a fresh,
/// anchored one whose first entry names the archive. The only way back to a
/// clean "verified" state after a failed or gapped check.
#[tauri::command]
async fn audit_archive() -> CmdResult<String> {
    utils::audit::archive()
}

/// Export the host catalogue to Documents\hawser-hosts.json and reveal it.
///
/// Topology only — names, addresses, folders, snippets. Passwords live in the
/// Credential Manager and are structurally absent from hosts.json, so an
/// export cannot leak a secret even by mistake. That boundary is the reason
/// export is safe to offer as one click.
#[tauri::command]
async fn hosts_export() -> CmdResult<String> {
    let tree = utils::hosts::load()
        .map_err(|e| e.to_string())?
        .ok_or("no host catalogue to export")?;

    let docs = utils::platform::documents_dir().ok_or("cannot resolve Documents folder")?;
    std::fs::create_dir_all(&docs).map_err(|e| e.to_string())?;
    let path = docs.join("hawser-hosts.json");
    let text = serde_json::to_string_pretty(&tree).map_err(|e| e.to_string())?;
    std::fs::write(&path, text).map_err(|e| e.to_string())?;

    // Reveal rather than open: the point is "here is the file to copy".
    let _ = utils::platform::reveal_file(&path);
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

/// Capture a device's config over a fresh exec channel and store a snapshot.
#[tauri::command]
async fn config_snapshot(
    registry: State<'_, Registry>,
    session_id: String,
    host: String,
    command: String,
) -> CmdResult<utils::configs::SnapshotResult> {
    let output = registry
        .exec_capture(&session_id, &command, 60)
        .await
        .map_err(|e| e.to_string())?;
    if output.trim().is_empty() {
        return Err(
            "capture returned nothing — the device may not support exec-channel commands"
                .to_string(),
        );
    }
    utils::configs::save_snapshot(&host, &output).map_err(|e| e.to_string())
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
    let output = registry
        .exec_capture(&session_id, &command, 60)
        .await
        .map_err(|e| e.to_string())?;
    if output.trim().is_empty() {
        return Err(
            "capture returned nothing — the device may not support exec-channel commands"
                .to_string(),
        );
    }
    let audited_host = host.clone();
    let check = tauri::async_runtime::spawn_blocking(move || {
        utils::configs::check_snapshot(&host, &output)
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())?;
    // Like capture_output: host and outcome only — never the command or config.
    utils::audit::record(
        "config.check",
        format!("checked the config on {audited_host}: {}", check.status),
        serde_json::json!({ "host": audited_host, "status": check.status, "added": check.added, "removed": check.removed, "ok": true }),
    );
    Ok(check)
}

#[tauri::command]
async fn config_list(host: String) -> CmdResult<Vec<utils::configs::SnapshotInfo>> {
    utils::configs::list_snapshots(&host).map_err(|e| e.to_string())
}

#[tauri::command]
async fn config_diff(host: String, older: String, newer: String) -> CmdResult<String> {
    utils::configs::diff_snapshots(&host, &older, &newer).map_err(|e| e.to_string())
}

#[tauri::command]
async fn config_read(host: String, name: String) -> CmdResult<String> {
    utils::configs::read_snapshot(&host, &name).map_err(|e| e.to_string())
}

/// Run one command over a fresh hidden exec channel and save its output to a
/// timestamped file under the host's captures folder — "log just this command's
/// output" for a `show tech-support`-sized dump, without it scrolling past in
/// the terminal. Same exec-capture path (and 16 MiB cap) as a config snapshot.
#[tauri::command]
async fn capture_output(
    registry: State<'_, Registry>,
    session_id: String,
    host: String,
    command: String,
) -> CmdResult<utils::captures::CaptureResult> {
    let output = registry
        .exec_capture(&session_id, &command, 120)
        .await
        .map_err(|e| e.to_string())?;
    if output.trim().is_empty() {
        return Err(
            "capture returned nothing — the device may not support exec-channel commands"
                .to_string(),
        );
    }
    let saved = utils::captures::save_capture(&host, &command, &output).map_err(|e| e.to_string());
    if let Ok(cap) = &saved {
        // Neither the command nor its output is logged: a command line can carry
        // a token or password (`curl -H 'Authorization: …'`). Only the host and
        // the size of what was saved.
        utils::audit::record(
            "exec.capture",
            format!("captured command output on {host}"),
            serde_json::json!({ "host": host, "bytes": cap.bytes, "lines": cap.lines, "ok": true }),
        );
    }
    saved
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
    prompts: State<'_, Arc<HostKeyPrompts>>,
    auth_prompts: State<'_, Arc<AuthPrompts>>,
    host: String,
    port: u16,
    username: String,
    password: String,
    public_key: String,
) -> CmdResult<()> {
    let result = ssh::copy_id(
        app,
        std::sync::Arc::clone(&prompts),
        std::sync::Arc::clone(&auth_prompts),
        &host,
        port,
        &username,
        &password,
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

#[tauri::command]
async fn ssh_keygen(comment: String) -> CmdResult<serde_json::Value> {
    use russh::keys::ssh_key::{self, getrandom::SysRng, rand_core::UnwrapErr, LineEnding};

    // Cross-platform home via the shared helper (USERPROFILE on Windows, HOME
    // on macOS/Linux) — keeps the Windows-only assumption out of keygen.
    let home = utils::platform::home_dir().ok_or("could not determine home directory")?;
    let dir = home.join(".ssh");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

    // Never clobber an existing key: a keypair someone already deployed to
    // twenty servers is irreplaceable. Reserve the name ATOMICALLY with an
    // exclusive create (O_EXCL) and bump the suffix on collision — a plain
    // exists()-then-write races two concurrent keygens onto the same path.
    let mut path = dir.join("hawser_ed25519");
    let mut n = 1;
    let mut file = loop {
        match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(f) => break f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                path = dir.join(format!("hawser_ed25519_{n}"));
                n += 1;
            }
            Err(e) => return Err(e.to_string()),
        }
    };
    // Private key file is 0600 on Unix (OpenSSH refuses group/world-readable keys).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
    }

    // ssh-key's RNG is fallible (SysRng: TryCryptoRng); UnwrapErr adapts it to
    // the infallible CryptoRng that PrivateKey::random requires.
    let mut rng = UnwrapErr(SysRng);
    let mut key = ssh_key::PrivateKey::random(&mut rng, ssh_key::Algorithm::Ed25519)
        .map_err(|e| e.to_string())?;
    key.set_comment(comment);

    // Write into the handle we already hold, not a fresh path open — keeps the
    // exclusive reservation intact.
    {
        use std::io::Write;
        let pem = key.to_openssh(LineEnding::LF).map_err(|e| e.to_string())?;
        file.write_all(pem.as_bytes()).map_err(|e| e.to_string())?;
    }

    let public = key
        .public_key()
        .to_openssh()
        .map_err(|e| e.to_string())?;
    let pub_path = path.with_extension("pub");
    std::fs::write(&pub_path, format!("{public}
")).map_err(|e| e.to_string())?;

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
    tokio::spawn(utils::ai::chat(app, run_id, cfg, profile, system_context, messages));
    Ok(())
}

#[tauri::command]
async fn ai_key_save(
    profile: String,
    key: String,
    kind: String,
    base_url: String,
) -> CmdResult<()> {
    let result = utils::ai::save_key(&profile, &key, &kind, &base_url);
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
    Ok(utils::ai::key_exists(&profile))
}

/// Remove a profile's saved API key and its origin binding — the way out after
/// switching to a provider that needs no key (e.g. local Ollama).
#[tauri::command]
async fn ai_key_delete(profile: String) -> CmdResult<()> {
    let result = utils::ai::delete_key(&profile);
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
    utils::hosts::load_named("ai.json").map_err(|e| e.to_string())
}

#[tauri::command]
async fn ai_config_save(config: serde_json::Value) -> CmdResult<()> {
    utils::hosts::save_named("ai.json", &config).map_err(|e| e.to_string())
}

/// App-wide settings (colour policies, device profiles, UI defaults).
/// %APPDATA%\hawser\settings.json — opaque JSON owned by the frontend, same
/// corrupt-tolerant contract as the host catalogue.
#[tauri::command]
async fn settings_load() -> CmdResult<Option<serde_json::Value>> {
    utils::hosts::load_named("settings.json").map_err(|e| e.to_string())
}

#[tauri::command]
async fn settings_save(settings: serde_json::Value) -> CmdResult<()> {
    utils::hosts::save_named("settings.json", &settings).map_err(|e| e.to_string())
}

/* -------------------------------------------------------------- credentials */

/// Save a password to the Windows Credential Manager.
///
/// This is the one command that accepts a secret, and only because the user
/// just typed it into the host editor. It goes straight into the OS vault and
/// is never echoed back: there is deliberately no `credential_read` command.
#[tauri::command]
async fn credential_save(
    host_id: String,
    username: String,
    password: String,
    host: String,
    port: u16,
) -> CmdResult<()> {
    if credentials::is_reserved_id(&host_id) {
        return Err(format!("'{host_id}' is a reserved vault id, not a host"));
    }
    credentials::write_secret(&host_id, &username, &password).map_err(|e| e.to_string())?;
    // Record, in backend-owned state, that this secret may be sent to this
    // destination (and to any catalogue borrower of it). ssh_connect authorizes
    // against this — not the frontend-writable hosts.json — so a later poisoned
    // catalogue cannot redirect the secret. Done here, where the human just
    // supplied the secret, is the trustworthy moment to bind it. Propagated so
    // the save is atomic: if the binding cannot be written, the save fails
    // rather than silently leaving a secret that ssh_connect will later refuse.
    utils::hosts::snapshot_binding(&host_id, &host, port, &username).map_err(|e| e.to_string())?;
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
    Ok(!credentials::is_reserved_id(&host_id) && credentials::has_secret(&host_id))
}

#[tauri::command]
async fn credential_delete(host_id: String) -> CmdResult<()> {
    if credentials::is_reserved_id(&host_id) {
        return Err(format!("'{host_id}' is a reserved vault id, not a host"));
    }
    // Drop the binding even when the secret is already gone, so stale bindings
    // do not accumulate.
    let deleted = credentials::delete_secret(&host_id);
    utils::hosts::remove_binding(&host_id);
    match deleted {
        Ok(()) | Err(credentials::CredError::NotFound(_)) => {
            utils::audit::record(
                "credential.delete",
                format!("removed the saved password for host '{host_id}'"),
                serde_json::json!({ "hostId": host_id, "ok": true }),
            );
            Ok(())
        }
        Err(e) => Err(e.to_string()),
    }
}

/* --------------------------------------------------------------------- run */

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            app.manage(Registry::default());
            app.manage(Arc::new(local_shell::LocalShells::default()));
            app.manage(Arc::new(HostKeyPrompts::default()));
            app.manage(Arc::new(AuthPrompts::default()));
            app.manage(utils::nettools::NetTools::default());

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
            local_list,
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
            ai_chat,
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
            audit_list,
            audit_verify,
            audit_archive,
            local_shell_profiles,
            local_shell_start,
            credential_save,
            credential_status,
            credential_delete,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
