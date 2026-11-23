//! Edit a remote file in a local editor.
//!
//! "Edit" on a remote file downloads it into a private folder, opens it with
//! the OS default app (or the user's editor command), and watches the local
//! copy: each save is pushed back over the remote file — but only after the
//! remote file is checked against what was downloaded, so a change someone
//! else made meanwhile is never silently overwritten.
//!
//! The SFTP half lives in `ssh.rs` (`edit_fetch_with` / `edit_push_with` /
//! `edit_save_copy_with`) and goes through the same staged, hardened transfer
//! paths as a normal download and upload. This module is the local half:
//!
//! - **Folders.** `<data dir>/remote-edit/<session>/<edit id>/file/<name>`,
//!   every folder `0700` and the file `0600` on Unix, so other local users
//!   cannot read what was downloaded. The original file name is kept so the
//!   editor picks the right syntax mode; `meta.json` (remote path and content
//!   hash, never contents) and the upload snapshot sit OUTSIDE `file/`.
//! - **Baseline.** The remote file as downloaded or last uploaded
//!   (`RemoteBaseline`: its size, mtime and the SHA-256 of its content), plus
//!   the SHA-256 of the bytes last known to be safe on the server
//!   (`synced_hash`). A save is committed only if the remote content still
//!   hashes to the baseline when read back immediately before the commit,
//!   and the upload is adopted as the new baseline only if reading it back
//!   afterwards finds exactly the bytes sent (see `ssh::edit_push_with`).
//! - **Watcher.** A 1 s poll of the local file's size and mtime, debounced:
//!   a change fires only once the file has been stable for a whole poll, so
//!   editors that write in steps, or save atomically by renaming a new file
//!   over the old one, push once with the finished file. A save that leaves
//!   the bytes unchanged (a touch) pushes nothing.
//! - **Push.** The local file is snapshotted (read once, hashed, written to a
//!   private snapshot) and the snapshot uploaded, so the bytes hashed are the
//!   bytes sent even while the editor keeps writing.
//! - **Opening.** The OS default app is used only for known inert text and
//!   document types (`default_app_refusal`, an ALLOW-list); anything else
//!   needs the editor command, which gets the file as ONE argv entry, never
//!   through a shell.
//! - **Cleanup.** Stopping, closing the session or quitting deletes a copy
//!   only when it is known to be clean. A copy with changes the server does
//!   not have, or one whose state is unknown (missing — perhaps mid-save —
//!   after the watcher's grace period, or unreadable), is kept and reported
//!   (`Leftover`); the next launch lists any that are still there. Deletion
//!   only ever touches a verified tree: real folders and plain files under a
//!   real edit root, never a symlink or reparse point (`remove_edit_dir`).
//!   The launch sweep finishes before the first edit can be created.

use std::collections::HashSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Emitter, Manager};
use tokio::sync::watch;

use crate::ssh::{EditPushed, Registry};

/// The largest remote file opened for editing (and the largest local copy
/// pushed back).
pub const MAX_EDIT_BYTES: u64 = 20 * 1024 * 1024;
/// How often the local copy is checked for a save.
const POLL_INTERVAL: Duration = Duration::from_secs(1);
/// How long the local copy may be missing (an atomic save renames a new file
/// into place) before the row says it is gone.
const MISSING_GRACE: Duration = Duration::from_secs(5);
/// The longest editor command accepted.
const MAX_EDITOR_COMMAND: usize = 1024;

/// One edit changed (`EditInfo`).
pub const EDIT_EVENT: &str = "sftp://edit";
/// An edit ended (`EditClosed`).
pub const EDIT_CLOSED_EVENT: &str = "sftp://edit-closed";
/// The list of kept copies changed (`Vec<Leftover>`).
pub const LEFTOVERS_EVENT: &str = "sftp://edit-leftovers";

/* ------------------------------------------------------------- baselines */

/// The remote file as the server reports it: what a save is checked against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteStamp {
    pub size: u64,
    /// Seconds since the epoch (SFTP v3 has no finer mtime). `None` when the
    /// server does not report one.
    pub mtime: Option<u32>,
}

/// What a save is checked against: the remote file as it was downloaded or
/// last uploaded — its stamp (a cheap first check) and the SHA-256 of its
/// content (the check that decides, made at the commit boundary).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteBaseline {
    pub stamp: RemoteStamp,
    pub hash: String,
}

impl RemoteStamp {
    /// Whether the remote file changed since `self` was recorded. A missing
    /// mtime on one side and not the other counts as a change.
    pub fn differs(&self, now: &RemoteStamp) -> bool {
        self != now
    }
}

/// The local copy's size and mtime: what the watcher compares between polls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalStamp {
    len: u64,
    modified: Option<SystemTime>,
}

/// The local copy's stamp, or None when it is not there as a regular file
/// (mid atomic save, deleted, or replaced by something else — LSTAT, so a
/// symlink planted in its place is never followed).
pub fn local_stamp(path: &Path) -> Option<LocalStamp> {
    let m = std::fs::symlink_metadata(path).ok()?;
    m.is_file().then(|| LocalStamp { len: m.len(), modified: m.modified().ok() })
}

/// What one poll of the local copy means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tick {
    /// Nothing new.
    Idle,
    /// It changed since the last poll: wait for it to settle.
    Settling,
    /// It changed and has now been stable for a whole poll: push it.
    Fire,
    /// It is not there, for this long so far.
    Missing(Duration),
}

/// Debounces saves: a change fires once the file has stayed the same for one
/// full poll. An editor that truncates and then writes, writes in chunks, or
/// saves to a temp file and renames it over the original (the file vanishes
/// for a moment, then reappears with a new stamp) fires once, at the end.
#[derive(Debug)]
pub struct Debounce {
    last: Option<LocalStamp>,
    pending: bool,
    missing_since: Option<Instant>,
}

impl Debounce {
    pub fn new(initial: Option<LocalStamp>) -> Self {
        Self { last: initial, pending: false, missing_since: None }
    }

    pub fn observe(&mut self, seen: Option<LocalStamp>, now: Instant) -> Tick {
        let Some(stamp) = seen else {
            let since = *self.missing_since.get_or_insert(now);
            return Tick::Missing(now.saturating_duration_since(since));
        };
        // Back after being missing: whatever is there now is a new save, even
        // if its stamp happens to equal the old one.
        let returned = self.missing_since.take().is_some();
        if returned || self.last != Some(stamp) {
            self.last = Some(stamp);
            self.pending = true;
            return Tick::Settling;
        }
        if self.pending {
            self.pending = false;
            return Tick::Fire;
        }
        Tick::Idle
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// SHA-256 of a file, streamed.
pub fn hash_file(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/* ---------------------------------------------------- what may be opened */

/// The only types handed to the OS default app: inert text and document
/// formats whose default handler shows them rather than runs them. HTML is
/// deliberately NOT here: it opens in a browser, which runs its scripts
/// against a local file. Everything else — scripts, launchers, `.wsb`,
/// installers, and any extension not on this list — needs the editor
/// command, because a default handler that is not in this list may run,
/// mount, install or follow what it is given.
const INERT_EXTS: &[&str] = &[
    "txt", "log", "md", "conf", "cfg", "ini", "toml", "yaml", "yml", "json", "xml", "csv", "tsv",
    "env", "properties", "diff", "patch",
];

/// The name as the OS will dispatch on it: Win32 strips trailing dots and
/// spaces (`run.wsb .` IS `run.wsb` there), so they are stripped here on
/// every platform.
fn normalized_name(name: &str) -> &str {
    name.trim_end_matches(['.', ' '])
}

/// The extension the OS will dispatch on, lowercased, or None for a name
/// with no dot at all. A leading dot counts: Windows dispatches `.wsb` on
/// its `wsb` extension, and `.bashrc` has the extension `bashrc`.
fn dispatch_extension(name: &str) -> Option<String> {
    let (_, ext) = normalized_name(name).rsplit_once('.')?;
    (!ext.is_empty()).then(|| ext.to_ascii_lowercase())
}

/// Why `name` must not be handed to the default app, if it must not: it is
/// not a known inert type (`INERT_EXTS`, or no extension at all), or any
/// execute bit is set in one of `modes` (the remote file's, and on Unix the
/// local copy's — an executable extensionless file is a program). The
/// configured editor command opens anything and skips this check.
pub fn default_app_refusal(name: &str, modes: &[Option<u32>]) -> Option<String> {
    const FIX: &str = "To open it, set an editor command (for example code --wait) in Settings → \
                       Remote editing; Hawser then opens every file with that editor.";
    let shown = normalized_name(name);
    if let Some(ext) = dispatch_extension(name).filter(|e| !INERT_EXTS.contains(&e.as_str())) {
        return Some(format!(
            "{shown} is a .{ext} file, and only plain text and document types are opened with the \
             system's default app (its default app could run it instead of opening it). {FIX}"
        ));
    }
    if modes.iter().flatten().any(|m| m & 0o111 != 0) {
        return Some(format!(
            "{shown} is marked executable, so the system's default app could run it instead of \
             opening it. {FIX}"
        ));
    }
    None
}

/// The local name for a remote path: its last component, which must be one
/// plain file name here (no separators, `..`, NUL, and on Windows no `:` or
/// device name) — a server-chosen name must not steer the write.
pub fn remote_file_name(remote: &str) -> Result<String, String> {
    let name = remote.rsplit('/').next().unwrap_or_default();
    if !crate::ssh::safe_local_component(name) || name.len() > 255 {
        return Err(format!("{remote} has a name that cannot be used as a local file name"));
    }
    Ok(name.to_string())
}

/* -------------------------------------------------------- editor command */

/// A validated editor command: the program (resolved to an absolute path) and
/// its own arguments. The file is appended as one more argument at launch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditorCommand {
    pub program: PathBuf,
    pub args: Vec<String>,
}

/// Split an editor command into words: whitespace separates, and "double" or
/// 'single' quotes group (`"C:\Program Files\Notepad++\notepad++.exe" -multiInst`).
/// There are no escapes — a backslash is an ordinary character, as Windows
/// paths need — and no other shell syntax: nothing here is ever given to a
/// shell.
pub fn split_command(s: &str) -> Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut quote: Option<char> = None;
    for c in s.chars() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => cur.push(c),
            None if c == '"' || c == '\'' => {
                quote = Some(c);
                in_word = true;
            }
            None if c.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            None => {
                cur.push(c);
                in_word = true;
            }
        }
    }
    if quote.is_some() {
        return Err("a quote is not closed".into());
    }
    if in_word {
        words.push(cur);
    }
    Ok(words)
}

/// Common mistakes caught when the editor command is saved: a shell or
/// interpreter (`bash`, `python`) would read the file as code, and a launcher
/// (`xdg-open`, `start`) would hand it back to the default app.
///
/// NOT a security boundary. The editor command is the user's own, trusted
/// choice — anyone who can change it can already run what they like as this
/// user — and a name list cannot tell programs apart anyway (`python3.12`,
/// a renamed copy or an alias all pass). What IS enforced for every command:
/// the program is an absolute path or found on PATH, it is started directly
/// with the file as one separate argv entry, and never through a shell.
const REFUSED_PROGRAMS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ash", "ksh", "mksh", "csh", "tcsh", "fish", "busybox", "cmd",
    "command", "powershell", "pwsh", "env", "sudo", "doas", "su", "xargs", "nohup", "exec",
    "osascript", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "explorer", "start",
    "xdg-open", "gio", "gnome-open", "kde-open", "kde-open5", "kioclient", "kioclient5", "exo-open",
    "python", "python3", "perl", "ruby", "node", "deno", "bun", "php", "lua", "tclsh", "wish",
];

/// The lowercased program name, without a Windows executable extension.
fn program_stem(program: &str) -> String {
    let base = program.rsplit(['/', '\\']).next().unwrap_or(program).to_ascii_lowercase();
    for ext in [".exe", ".com", ".cmd", ".bat"] {
        if let Some(s) = base.strip_suffix(ext) {
            return s.to_string();
        }
    }
    base
}

/// Where a bare program name is looked up: PATH, then the usual install
/// folders a GUI app's minimal PATH misses (an app started from the Dock gets
/// only `/usr/bin:/bin:…`, without Homebrew's or `~/.local/bin`).
pub fn search_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    #[cfg(not(windows))]
    {
        for d in ["/usr/local/bin", "/opt/homebrew/bin", "/snap/bin", "/usr/bin", "/bin"] {
            dirs.push(PathBuf::from(d));
        }
        if let Some(home) = super::platform::home_dir() {
            dirs.push(home.join(".local/bin"));
            dirs.push(home.join("bin"));
        }
    }
    dirs.retain(|d| d.is_absolute());
    dirs
}

fn runnable(p: &Path) -> bool {
    let Ok(m) = std::fs::metadata(p) else { return false };
    if !m.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        m.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Find a bare program name in `dirs` (on Windows also with `.exe`, `.cmd`,
/// `.bat` when it has no extension of its own).
fn resolve_program(name: &str, dirs: &[PathBuf]) -> Option<PathBuf> {
    let candidates: Vec<String> = if cfg!(windows) && !name.contains('.') {
        ["", ".exe", ".cmd", ".bat"].iter().map(|e| format!("{name}{e}")).collect()
    } else {
        vec![name.to_string()]
    };
    dirs.iter()
        .flat_map(|d| candidates.iter().map(move |c| d.join(c)))
        .find(|p| runnable(p))
}

/// Validate an editor command. Empty means "the default app" (`Ok(None)`).
///
/// The program must be an absolute path to a program, or a bare name found in
/// `dirs`; a relative path (`./x`, `bin/x`) is refused, since it would depend
/// on the app's working directory. A few common mistakes are caught
/// (`REFUSED_PROGRAMS`, which is a convenience, not a security check); macOS
/// `open` only with `-a`/`-b`/`-e`/`-t`, which name the app to use rather than
/// the file's default one.
pub fn parse_editor(raw: &str, dirs: &[PathBuf]) -> Result<Option<EditorCommand>, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    if raw.len() > MAX_EDITOR_COMMAND {
        return Err(format!("it is longer than {MAX_EDITOR_COMMAND} characters"));
    }
    if raw.chars().any(char::is_control) {
        return Err("it contains a control character or line break".into());
    }
    let mut words = split_command(raw)?;
    if words.is_empty() || words[0].is_empty() {
        return Err("it names no program".into());
    }
    let program = words.remove(0);
    let stem = program_stem(&program);
    if REFUSED_PROGRAMS.contains(&stem.as_str()) {
        return Err(format!(
            "{program} is a shell, interpreter or launcher; name the editor itself (for example code --wait)"
        ));
    }
    if stem == "open" && !cfg!(windows) && !words.iter().any(|w| matches!(w.as_str(), "-a" | "-b" | "-e" | "-t")) {
        return Err("open without -a would use the file's default app; use open -a <Editor>, or the editor's own command".into());
    }
    let path = Path::new(&program);
    let resolved = if path.is_absolute() {
        if !runnable(path) {
            return Err(format!("{program} is not a program on this computer"));
        }
        path.to_path_buf()
    } else if program.contains(['/', '\\']) {
        return Err(format!("{program} is a relative path; use a full path or a program name on PATH"));
    } else {
        resolve_program(&program, dirs).ok_or_else(|| format!("{program} was not found on PATH"))?
    };
    Ok(Some(EditorCommand { program: resolved, args: words }))
}

/// The argv after the program for opening `file`: the command's own
/// arguments, then the file as ONE separate entry — whatever its name holds
/// (spaces, quotes, `;`, `$(…)`), it is never parsed by anything.
pub fn editor_argv(cmd: &EditorCommand, file: &Path) -> Vec<OsString> {
    cmd.args.iter().map(OsString::from).chain(std::iter::once(file.as_os_str().to_os_string())).collect()
}

/// Open `file`: with the editor command when one is set, else the default app.
fn launch(editor: Option<&EditorCommand>, file: &Path) -> std::io::Result<()> {
    match editor {
        Some(cmd) => {
            let mut c = std::process::Command::new(&cmd.program);
            c.args(editor_argv(cmd, file));
            super::platform::spawn_program(&mut c)
        }
        None => super::platform::open_file_default(file),
    }
}

const EDITOR_FILE: &str = "editor.json";

/// The saved editor command as typed ("" when none).
pub fn editor_raw() -> Result<String, String> {
    let v = super::hosts::load_named(EDITOR_FILE).map_err(|e| e.to_string())?;
    Ok(v.and_then(|v| v.get("command").and_then(|c| c.as_str()).map(str::to_string)).unwrap_or_default())
}

/// The saved editor command, validated again now (the program may have been
/// uninstalled since it was saved).
fn load_editor() -> Result<Option<EditorCommand>, String> {
    parse_editor(&editor_raw()?, &search_dirs())
        .map_err(|e| format!("The editor command in Settings can't be used: {e}."))
}

/// The editor setting as the Settings dialog shows it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EditorView {
    pub command: String,
    /// The program it runs, resolved to a full path (None: the default app).
    pub resolved: Option<String>,
}

/// Validate and save the editor command ("" returns to the default app).
pub fn editor_save(raw: &str) -> Result<EditorView, String> {
    let raw = raw.trim();
    let parsed = parse_editor(raw, &search_dirs()).map_err(|e| format!("That editor command can't be used: {e}."))?;
    super::hosts::save_named(EDITOR_FILE, &serde_json::json!({ "command": raw })).map_err(|e| e.to_string())?;
    Ok(EditorView { command: raw.to_string(), resolved: parsed.map(|c| c.program.to_string_lossy().to_string()) })
}

pub fn editor_view() -> Result<EditorView, String> {
    let command = editor_raw()?;
    let resolved = parse_editor(&command, &search_dirs())
        .ok()
        .flatten()
        .map(|c| c.program.to_string_lossy().to_string());
    Ok(EditorView { command, resolved })
}

/* ---------------------------------------------------------------- folders */

/// `<data dir>/remote-edit` (beside known_hosts: `%APPDATA%\hawser`,
/// `~/.config/hawser`), never a shared temp folder.
pub fn edit_root() -> Result<PathBuf, String> {
    let store = super::known_hosts::store_path().map_err(|e| e.to_string())?;
    let dir = store.parent().ok_or("no app data folder")?;
    Ok(dir.join("remote-edit"))
}

/// Create `dir` owner-only (`0700` on Unix), failing if it exists.
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(dir)?;
    }
    #[cfg(not(unix))]
    std::fs::create_dir(dir)?;
    super::platform::restrict_perms(dir, 0o700);
    Ok(())
}

/// Make sure `dir` is a real (not symlinked) owner-only folder.
fn ensure_private_dir(dir: &Path) -> std::io::Result<()> {
    match create_private_dir(dir) {
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        other => other?,
    }
    let m = std::fs::symlink_metadata(dir)?;
    if !super::platform::is_real_dir(&m) {
        return Err(std::io::Error::other(format!("{} is not a plain folder", dir.display())));
    }
    super::platform::restrict_perms(dir, 0o700);
    Ok(())
}

/// The per-session folder name: the session id when it is plain, else a hash
/// of it (an id is frontend-chosen and must not shape a path).
pub fn session_dir_name(session_id: &str) -> String {
    let plain = !session_id.is_empty()
        && session_id.len() <= 64
        && session_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if plain {
        session_id.to_string()
    } else {
        format!("s-{}", &sha256_hex(session_id.as_bytes())[..16])
    }
}

/// A fresh private folder for one edit, and the path its file goes to:
/// `<root>/<session>/<random>/file/<name>`.
pub fn prepare_edit_dir(root: &Path, session_id: &str, name: &str) -> std::io::Result<(PathBuf, PathBuf)> {
    ensure_private_dir(root)?;
    let session = root.join(session_dir_name(session_id));
    ensure_private_dir(&session)?;
    let dir = session.join(super::artifacts::random_hex(8));
    create_private_dir(&dir)?;
    create_private_dir(&dir.join("file"))?;
    let file = dir.join("file").join(name);
    Ok((dir, file))
}

/// Write `bytes` to a NEW owner-only file (`0600`), replacing a leftover one.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let _ = std::fs::remove_file(path);
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(path)?;
    f.write_all(bytes)?;
    Ok(())
}

/// What `meta.json` records: enough for the next launch to tell a clean copy
/// (delete it) from one with changes the server does not have (keep it, and
/// say where). Metadata only, never contents.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Meta {
    remote: String,
    name: String,
    synced_hash: String,
}

fn write_meta(dir: &Path, meta: &Meta) -> std::io::Result<()> {
    let text = serde_json::to_vec_pretty(meta).map_err(std::io::Error::other)?;
    let tmp = dir.join("meta.json.tmp");
    write_private(&tmp, &text)?;
    std::fs::rename(&tmp, dir.join("meta.json"))
}

/// `meta.json`, read only when it is a plain file (never through a link).
fn read_meta(dir: &Path) -> Option<Meta> {
    let path = dir.join("meta.json");
    if !super::platform::is_real_file(&std::fs::symlink_metadata(&path).ok()?) {
        return None;
    }
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

/// What the local copy holds compared with what the server is known to have.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalState {
    /// The same bytes: deleting it loses nothing.
    Clean,
    /// Changes the server does not have.
    Dirty,
    /// Missing (an editor may be mid-save, with the original moved aside),
    /// not a plain file, or unreadable: it may hold changes, so it is kept.
    Unknown,
}

fn local_state(local: &Path, synced_hash: &str) -> LocalState {
    match std::fs::symlink_metadata(local) {
        Ok(m) if super::platform::is_real_file(&m) => match hash_file(local) {
            Ok(h) if h == synced_hash => LocalState::Clean,
            Ok(_) => LocalState::Dirty,
            Err(_) => LocalState::Unknown,
        },
        _ => LocalState::Unknown,
    }
}

/// `local_state`, giving a missing or odd copy up to `grace` to come back
/// (the watcher's `MISSING_GRACE`): an editor that renames the original aside
/// before writing the new one leaves the path missing for a moment.
fn settled_local_state(local: &Path, synced_hash: &str, grace: Duration) -> LocalState {
    let deadline = Instant::now() + grace;
    loop {
        let st = local_state(local, synced_hash);
        if st != LocalState::Unknown || Instant::now() >= deadline {
            return st;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// The most entries one edit folder may hold for deletion to go ahead (the
/// file, `meta.json`, a snapshot, and an editor's own temp/backup files).
const MAX_TREE_ENTRIES: usize = 10_000;

/// Check that everything under `dir` is a real folder or a plain file — no
/// symlink, no Windows reparse point (junction, mount point), nothing else —
/// LSTAT only, never following anything.
fn verify_tree(dir: &Path) -> Result<(), String> {
    let mut stack = vec![(dir.to_path_buf(), 0usize)];
    let mut seen = 0usize;
    while let Some((d, depth)) = stack.pop() {
        let m = std::fs::symlink_metadata(&d).map_err(|e| format!("{}: {e}", d.display()))?;
        if !super::platform::is_real_dir(&m) {
            return Err(format!("{} is not a plain folder", d.display()));
        }
        for e in std::fs::read_dir(&d).map_err(|e| format!("{}: {e}", d.display()))? {
            let p = e.map_err(|e| format!("{}: {e}", d.display()))?.path();
            seen += 1;
            if seen > MAX_TREE_ENTRIES || depth > 16 {
                return Err(format!("{} holds more than expected", dir.display()));
            }
            let m = std::fs::symlink_metadata(&p).map_err(|e| format!("{}: {e}", p.display()))?;
            if super::platform::is_real_dir(&m) {
                stack.push((p, depth + 1));
            } else if !super::platform::is_real_file(&m) {
                return Err(format!("{} is a link or special file", p.display()));
            }
        }
    }
    Ok(())
}

/// `dir` is exactly `<root>/<session>/<edit>`, with plain names, and the
/// root, the session folder and `dir` are all real folders (LSTAT).
fn verify_edit_dir(root: &Path, dir: &Path) -> Result<(), String> {
    use std::path::Component;
    let session = dir.parent().ok_or("no session folder")?;
    if session.parent() != Some(root) {
        return Err(format!("{} is not an edit folder under {}", dir.display(), root.display()));
    }
    for p in [dir, session] {
        if !matches!(p.components().next_back(), Some(Component::Normal(_))) {
            return Err(format!("{} is not a plain folder name", p.display()));
        }
    }
    for p in [root, session, dir] {
        let m = std::fs::symlink_metadata(p).map_err(|e| format!("{}: {e}", p.display()))?;
        if !super::platform::is_real_dir(&m) {
            return Err(format!("{} is a link or not a folder", p.display()));
        }
    }
    Ok(())
}

/// Delete one edit's folder — only `<root>/<session>/<edit>`, only when the
/// whole chain and everything inside is verified (`verify_edit_dir`,
/// `verify_tree`), and never following a link. Anything else is refused and
/// left as it is. The session folder goes too once it is empty.
///
/// The delete itself is `std::fs::remove_dir_all`, which removes a link
/// rather than following it (openat/unlinkat on Unix, handles on Windows), so
/// even an entry swapped for a link after the check is not followed inside
/// `dir`. RESIDUAL: an ancestor (the root or session folder) swapped for a
/// link between the check and the delete — by a process running as this
/// same user — would redirect the path.
fn remove_edit_dir(root: &Path, dir: &Path) -> Result<(), String> {
    verify_edit_dir(root, dir)?;
    verify_tree(dir)?;
    std::fs::remove_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    if let Some(session) = dir.parent() {
        if std::fs::symlink_metadata(session).is_ok_and(|m| super::platform::is_real_dir(&m)) {
            let _ = std::fs::remove_dir(session); // only if now empty
        }
    }
    Ok(())
}

/// `remove_edit_dir`, logging a refusal (the folder is then left alone).
fn remove_edit_dir_logged(root: &Path, dir: &Path) -> bool {
    match remove_edit_dir(root, dir) {
        Ok(()) => true,
        Err(e) => {
            eprintln!("hawser: left an edit folder in place: {e}");
            false
        }
    }
}

/// A local copy kept because it has changes the server does not have.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Leftover {
    /// `<session folder>/<edit folder>`: how the frontend names it back.
    pub id: String,
    pub remote_path: String,
    pub local_path: String,
    pub name: String,
    #[serde(skip)]
    dir: PathBuf,
}

/// At launch: delete every edit folder whose copy is known to be clean (or
/// that never finished downloading: no `meta.json`, so it was never opened),
/// and return the rest — unsynced, missing or unreadable copies — which are
/// kept where they are and reported.
///
/// The root and every folder are checked with LSTAT before they are read or
/// deleted: a root, session or edit folder that is a symlink or reparse point
/// is refused (nothing is traversed through it or deleted), and so is an edit
/// folder holding a link. `is_current` names folders created by this run,
/// which are never touched (`startup_sweep` also runs before any can exist).
pub fn sweep(root: &Path, is_current: &dyn Fn(&Path) -> bool) -> Vec<Leftover> {
    let mut kept = Vec::new();
    match std::fs::symlink_metadata(root) {
        Ok(m) if super::platform::is_real_dir(&m) => {}
        Ok(_) => {
            eprintln!("hawser: {} is a link or not a folder; not sweeping it", root.display());
            return kept;
        }
        Err(_) => return kept,
    }
    let real_dir = |p: &Path| std::fs::symlink_metadata(p).is_ok_and(|m| super::platform::is_real_dir(&m));
    let Ok(sessions) = std::fs::read_dir(root) else { return kept };
    for s in sessions.flatten() {
        let sdir = s.path();
        if !real_dir(&sdir) {
            continue; // a link (or a stray file): never followed, never deleted
        }
        for e in std::fs::read_dir(&sdir).into_iter().flatten().flatten() {
            let dir = e.path();
            if !real_dir(&dir) || is_current(&dir) {
                continue;
            }
            if let Err(why) = verify_edit_dir(root, &dir).and_then(|()| verify_tree(&dir)) {
                eprintln!("hawser: left an edit folder in place: {why}");
                continue;
            }
            let id = format!("{}/{}", s.file_name().to_string_lossy(), e.file_name().to_string_lossy());
            let leftover = |remote: String, name: String, local: PathBuf| Leftover {
                id: id.clone(),
                remote_path: remote,
                local_path: local.to_string_lossy().to_string(),
                name,
                dir: dir.clone(),
            };
            let has_meta = std::fs::symlink_metadata(dir.join("meta.json")).is_ok();
            match read_meta(&dir) {
                // Never finished downloading, so never opened: nothing to lose.
                None if !has_meta => {
                    remove_edit_dir_logged(root, &dir);
                }
                // Unreadable metadata: what it holds is unknown, so keep it.
                None => kept.push(leftover("(unknown)".into(), id.clone(), dir.join("file"))),
                Some(m) if !crate::ssh::safe_local_component(&m.name) => {
                    kept.push(leftover(m.remote, id.clone(), dir.join("file")))
                }
                Some(m) => {
                    let local = dir.join("file").join(&m.name);
                    match local_state(&local, &m.synced_hash) {
                        LocalState::Clean => {
                            remove_edit_dir_logged(root, &dir);
                        }
                        LocalState::Dirty | LocalState::Unknown => kept.push(leftover(m.remote, m.name, local)),
                    }
                }
            }
        }
        let _ = std::fs::remove_dir(&sdir); // only if now empty
    }
    kept
}

/* ------------------------------------------------------------ live edits */

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EditStatus {
    /// The server has what is on disk here.
    Synced,
    /// A save is being checked and uploaded.
    Uploading,
    /// The remote file changed since it was downloaded: nothing was uploaded,
    /// and the user chooses what happens.
    Conflict,
    /// The last push or check failed (see `message`).
    Error,
}

/// One edit, as the frontend lists it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EditInfo {
    pub edit_id: String,
    pub session_id: String,
    pub remote_path: String,
    pub local_path: String,
    pub name: String,
    pub status: EditStatus,
    pub message: Option<String>,
    /// The local copy has (or may have) changes the server does not.
    pub dirty: bool,
    /// Size of the last version downloaded or uploaded.
    pub bytes: u64,
    /// When the server last matched the local copy (Unix seconds).
    pub last_sync: Option<u64>,
    /// Bumped on every conflict found, so the frontend can prompt again for a
    /// new one after "Keep editing" dismissed the last.
    pub conflict_seq: u64,
    /// "default" (the OS default app) or "command" (the editor command).
    pub opener: &'static str,
}

/// An edit ended. `kept_at`: its copy had unsynced changes and was kept there.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EditClosed {
    pub edit_id: String,
    pub kept_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StopOutcome {
    /// False when the copy has unsynced changes and the caller must choose.
    pub stopped: bool,
    pub dirty: bool,
    pub kept_at: Option<String>,
}

/// What to do with unsynced changes when an edit stops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopMode {
    /// Stop only if there is nothing to lose; otherwise report it.
    Ask,
    Discard,
    /// Keep the copy where it is (listed as a `Leftover`).
    Keep,
}

impl StopMode {
    pub fn parse(v: Option<&str>) -> Result<Self, String> {
        match v.unwrap_or("ask") {
            "ask" => Ok(Self::Ask),
            "discard" => Ok(Self::Discard),
            "keep" => Ok(Self::Keep),
            other => Err(format!("unknown stop mode: {other}")),
        }
    }
}

/// How a push is asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushMode {
    /// The watcher saw a save. Skipped when the bytes did not change.
    Auto,
    /// "Upload now": checked against the baseline like a save, even unchanged.
    Now,
    /// "Overwrite remote" after a conflict: no baseline check.
    Overwrite,
    /// "Save a copy as name.conflict": the original is left as it is.
    SaveCopy,
}

impl PushMode {
    pub fn parse(v: &str) -> Result<Self, String> {
        match v {
            "now" => Ok(Self::Now),
            "overwrite" => Ok(Self::Overwrite),
            "copy" => Ok(Self::SaveCopy),
            other => Err(format!("unknown upload mode: {other}")),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Auto => "save",
            Self::Now => "now",
            Self::Overwrite => "overwrite",
            Self::SaveCopy => "copy",
        }
    }
}

struct EditState {
    /// The remote file as downloaded or last uploaded (and read back).
    baseline: RemoteBaseline,
    /// The bytes last known to be safe on the server (after "Save a copy",
    /// under another name): what decides whether the local copy is unsynced.
    synced_hash: String,
    status: EditStatus,
    message: Option<String>,
    dirty: bool,
    bytes: u64,
    last_sync: Option<u64>,
    conflict_seq: u64,
    missing_reported: bool,
}

pub struct Edit {
    id: String,
    session_id: String,
    /// The endpoint the file came from: a push refuses a tab that is now
    /// connected somewhere else.
    endpoint: String,
    remote: String,
    name: String,
    dir: PathBuf,
    local: PathBuf,
    remote_mode: Option<u32>,
    opener: &'static str,
    state: Mutex<EditState>,
    stop: watch::Sender<bool>,
    /// One push at a time; stopping waits for one in flight.
    push_lock: tokio::sync::Mutex<()>,
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl Edit {
    fn info(&self) -> EditInfo {
        let s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        EditInfo {
            edit_id: self.id.clone(),
            session_id: self.session_id.clone(),
            remote_path: self.remote.clone(),
            local_path: self.local.to_string_lossy().to_string(),
            name: self.name.clone(),
            status: s.status,
            message: s.message.clone(),
            dirty: s.dirty,
            bytes: s.bytes,
            last_sync: s.last_sync,
            conflict_seq: s.conflict_seq,
            opener: self.opener,
        }
    }

    fn update(&self, f: impl FnOnce(&mut EditState)) -> EditInfo {
        {
            let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
            f(&mut s);
        }
        self.info()
    }

    fn synced_hash(&self) -> String {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).synced_hash.clone()
    }
}

/// Every live edit, plus the kept copies. Managed Tauri state.
pub struct RemoteEdits {
    edits: DashMap<String, Arc<Edit>>,
    leftovers: Mutex<Vec<Leftover>>,
    /// (session, remote path) being opened right now: a double-click opens once.
    opening: Mutex<HashSet<(String, String)>>,
    /// True once the launch sweep has finished: no edit folder is created
    /// before then, so the sweep can never delete one of this run's.
    swept: watch::Sender<bool>,
    /// Every edit folder this run created; the sweep never touches them.
    created: Mutex<HashSet<PathBuf>>,
}

impl Default for RemoteEdits {
    fn default() -> Self {
        Self {
            edits: DashMap::new(),
            leftovers: Mutex::new(Vec::new()),
            opening: Mutex::new(HashSet::new()),
            swept: watch::channel(false).0,
            created: Mutex::new(HashSet::new()),
        }
    }
}

/// Marks the launch sweep finished when dropped — also when it failed or
/// panicked, so a broken sweep cannot block editing forever.
struct SweptOnDrop<'a>(&'a watch::Sender<bool>);

impl Drop for SweptOnDrop<'_> {
    fn drop(&mut self) {
        self.0.send_replace(true);
    }
}

/// Releases an `opening` claim.
struct OpeningClaim<'a> {
    edits: &'a RemoteEdits,
    key: (String, String),
}

impl Drop for OpeningClaim<'_> {
    fn drop(&mut self) {
        self.edits.opening.lock().unwrap_or_else(|p| p.into_inner()).remove(&self.key);
    }
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T, String> + Send + 'static) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(|e| e.to_string())?
}

fn emit_edit(app: &AppHandle, info: &EditInfo) {
    let _ = app.emit(EDIT_EVENT, info.clone());
}

impl RemoteEdits {
    fn find(&self, session_id: &str, remote: &str) -> Option<Arc<Edit>> {
        self.edits
            .iter()
            .find(|e| e.session_id == session_id && e.remote == remote)
            .map(|e| Arc::clone(e.value()))
    }

    fn get(&self, edit_id: &str) -> Result<Arc<Edit>, String> {
        self.edits
            .get(edit_id)
            .map(|e| Arc::clone(e.value()))
            .ok_or_else(|| "that file is no longer being edited".to_string())
    }

    fn claim(&self, session_id: &str, remote: &str) -> Result<OpeningClaim<'_>, String> {
        let key = (session_id.to_string(), remote.to_string());
        if !self.opening.lock().unwrap_or_else(|p| p.into_inner()).insert(key.clone()) {
            return Err(format!("{remote} is already being opened"));
        }
        Ok(OpeningClaim { edits: self, key })
    }

    pub fn list(&self) -> Vec<EditInfo> {
        let mut v: Vec<EditInfo> = self.edits.iter().map(|e| e.info()).collect();
        v.sort_by(|a, b| a.name.cmp(&b.name).then(a.edit_id.cmp(&b.edit_id)));
        v
    }

    pub fn leftovers(&self) -> Vec<Leftover> {
        self.leftovers.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    fn add_leftover(&self, l: Leftover) {
        self.leftovers.lock().unwrap_or_else(|p| p.into_inner()).push(l);
    }

    fn take_leftover(&self, id: &str) -> Result<Leftover, String> {
        let mut v = self.leftovers.lock().unwrap_or_else(|p| p.into_inner());
        let i = v.iter().position(|l| l.id == id).ok_or("that kept copy is no longer listed")?;
        Ok(v.remove(i))
    }

    /// Reveal a live edit's copy in the file manager. By id: no path crosses IPC.
    pub fn reveal(&self, edit_id: &str) -> Result<(), String> {
        let e = self.get(edit_id)?;
        super::platform::reveal_file(&e.local).map_err(|e| e.to_string())
    }

    pub fn leftover_reveal(&self, id: &str) -> Result<(), String> {
        let v = self.leftovers.lock().unwrap_or_else(|p| p.into_inner());
        let l = v.iter().find(|l| l.id == id).ok_or("that kept copy is no longer listed")?;
        super::platform::reveal_file(Path::new(&l.local_path)).map_err(|e| e.to_string())
    }

    /// Delete a kept copy (the user chose Discard). A folder that fails the
    /// checks (`remove_edit_dir`) is left alone and stays listed.
    pub fn leftover_discard(&self, id: &str) -> Result<(), String> {
        let l = self.take_leftover(id)?;
        let root = edit_root()?;
        if let Err(e) = remove_edit_dir(&root, &l.dir) {
            self.add_leftover(l);
            return Err(format!("the kept copy was not deleted: {e}"));
        }
        Ok(())
    }

    /// Stop one edit's watcher and settle its folder: deleted only when its
    /// copy is known to be clean (or when `discard`), else kept and listed. A
    /// missing copy gets the watcher's grace period to come back, then counts
    /// as unknown and is kept. Returns where it was kept.
    fn finish(&self, edit: &Edit, discard: bool) -> Option<String> {
        let _ = edit.stop.send(true);
        self.edits.remove(&edit.id);
        let Ok(root) = edit_root() else { return Some(edit.local.to_string_lossy().to_string()) };
        let keep = !discard && settled_local_state(&edit.local, &edit.synced_hash(), MISSING_GRACE) != LocalState::Clean;
        if keep || !remove_edit_dir_logged(&root, &edit.dir) {
            let local = edit.local.to_string_lossy().to_string();
            let session = edit.dir.parent().and_then(|p| p.file_name()).map(|n| n.to_string_lossy().to_string());
            let leaf = edit.dir.file_name().map(|n| n.to_string_lossy().to_string());
            self.add_leftover(Leftover {
                id: format!("{}/{}", session.unwrap_or_default(), leaf.unwrap_or_default()),
                remote_path: edit.remote.clone(),
                local_path: local.clone(),
                name: edit.name.clone(),
                dir: edit.dir.clone(),
            });
            return Some(local);
        }
        None
    }

    /// At exit: stop every watcher, delete clean copies, keep the rest (the
    /// next launch lists them).
    pub fn shutdown(&self) {
        let all: Vec<Arc<Edit>> = self.edits.iter().map(|e| Arc::clone(e.value())).collect();
        for e in all {
            if let Some(at) = self.finish(&e, false) {
                eprintln!("hawser: kept unsynced edit of {} at {at}", e.remote);
            }
        }
    }
}

/// At launch, off the setup thread: settle what an earlier run left behind
/// and tell the frontend about kept copies.
///
/// Ordering: `open` waits for this sweep to finish (`RemoteEdits::swept`)
/// before it creates an edit folder, so the sweep only ever sees folders
/// left by earlier runs (and skips any in `created` regardless).
pub fn startup_sweep(app: AppHandle) {
    let edits = Arc::clone(&app.state::<Arc<RemoteEdits>>());
    std::thread::spawn(move || {
        let _done = SweptOnDrop(&edits.swept);
        let Ok(root) = edit_root() else { return };
        let is_current = |p: &Path| edits.created.lock().unwrap_or_else(|p| p.into_inner()).contains(p);
        let found = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| sweep(&root, &is_current))).unwrap_or_default();
        if found.is_empty() {
            return;
        }
        for l in found {
            edits.add_leftover(l);
        }
        let _ = app.emit(LEFTOVERS_EVENT, edits.leftovers());
    });
}

/// Open `remote` for editing on `session_id`: download, open, watch. Opening a
/// file already being edited on this session opens the same local copy again.
pub async fn open(app: &AppHandle, session_id: &str, remote: &str) -> Result<EditInfo, String> {
    let edits = Arc::clone(&app.state::<Arc<RemoteEdits>>());
    let editor = blocking(load_editor).await?;
    if let Some(e) = edits.find(session_id, remote) {
        if editor.is_none() {
            if let Some(why) = default_app_refusal(&e.name, &[e.remote_mode]) {
                return Err(why);
            }
        }
        let local = e.local.clone();
        blocking(move || launch(editor.as_ref(), &local).map_err(|e| format!("could not open the editor: {e}"))).await?;
        return Ok(e.info());
    }

    let name = remote_file_name(remote)?;
    // No edit folder before the launch sweep is done (see `startup_sweep`).
    let _ = edits.swept.subscribe().wait_for(|done| *done).await;
    let registry = app.state::<Registry>();
    let endpoint = registry.endpoint_of(session_id).map_err(|e| e.to_string())?;
    let _claim = edits.claim(session_id, remote)?;
    let probe = registry.edit_probe(session_id, remote).await.map_err(|e| e.to_string())?;
    if editor.is_none() {
        if let Some(why) = default_app_refusal(&name, &[probe.mode]) {
            return Err(why);
        }
    }

    let root = edit_root()?;
    let (sid, n) = (session_id.to_string(), name.clone());
    let r2 = root.clone();
    let (dir, local) = blocking(move || {
        prepare_edit_dir(&r2, &sid, &n).map_err(|e| format!("could not create the edit folder: {e}"))
    })
    .await?;
    edits.created.lock().unwrap_or_else(|p| p.into_inner()).insert(dir.clone());
    let local_s = local.to_string_lossy().to_string();
    let fetched = match registry.edit_fetch(session_id, remote, &local_s).await {
        Ok(v) => v,
        Err(e) => {
            remove_edit_dir_logged(&root, &dir);
            return Err(e.to_string());
        }
    };
    let (probe, bytes) = (fetched.probe, fetched.bytes);

    // Owner-only, and never executable here whatever the server's mode.
    let (l2, d2) = (local.clone(), dir.clone());
    let meta = Meta { remote: remote.to_string(), name: name.clone(), synced_hash: String::new() };
    let hash = fetched.baseline.hash.clone();
    let h2 = hash.clone();
    let settled = blocking(move || {
        super::platform::restrict_perms(&l2, 0o600);
        write_meta(&d2, &Meta { synced_hash: h2, ..meta }).map_err(|e| e.to_string())?;
        Ok(local_stamp(&l2))
    })
    .await;
    let stamp = match settled {
        Ok(v) => v,
        Err(e) => {
            remove_edit_dir_logged(&root, &dir);
            return Err(format!("could not prepare the local copy: {e}"));
        }
    };

    let opener = if editor.is_some() { "command" } else { "default" };
    let l3 = local.clone();
    if let Err(e) = blocking(move || launch(editor.as_ref(), &l3).map_err(|e| format!("could not open the editor: {e}"))).await {
        remove_edit_dir_logged(&root, &dir);
        return Err(e);
    }

    let id = format!("e-{}", super::artifacts::random_hex(8));
    let edit = Arc::new(Edit {
        id: id.clone(),
        session_id: session_id.to_string(),
        endpoint,
        remote: remote.to_string(),
        name,
        dir,
        local,
        remote_mode: probe.mode,
        opener,
        state: Mutex::new(EditState {
            baseline: fetched.baseline,
            synced_hash: hash,
            status: EditStatus::Synced,
            message: None,
            dirty: false,
            bytes,
            last_sync: Some(now_secs()),
            conflict_seq: 0,
            missing_reported: false,
        }),
        stop: watch::channel(false).0,
        push_lock: tokio::sync::Mutex::new(()),
    });
    edits.edits.insert(id, Arc::clone(&edit));
    spawn_watcher(app.clone(), Arc::clone(&edit), stamp);
    let info = edit.info();
    emit_edit(app, &info);
    Ok(info)
}

/// Push an edit now ("Upload now", or a conflict's "Overwrite remote" / "Save
/// a copy").
pub async fn upload(app: &AppHandle, edit_id: &str, mode: PushMode) -> Result<EditInfo, String> {
    let edit = app.state::<Arc<RemoteEdits>>().get(edit_id)?;
    Ok(push(app, &edit, mode).await)
}

/// Stop editing. With unsynced changes and `StopMode::Ask`, nothing stops and
/// the outcome says so; `Discard` deletes the copy, `Keep` keeps it.
pub async fn stop(app: &AppHandle, edit_id: &str, mode: StopMode) -> Result<StopOutcome, String> {
    let edits = Arc::clone(&app.state::<Arc<RemoteEdits>>());
    let edit = edits.get(edit_id)?;
    // Let a push in flight finish first: its result decides what is unsynced.
    let _g = edit.push_lock.lock().await;
    let (local, synced) = (edit.local.clone(), edit.synced_hash());
    // Missing (perhaps mid-save) after the grace period counts as unsynced.
    let dirty = blocking(move || Ok(settled_local_state(&local, &synced, MISSING_GRACE) != LocalState::Clean)).await?;
    if dirty && mode == StopMode::Ask {
        return Ok(StopOutcome { stopped: false, dirty: true, kept_at: None });
    }
    let (e2, ed2) = (Arc::clone(&edit), Arc::clone(&edits));
    let kept_at = blocking(move || Ok(ed2.finish(&e2, mode == StopMode::Discard))).await?;
    let _ = app.emit(EDIT_CLOSED_EVENT, EditClosed { edit_id: edit.id.clone(), kept_at: kept_at.clone() });
    if kept_at.is_some() {
        let _ = app.emit(LEFTOVERS_EVENT, edits.leftovers());
    }
    Ok(StopOutcome { stopped: true, dirty, kept_at })
}

/// A session closed: end its edits. Clean copies are deleted; ones with
/// unsynced changes are kept, and the frontend is told where.
pub async fn close_session(app: &AppHandle, session_id: &str) {
    let edits = Arc::clone(&app.state::<Arc<RemoteEdits>>());
    let mine: Vec<Arc<Edit>> = edits
        .edits
        .iter()
        .filter(|e| e.session_id == session_id)
        .map(|e| Arc::clone(e.value()))
        .collect();
    if mine.is_empty() {
        return;
    }
    let mut kept_any = false;
    for edit in mine {
        let _ = edit.stop.send(true);
        let _g = edit.push_lock.lock().await;
        let (e2, ed2) = (Arc::clone(&edit), Arc::clone(&edits));
        let kept_at = blocking(move || Ok(ed2.finish(&e2, false))).await.unwrap_or(None);
        kept_any |= kept_at.is_some();
        let _ = app.emit(EDIT_CLOSED_EVENT, EditClosed { edit_id: edit.id.clone(), kept_at });
    }
    if kept_any {
        let _ = app.emit(LEFTOVERS_EVENT, edits.leftovers());
    }
}

/// Read the local copy once: its hash, length and bytes, written to a private
/// snapshot that is what gets uploaded.
fn snapshot(local: &Path, snap: &Path) -> Result<(String, u64), String> {
    let m = std::fs::symlink_metadata(local).map_err(|e| format!("the local copy can't be read: {e}"))?;
    if !m.is_file() {
        return Err("the local copy is no longer a plain file".into());
    }
    if m.len() > MAX_EDIT_BYTES {
        return Err(format!(
            "the local copy is over {} MB; it was not uploaded",
            MAX_EDIT_BYTES / (1024 * 1024)
        ));
    }
    let bytes = std::fs::read(local).map_err(|e| format!("the local copy can't be read: {e}"))?;
    if bytes.len() as u64 > MAX_EDIT_BYTES {
        return Err(format!(
            "the local copy is over {} MB; it was not uploaded",
            MAX_EDIT_BYTES / (1024 * 1024)
        ));
    }
    write_private(snap, &bytes).map_err(|e| format!("could not stage the upload: {e}"))?;
    Ok((sha256_hex(&bytes), bytes.len() as u64))
}

fn audit_upload(edit: &Edit, mode: PushMode, outcome: serde_json::Value, summary: String) {
    let mut detail = serde_json::json!({ "remote": edit.remote, "sessionId": edit.session_id, "mode": mode.label() });
    if let (Some(d), Some(o)) = (detail.as_object_mut(), outcome.as_object()) {
        for (k, v) in o {
            d.insert(k.clone(), v.clone());
        }
    }
    super::audit::record("sftp.edit.upload", summary, detail);
}

/// Check and push the local copy (see the module comment). Always returns the
/// edit as it now is, having emitted it.
async fn push(app: &AppHandle, edit: &Arc<Edit>, mode: PushMode) -> EditInfo {
    let _g = edit.push_lock.lock().await;
    if *edit.stop.borrow() {
        return edit.info();
    }
    let fail = |text: String| {
        let info = edit.update(|s| {
            s.status = EditStatus::Error;
            s.message = Some(text.clone());
        });
        emit_edit(app, &info);
        info
    };

    let (local, snap) = (edit.local.clone(), edit.dir.join("upload.snap"));
    let s2 = snap.clone();
    let (hash, len) = match blocking(move || snapshot(&local, &s2)).await {
        Ok(v) => v,
        Err(e) => {
            audit_upload(edit, mode, serde_json::json!({ "ok": false, "error": e }), format!("edit upload of {} failed", edit.remote));
            return fail(e);
        }
    };
    let cleanup = |snap: PathBuf| async move {
        let _ = blocking(move || Ok(std::fs::remove_file(snap).ok())).await;
    };
    if mode == PushMode::Auto && hash == edit.synced_hash() {
        // Saved without a change (or changed back): nothing to send.
        cleanup(snap).await;
        let info = edit.update(|s| {
            s.dirty = false;
            if s.status == EditStatus::Error {
                s.status = EditStatus::Synced;
                s.message = None;
            }
        });
        emit_edit(app, &info);
        return info;
    }

    let registry = app.state::<Registry>();
    let live = match registry.endpoint_of(&edit.session_id) {
        Ok(ep) if ep == edit.endpoint => None,
        Ok(_) => Some("this tab is now connected to a different host; the file was not uploaded".to_string()),
        Err(_) => Some("the session is disconnected; reconnect the tab, then choose Upload now".to_string()),
    };
    if let Some(why) = live {
        cleanup(snap).await;
        audit_upload(edit, mode, serde_json::json!({ "ok": false, "error": why }), format!("edit upload of {} failed", edit.remote));
        edit.update(|s| s.dirty = true);
        return fail(why);
    }

    let baseline = edit.state.lock().unwrap_or_else(|p| p.into_inner()).baseline.clone();
    let info = edit.update(|s| {
        s.status = EditStatus::Uploading;
        s.message = None;
        s.dirty = true;
    });
    emit_edit(app, &info);

    let snap_s = snap.to_string_lossy().to_string();
    let result = match mode {
        PushMode::SaveCopy => registry
            .edit_save_copy(&edit.session_id, &snap_s, &edit.remote)
            .await
            .map(|(target, bytes)| Outcome::Copied { target, bytes }),
        PushMode::Overwrite => registry.edit_push(&edit.session_id, &snap_s, &edit.remote, None).await.map(Outcome::from),
        PushMode::Auto | PushMode::Now => registry
            .edit_push(&edit.session_id, &snap_s, &edit.remote, Some(&baseline))
            .await
            .map(Outcome::from),
    };
    cleanup(snap).await;

    let synced_meta = || {
        let (d, m) = (
            edit.dir.clone(),
            Meta { remote: edit.remote.clone(), name: edit.name.clone(), synced_hash: hash.clone() },
        );
        blocking(move || write_meta(&d, &m).map_err(|e| e.to_string()))
    };
    let info = match result {
        // Nothing was uploaded.
        Ok(Outcome::Conflict { gone, during_upload }) => {
            let what = match (during_upload, gone) {
                (true, _) => format!(
                    "{} was changed on the server while your save was being uploaded; the server may \
                     now hold the other version instead of yours. Check it, then upload again.",
                    edit.name
                ),
                (false, true) => format!(
                    "{} was deleted or moved on the server since you opened it. Your save was not uploaded.",
                    edit.name
                ),
                (false, false) => format!(
                    "{} was changed on the server since you opened it. Your save was not uploaded.",
                    edit.name
                ),
            };
            audit_upload(
                edit,
                mode,
                serde_json::json!({ "ok": false, "conflict": true, "bytes": 0 }),
                format!("edit upload of {} held back: changed on the server", edit.remote),
            );
            edit.update(|s| {
                s.status = EditStatus::Conflict;
                s.message = Some(what);
                s.dirty = true;
                s.conflict_seq += 1;
            })
        }
        Ok(Outcome::Uploaded { baseline, bytes, notes }) => {
            audit_upload(
                edit,
                mode,
                serde_json::json!({ "ok": true, "bytes": bytes }),
                format!("uploaded edited {} ({bytes} bytes)", edit.remote),
            );
            let _ = synced_meta().await;
            edit.update(|s| {
                s.baseline = baseline;
                s.synced_hash = hash.clone();
                s.status = EditStatus::Synced;
                s.message = (!notes.is_empty()).then(|| notes.join("; "));
                s.dirty = false;
                s.bytes = len;
                s.last_sync = Some(now_secs());
            })
        }
        Ok(Outcome::Copied { target, bytes }) => {
            audit_upload(
                edit,
                mode,
                serde_json::json!({ "ok": true, "bytes": bytes, "copy": target }),
                format!("saved edited {} as {target} ({bytes} bytes)", edit.remote),
            );
            // The local version is now safe on the server under the new name,
            // so it is not "unsynced" any more; the baseline stays the
            // original's, so the next save into it is checked again.
            let _ = synced_meta().await;
            edit.update(|s| {
                s.synced_hash = hash.clone();
                s.status = EditStatus::Synced;
                s.message = Some(format!("Your version was saved as {target}; {} was left as it is.", edit.remote));
                s.dirty = false;
            })
        }
        Err(e) => {
            let text = e.to_string();
            audit_upload(edit, mode, serde_json::json!({ "ok": false, "error": text }), format!("edit upload of {} failed", edit.remote));
            edit.update(|s| {
                s.status = EditStatus::Error;
                s.message = Some(text);
                s.dirty = true;
            })
        }
    };
    emit_edit(app, &info);
    info
}

/// How a push ended, as `push` reports it.
enum Outcome {
    Uploaded { baseline: RemoteBaseline, bytes: u64, notes: Vec<String> },
    /// The remote file changed (or is `gone`). Before the commit: nothing
    /// was uploaded. `during_upload`: it changed as the save was committed.
    Conflict { gone: bool, during_upload: bool },
    Copied { target: String, bytes: u64 },
}

impl From<EditPushed> for Outcome {
    fn from(p: EditPushed) -> Self {
        match p {
            EditPushed::Uploaded { baseline, bytes, notes } => Self::Uploaded { baseline, bytes, notes },
            EditPushed::Conflict { now, during_upload } => Self::Conflict { gone: now.is_none(), during_upload },
        }
    }
}

/// Poll the local copy and push each settled save (see `Debounce`).
fn spawn_watcher(app: AppHandle, edit: Arc<Edit>, initial: Option<LocalStamp>) {
    tauri::async_runtime::spawn(async move {
        let mut stop = edit.stop.subscribe();
        let mut deb = Debounce::new(initial);
        loop {
            tokio::select! {
                r = stop.changed() => if r.is_err() { break },
                _ = tokio::time::sleep(POLL_INTERVAL) => {}
            }
            if *stop.borrow() {
                break;
            }
            let p = edit.local.clone();
            let seen = tauri::async_runtime::spawn_blocking(move || local_stamp(&p)).await.ok().flatten();
            match deb.observe(seen, Instant::now()) {
                Tick::Idle => {}
                Tick::Settling => {
                    let was = edit.state.lock().unwrap_or_else(|p| p.into_inner()).dirty;
                    let info = edit.update(|s| {
                        s.dirty = true;
                        if s.missing_reported {
                            s.missing_reported = false;
                            if s.status == EditStatus::Error {
                                s.status = EditStatus::Synced;
                                s.message = None;
                            }
                        }
                    });
                    if !was {
                        emit_edit(&app, &info);
                    }
                }
                Tick::Fire => {
                    push(&app, &edit, PushMode::Auto).await;
                }
                Tick::Missing(gone) if gone >= MISSING_GRACE => {
                    let first = !std::mem::replace(
                        &mut edit.state.lock().unwrap_or_else(|p| p.into_inner()).missing_reported,
                        true,
                    );
                    if first {
                        let info = edit.update(|s| {
                            s.status = EditStatus::Error;
                            s.message = Some(format!(
                                "The local copy of {} was moved or deleted; saves are not uploaded until it is back.",
                                edit.name
                            ));
                        });
                        emit_edit(&app, &info);
                    }
                }
                Tick::Missing(_) => {}
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "hawser-edit-{tag}-{}-{}",
            std::process::id(),
            crate::utils::artifacts::random_hex(4)
        ));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::canonicalize(&d).unwrap()
    }

    #[test]
    fn remote_stamps_differ_on_size_or_mtime() {
        let base = RemoteStamp { size: 10, mtime: Some(100) };
        assert!(!base.differs(&RemoteStamp { size: 10, mtime: Some(100) }));
        assert!(base.differs(&RemoteStamp { size: 11, mtime: Some(100) }));
        assert!(base.differs(&RemoteStamp { size: 10, mtime: Some(101) }));
        assert!(base.differs(&RemoteStamp { size: 10, mtime: None }));
    }

    #[test]
    fn a_save_fires_once_after_it_settles() {
        let t0 = Instant::now();
        let s = |len, secs| Some(LocalStamp { len, modified: Some(UNIX_EPOCH + Duration::from_secs(secs)) });
        let mut d = Debounce::new(s(5, 1));
        assert_eq!(d.observe(s(5, 1), t0), Tick::Idle);
        // A save in two steps (truncate, then write) across two polls.
        assert_eq!(d.observe(s(0, 2), t0), Tick::Settling);
        assert_eq!(d.observe(s(9, 2), t0), Tick::Settling);
        // Stable for a whole poll: push, once.
        assert_eq!(d.observe(s(9, 2), t0), Tick::Fire);
        assert_eq!(d.observe(s(9, 2), t0), Tick::Idle);
    }

    #[test]
    fn an_atomic_rename_save_fires_once_it_is_back() {
        let t0 = Instant::now();
        let s = |len| Some(LocalStamp { len, modified: Some(UNIX_EPOCH + Duration::from_secs(7)) });
        let mut d = Debounce::new(s(5));
        assert_eq!(d.observe(None, t0), Tick::Missing(Duration::ZERO));
        assert_eq!(d.observe(None, t0 + Duration::from_secs(1)), Tick::Missing(Duration::from_secs(1)));
        // Back with the same stamp (same size, same-second mtime): still a save.
        assert_eq!(d.observe(s(5), t0 + Duration::from_secs(2)), Tick::Settling);
        assert_eq!(d.observe(s(5), t0 + Duration::from_secs(3)), Tick::Fire);
    }

    #[cfg(unix)]
    #[test]
    fn edit_folders_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let root = scratch("perms").join("remote-edit");
        let (dir, file) = prepare_edit_dir(&root, "tab-1", "nginx.conf").unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&root), 0o700);
        assert_eq!(mode(dir.parent().unwrap()), 0o700, "session folder");
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(file.parent().unwrap()), 0o700);
        // The original name is kept, so the editor picks the syntax mode.
        assert_eq!(file.file_name().unwrap(), "nginx.conf");
        write_private(&file, b"x").unwrap();
        assert_eq!(mode(&file), 0o600);
        write_meta(&dir, &Meta { remote: "/etc/nginx.conf".into(), name: "nginx.conf".into(), synced_hash: "h".into() }).unwrap();
        assert_eq!(mode(&dir.join("meta.json")), 0o600);
        // A second edit of the same name gets its own folder.
        let (dir2, _) = prepare_edit_dir(&root, "tab-1", "nginx.conf").unwrap();
        assert_ne!(dir, dir2);
        let _ = std::fs::remove_dir_all(root.parent().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_edit_root_is_refused() {
        let base = scratch("link");
        let elsewhere = base.join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, base.join("remote-edit")).unwrap();
        assert!(prepare_edit_dir(&base.join("remote-edit"), "t", "a.txt").is_err());
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn session_folder_names_never_carry_path_syntax() {
        assert_eq!(session_dir_name("tab-1_a"), "tab-1_a");
        for bad in ["../x", "a/b", "a\\b", "", "C:", &"x".repeat(80)] {
            let n = session_dir_name(bad);
            assert!(n.starts_with("s-") && n.len() == 18, "{bad:?} -> {n}");
        }
    }

    #[test]
    fn only_inert_types_go_to_the_default_app() {
        let ok = |n: &str| default_app_refusal(n, &[Some(0o100644)]).is_none();
        for name in [
            "nginx.conf", "notes.TXT", "app.log", "README.md", "x.yaml", "x.yml", "Cargo.toml", "a.ini",
            "a.cfg", "data.json", "pom.xml", "t.csv", "t.tsv", "prod.env", "app.properties", "fix.diff",
            "fix.patch", "README", "Makefile", "notes.txt.", "notes.txt . ", "a.",
        ] {
            assert!(ok(name), "{name} should open with the default app");
        }
        for name in [
            // The audit's case: Windows Sandbox config runs a logon command.
            "box.wsb", "box.WSB", "box.wsb.", "box.wsb . ", "box.wsb  ",
            // Scripts, launchers and installers.
            "deploy.sh", "a.py", "script.ps1", "a.vbs", "Evil.app", "run.command", "x.EXE", "setup.bat",
            "a.cmd", "x.desktop", "tool.jar", "notes.txt.exe", "img.dmg", "link.lnk", "x.AppImage",
            "app.js", "page.html", "page.htm", "a.svg",
            // Unknown types are not assumed safe.
            "a.zzz", "archive.tar.gz", "a.sh.txt.bin",
        ] {
            assert!(!ok(name), "{name} must need the editor command");
        }
        // Any execute bit, on the server or here: an extensionless program.
        assert!(default_app_refusal("backup", &[Some(0o100755)]).is_some());
        assert!(default_app_refusal("backup", &[Some(0o100644), Some(0o100700)]).is_some());
        assert!(default_app_refusal("backup", &[Some(0o100640), None]).is_none());
        assert!(default_app_refusal("a.txt", &[Some(0o100755)]).is_some());
        // The message says how to fix it.
        let why = default_app_refusal("box.wsb", &[None]).unwrap();
        assert!(why.contains("editor command") && why.contains("Settings"), "{why}");
    }

    /// Dotfiles dispatch on their suffix (Windows reads `.wsb` as the `wsb`
    /// extension), so a bare dot plus a launcher suffix is never "no
    /// extension"; a dotfile with an inert suffix is fine.
    #[test]
    fn dotfiles_and_a_bare_dot_plus_suffix_are_classified_by_that_suffix() {
        assert_eq!(dispatch_extension(".wsb").as_deref(), Some("wsb"));
        assert_eq!(dispatch_extension(".bashrc").as_deref(), Some("bashrc"));
        assert_eq!(dispatch_extension(".env").as_deref(), Some("env"));
        assert_eq!(dispatch_extension(".wsb. ").as_deref(), Some("wsb"));
        assert_eq!(dispatch_extension("README"), None);
        assert_eq!(dispatch_extension("a."), None);
        for name in [".wsb", ".WSB", ".sh", ".py", ".exe", ".desktop", ".command", ".wsb.", ".bashrc", ".profile"] {
            assert!(default_app_refusal(name, &[Some(0o100644)]).is_some(), "{name}");
        }
        for name in [".env", ".txt", ".conf", ".json"] {
            assert!(default_app_refusal(name, &[Some(0o100644)]).is_none(), "{name}");
        }
    }

    #[test]
    fn remote_names_must_be_one_plain_local_name() {
        assert_eq!(remote_file_name("/etc/nginx/nginx.conf").unwrap(), "nginx.conf");
        assert_eq!(remote_file_name("relative.txt").unwrap(), "relative.txt");
        for bad in ["/etc/", "/", "/x/..", "/x/.", ""] {
            assert!(remote_file_name(bad).is_err(), "{bad:?}");
        }
        assert!(remote_file_name("/x/a\\b").is_err());
    }

    #[test]
    fn editor_commands_split_on_spaces_and_quotes_only() {
        assert_eq!(split_command("code --wait").unwrap(), ["code", "--wait"]);
        assert_eq!(
            split_command(r#""C:\Program Files\Notepad++\notepad++.exe" -multiInst"#).unwrap(),
            [r"C:\Program Files\Notepad++\notepad++.exe", "-multiInst"]
        );
        assert_eq!(split_command("subl  -n   'a b'").unwrap(), ["subl", "-n", "a b"]);
        assert_eq!(split_command(r#"x "" y"#).unwrap(), ["x", "", "y"]);
        // No shell syntax: these are plain characters.
        assert_eq!(split_command("vim;rm $(x) | y").unwrap(), ["vim;rm", "$(x)", "|", "y"]);
        assert!(split_command("code \"--wait").is_err());
    }

    #[cfg(unix)]
    fn fake_program(dir: &Path, name: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join(name);
        std::fs::write(&p, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    #[cfg(unix)]
    #[test]
    fn editor_commands_are_validated_and_resolved() {
        let bin = scratch("bin");
        let code = fake_program(&bin, "code");
        fake_program(&bin, "bash");
        let dirs = vec![bin.clone()];
        assert_eq!(parse_editor("  ", &dirs).unwrap(), None, "empty is the default app");
        assert_eq!(
            parse_editor("code --wait", &dirs).unwrap(),
            Some(EditorCommand { program: code.clone(), args: vec!["--wait".into()] })
        );
        assert_eq!(parse_editor(&format!("{} -n", code.display()), &[]).unwrap().unwrap().program, code);
        for (cmd, why) in [
            ("nosuch --wait", "not found"),
            ("bash -c 'vim'", "shell"),
            ("/bin/sh", "shell"),
            ("env vim", "shell"),
            ("xdg-open", "launcher"),
            ("open", "-a"),
            ("./code", "relative"),
            ("bin/code", "relative"),
            ("code\n--wait", "control"),
            ("\"code", "quote"),
        ] {
            let e = parse_editor(cmd, &dirs).unwrap_err();
            assert!(e.contains(why), "{cmd:?}: {e}");
        }
        // A file that is not executable is not a program.
        let plain = bin.join("plain");
        std::fs::write(&plain, "x").unwrap();
        assert!(parse_editor(&plain.to_string_lossy(), &[]).is_err());
        let _ = std::fs::remove_dir_all(bin);
    }

    #[test]
    fn the_file_is_one_separate_argument_after_the_editors_own() {
        let cmd = EditorCommand { program: PathBuf::from("/usr/bin/editor"), args: vec!["--wait".into(), "-n".into()] };
        let file = Path::new("/data/a b; rm -rf ~ $(id) \"q\".conf");
        let argv = editor_argv(&cmd, file);
        assert_eq!(argv.len(), 3);
        assert_eq!(argv[0], "--wait");
        assert_eq!(argv[1], "-n");
        assert_eq!(argv[2], file.as_os_str());
    }

    /// End to end: the editor really receives the path as one argv entry, with
    /// nothing in the name interpreted.
    #[cfg(unix)]
    #[test]
    fn launching_the_editor_passes_the_path_verbatim() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("launch");
        let out = dir.join("argv.out");
        let prog = dir.join("rec-editor");
        std::fs::write(&prog, format!("#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done > '{}'\n", out.display())).unwrap();
        std::fs::set_permissions(&prog, std::fs::Permissions::from_mode(0o755)).unwrap();
        let cmd = parse_editor(&format!("'{}' --wait", prog.display()), &[]).unwrap().unwrap();
        let file = dir.join("we$(touch pwned)ird; name`id`.conf");
        std::fs::write(&file, "x").unwrap();
        launch(Some(&cmd), &file).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let got = loop {
            if let Ok(s) = std::fs::read_to_string(&out) {
                if s.lines().count() == 2 {
                    break s;
                }
            }
            assert!(Instant::now() < deadline, "the editor never ran");
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(got, format!("--wait\n{}\n", file.display()));
        assert!(!dir.join("pwned").exists(), "the file name was run as shell syntax");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_launch_sweep_keeps_only_unsynced_copies() {
        let root = scratch("sweep").join("remote-edit");
        let mk = |body: &[u8], synced: &[u8]| {
            let (dir, file) = prepare_edit_dir(&root, "tab", "a.conf").unwrap();
            write_private(&file, body).unwrap();
            write_meta(&dir, &Meta { remote: "/etc/a.conf".into(), name: "a.conf".into(), synced_hash: sha256_hex(synced) }).unwrap();
            dir
        };
        let clean = mk(b"same", b"same");
        let dirty = mk(b"edited", b"original");
        // A download that never finished: no meta.
        let (half, _) = prepare_edit_dir(&root, "tab2", "b.conf").unwrap();
        // The local copy is missing (an editor mid-save): unknown, so kept.
        let missing = mk(b"x", b"x");
        std::fs::remove_file(missing.join("file").join("a.conf")).unwrap();
        // Created by this run: never touched, whatever its state.
        let (current, _) = prepare_edit_dir(&root, "tab3", "c.conf").unwrap();
        let cur = current.clone();
        let kept = sweep(&root, &|p: &Path| p == cur);
        assert_eq!(kept.len(), 2, "{kept:?}");
        assert!(kept.iter().all(|k| k.remote_path == "/etc/a.conf" && k.local_path.ends_with("a.conf")));
        assert!(dirty.exists());
        assert!(missing.exists(), "a missing copy is unknown, never deleted");
        assert!(current.exists(), "this run's folder is never swept");
        assert!(!clean.exists());
        assert!(!half.exists());
        assert!(!half.parent().unwrap().exists(), "an emptied session folder goes too");
        let _ = std::fs::remove_dir_all(root.parent().unwrap());
    }

    /// A planted link must never steer the sweep outside the edit root: a
    /// symlinked root is not traversed, a symlinked session or edit folder is
    /// skipped, and an edit folder holding a link is left whole.
    #[cfg(unix)]
    #[test]
    fn the_sweep_refuses_links_and_touches_nothing_outside_the_root() {
        use std::os::unix::fs::symlink;
        let none = |_: &Path| false;
        let base = scratch("sweeplink");
        // Something outside that looks exactly like an edit tree (no meta:
        // a sweep that followed the link would delete it).
        let outside = base.join("project");
        std::fs::create_dir_all(outside.join("src").join("lib")).unwrap();
        std::fs::write(outside.join("src").join("lib").join("main.rs"), b"fn main() {}").unwrap();

        // 1. The root itself is a symlink.
        let root = base.join("remote-edit");
        symlink(&outside, &root).unwrap();
        assert!(sweep(&root, &none).is_empty());
        assert!(outside.join("src/lib/main.rs").exists(), "a symlinked root is not traversed");
        std::fs::remove_file(&root).unwrap();

        // 2. A real root whose session folder, edit folder, or content links out.
        std::fs::create_dir(&root).unwrap();
        symlink(&outside, root.join("sess-link")).unwrap();
        std::fs::create_dir(root.join("sess")).unwrap();
        symlink(outside.join("src"), root.join("sess").join("edit-link")).unwrap();
        let (holder, file) = prepare_edit_dir(&root, "sess2", "a.conf").unwrap();
        write_private(&file, b"same").unwrap();
        write_meta(&holder, &Meta { remote: "/a.conf".into(), name: "a.conf".into(), synced_hash: sha256_hex(b"same") }).unwrap();
        symlink(&outside, holder.join("file").join("planted")).unwrap();

        let kept = sweep(&root, &none);
        assert!(kept.is_empty(), "{kept:?}");
        assert!(outside.join("src/lib/main.rs").exists(), "nothing outside the root was touched");
        assert!(root.join("sess-link").symlink_metadata().is_ok(), "the session link is left as it is");
        assert!(root.join("sess/edit-link").symlink_metadata().is_ok(), "the edit link is left as it is");
        assert!(holder.join("file/a.conf").exists(), "a folder holding a link is not deleted");

        // Direct deletion refuses the same things.
        assert!(remove_edit_dir(&root, &holder).is_err());
        assert!(remove_edit_dir(&root, &root.join("sess").join("edit-link")).is_err());
        assert!(remove_edit_dir(&root, &outside.join("src")).is_err(), "not under the root");
        assert!(remove_edit_dir(&root, &root.join("sess")).is_err(), "not an edit folder");
        assert!(outside.join("src/lib/main.rs").exists());
        // Once the planted link is gone, the clean copy is swept as usual.
        std::fs::remove_file(holder.join("file").join("planted")).unwrap();
        assert!(sweep(&root, &none).is_empty());
        assert!(!holder.exists());
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn a_snapshot_is_what_gets_hashed_and_capped() {
        let dir = scratch("snap");
        let local = dir.join("f.txt");
        std::fs::write(&local, b"hello").unwrap();
        let snap = dir.join("upload.snap");
        let (hash, len) = snapshot(&local, &snap).unwrap();
        assert_eq!((hash.as_str(), len), (sha256_hex(b"hello").as_str(), 5));
        assert_eq!(std::fs::read(&snap).unwrap(), b"hello");
        assert_eq!(hash_file(&local).unwrap(), hash);
        let big = std::fs::File::create(&local).unwrap();
        big.set_len(MAX_EDIT_BYTES + 1).unwrap();
        assert!(snapshot(&local, &snap).unwrap_err().contains("20 MB"));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// `open` waits on `swept` before creating an edit folder; it opens only
    /// once the launch sweep is done — also when the sweep failed or panicked.
    #[tokio::test]
    async fn no_edit_starts_before_the_launch_sweep_finishes() {
        for panics in [false, true] {
            let edits = Arc::new(RemoteEdits::default());
            let mut rx = edits.swept.subscribe();
            assert!(!*rx.borrow(), "not swept yet");
            let e2 = Arc::clone(&edits);
            let sweeper = std::thread::spawn(move || {
                let _done = SweptOnDrop(&e2.swept);
                std::thread::sleep(Duration::from_millis(200));
                if panics {
                    panic!("sweep failed");
                }
            });
            let t0 = Instant::now();
            tokio::time::timeout(Duration::from_secs(10), rx.wait_for(|d| *d)).await.unwrap().unwrap();
            assert!(t0.elapsed() >= Duration::from_millis(150), "waited for the sweep");
            assert_eq!(sweeper.join().is_err(), panics);
        }
    }

    #[test]
    fn unsynced_means_different_bytes_and_a_missing_copy_is_unknown() {
        let dir = scratch("dirty");
        let f = dir.join("x");
        std::fs::write(&f, b"abc").unwrap();
        assert_eq!(local_state(&f, &sha256_hex(b"abc")), LocalState::Clean);
        assert_eq!(local_state(&f, &sha256_hex(b"abd")), LocalState::Dirty);
        assert_eq!(local_state(&dir.join("gone"), "whatever"), LocalState::Unknown);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Cleanup gives a copy that is missing mid-save the grace period: one
    /// that comes back in time is judged on its bytes, one that does not
    /// stays unknown (kept).
    #[test]
    fn cleanup_waits_out_an_editors_rename_save() {
        let dir = scratch("grace");
        let f = dir.join("x.conf");
        let hash = sha256_hex(b"v1");
        let f2 = f.clone();
        let saver = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(400));
            std::fs::write(&f2, b"v2").unwrap();
        });
        assert_eq!(settled_local_state(&f, &hash, Duration::from_secs(5)), LocalState::Dirty);
        saver.join().unwrap();
        std::fs::remove_file(&f).unwrap();
        let t0 = Instant::now();
        assert_eq!(settled_local_state(&f, &hash, Duration::from_millis(500)), LocalState::Unknown);
        assert!(t0.elapsed() >= Duration::from_millis(500), "the grace period is waited out");
        let _ = std::fs::remove_dir_all(dir);
    }
}
