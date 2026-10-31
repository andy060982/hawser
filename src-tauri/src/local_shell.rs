//! Local terminals: PowerShell, cmd, WSL, Git Bash on Windows; the login shell
//! (zsh, bash, fish…) on macOS and Linux.
//!
//! A local shell runs in a real pseudo-terminal — ConPTY on Windows, openpty on
//! Unix — via `portable-pty`, so full-screen programs, colours, and resizing
//! behave as they do in Windows Terminal or iTerm.
//!
//! To the frontend a local shell is just another session: output streams on the
//! same `ssh://{id}` topic, lifecycle on `ssh://status`, and `ssh_write` /
//! `ssh_resize` / `ssh_disconnect` route here for ids this registry owns. So
//! tabs, split panes, find, copy-on-select, transcripts, and session search all
//! work unchanged.
//!
//! # What may be launched
//!
//! The webview names a *profile id*, never a program path: the backend
//! discovers the shells itself ([`profiles`]) and starts only those. A local
//! terminal still runs arbitrary commands by design — it is a shell — but the
//! IPC surface does not grow a "run this executable with these arguments"
//! primitive.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use std::sync::{Arc, Mutex};

use dashmap::DashMap;
use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Runtime};

use crate::ssh::{decode_utf8_stream, SessionStatusEvent};
use crate::utils::session_log::SessionLog;

/// A shell the user can open. Discovered on this machine, not configured.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShellProfile {
    /// Stable id the UI stores and sends back ("pwsh", "cmd", "login", …).
    pub id: String,
    /// Menu label, e.g. "PowerShell 7" or "Login shell (zsh)".
    pub label: String,
    /// Shown as a hint in the UI; never accepted back from it.
    pub program: PathBuf,
    #[serde(skip)]
    args: Vec<String>,
}

fn profile(id: &str, label: impl Into<String>, program: PathBuf, args: &[&str]) -> ShellProfile {
    ShellProfile {
        id: id.to_string(),
        label: label.into(),
        program,
        args: args.iter().map(|a| a.to_string()).collect(),
    }
}

/// First `name` found on PATH.
#[cfg(windows)]
fn on_path(name: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(name))
        .find(|p| p.is_file())
}

/// Shells available on this machine, best default first.
#[cfg(windows)]
pub fn profiles() -> Vec<ShellProfile> {
    let root = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    let sys32 = root.join("System32");
    let program_files = std::env::var_os("ProgramFiles")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"));

    let mut out = Vec::new();
    let pwsh = on_path("pwsh.exe")
        .or_else(|| Some(program_files.join(r"PowerShell\7\pwsh.exe")).filter(|p| p.is_file()));
    if let Some(p) = pwsh {
        out.push(profile("pwsh", "PowerShell 7", p, &["-NoLogo"]));
    }
    let winps = sys32.join(r"WindowsPowerShell\v1.0\powershell.exe");
    if winps.is_file() {
        out.push(profile("powershell", "Windows PowerShell", winps, &["-NoLogo"]));
    }
    let cmd = std::env::var_os("ComSpec")
        .map(PathBuf::from)
        .filter(|p| p.is_file())
        .unwrap_or_else(|| sys32.join("cmd.exe"));
    out.push(profile("cmd", "Command Prompt", cmd, &[]));
    let wsl = sys32.join("wsl.exe");
    if wsl.is_file() {
        // "~" starts in the Linux home rather than the Windows working dir.
        out.push(profile("wsl", "WSL", wsl, &["~"]));
    }
    let git_bash = program_files.join(r"Git\bin\bash.exe");
    if git_bash.is_file() {
        out.push(profile("gitbash", "Git Bash", git_bash, &["--login", "-i"]));
    }
    out
}

/// Shells available on this machine, best default first: the user's login
/// shell, then any other common shell listed in /etc/shells.
#[cfg(not(windows))]
pub fn profiles() -> Vec<ShellProfile> {
    let fallback = if cfg!(target_os = "macos") { "/bin/zsh" } else { "/bin/bash" };
    let login = std::env::var_os("SHELL")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute() && p.is_file())
        .unwrap_or_else(|| PathBuf::from(fallback));
    let name = |p: &Path| p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();

    // `-l`: a login shell, so a GUI-launched app still gets the user's PATH and
    // profile (macOS apps started from Finder inherit almost no environment).
    let mut out = vec![profile("login", format!("Login shell ({})", name(&login)), login.clone(), &["-l"])];
    let listed = std::fs::read_to_string("/etc/shells").unwrap_or_default();
    for want in ["zsh", "bash", "fish"] {
        let found = listed
            .lines()
            .map(str::trim)
            .filter(|l| l.starts_with('/'))
            .map(PathBuf::from)
            .find(|p| name(p) == want && p.is_file());
        if let Some(p) = found {
            if name(&p) != name(&login) {
                out.push(profile(want, want, p, &["-l"]));
            }
        }
    }
    out
}

/// One running local shell.
struct LocalShell {
    /// Replaced by a sink once the session is finished, closing our copy of
    /// the PTY so a lingering background job sees the terminal go away.
    writer: Mutex<Box<dyn Write + Send>>,
    /// None once the shell has exited: dropping the master closes the PTY.
    master: Mutex<Option<Box<dyn MasterPty + Send>>>,
    /// The shell process; None once reaped. Reaping (the waiter) and killing
    /// (`close`) both happen under this lock, so a kill can never reach a pid
    /// that was already reaped and possibly reused.
    child: Mutex<Option<Box<dyn Child + Send + Sync>>>,
    /// Why the shell ended, recorded by whoever reaped it (the waiter, or a
    /// kill that collected the exit) under the child lock.
    exit_reason: Mutex<Option<String>>,
    /// Publication gate: true once the session has been reported finished.
    /// Output is emitted while holding it and the finish happens under it, so
    /// nothing from this shell is published after its "disconnected" status,
    /// and its id is released only after that status went out.
    gate: Mutex<bool>,
    /// Lock-free mirror of `gate`, for the reader's loop condition.
    finished: AtomicBool,
    /// `close` was requested: input is refused from then on.
    closing: AtomicBool,
}

/// Running local shells by session id.
#[derive(Default)]
pub struct LocalShells {
    shells: Arc<DashMap<String, Arc<LocalShell>>>,
    /// Live reader threads (for tests: proves a finished session's reader
    /// actually exits and releases the terminal).
    readers: Arc<AtomicUsize>,
}

/// PTY geometry, clamped to what every backend accepts: ConPTY sizes are
/// signed 16-bit (COORD), so anything above i16::MAX would wrap negative.
fn size(cols: u32, rows: u32) -> PtySize {
    let clamp = |v: u32| v.clamp(1, i16::MAX as u32) as u16;
    PtySize {
        rows: clamp(rows),
        cols: clamp(cols),
        pixel_width: 0,
        pixel_height: 0,
    }
}

/// How long after the shell exits its output may keep draining before the
/// session is reported finished anyway. On Linux a disowned background job
/// can hold the terminal open indefinitely, so EOF alone is not a signal.
const EXIT_GRACE: Duration = Duration::from_secs(2);
/// How often the waiter checks whether the shell has exited.
const REAP_POLL: Duration = Duration::from_millis(50);

/// Thread-name-safe form of a session id (names may not contain NUL).
fn thread_tag(id: &str) -> String {
    id.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(40)
        .collect()
}

fn exit_reason(status: portable_pty::ExitStatus) -> String {
    if status.success() {
        "shell exited".to_string()
    } else {
        format!("shell exited with code {}", status.exit_code())
    }
}

impl LocalShells {
    pub fn owns(&self, session_id: &str) -> bool {
        self.shells.contains_key(session_id)
    }

    /// Start profile `profile_id` in a new PTY for `session_id` and stream its
    /// output. Returns the profile that was started.
    pub fn start<R: Runtime>(
        &self,
        app: &AppHandle<R>,
        session_id: &str,
        profile_id: &str,
        cols: u32,
        rows: u32,
        record: bool,
    ) -> Result<ShellProfile, String> {
        let prof = profiles()
            .into_iter()
            .find(|p| p.id == profile_id)
            .ok_or_else(|| format!("no local shell profile '{profile_id}' on this machine"))?;
        self.ensure_free(session_id)?;

        // Everything that can fail happens before the shell exists, so a
        // failure never leaves an orphaned process behind. No registry lock is
        // held meanwhile (spawning pwsh takes tens of ms).
        let pair = native_pty_system()
            .openpty(size(cols, rows))
            .map_err(|e| format!("could not open a terminal: {e}"))?;
        let reader = pair.master.try_clone_reader().map_err(|e| e.to_string())?;
        let writer = pair.master.take_writer().map_err(|e| e.to_string())?;
        #[cfg(unix)]
        let wake = ReadyFd::dup(&*pair.master)?;
        let mut cmd = CommandBuilder::new(&prof.program);
        cmd.args(&prof.args);
        if let Some(home) = crate::utils::platform::home_dir() {
            cmd.cwd(home);
        }
        cmd.env("TERM", "xterm-256color");
        cmd.env("COLORTERM", "truecolor");
        cmd.env("TERM_PROGRAM", "Hawser");
        let child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| format!("could not start {}: {e}", prof.label))?;
        // Only the child may hold the slave side: while we keep it open, the
        // reader would never see EOF after the shell exits.
        drop(pair.slave);

        let shell = Arc::new(LocalShell {
            writer: Mutex::new(writer),
            master: Mutex::new(Some(pair.master)),
            child: Mutex::new(Some(child)),
            exit_reason: Mutex::new(None),
            gate: Mutex::new(false),
            finished: AtomicBool::new(false),
            closing: AtomicBool::new(false),
        });
        // Register; a concurrent start for the same id that got here first wins.
        let registered = match self.shells.entry(session_id.to_string()) {
            dashmap::Entry::Occupied(_) => false,
            dashmap::Entry::Vacant(v) => {
                v.insert(Arc::clone(&shell));
                true
            }
        };
        if !registered {
            terminate(&shell);
            return Err(format!("session {session_id} is already running"));
        }

        let topic = format!("ssh://{session_id}");
        let log = if record {
            let user = std::env::var("USER")
                .or_else(|_| std::env::var("USERNAME"))
                .unwrap_or_else(|_| "local".to_string());
            SessionLog::create(&format!("local-{}", prof.id), &user).ok()
        } else {
            None
        };
        if let Some(l) = log.as_ref() {
            let _ = app.emit(
                &topic,
                format!("\x1b[38;5;244mlogging to {}\x1b[0m\r\n", l.path().display()),
            );
        }

        // Two plain threads (PTY handles are blocking everywhere, and a tokio
        // worker must never sit in read()):
        //  * the waiter reaps the shell (polling under the child lock), closes
        //    the PTY (ConPTY otherwise never EOFs), and, if the reader hasn't
        //    finished within EXIT_GRACE (a background job still holding the
        //    terminal on Linux), finishes the session itself.
        //  * the reader streams output until EOF or the finish, then finishes.
        let fin = Finisher {
            app: app.clone(),
            sid: session_id.to_string(),
            topic,
            shell: Arc::clone(&shell),
            registry: Arc::clone(&self.shells),
        };
        let fin_waiter = fin.clone();
        let (exit_tx, exit_rx) = std::sync::mpsc::channel::<String>();
        let tag = thread_tag(session_id);
        let waiter = std::thread::Builder::new()
            .name(format!("hawser-local-wait-{tag}"))
            .spawn(move || {
                let reason = reap(&fin_waiter.shell);
                if let Ok(mut m) = fin_waiter.shell.master.lock() {
                    m.take();
                }
                let _ = exit_tx.send(reason.clone());
                std::thread::sleep(EXIT_GRACE);
                fin_waiter.finish(&reason);
            });
        if let Err(e) = waiter {
            terminate(&shell);
            self.shells.remove_if(session_id, |_, s| Arc::ptr_eq(s, &shell));
            return Err(format!("could not start the exit watcher: {e}"));
        }
        let readers = Arc::clone(&self.readers);
        readers.fetch_add(1, Ordering::SeqCst);
        let reader_thread = std::thread::Builder::new()
            .name(format!("hawser-local-read-{tag}"))
            .spawn(move || {
                #[cfg(unix)]
                pump(fin, reader, wake, log, exit_rx);
                #[cfg(not(unix))]
                pump(fin, reader, log, exit_rx);
                readers.fetch_sub(1, Ordering::SeqCst);
            });
        if let Err(e) = reader_thread {
            self.readers.fetch_sub(1, Ordering::SeqCst);
            terminate(&shell);
            return Err(format!("could not start the output reader: {e}"));
        }
        Ok(prof)
    }

    /// Ok if `session_id` is free, or held only by a session that has finished
    /// (its last events are out and it is about to release the id).
    fn ensure_free(&self, session_id: &str) -> Result<(), String> {
        // Clone the Arc and drop the map guard before taking the gate: the
        // finisher holds the gate while it removes the map entry.
        let Some(existing) = self.shells.get(session_id).map(|s| Arc::clone(&s)) else {
            return Ok(());
        };
        let done = existing.gate.lock().map(|g| *g).unwrap_or(true);
        if done {
            // Finished under the gate, which also released the entry.
            Ok(())
        } else if existing.closing.load(Ordering::SeqCst) {
            Err("the previous terminal in this tab is still closing; try again in a moment".into())
        } else {
            Err(format!("session {session_id} is already running"))
        }
    }

    pub fn write(&self, session_id: &str, data: &[u8]) -> Result<(), String> {
        let shell = self.get(session_id)?;
        if shell.closing.load(Ordering::SeqCst) || shell.finished.load(Ordering::SeqCst) {
            return Err("the terminal is closing".to_string());
        }
        let mut w = shell.writer.lock().map_err(|_| "terminal writer poisoned")?;
        w.write_all(data).and_then(|_| w.flush()).map_err(|e| e.to_string())
    }

    pub fn resize(&self, session_id: &str, cols: u32, rows: u32) -> Result<(), String> {
        let shell = self.get(session_id)?;
        let m = shell.master.lock().map_err(|_| "terminal poisoned")?;
        match m.as_ref() {
            Some(m) => m.resize(size(cols, rows)).map_err(|e| e.to_string()),
            None => Err("the shell has exited".to_string()),
        }
    }

    /// End the shell: SIGHUP, then SIGKILL if it is still alive shortly after
    /// (TerminateProcess on Windows). Blocks up to ~250 ms; call off the async
    /// runtime. The session then finishes through the normal path, which is
    /// what releases the id — so a reused id never receives this shell's
    /// final events.
    pub fn close(&self, session_id: &str) {
        if let Ok(shell) = self.get(session_id) {
            shell.closing.store(true, Ordering::SeqCst);
            terminate(&shell);
        }
    }

    #[cfg(test)]
    fn pid(&self, session_id: &str) -> Option<u32> {
        let shell = self.get(session_id).ok()?;
        let g = shell.child.lock().ok()?;
        g.as_ref().and_then(|c| c.process_id())
    }

    fn get(&self, session_id: &str) -> Result<Arc<LocalShell>, String> {
        self.shells
            .get(session_id)
            .map(|s| Arc::clone(&s))
            .ok_or_else(|| format!("no local terminal {session_id}"))
    }
}

/// Collect the child's exit if it has one: clear the slot (so nothing ever
/// signals that pid again) and record why it ended. Call with the child lock
/// held. True once reaped.
fn collect(slot: &mut Option<Box<dyn Child + Send + Sync>>, shell: &LocalShell) -> bool {
    let reason = match slot.as_mut().map(|c| c.try_wait()) {
        None => return true,
        Some(Ok(None)) => return false,
        Some(Ok(Some(status))) => exit_reason(status),
        Some(Err(_)) => "terminal closed".to_string(),
    };
    *slot = None;
    if let Ok(mut r) = shell.exit_reason.lock() {
        r.get_or_insert(reason);
    }
    true
}

/// Kill the shell if it is still running. Everything happens under the child
/// lock, so it can't interleave with the waiter's reaping: an already-exited
/// child is collected instead of signalled (portable-pty's kill sends SIGHUP
/// before it checks), and an exit the kill itself collected is recorded right
/// after, so a later close finds the slot empty rather than signalling a pid
/// that may have been reused. `Child::kill` escalates: SIGHUP, short grace,
/// SIGKILL on Unix; TerminateProcess on Windows.
fn terminate(shell: &LocalShell) {
    let Ok(mut g) = shell.child.lock() else { return };
    if collect(&mut g, shell) {
        return;
    }
    if let Some(c) = g.as_mut() {
        let _ = c.kill();
    }
    collect(&mut g, shell);
}

/// Wait for the shell to exit (polling under the child lock) and say why.
fn reap(shell: &LocalShell) -> String {
    loop {
        let done = match shell.child.lock() {
            Ok(mut g) => collect(&mut g, shell),
            Err(_) => true,
        };
        if done {
            return shell
                .exit_reason
                .lock()
                .ok()
                .and_then(|r| r.clone())
                .unwrap_or_else(|| "terminal closed".to_string());
        }
        std::thread::sleep(REAP_POLL);
    }
}

/// Reports a session finished, exactly once.
struct Finisher<R: Runtime> {
    app: AppHandle<R>,
    sid: String,
    topic: String,
    shell: Arc<LocalShell>,
    registry: Arc<DashMap<String, Arc<LocalShell>>>,
}

impl<R: Runtime> Clone for Finisher<R> {
    fn clone(&self) -> Self {
        Self {
            app: self.app.clone(),
            sid: self.sid.clone(),
            topic: self.topic.clone(),
            shell: Arc::clone(&self.shell),
            registry: Arc::clone(&self.registry),
        }
    }
}

impl<R: Runtime> Finisher<R> {
    /// Emit output unless the session already finished (under the gate, so it
    /// can't interleave with the finish). False once finished.
    fn emit_output(&self, text: String) -> bool {
        let Ok(gate) = self.shell.gate.lock() else { return false };
        if *gate {
            return false;
        }
        let _ = self.app.emit(&self.topic, text);
        true
    }

    fn finish(&self, reason: &str) {
        let Ok(mut gate) = self.shell.gate.lock() else { return };
        if *gate {
            return;
        }
        *gate = true;
        self.shell.finished.store(true, Ordering::SeqCst);
        // Final line and status go out BEFORE the id is released, and nothing
        // of this shell's is published after them (the gate), so a terminal
        // restarted on the same id can never receive them.
        let _ = self.app.emit(
            &self.topic,
            format!("\r\n\x1b[38;2;242;178;92m\u{25cf} {reason}\x1b[0m\r\n"),
        );
        let _ = self.app.emit(
            "ssh://status",
            SessionStatusEvent {
                session_id: self.sid.clone(),
                status: "disconnected",
                detail: reason.to_string(),
            },
        );
        // Only if the id still maps to THIS shell.
        self.registry.remove_if(&self.sid, |_, s| Arc::ptr_eq(s, &self.shell));
        // Drop our write handle so a background job left on the terminal sees
        // it close rather than keeping it alive through us.
        if let Ok(mut w) = self.shell.writer.lock() {
            *w = Box::new(std::io::sink());
        }
    }
}

/// A duplicate of the PTY master's descriptor, used only to wait for
/// readability with a timeout, so the reader can notice the session finished
/// and let go of the terminal even while a background job keeps it open.
///
/// Linux uses poll(), which has no descriptor-number limit. macOS poll() does
/// not support tty devices, so it uses select(), which cannot take
/// descriptors >= FD_SETSIZE; such a descriptor is refused before the shell is
/// spawned (falling back to an uncancellable blocking read would reintroduce
/// the leak).
#[cfg(unix)]
struct ReadyFd(std::os::fd::OwnedFd);

#[cfg(unix)]
impl ReadyFd {
    fn dup(master: &dyn MasterPty) -> Result<Self, String> {
        use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};
        let fd = master.as_raw_fd().ok_or("terminal has no descriptor")?;
        // SAFETY: `fd` is the live master descriptor, borrowed only to dup it.
        let owned: OwnedFd = unsafe { BorrowedFd::borrow_raw(fd) }
            .try_clone_to_owned()
            .map_err(|e| e.to_string())?;
        if !cfg!(target_os = "linux") && owned.as_raw_fd() as usize >= libc::FD_SETSIZE {
            return Err(format!(
                "too many open files to start a terminal (descriptor {} is beyond {})",
                owned.as_raw_fd(),
                libc::FD_SETSIZE
            ));
        }
        Ok(Self(owned))
    }

    /// Readable (or hung up / errored) within `timeout`? Errors count as
    /// readable so the following read() surfaces them.
    #[cfg(target_os = "linux")]
    fn ready(&self, timeout: Duration) -> bool {
        use std::os::fd::AsRawFd;
        let mut p = libc::pollfd { fd: self.0.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        // SAFETY: one valid pollfd on the stack for the duration of the call.
        let n = unsafe { libc::poll(&mut p, 1, timeout.as_millis() as libc::c_int) };
        n != 0
    }

    #[cfg(not(target_os = "linux"))]
    fn ready(&self, timeout: Duration) -> bool {
        use std::os::fd::AsRawFd;
        let fd = self.0.as_raw_fd();
        // SAFETY: fd < FD_SETSIZE (checked in `dup`); fd_set is plain data and
        // every pointer refers to a local that outlives the call.
        unsafe {
            let mut set: libc::fd_set = std::mem::zeroed();
            libc::FD_ZERO(&mut set);
            libc::FD_SET(fd, &mut set);
            let mut tv = libc::timeval {
                tv_sec: timeout.as_secs() as _,
                tv_usec: timeout.subsec_micros() as _,
            };
            let n = libc::select(fd + 1, &mut set, std::ptr::null_mut(), std::ptr::null_mut(), &mut tv);
            n != 0
        }
    }
}

/// Stream output until EOF or the session finishing, then finish it with the
/// exit reason. Returning drops the reader (and on Unix the wake descriptor),
/// releasing our hold on the terminal.
fn pump<R: Runtime>(
    fin: Finisher<R>,
    mut reader: Box<dyn Read + Send>,
    #[cfg(unix)] wake: ReadyFd,
    mut log: Option<SessionLog>,
    exit: std::sync::mpsc::Receiver<String>,
) {
    let mut pending = Vec::new();
    let mut buf = [0u8; 16 * 1024];
    loop {
        if fin.shell.finished.load(Ordering::SeqCst) {
            break;
        }
        #[cfg(unix)]
        if !wake.ready(Duration::from_millis(100)) {
            continue;
        }
        match reader.read(&mut buf) {
            // EOF, or EIO on Linux once the shell is gone: either way, done.
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let text = decode_utf8_stream(&mut pending, &buf[..n]);
                if fin.shell.finished.load(Ordering::SeqCst) {
                    break;
                }
                if let Some(l) = log.as_mut() {
                    l.append(&buf[..n]);
                }
                if !text.is_empty() && !fin.emit_output(text) {
                    break;
                }
            }
        }
    }
    // If the waiter already finished (grace expired), the reason is waiting.
    let reason = exit.recv().unwrap_or_else(|_| "terminal closed".to_string());
    if let Some(l) = log.as_mut() {
        l.footer(&reason);
    }
    fin.finish(&reason);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_exist_and_ids_are_unique() {
        let ps = profiles();
        assert!(!ps.is_empty(), "every platform has at least one shell");
        let mut ids: Vec<_> = ps.iter().map(|p| p.id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), ps.len());
        assert!(ps.iter().all(|p| p.program.is_absolute()));
    }

    /// End to end through the registry with a mock Tauri app: start the login
    /// shell, write a command, resize, see its output on the session topic,
    /// then `exit` and observe the disconnected status and deregistration.
    #[cfg(unix)]
    #[test]
    fn registry_start_write_exit_end_to_end() {
        let _serial = serial();
        use std::sync::mpsc;
        use tauri::Listener;

        let app = tauri::test::mock_app();
        let handle = app.handle().clone();
        let (out_tx, out_rx) = mpsc::channel::<String>();
        let (st_tx, st_rx) = mpsc::channel::<String>();
        handle.listen("ssh://t1", move |e| {
            let _ = out_tx.send(e.payload().to_string());
        });
        handle.listen("ssh://status", move |e| {
            let _ = st_tx.send(e.payload().to_string());
        });

        let shells = LocalShells::default();
        let login = profiles().into_iter().next().unwrap();
        shells.start(&handle, "t1", &login.id, 80, 24, false).unwrap();
        assert!(shells.owns("t1"));
        assert!(shells.start(&handle, "t1", &login.id, 80, 24, false).is_err(), "id reuse refused");
        assert!(shells.start(&handle, "t2", "no-such-shell", 80, 24, false).is_err());
        shells.resize("t1", 120, 40).unwrap();
        shells.write("t1", b"echo hawser-$((6*7))\n").unwrap();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        let mut seen = String::new();
        while !seen.contains("hawser-42") {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            seen.push_str(&out_rx.recv_timeout(left).expect("shell output"));
        }
        shells.write("t1", b"exit 0\n").unwrap();
        let status = st_rx.recv_timeout(std::time::Duration::from_secs(20)).expect("status");
        assert!(status.contains("disconnected") && status.contains("t1"), "{status}");
        assert!(!shells.owns("t1"), "exited shell deregisters itself");
    }

    /// A disowned background job can keep the terminal open after the shell
    /// exits (indefinitely on Linux). The session must still finish, within
    /// the grace period, and release its id.
    #[cfg(unix)]
    #[test]
    fn exit_is_reported_even_with_a_background_job_holding_the_terminal() {
        let _serial = serial();
        use std::sync::mpsc;
        use tauri::Listener;

        let app = tauri::test::mock_app();
        let handle = app.handle().clone();
        let (st_tx, st_rx) = mpsc::channel::<String>();
        handle.listen("ssh://status", move |e| {
            let _ = st_tx.send(e.payload().to_string());
        });
        let shells = LocalShells::default();
        let login = profiles().into_iter().next().unwrap();
        shells.start(&handle, "bg1", &login.id, 80, 24, false).unwrap();
        // A subshell's background job is not one of the shell's jobs (so no
        // "you have running jobs" refusal, no hangup on exit) but it inherits
        // the terminal and keeps it open.
        shells.write("bg1", b"(sleep 30 &)\nexit\n").unwrap();
        let status = st_rx
            .recv_timeout(EXIT_GRACE + std::time::Duration::from_secs(15))
            .expect("finished despite the background job");
        assert!(status.contains("bg1") && status.contains("disconnected"), "{status}");
        assert!(!shells.owns("bg1"));
        // A restart on the same id is accepted straight away.
        shells.start(&handle, "bg1", &login.id, 80, 24, false).unwrap();
        shells.close("bg1");
    }

    /// Close twice, and close concurrently with the shell's own exit: the slot
    /// is emptied by whoever collects the exit, so no later close signals the
    /// (possibly reused) pid, and the exit reason still reaches the session.
    #[cfg(unix)]
    #[test]
    fn repeated_and_racing_closes_never_signal_a_collected_pid() {
        let _serial = serial();
        let app = tauri::test::mock_app();
        let shells = Arc::new(LocalShells::default());
        let login = profiles().into_iter().next().unwrap();
        for round in 0..5 {
            let id = format!("rc{round}");
            shells.start(app.handle(), &id, &login.id, 80, 24, false).unwrap();
            let shell = shells.get(&id).unwrap();
            // Racing: the shell exits on its own while three closers pile in.
            shells.write(&id, b"exit\n").unwrap();
            let closers: Vec<_> = (0..3)
                .map(|_| {
                    let (shells, id) = (Arc::clone(&shells), id.clone());
                    std::thread::spawn(move || shells.close(&id))
                })
                .collect();
            for c in closers {
                c.join().unwrap();
            }
            // Whoever collected the exit emptied the slot and kept a reason.
            wait_until("the child to be collected", 10, || shell.child.lock().unwrap().is_none());
            assert!(shell.exit_reason.lock().unwrap().is_some());
            // Further closes find nothing to signal.
            shells.close(&id);
            terminate(&shell);
            assert!(shell.child.lock().unwrap().is_none());
            wait_until("the session to finish", 10, || !shells.owns(&id));
        }
    }

    /// Descriptor numbers beyond FD_SETSIZE: Linux (poll) still runs and
    /// finishes cleanly; elsewhere (select) the start is refused up front
    /// rather than falling back to an uncancellable read. Either way no reader
    /// is left behind.
    #[cfg(unix)]
    #[test]
    fn high_descriptors_never_leave_an_uncancellable_reader() {
        let _serial = serial();
        // Make room above FD_SETSIZE, then fill the table up to it.
        // SAFETY: plain rlimit get/set on this test process.
        unsafe {
            let mut lim: libc::rlimit = std::mem::zeroed();
            libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim);
            let want = (libc::FD_SETSIZE as libc::rlim_t + 256).min(lim.rlim_max);
            if lim.rlim_cur < want {
                lim.rlim_cur = want;
                libc::setrlimit(libc::RLIMIT_NOFILE, &lim);
            }
        }
        let mut hold = Vec::new();
        loop {
            let f = std::fs::File::open("/dev/null").unwrap();
            let fd = std::os::fd::AsRawFd::as_raw_fd(&f) as usize;
            hold.push(f);
            if fd >= libc::FD_SETSIZE {
                break;
            }
        }
        let app = tauri::test::mock_app();
        let shells = LocalShells::default();
        let login = profiles().into_iter().next().unwrap();
        let started = shells.start(app.handle(), "fd1", &login.id, 80, 24, false);
        if cfg!(target_os = "linux") {
            started.unwrap();
            shells.write("fd1", b"(sleep 300 &)\nexit\n").unwrap();
            wait_until("the session to finish", 20, || !shells.owns("fd1"));
        } else {
            let err = started.unwrap_err();
            assert!(err.contains("too many open files"), "{err}");
            assert!(!shells.owns("fd1"));
        }
        wait_until("no reader left", 10, || shells.readers.load(Ordering::SeqCst) == 0);
        drop(hold);
    }

    #[test]
    fn sizes_clamp_to_conpty_limits_and_thread_tags_are_safe() {
        let s = size(100_000, 0);
        assert_eq!((s.cols, s.rows), (i16::MAX as u16, 1));
        assert_eq!(thread_tag("s-local\0evil/../x"), "s-localevilx");
    }

    /// Shell tests run one at a time: the descriptor-exhaustion test fills the
    /// process's fd table, which would starve a concurrent test's PTY.
    static SHELL_TESTS: Mutex<()> = Mutex::new(());
    fn serial() -> std::sync::MutexGuard<'static, ()> {
        SHELL_TESTS.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn wait_until(what: &str, secs: u64, mut ok: impl FnMut() -> bool) {
        let deadline = std::time::Instant::now() + Duration::from_secs(secs);
        while !ok() {
            assert!(std::time::Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Wait for `needle` on a session's output topic.
    fn await_output(rx: &std::sync::mpsc::Receiver<String>, needle: &str) {
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        let mut seen = String::new();
        while !seen.contains(needle) {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            seen.push_str(&rx.recv_timeout(left).unwrap_or_else(|_| panic!("no {needle} in {seen:?}")));
        }
    }

    /// Closing must actually terminate the process, even one that ignores
    /// SIGHUP (the cloned killer alone only sends SIGHUP).
    #[cfg(unix)]
    #[test]
    fn close_terminates_a_shell_that_ignores_sighup() {
        let _serial = serial();
        use tauri::Listener;
        let app = tauri::test::mock_app();
        let handle = app.handle().clone();
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        handle.listen("ssh://h1", move |e| {
            let _ = tx.send(e.payload().to_string());
        });
        let shells = LocalShells::default();
        let login = profiles().into_iter().next().unwrap();
        shells.start(&handle, "h1", &login.id, 80, 24, false).unwrap();
        let pid = shells.pid("h1").unwrap() as i32;
        shells.write("h1", b"trap '' HUP; echo trap-$((1+1))-set\n").unwrap();
        await_output(&rx, "trap-2-set");
        shells.close("h1");
        // SAFETY: signal 0 only probes for existence.
        wait_until("the process to die", 10, || unsafe { libc::kill(pid, 0) } != 0);
        wait_until("the id to be released", 10, || !shells.owns("h1"));
        assert!(shells.write("h1", b"x").is_err());
    }

    /// close → immediate restart on the same id: the restarted terminal must
    /// never receive the old shell's final line or its "disconnected" status.
    #[cfg(unix)]
    #[test]
    fn restart_on_the_same_id_never_receives_the_old_shells_events() {
        let _serial = serial();
        use tauri::Listener;
        let app = tauri::test::mock_app();
        let handle = app.handle().clone();
        let events = Arc::new(Mutex::new(Vec::<String>::new()));
        for topic in ["ssh://r1", "ssh://status"] {
            let ev = Arc::clone(&events);
            handle.listen(topic, move |e| ev.lock().unwrap().push(e.payload().to_string()));
        }
        let shells = LocalShells::default();
        let login = profiles().into_iter().next().unwrap();
        shells.start(&handle, "r1", &login.id, 80, 24, false).unwrap();
        shells.close("r1");
        // Retry until the old session has published its end and freed the id.
        wait_until("restart to be accepted", 10, || {
            shells.start(&handle, "r1", &login.id, 80, 24, false).is_ok()
        });
        let boundary = events.lock().unwrap().len();
        let statuses = |evs: &[String]| evs.iter().filter(|e| e.contains("disconnected")).count();
        assert_eq!(statuses(&events.lock().unwrap()[..boundary]), 1, "old shell reported once");
        shells.write("r1", b"echo second-$((2+3))\n").unwrap();
        wait_until("the new shell's output", 20, || {
            events.lock().unwrap()[boundary..].iter().any(|e| e.contains("second-5"))
        });
        std::thread::sleep(Duration::from_millis(500));
        let after = events.lock().unwrap()[boundary..].to_vec();
        assert_eq!(statuses(&after), 0, "nothing from the old shell after the restart: {after:?}");
        assert!(after.iter().all(|e| !e.contains("shell exited")), "{after:?}");
        assert!(shells.owns("r1"));
        shells.close("r1");
    }

    /// A background job holding the terminal: once the session finishes, the
    /// reader thread must exit (releasing its descriptors and the transcript),
    /// not block on the job forever.
    #[cfg(unix)]
    #[test]
    fn finished_session_releases_its_reader_despite_a_background_job() {
        let _serial = serial();
        let app = tauri::test::mock_app();
        let shells = LocalShells::default();
        let login = profiles().into_iter().next().unwrap();
        shells.start(app.handle(), "k1", &login.id, 80, 24, false).unwrap();
        assert_eq!(shells.readers.load(Ordering::SeqCst), 1);
        shells.write("k1", b"(sleep 300 &)\nexit\n").unwrap();
        wait_until("the session to finish", 20, || !shells.owns("k1"));
        wait_until("the reader thread to exit", 10, || shells.readers.load(Ordering::SeqCst) == 0);
    }

    /// A real PTY round trip with the platform's shell: input in, output out,
    /// exit observed. No Tauri involved — this drives portable-pty the way
    /// `start` does.
    #[cfg(unix)]
    #[test]
    fn pty_round_trip_with_the_login_shell() {
        let _serial = serial();
        let pair = native_pty_system().openpty(size(80, 24)).unwrap();
        let mut cmd = CommandBuilder::new("/bin/sh");
        cmd.env("TERM", "xterm-256color");
        let mut child = pair.slave.spawn_command(cmd).unwrap();
        drop(pair.slave);
        let mut reader = pair.master.try_clone_reader().unwrap();
        let mut writer = pair.master.take_writer().unwrap();
        writer.write_all(b"echo hawser-$((40+2))\nexit 3\n").unwrap();
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        while let Ok(n) = reader.read(&mut buf) {
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("hawser-42"), "{text}");
        assert_eq!(child.wait().unwrap().exit_code(), 3);
    }
}
