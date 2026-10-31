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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use dashmap::DashMap;
use portable_pty::{native_pty_system, ChildKiller, CommandBuilder, MasterPty, PtySize};
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
    killer: Mutex<Box<dyn ChildKiller + Send + Sync>>,
    /// Set by the waiter when the shell has been reaped. After that its pid
    /// may belong to another process, so `close` must not signal it.
    exited: AtomicBool,
    /// Set once the session has been reported finished (exactly once, by
    /// whichever of reader / waiter gets there first). Output read after it
    /// is dropped: the id may already belong to a restarted shell.
    finished: AtomicBool,
}

/// Running local shells by session id.
#[derive(Default)]
pub struct LocalShells {
    shells: Arc<DashMap<String, Arc<LocalShell>>>,
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
const EXIT_GRACE: std::time::Duration = std::time::Duration::from_secs(2);

/// Thread-name-safe form of a session id (names may not contain NUL).
fn thread_tag(id: &str) -> String {
    id.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(40)
        .collect()
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
        if self.owns(session_id) {
            return Err(format!("session {session_id} is already running"));
        }

        // Everything that can fail happens before the shell exists, so a
        // failure never leaves an orphaned process behind. No registry lock is
        // held meanwhile (spawning pwsh takes tens of ms).
        let pair = native_pty_system()
            .openpty(size(cols, rows))
            .map_err(|e| format!("could not open a terminal: {e}"))?;
        let reader = pair.master.try_clone_reader().map_err(|e| e.to_string())?;
        let writer = pair.master.take_writer().map_err(|e| e.to_string())?;
        let mut cmd = CommandBuilder::new(&prof.program);
        cmd.args(&prof.args);
        if let Some(home) = crate::utils::platform::home_dir() {
            cmd.cwd(home);
        }
        cmd.env("TERM", "xterm-256color");
        cmd.env("COLORTERM", "truecolor");
        cmd.env("TERM_PROGRAM", "Hawser");
        let mut child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| format!("could not start {}: {e}", prof.label))?;
        // Only the child may hold the slave side: while we keep it open, the
        // reader would never see EOF after the shell exits.
        drop(pair.slave);

        let shell = Arc::new(LocalShell {
            writer: Mutex::new(writer),
            master: Mutex::new(Some(pair.master)),
            killer: Mutex::new(child.clone_killer()),
            exited: AtomicBool::new(false),
            finished: AtomicBool::new(false),
        });
        let mut abort = |why: String| {
            let _ = child.kill();
            let _ = child.wait();
            why
        };
        // Register; a concurrent start for the same id that got here first wins.
        match self.shells.entry(session_id.to_string()) {
            dashmap::Entry::Occupied(_) => {
                return Err(abort(format!("session {session_id} is already running")))
            }
            dashmap::Entry::Vacant(v) => {
                v.insert(Arc::clone(&shell));
            }
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
        //  * the waiter owns the child. When the shell exits it marks it
        //    exited, closes the PTY (ConPTY otherwise never EOFs), and, if the
        //    reader hasn't finished within EXIT_GRACE (a background job still
        //    holding the terminal on Linux), finishes the session itself.
        //  * the reader streams output until EOF, then finishes the session.
        let fin = Finisher {
            app: app.clone(),
            sid: session_id.to_string(),
            topic: topic.clone(),
            shell: Arc::clone(&shell),
            registry: Arc::clone(&self.shells),
        };
        let fin_waiter = fin.clone();
        let (exit_tx, exit_rx) = std::sync::mpsc::channel::<String>();
        let tag = thread_tag(session_id);
        let waiter = std::thread::Builder::new()
            .name(format!("hawser-local-wait-{tag}"))
            .spawn(move || {
                let reason = match child.wait() {
                    Ok(s) if s.success() => "shell exited".to_string(),
                    Ok(s) => format!("shell exited with code {}", s.exit_code()),
                    Err(_) => "terminal closed".to_string(),
                };
                fin_waiter.shell.exited.store(true, Ordering::SeqCst);
                if let Ok(mut m) = fin_waiter.shell.master.lock() {
                    m.take();
                }
                let _ = exit_tx.send(reason.clone());
                std::thread::sleep(EXIT_GRACE);
                fin_waiter.finish(&reason);
            });
        if let Err(e) = waiter {
            // The child moved into the failed closure and was dropped; kill
            // through the shared killer and deregister.
            if let Ok(mut k) = shell.killer.lock() {
                let _ = k.kill();
            }
            self.shells.remove_if(session_id, |_, s| Arc::ptr_eq(s, &shell));
            return Err(format!("could not start the exit watcher: {e}"));
        }
        let reader_thread = std::thread::Builder::new()
            .name(format!("hawser-local-read-{tag}"))
            .spawn(move || pump(fin, reader, log, exit_rx));
        if let Err(e) = reader_thread {
            self.close(session_id);
            return Err(format!("could not start the output reader: {e}"));
        }
        Ok(prof)
    }

    pub fn write(&self, session_id: &str, data: &[u8]) -> Result<(), String> {
        let shell = self.get(session_id)?;
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

    /// End the shell. The waiter then closes the PTY and the session reports
    /// itself finished.
    pub fn close(&self, session_id: &str) {
        if let Some((_, shell)) = self.shells.remove(session_id) {
            // Never signal a pid the waiter already reaped: it may be reused.
            if !shell.exited.load(Ordering::SeqCst) {
                if let Ok(mut k) = shell.killer.lock() {
                    let _ = k.kill();
                }
            }
        }
    }

    fn get(&self, session_id: &str) -> Result<Arc<LocalShell>, String> {
        self.shells
            .get(session_id)
            .map(|s| Arc::clone(&s))
            .ok_or_else(|| format!("no local terminal {session_id}"))
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
    fn finished(&self) -> bool {
        self.shell.finished.load(Ordering::SeqCst)
    }

    fn finish(&self, reason: &str) {
        if self.shell.finished.swap(true, Ordering::SeqCst) {
            return;
        }
        // Deregister only if the id still maps to THIS shell: after a close the
        // id may already belong to a new terminal, which must not be torn down.
        self.registry.remove_if(&self.sid, |_, s| Arc::ptr_eq(s, &self.shell));
        // Drop our write handle so a background job left on the terminal sees
        // it close rather than keeping it alive through us.
        if let Ok(mut w) = self.shell.writer.lock() {
            *w = Box::new(std::io::sink());
        }
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
    }
}

/// Stream output until EOF, then finish the session with the exit reason.
fn pump<R: Runtime>(
    fin: Finisher<R>,
    mut reader: Box<dyn Read + Send>,
    mut log: Option<SessionLog>,
    exit: std::sync::mpsc::Receiver<String>,
) {
    let mut pending = Vec::new();
    let mut buf = [0u8; 16 * 1024];
    loop {
        match reader.read(&mut buf) {
            // EOF, or EIO on Linux once the shell is gone: either way, done.
            Ok(0) | Err(_) => break,
            Ok(n) => {
                // Past the finish line (the waiter gave up on EOF): this is a
                // background job's output on a session the tab no longer owns.
                if fin.finished() {
                    continue;
                }
                if let Some(l) = log.as_mut() {
                    l.append(&buf[..n]);
                }
                let text = decode_utf8_stream(&mut pending, &buf[..n]);
                if !text.is_empty() {
                    let _ = fin.app.emit(&fin.topic, text);
                }
            }
        }
    }
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

    #[test]
    fn sizes_clamp_to_conpty_limits_and_thread_tags_are_safe() {
        let s = size(100_000, 0);
        assert_eq!((s.cols, s.rows), (i16::MAX as u16, 1));
        assert_eq!(thread_tag("s-local\0evil/../x"), "s-localevilx");
    }

    #[test]
    fn close_kills_the_shell() {
        let app = tauri::test::mock_app();
        let shells = LocalShells::default();
        let login = profiles().into_iter().next().unwrap();
        shells.start(app.handle(), "c1", &login.id, 80, 24, false).unwrap();
        shells.close("c1");
        assert!(!shells.owns("c1"));
        assert!(shells.write("c1", b"x").is_err());
    }

    /// A real PTY round trip with the platform's shell: input in, output out,
    /// exit observed. No Tauri involved — this drives portable-pty the way
    /// `start` does.
    #[cfg(unix)]
    #[test]
    fn pty_round_trip_with_the_login_shell() {
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
