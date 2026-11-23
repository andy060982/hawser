//! App-wide single-instance lock.
//!
//! The single-instance plugin hands a second launch over to the running
//! window, but it is not a lock: in 2.4.1 two simultaneous macOS launches can
//! both find no socket (and the second's cleanup unlinks the socket the first
//! just bound), and on Linux processes on different session buses can each
//! own the D-Bus name. Two processes over one data directory would race on
//! the audit chain, the vault bindings and every settings file.
//!
//! So the app takes an OS advisory lock on `<appdata>/hawser.instance.lock`
//! FIRST, before any store is opened (hosts, bindings, vault journal, audit,
//! settings). The lock is held for the life of the process and released by
//! the OS when it exits, however it exits, so a stale lock file is harmless.
//! A process that finds it held opens nothing: it lets the plugin hand its
//! launch to the running window and exits.
//!
//! The lock fails CLOSED: if it cannot be taken for any reason other than
//! another live instance holding it (an unwritable data folder, a path that is
//! not a file), the app says so in a native dialog and exits rather than run
//! unguarded (`decide`).
//!
//! Plugin limitation (tauri-plugin-single-instance 2.4.1): its hand-off is
//! not a lock, and a losing launch that runs it can briefly CLAIM the hand-off
//! endpoint itself (the macOS socket, the Windows mutex + window, the Linux
//! D-Bus name). A primary whose own plugin setup ran in that window would hand
//! itself to the loser and exit with it. On macOS a losing launch therefore
//! never runs the plugin: it connects to the primary's socket itself, retrying
//! with backoff while the primary starts (`hand_off`). Elsewhere the plugin
//! still does the hand-off after a short delay; if the race is lost there, the
//! instance lock still keeps the data safe and the user launches again.

use std::fs::{File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};

pub const LOCK_FILE: &str = "hawser.instance.lock";

/// Proof that this process is the one instance. Keep it alive until exit.
#[derive(Debug)]
pub struct InstanceLock(#[allow(dead_code)] File);

#[derive(Debug)]
pub enum Acquire {
    /// This process is the instance.
    Held(InstanceLock),
    /// Another process holds the lock.
    Busy,
}

/// What startup does with the lock result.
#[derive(Debug)]
pub enum Startup {
    /// This process is the instance: run normally, holding the lock.
    Run(InstanceLock),
    /// Another live instance holds it: hand this launch over and exit.
    HandOff,
    /// The lock could not be taken at all: show this and exit. Never run
    /// unguarded.
    Refuse(String),
}

/// Fail closed: only "held by another live instance" leads anywhere but a
/// refusal, and only "held by us" runs.
pub fn decide(acquired: Result<Acquire, String>) -> Startup {
    match acquired {
        Ok(Acquire::Held(lock)) => Startup::Run(lock),
        Ok(Acquire::Busy) => Startup::HandOff,
        Err(e) => Startup::Refuse(format!(
            "Hawser could not lock its data folder, so it cannot make sure it is the only copy running and \
             will not start.\n\n{e}\n\nCheck that the folder exists and that you can write to it, then start \
             Hawser again."
        )),
    }
}

/// Show a fatal startup error natively (no webview exists yet), best effort:
/// a message box on Windows, an alert via osascript on macOS, zenity or
/// kdialog on Linux. Always also on stderr.
pub fn fatal_dialog(title: &str, message: &str) {
    eprintln!("hawser: {title}: {message}");
    #[cfg(windows)]
    {
        use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK};
        let wide = |s: &str| s.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
        let (t, m) = (wide(title), wide(message));
        // SAFETY: both buffers are NUL-terminated and outlive the call; no owner window.
        unsafe { MessageBoxW(std::ptr::null_mut(), m.as_ptr(), t.as_ptr(), MB_OK | MB_ICONERROR) };
    }
    #[cfg(target_os = "macos")]
    {
        // Text passed as arguments, never spliced into the script.
        let _ = std::process::Command::new("/usr/bin/osascript")
            .args(["-e", "on run argv", "-e", "display alert (item 1 of argv) message (item 2 of argv) as critical", "-e", "end run"])
            .args([title, message])
            .status();
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let shown = std::process::Command::new("zenity")
            .args(["--error", "--title", title, "--text", message])
            .status()
            .is_ok_and(|s| s.success());
        if !shown {
            let _ = std::process::Command::new("kdialog").args(["--title", title, "--error", message]).status();
        }
    }
}

/// The single-instance plugin's macOS socket for `identifier` (2.4.1 without
/// its `semver` feature, which this app does not enable): `/tmp/<id>_si.sock`
/// with `.` and `-` replaced by `_`.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn plugin_socket(identifier: &str) -> PathBuf {
    PathBuf::from(format!("/tmp/{}_si.sock", identifier.replace(['.', '-'], "_")))
}

/// The plugin's hand-off message: cwd, `\0\0`, then the arguments joined by `\0`.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn hand_off_message() -> Vec<u8> {
    let cwd = std::env::current_dir().unwrap_or_default().to_string_lossy().to_string();
    let args = std::env::args().collect::<Vec<String>>().join("\0");
    [cwd.as_bytes(), b"\0\0", args.as_bytes()].concat()
}

/// Backoff between hand-off attempts: ~3 s in all, for a primary that is
/// still starting (its listener opens during its plugin setup).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub const HAND_OFF_BACKOFF_MS: [u64; 7] = [0, 50, 100, 200, 400, 800, 1500];

/// Hand this launch to the running instance through the plugin's Unix socket,
/// retrying with `backoff` while the primary starts. Only ever CONNECTS: it
/// never binds the socket, so it cannot capture the primary's own hand-off.
/// True once the message was delivered.
#[cfg(unix)]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn hand_off(socket: &Path, message: &[u8], backoff: &[std::time::Duration]) -> bool {
    use std::io::Write;
    for wait in backoff {
        std::thread::sleep(*wait);
        if let Ok(mut s) = std::os::unix::net::UnixStream::connect(socket) {
            if s.write_all(message).and_then(|_| s.flush()).is_ok() {
                return true;
            }
        }
    }
    false
}

/// `<appdata>/hawser.instance.lock`. Computing it touches no store.
pub fn lock_path() -> Result<PathBuf, String> {
    super::artifacts::app_data_root().map(|d| d.join(LOCK_FILE)).map_err(|e| e.to_string())
}

/// Take the app-wide lock (non-blocking).
pub fn acquire() -> Result<Acquire, String> {
    let path = lock_path()?;
    acquire_at(&path).map_err(|e| format!("{}: {e}", path.display()))
}

/// Take an exclusive advisory lock on `path` without waiting (flock on Unix,
/// LockFileEx on Windows, via std). The locks belong to the open file, so a
/// second open in the same process conflicts too, which is what the tests use.
pub fn acquire_at(path: &Path) -> std::io::Result<Acquire> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
        super::platform::restrict_perms(dir, 0o700);
    }
    let mut opts = OpenOptions::new();
    opts.create(true).read(true).write(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let f = opts.open(path)?;
    match f.try_lock() {
        Ok(()) => Ok(Acquire::Held(InstanceLock(f))),
        Err(TryLockError::WouldBlock) => Ok(Acquire::Busy),
        Err(TryLockError::Error(e)) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "hawser-instance-{}-{}",
            std::process::id(),
            super::super::artifacts::random_hex(4)
        ));
        let _ = std::fs::remove_dir_all(&d);
        d.join(LOCK_FILE)
    }

    #[test]
    fn a_second_holder_is_refused_until_the_first_lets_go() {
        let p = tmp();
        let first = acquire_at(&p).unwrap();
        assert!(matches!(first, Acquire::Held(_)));
        assert!(matches!(acquire_at(&p).unwrap(), Acquire::Busy));
        assert!(matches!(acquire_at(&p).unwrap(), Acquire::Busy), "still busy, never queued");
        drop(first); // the process exiting
        assert!(matches!(acquire_at(&p).unwrap(), Acquire::Held(_)));
    }

    #[test]
    fn a_leftover_lock_file_does_not_block_a_new_instance() {
        let p = tmp();
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, b"stale").unwrap();
        assert!(matches!(acquire_at(&p).unwrap(), Acquire::Held(_)));
        assert_eq!(std::fs::read(&p).unwrap(), b"stale", "never truncated");
    }

    /// W4c: anything but "held by another instance" refuses to start.
    #[test]
    fn the_lock_fails_closed() {
        let p = tmp();
        // A directory where the lock file should be: it cannot be opened.
        std::fs::create_dir_all(&p).unwrap();
        let r = acquire_at(&p).map_err(|e| e.to_string());
        assert!(r.is_err(), "{r:?}");
        assert!(matches!(decide(r), Startup::Refuse(m) if m.contains("will not start")));
        let q = tmp();
        let held = acquire_at(&q).unwrap();
        assert!(matches!(decide(acquire_at(&q).map_err(|e| e.to_string())), Startup::HandOff));
        assert!(matches!(decide(Ok(held)), Startup::Run(_)));
    }

    #[test]
    fn the_plugin_socket_path_matches_its_naming() {
        assert_eq!(plugin_socket("com.andyarevalo.hawser-app"), PathBuf::from("/tmp/com_andyarevalo_hawser_app_si.sock"));
    }

    /// W4c: the hand-off retries while the primary is still starting, and
    /// gives up in bounded time when nothing listens.
    #[cfg(unix)]
    #[test]
    fn the_hand_off_retries_until_the_primary_listens() {
        use std::io::Read;
        use std::time::Duration;
        let dir = std::env::temp_dir().join(format!("hsi-{}", super::super::artifacts::random_hex(4)));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("s.sock");
        let backoff: Vec<Duration> = [0u64, 50, 100, 200, 400, 800].iter().map(|m| Duration::from_millis(*m)).collect();
        let started = std::time::Instant::now();
        assert!(!hand_off(&sock, b"x", &backoff), "nobody listening");
        assert!(started.elapsed() < Duration::from_secs(5));
        let late = {
            let sock = sock.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(250));
                let l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
                let (mut s, _) = l.accept().unwrap();
                let mut got = Vec::new();
                s.read_to_end(&mut got).unwrap();
                got
            })
        };
        assert!(hand_off(&sock, b"cwd\0\0hawser", &backoff));
        assert_eq!(late.join().unwrap(), b"cwd\0\0hawser");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn the_lock_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let p = tmp();
        let _held = acquire_at(&p).unwrap();
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
    }
}
