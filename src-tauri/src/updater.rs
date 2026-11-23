//! Self-update support around tauri-plugin-updater.
//!
//! The plugin does the work that matters for safety: it fetches `latest.json`
//! from the GitHub release, downloads the bundle, and verifies its minisign
//! signature against the public key in tauri.conf.json before installing
//! anything. Nothing here touches that path or can bypass it.
//!
//! What this module adds:
//! - `update_install_kind`: whether this copy can replace itself. The portable
//!   Windows exe and the Linux .deb cannot (the updater would install an NSIS
//!   copy beside the portable one, or need root for the package), so the UI
//!   links to the releases page for those instead.
//! - `update_open_releases`: opens that fixed URL (never a webview-supplied one).
//! - `update_prepare_install`: on Windows the plugin launches the installer and
//!   calls `std::process::exit` itself, skipping the app's normal exit path, so
//!   the audit queue is drained here first.
//! - A relaunch hand-over: a restart spawns the new process while this one
//!   still holds the instance lock (utils::instance), which would make the new
//!   process hand itself off to the dying one and exit. `mark_relaunch` tags the
//!   child; `acquire_instance` lets a tagged child wait for the lock instead.

use std::ffi::OsStr;
use std::path::Path;
use std::time::Duration;

use serde::Serialize;

use crate::utils;

/// Where a copy that cannot self-update is sent.
pub const RELEASES_URL: &str = "https://github.com/andy060982/hawser/releases/latest";

/// Set on the restarted child so it waits for the instance lock.
const RELAUNCH_ENV: &str = "HAWSER_RELAUNCH_WAIT";

/// How long a relaunched child waits for the old process to let go. The old
/// process drains the audit queue for up to 10 s on exit.
const RELAUNCH_WAIT: Duration = Duration::from_secs(20);
const RELAUNCH_POLL: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// The updater can replace this copy in place.
    #[serde(rename = "self")]
    SelfUpdate,
    /// Download a new copy by hand.
    Manual,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstallKind {
    pub kind: Kind,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    Windows,
    MacOs,
    Linux,
    Other,
}

impl Os {
    fn current() -> Os {
        if cfg!(target_os = "windows") {
            Os::Windows
        } else if cfg!(target_os = "macos") {
            Os::MacOs
        } else if cfg!(target_os = "linux") {
            Os::Linux
        } else {
            Os::Other
        }
    }
}

fn manual(reason: &str) -> InstallKind {
    InstallKind { kind: Kind::Manual, reason: reason.into() }
}

fn self_update(reason: &str) -> InstallKind {
    InstallKind { kind: Kind::SelfUpdate, reason: reason.into() }
}

/// Decide how this copy is updated. Pure: the caller supplies the running
/// executable, the `APPIMAGE` variable, and a file-exists probe.
///
/// - Windows: the NSIS installer writes `uninstall.exe` beside `hawser.exe`;
///   without it this is the portable exe.
/// - Linux: only an AppImage (the AppImage runtime sets `APPIMAGE`) can be
///   replaced; anything else is the .deb or a build from source.
/// - macOS: the executable must be inside `<name>.app/Contents/MacOS`, and not
///   on the mounted disk image or under App Translocation (both read-only).
pub fn classify(os: Os, exe: &Path, appimage: Option<&OsStr>, exists: impl Fn(&Path) -> bool) -> InstallKind {
    match os {
        Os::Windows => {
            let dir = exe.parent().unwrap_or(exe);
            if exists(&dir.join("uninstall.exe")) {
                self_update("installed with the Windows installer")
            } else {
                manual("portable copy (not installed with the Windows installer)")
            }
        }
        Os::Linux => match appimage {
            Some(p) if !p.is_empty() && exists(Path::new(p)) => self_update("AppImage"),
            _ => manual("installed from a .deb package or built from source"),
        },
        Os::MacOs => {
            let s = exe.to_string_lossy();
            let in_bundle = exe
                .parent()
                .filter(|d| d.file_name() == Some(OsStr::new("MacOS")))
                .and_then(Path::parent)
                .filter(|d| d.file_name() == Some(OsStr::new("Contents")))
                .and_then(Path::parent)
                .and_then(Path::extension)
                == Some(OsStr::new("app"));
            if !in_bundle {
                manual("not running from an app bundle")
            } else if s.starts_with("/Volumes/") {
                manual("running from the disk image; drag Hawser to Applications first")
            } else if s.contains("/AppTranslocation/") {
                manual("macOS is running this copy from a read-only location; move it to Applications")
            } else {
                self_update("app bundle")
            }
        }
        Os::Other => manual("self-update is not supported on this platform"),
    }
}

/// `classify` for this process.
pub fn current_install_kind() -> InstallKind {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => return manual(&format!("could not locate the running program ({e})")),
    };
    let appimage = std::env::var_os("APPIMAGE");
    classify(Os::current(), &exe, appimage.as_deref(), |p| p.is_file())
}

#[tauri::command]
pub fn update_install_kind() -> InstallKind {
    current_install_kind()
}

/// Open the releases page in the default browser. The URL is a constant.
#[tauri::command]
pub async fn update_open_releases() -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(|| {
        utils::platform::open_file_default(Path::new(RELEASES_URL)).map_err(|e| format!("could not open the browser: {e}"))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Called once the update is downloaded and verified, just before install.
/// Records the update; on Windows (where the plugin exits the process itself)
/// also drains the audit queue, as the normal exit path would.
#[tauri::command]
pub async fn update_prepare_install(version: String) -> Result<(), String> {
    let version: String = version.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+')).take(64).collect();
    utils::audit::record(
        "app.update",
        format!("installing Hawser {version}"),
        serde_json::json!({ "from": env!("CARGO_PKG_VERSION"), "to": version }),
    );
    #[cfg(windows)]
    tauri::async_runtime::spawn_blocking(|| utils::audit::shutdown(Duration::from_secs(10)))
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// From the run-event loop: an exit carrying RESTART_EXIT_CODE is a relaunch.
/// Tag the environment the child inherits so it waits for the instance lock.
pub fn mark_relaunch(code: Option<i32>) {
    if code == Some(tauri::RESTART_EXIT_CODE) {
        std::env::set_var(RELAUNCH_ENV, "1");
    }
}

/// Retry `attempt` while it reports Busy, sleeping `poll` between tries, for
/// at most `tries` attempts. Anything other than Busy returns at once.
pub fn retry_while_busy(
    mut attempt: impl FnMut() -> Result<utils::instance::Acquire, String>,
    tries: u32,
    mut sleep: impl FnMut(),
) -> Result<utils::instance::Acquire, String> {
    let mut r = attempt();
    for _ in 1..tries.max(1) {
        if !matches!(r, Ok(utils::instance::Acquire::Busy)) {
            break;
        }
        sleep();
        r = attempt();
    }
    r
}

/// utils::instance::acquire, except that a relaunched child waits for the old
/// process to exit. The marker is removed first so shells and helpers this
/// process starts never inherit it.
pub fn acquire_instance() -> Result<utils::instance::Acquire, String> {
    let relaunched = std::env::var_os(RELAUNCH_ENV).is_some();
    if !relaunched {
        return utils::instance::acquire();
    }
    std::env::remove_var(RELAUNCH_ENV);
    let tries = (RELAUNCH_WAIT.as_millis() / RELAUNCH_POLL.as_millis()) as u32;
    retry_while_busy(utils::instance::acquire, tries, || std::thread::sleep(RELAUNCH_POLL))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use utils::instance::Acquire;

    fn has(files: &'static [&'static str]) -> impl Fn(&Path) -> bool {
        move |p| files.iter().any(|f| Path::new(f) == p)
    }

    #[test]
    fn windows_installed_copy_self_updates_and_portable_does_not() {
        // Forward slashes so the test reads the same on every host OS.
        let exe = PathBuf::from("C:/Users/a/AppData/Local/Hawser/hawser.exe");
        let uninstall = exe.parent().unwrap().join("uninstall.exe");
        let probe = move |p: &Path| p == uninstall;
        assert_eq!(classify(Os::Windows, &exe, None, &probe).kind, Kind::SelfUpdate);
        let portable = PathBuf::from("D:/tools/hawser.exe");
        let k = classify(Os::Windows, &portable, None, &probe);
        assert_eq!(k.kind, Kind::Manual);
        assert!(k.reason.contains("portable"));
    }

    #[test]
    fn linux_appimage_self_updates_deb_does_not() {
        let exe = Path::new("/usr/bin/hawser");
        let k = classify(Os::Linux, exe, None, has(&[]));
        assert_eq!(k.kind, Kind::Manual);
        assert!(k.reason.contains(".deb"));
        let img = OsStr::new("/home/a/Apps/Hawser.AppImage");
        assert_eq!(classify(Os::Linux, Path::new("/tmp/.mount_x/usr/bin/hawser"), Some(img), has(&["/home/a/Apps/Hawser.AppImage"])).kind, Kind::SelfUpdate);
        // A stale or empty APPIMAGE (inherited from another AppImage) is not ours.
        assert_eq!(classify(Os::Linux, exe, Some(img), has(&[])).kind, Kind::Manual);
        assert_eq!(classify(Os::Linux, exe, Some(OsStr::new("")), has(&[""])).kind, Kind::Manual);
    }

    #[test]
    fn macos_needs_a_writable_app_bundle() {
        let ok = Path::new("/Applications/Hawser.app/Contents/MacOS/hawser");
        assert_eq!(classify(Os::MacOs, ok, None, has(&[])).kind, Kind::SelfUpdate);
        let dmg = Path::new("/Volumes/Hawser/Hawser.app/Contents/MacOS/hawser");
        assert_eq!(classify(Os::MacOs, dmg, None, has(&[])).kind, Kind::Manual);
        let tr = Path::new("/private/var/folders/x/AppTranslocation/ABC/d/Hawser.app/Contents/MacOS/hawser");
        assert_eq!(classify(Os::MacOs, tr, None, has(&[])).kind, Kind::Manual);
        let dev = Path::new("/Users/a/src/hawser/src-tauri/target/debug/hawser");
        assert_eq!(classify(Os::MacOs, dev, None, has(&[])).kind, Kind::Manual);
        assert_eq!(classify(Os::Other, dev, None, has(&[])).kind, Kind::Manual);
    }

    #[test]
    fn install_kind_serialises_as_self_or_manual() {
        let v = serde_json::to_value(self_update("x")).unwrap();
        assert_eq!(v, serde_json::json!({ "kind": "self", "reason": "x" }));
        assert_eq!(serde_json::to_value(manual("y")).unwrap()["kind"], "manual");
    }

    #[test]
    fn relaunch_waits_while_busy_then_takes_the_lock() {
        let dir = std::env::temp_dir().join(format!("hawser-relaunch-{}", utils::artifacts::random_hex(6)));
        let path = dir.join(utils::instance::LOCK_FILE);
        let first = utils::instance::acquire_at(&path).unwrap();
        assert!(matches!(first, Acquire::Held(_)));
        let mut holder = Some(first);
        let mut sleeps = 0;
        let r = retry_while_busy(
            || utils::instance::acquire_at(&path).map_err(|e| e.to_string()),
            50,
            || {
                sleeps += 1;
                if sleeps == 3 {
                    holder.take(); // the old process exits
                }
            },
        );
        assert!(matches!(r, Ok(Acquire::Held(_))));
        assert_eq!(sleeps, 3);
        drop(r);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn relaunch_gives_up_after_the_budget_and_errors_pass_through() {
        let mut n = 0;
        let r = retry_while_busy(
            || {
                n += 1;
                Ok(Acquire::Busy)
            },
            4,
            || {},
        );
        assert!(matches!(r, Ok(Acquire::Busy)));
        assert_eq!(n, 4);
        let mut m = 0;
        let r = retry_while_busy(
            || {
                m += 1;
                Err("disk".to_string())
            },
            4,
            || {},
        );
        assert!(r.is_err());
        assert_eq!(m, 1);
    }

    #[test]
    fn only_a_restart_code_marks_the_relaunch() {
        // Serialised through one test so the env var is not raced.
        std::env::remove_var(RELAUNCH_ENV);
        mark_relaunch(Some(0));
        mark_relaunch(None);
        assert!(std::env::var_os(RELAUNCH_ENV).is_none());
        mark_relaunch(Some(tauri::RESTART_EXIT_CODE));
        assert!(std::env::var_os(RELAUNCH_ENV).is_some());
        std::env::remove_var(RELAUNCH_ENV);
    }
}
