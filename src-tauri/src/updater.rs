//! Self-update support around tauri-plugin-updater.
//!
//! The plugin does the work that matters for safety: it fetches `latest.json`
//! from the GitHub release, downloads the bundle, and verifies its minisign
//! signature against the public key in tauri.conf.json before installing
//! anything. Nothing here touches that path or can bypass it.
//!
//! What this module adds:
//! - `update_install_kind`: whether this copy can replace itself. The portable
//!   Windows exe, the Linux .deb and a macOS bundle on a read-only disk cannot
//!   (the updater would install an NSIS copy beside the portable one, need
//!   root for the package, or fail to move the bundle), so the UI links to the
//!   releases page for those instead.
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

/// The NSIS installer's uninstall key (HKCU for a per-user install, HKLM for
/// a per-machine one); `InstallLocation` holds the quoted install folder.
/// "Hawser" is `productName` in tauri.conf.json.
#[cfg_attr(not(windows), allow(dead_code))]
const NSIS_UNINSTALL_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\Hawser";

/// Can this process replace files in a folder?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirAccess {
    Writable,
    /// Not writable by this user, but the filesystem is: the macOS updater
    /// then asks for an administrator password and moves the bundle as root.
    NeedsAdmin,
    /// A read-only filesystem (a mounted disk image, App Translocation) or a
    /// folder that could not be probed. Nothing can update in place.
    ReadOnly,
}

/// What `classify` needs from the system, so it stays testable.
pub trait Probe {
    fn is_file(&self, path: &Path) -> bool;
    /// Install folders the NSIS installer recorded in the registry.
    fn nsis_install_dirs(&self) -> Vec<String>;
    fn dir_access(&self, dir: &Path) -> DirAccess;
}

/// Compare Windows folder paths: quotes, a `\\?\` prefix, separators,
/// trailing separators and ASCII case do not matter.
fn same_windows_dir(a: &str, b: &str) -> bool {
    fn norm(s: &str) -> String {
        let s = s.trim().trim_matches('"').replace('/', "\\");
        let s = s.strip_prefix(r"\\?\").unwrap_or(&s);
        s.trim_end_matches('\\').to_ascii_lowercase()
    }
    let (a, b) = (norm(a), norm(b));
    !a.is_empty() && a == b
}

/// Decide how this copy is updated. Pure: the caller supplies the running
/// executable, the `APPIMAGE` variable and a system probe.
///
/// - Windows: the NSIS installer writes `uninstall.exe` beside `hawser.exe`
///   AND records that folder as `InstallLocation` under its uninstall key.
///   Both must hold; a copy beside some other `uninstall.exe`, or a copy of
///   an installed folder moved elsewhere, is treated as portable.
/// - Linux: only an AppImage (the AppImage runtime sets `APPIMAGE`) can be
///   replaced; anything else is the .deb or a build from source.
/// - macOS: the executable must be inside `<name>.app/Contents/MacOS`, and the
///   folder holding the bundle must be on a writable filesystem (the updater
///   moves the bundle out and the new one in there). A disk image or App
///   Translocation is read-only, wherever it is mounted.
pub fn classify(os: Os, exe: &Path, appimage: Option<&OsStr>, probe: &impl Probe) -> InstallKind {
    match os {
        Os::Windows => {
            let dir = exe.parent().unwrap_or(exe);
            let has_uninstaller = probe.is_file(&dir.join("uninstall.exe"));
            let dir_s = dir.to_string_lossy();
            let registered = probe.nsis_install_dirs().iter().any(|d| same_windows_dir(d, &dir_s));
            match (has_uninstaller, registered) {
                (true, true) => self_update("installed with the Windows installer"),
                (true, false) => manual("portable copy (this folder is not where Windows lists Hawser as installed)"),
                (false, _) => manual("portable copy (not installed with the Windows installer)"),
            }
        }
        Os::Linux => match appimage {
            Some(p) if !p.is_empty() && probe.is_file(Path::new(p)) => self_update("AppImage"),
            _ => manual("installed from a .deb package or built from source"),
        },
        Os::MacOs => {
            let bundle = exe
                .parent()
                .filter(|d| d.file_name() == Some(OsStr::new("MacOS")))
                .and_then(Path::parent)
                .filter(|d| d.file_name() == Some(OsStr::new("Contents")))
                .and_then(Path::parent)
                .filter(|d| d.extension() == Some(OsStr::new("app")));
            let Some(folder) = bundle.and_then(Path::parent) else {
                return manual("not running from an app bundle");
            };
            match probe.dir_access(folder) {
                DirAccess::Writable => self_update("app bundle"),
                DirAccess::NeedsAdmin => self_update("app bundle (installing asks for an administrator password)"),
                DirAccess::ReadOnly => {
                    // The decision is made; the path only picks the advice.
                    let s = exe.to_string_lossy();
                    if s.contains("/AppTranslocation/") {
                        manual("macOS is running this copy from a read-only location; move it to Applications")
                    } else if s.starts_with("/Volumes/") {
                        manual("running from a read-only disk; drag Hawser to Applications first")
                    } else {
                        manual("Hawser's folder is read-only; move Hawser to Applications")
                    }
                }
            }
        }
        Os::Other => manual("self-update is not supported on this platform"),
    }
}

/// Probe a folder by creating (and removing) a uniquely named file in it.
pub fn probe_dir_access(dir: &Path) -> DirAccess {
    let path = dir.join(format!(".hawser-update-probe-{}", utils::artifacts::random_hex(8)));
    match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(f) => {
            drop(f);
            let _ = std::fs::remove_file(&path);
            DirAccess::Writable
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => DirAccess::NeedsAdmin,
        // ReadOnlyFilesystem (EROFS) and anything unexpected.
        Err(_) => DirAccess::ReadOnly,
    }
}

/// The real system.
struct System;

impl Probe for System {
    fn is_file(&self, path: &Path) -> bool {
        path.is_file()
    }

    fn nsis_install_dirs(&self) -> Vec<String> {
        #[cfg(windows)]
        {
            win::install_locations(NSIS_UNINSTALL_KEY)
        }
        #[cfg(not(windows))]
        {
            Vec::new()
        }
    }

    fn dir_access(&self, dir: &Path) -> DirAccess {
        probe_dir_access(dir)
    }
}

#[cfg(windows)]
mod win {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ,
        KEY_WOW64_64KEY, REG_EXPAND_SZ, REG_SZ,
    };

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// `InstallLocation` under `sub` in HKCU and HKLM, where present.
    pub fn install_locations(sub: &str) -> Vec<String> {
        [HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE].into_iter().filter_map(|root| read(root, sub, "InstallLocation")).collect()
    }

    fn read(root: HKEY, sub: &str, value: &str) -> Option<String> {
        let sub_w = wide(sub);
        let value_w = wide(value);
        let mut h: HKEY = std::ptr::null_mut();
        // SAFETY: `sub_w` is NUL-terminated and outlives the call; `h` is a
        // valid out pointer.
        if unsafe { RegOpenKeyExW(root, sub_w.as_ptr(), 0, KEY_READ | KEY_WOW64_64KEY, &mut h) } != ERROR_SUCCESS {
            return None;
        }
        let mut ty = 0u32;
        let mut buf = vec![0u16; 1024];
        let mut len = (buf.len() * 2) as u32;
        // SAFETY: `h` is open; buffer and length describe the same allocation.
        let rc = unsafe {
            RegQueryValueExW(h, value_w.as_ptr(), std::ptr::null(), &mut ty, buf.as_mut_ptr() as *mut u8, &mut len)
        };
        // SAFETY: `h` came from a successful RegOpenKeyExW and is closed once.
        unsafe { RegCloseKey(h) };
        if rc != ERROR_SUCCESS || (ty != REG_SZ && ty != REG_EXPAND_SZ) {
            return None;
        }
        let units = &buf[..((len as usize) / 2).min(buf.len())];
        let units = units.iter().position(|&c| c == 0).map_or(units, |z| &units[..z]);
        Some(String::from_utf16_lossy(units))
    }
}

/// `classify` for this process.
pub fn current_install_kind() -> InstallKind {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => return manual(&format!("could not locate the running program ({e})")),
    };
    let appimage = std::env::var_os("APPIMAGE");
    classify(Os::current(), &exe, appimage.as_deref(), &System)
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

    /// A fake system: these files exist, these install folders are in the
    /// registry, and folders are writable unless listed otherwise.
    struct Fake {
        files: Vec<PathBuf>,
        nsis: Vec<String>,
        access: Vec<(PathBuf, DirAccess)>,
    }

    impl Fake {
        fn new() -> Self {
            Fake { files: vec![], nsis: vec![], access: vec![] }
        }
        fn file(mut self, p: impl Into<PathBuf>) -> Self {
            self.files.push(p.into());
            self
        }
        fn nsis(mut self, d: &str) -> Self {
            self.nsis.push(d.into());
            self
        }
        fn dir(mut self, d: &str, a: DirAccess) -> Self {
            self.access.push((d.into(), a));
            self
        }
    }

    impl Probe for Fake {
        fn is_file(&self, p: &Path) -> bool {
            self.files.iter().any(|f| f == p)
        }
        fn nsis_install_dirs(&self) -> Vec<String> {
            self.nsis.clone()
        }
        fn dir_access(&self, d: &Path) -> DirAccess {
            self.access.iter().find(|(p, _)| p == d).map_or(DirAccess::Writable, |(_, a)| *a)
        }
    }

    #[test]
    fn windows_self_update_needs_the_uninstaller_and_the_registry_entry() {
        // Forward slashes so the test reads the same on every host OS.
        let exe = PathBuf::from("C:/Users/a/AppData/Local/Hawser/hawser.exe");
        let uninstall = exe.parent().unwrap().join("uninstall.exe");
        // What NSIS writes: the folder, quoted, backslashed.
        let reg = r#""C:\Users\a\AppData\Local\Hawser""#;
        let installed = Fake::new().file(&uninstall).nsis(reg);
        assert_eq!(classify(Os::Windows, &exe, None, &installed).kind, Kind::SelfUpdate);

        // An unrelated uninstall.exe beside a portable copy, Hawser not installed.
        let k = classify(Os::Windows, &exe, None, &Fake::new().file(&uninstall));
        assert_eq!(k.kind, Kind::Manual);
        assert!(k.reason.contains("not where Windows lists Hawser"), "{}", k.reason);

        // Hawser is installed, but this is a copy in another folder that
        // happens to sit beside an uninstaller.
        let tools = PathBuf::from("D:/tools/hawser.exe");
        let k = classify(Os::Windows, &tools, None, &Fake::new().file("D:/tools/uninstall.exe").nsis(reg));
        assert_eq!(k.kind, Kind::Manual);

        // Registered, but the uninstaller is gone: not a working install.
        let k = classify(Os::Windows, &exe, None, &Fake::new().nsis(reg));
        assert_eq!(k.kind, Kind::Manual);
        assert!(k.reason.contains("portable"));
        assert_eq!(classify(Os::Windows, &tools, None, &Fake::new()).kind, Kind::Manual);
    }

    #[test]
    fn windows_install_folders_compare_loosely_but_exactly() {
        assert!(same_windows_dir(r#""C:\Program Files\Hawser""#, "C:/program files/hawser"));
        assert!(same_windows_dir(r"\\?\C:\Hawser\", r"c:\hawser"));
        assert!(!same_windows_dir(r"C:\Hawser2", r"C:\Hawser"));
        assert!(!same_windows_dir(r"C:\Hawser\sub", r"C:\Hawser"));
        assert!(!same_windows_dir(r#""""#, ""), "an empty value matches nothing");
    }

    #[test]
    fn linux_appimage_self_updates_deb_does_not() {
        let exe = Path::new("/usr/bin/hawser");
        let k = classify(Os::Linux, exe, None, &Fake::new());
        assert_eq!(k.kind, Kind::Manual);
        assert!(k.reason.contains(".deb"));
        let img = OsStr::new("/home/a/Apps/Hawser.AppImage");
        let has_img = Fake::new().file("/home/a/Apps/Hawser.AppImage");
        assert_eq!(classify(Os::Linux, Path::new("/tmp/.mount_x/usr/bin/hawser"), Some(img), &has_img).kind, Kind::SelfUpdate);
        // A stale or empty APPIMAGE (inherited from another AppImage) is not ours.
        assert_eq!(classify(Os::Linux, exe, Some(img), &Fake::new()).kind, Kind::Manual);
        assert_eq!(classify(Os::Linux, exe, Some(OsStr::new("")), &Fake::new().file("")).kind, Kind::Manual);
    }

    #[test]
    fn macos_decides_by_whether_the_bundle_folder_is_writable() {
        let ok = Path::new("/Applications/Hawser.app/Contents/MacOS/hawser");
        assert_eq!(classify(Os::MacOs, ok, None, &Fake::new()).kind, Kind::SelfUpdate);
        // A standard user: /Applications is not theirs, the updater prompts.
        let admin = Fake::new().dir("/Applications", DirAccess::NeedsAdmin);
        let k = classify(Os::MacOs, ok, None, &admin);
        assert_eq!(k.kind, Kind::SelfUpdate);
        assert!(k.reason.contains("administrator"));
        // Read-only anywhere is manual, not just at the known paths.
        let elsewhere = Path::new("/Users/a/Desktop/Hawser.app/Contents/MacOS/hawser");
        let k = classify(Os::MacOs, elsewhere, None, &Fake::new().dir("/Users/a/Desktop", DirAccess::ReadOnly));
        assert_eq!(k.kind, Kind::Manual);
        assert!(k.reason.contains("read-only"));
        // A writable external disk under /Volumes self-updates.
        let ext = Path::new("/Volumes/Work/Apps/Hawser.app/Contents/MacOS/hawser");
        assert_eq!(classify(Os::MacOs, ext, None, &Fake::new()).kind, Kind::SelfUpdate);
        let dmg = Path::new("/Volumes/Hawser/Hawser.app/Contents/MacOS/hawser");
        let k = classify(Os::MacOs, dmg, None, &Fake::new().dir("/Volumes/Hawser", DirAccess::ReadOnly));
        assert_eq!(k.kind, Kind::Manual);
        assert!(k.reason.contains("drag Hawser"));
        let tr = Path::new("/private/var/folders/x/AppTranslocation/ABC/d/Hawser.app/Contents/MacOS/hawser");
        let k = classify(Os::MacOs, tr, None, &Fake::new().dir("/private/var/folders/x/AppTranslocation/ABC/d", DirAccess::ReadOnly));
        assert_eq!(k.kind, Kind::Manual);
        assert!(k.reason.contains("move it to Applications"));
        let dev = Path::new("/Users/a/src/hawser/src-tauri/target/debug/hawser");
        assert_eq!(classify(Os::MacOs, dev, None, &Fake::new()).kind, Kind::Manual);
        let not_app = Path::new("/Users/a/Hawser/Contents/MacOS/hawser");
        assert_eq!(classify(Os::MacOs, not_app, None, &Fake::new()).kind, Kind::Manual);
        assert_eq!(classify(Os::Other, dev, None, &Fake::new()).kind, Kind::Manual);
    }

    #[test]
    fn the_folder_probe_sees_writable_and_missing_folders_and_cleans_up() {
        let dir = std::env::temp_dir().join(format!("hawser-probe-{}", utils::artifacts::random_hex(6)));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(probe_dir_access(&dir), DirAccess::Writable);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0, "the probe file is removed");
        assert_eq!(probe_dir_access(&dir.join("missing")), DirAccess::ReadOnly);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let locked = dir.join("locked");
            std::fs::create_dir(&locked).unwrap();
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o555)).unwrap();
            // Root ignores the mode bits; only check as an ordinary user.
            if probe_dir_access(&locked) != DirAccess::Writable {
                assert_eq!(probe_dir_access(&locked), DirAccess::NeedsAdmin);
            }
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let _ = std::fs::remove_dir_all(&dir);
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
