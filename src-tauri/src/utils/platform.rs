//! Small OS-integration shims kept behind one API so the rest of the backend
//! stays platform-agnostic.
//!
//! Each opens a **fixed or Rust-computed** path — never a webview-supplied
//! string used as a shell target — so this stays a "reveal this folder"
//! primitive, not a general execute-anything one.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The file-manager program for the current platform.
#[cfg(target_os = "windows")]
const FILE_MANAGER: &str = "explorer";
#[cfg(target_os = "macos")]
const FILE_MANAGER: &str = "open";
#[cfg(all(unix, not(target_os = "macos")))]
const FILE_MANAGER: &str = "xdg-open";

/// Start a helper program and reap it in the background, so it never stays
/// behind as a zombie (`open` / `xdg-open` exit at once; explorer may not).
fn spawn_reaped(cmd: &mut Command) -> std::io::Result<()> {
    reaped(cmd).map(|_| ())
}

/// The child's exit, as collected by its reaper thread.
type Reaper = std::thread::JoinHandle<Option<std::process::ExitStatus>>;

fn reaped(cmd: &mut Command) -> std::io::Result<Option<Reaper>> {
    let child = std::sync::Arc::new(std::sync::Mutex::new(cmd.spawn()?));
    let waiter = std::sync::Arc::clone(&child);
    match std::thread::Builder::new()
        .name("hawser-reap".into())
        .spawn(move || waiter.lock().ok()?.wait().ok())
    {
        Ok(h) => Ok(Some(h)),
        Err(e) => {
            // No thread to wait on it: the helper is short-lived, so wait for
            // it here instead (callers run off the async runtime).
            eprintln!("hawser: could not start a reaper thread ({e}); waiting inline");
            if let Ok(mut c) = child.lock() {
                let _ = c.wait();
            }
            Ok(None)
        }
    }
}

/// Open a directory in the platform's file manager.
pub fn open_dir(path: &Path) -> std::io::Result<()> {
    spawn_reaped(Command::new(FILE_MANAGER).arg(path))
}

/// Reveal (and, where supported, select) a single file in the file manager.
///
/// Windows and macOS can select the file itself; Linux has no portable
/// select-in-file-manager, so it opens the containing folder instead.
pub fn reveal_file(path: &Path) -> std::io::Result<()> {
    #[cfg(target_os = "windows")]
    {
        spawn_reaped(Command::new("explorer").arg("/select,").arg(path))
    }
    #[cfg(target_os = "macos")]
    {
        spawn_reaped(Command::new("open").arg("-R").arg(path))
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let dir = path.parent().unwrap_or(path);
        spawn_reaped(Command::new("xdg-open").arg(dir))
    }
}

/// Restrict a path to the owner only — `0700` for a directory, `0600` for a
/// file. Best-effort: a failure to chmod must not sink the operation that
/// created the path, so the result is discarded.
///
/// Unix only. On Windows these artifacts live under the per-user profile, whose
/// ACLs already exclude other standard users; tightening NTFS ACLs further is a
/// separate, larger change and not what this bug is about.
#[cfg(unix)]
pub fn restrict_perms(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}

#[cfg(not(unix))]
pub fn restrict_perms(_path: &Path, _mode: u32) {}

/// The current user's home directory, resolved through the platform's own
/// environment variable (`USERPROFILE` on Windows, `HOME` on macOS/Linux).
/// Keeping this in one place stops Windows-only assumptions (`USERPROFILE`)
/// from leaking into cross-platform code paths like key generation.
pub fn home_dir() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    let var = std::env::var_os("USERPROFILE");
    #[cfg(not(target_os = "windows"))]
    let var = std::env::var_os("HOME");
    // Treat a set-but-EMPTY value as absent: an empty home would otherwise make
    // ssh_keygen write ".ssh" relative to the current directory rather than fail.
    var.filter(|v| !v.is_empty()).map(PathBuf::from)
}

/// Best-effort user "Documents" directory for exports. Falls back to the home
/// directory when there is no Documents folder.
///
/// On Windows this is the shell's FOLDERID_Documents, which follows OneDrive
/// Known Folder Move and enterprise folder redirection; `%USERPROFILE%\Documents`
/// is only the fallback when the shell cannot answer.
pub fn documents_dir() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        known_documents().or_else(|| home_dir().map(|p| p.join("Documents")))
    }
    #[cfg(not(target_os = "windows"))]
    {
        home_dir().map(|home| {
            let docs = home.join("Documents");
            if docs.is_dir() {
                docs
            } else {
                home
            }
        })
    }
}

/// FOLDERID_Documents via SHGetKnownFolderPath.
#[cfg(target_os = "windows")]
fn known_documents() -> Option<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{FOLDERID_Documents, SHGetKnownFolderPath, KF_FLAG_DEFAULT};

    let mut raw: windows_sys::core::PWSTR = std::ptr::null_mut();
    // SAFETY: a valid GUID pointer, no token (the current user), and an
    // out-pointer the shell fills with a CoTaskMemAlloc'd, NUL-terminated
    // string that is freed below on every path (CoTaskMemFree accepts NULL).
    let hr = unsafe {
        SHGetKnownFolderPath(&FOLDERID_Documents, KF_FLAG_DEFAULT as u32, std::ptr::null_mut(), &mut raw)
    };
    let path = if hr >= 0 && !raw.is_null() {
        // SAFETY: `raw` is NUL-terminated (documented contract of the API).
        let len = unsafe { (0..).take_while(|&i| *raw.add(i) != 0).count() };
        // SAFETY: `len` u16s precede the terminator.
        let wide = unsafe { std::slice::from_raw_parts(raw, len) };
        Some(PathBuf::from(std::ffi::OsString::from_wide(wide)))
    } else {
        None
    };
    // SAFETY: allocated by the shell (or NULL); freed exactly once.
    unsafe { CoTaskMemFree(raw as *const core::ffi::c_void) };
    path.filter(|p| !p.as_os_str().is_empty())
}

#[cfg(test)]
mod tests {
    #[test]
    fn documents_dir_resolves_to_an_absolute_path() {
        if let Some(p) = super::documents_dir() {
            assert!(p.is_absolute(), "{}", p.display());
        }
    }

    #[cfg(unix)]
    #[test]
    fn helpers_are_reaped_not_left_as_zombies() {
        let mut cmd = std::process::Command::new("/bin/sh");
        cmd.args(["-c", "exit 3"]);
        let reaper = super::reaped(&mut cmd).unwrap().expect("a reaper thread");
        // The reaper collected the exit status: no zombie is left.
        assert_eq!(reaper.join().unwrap().and_then(|s| s.code()), Some(3));
    }
}
