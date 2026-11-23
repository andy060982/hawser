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

    #[cfg(unix)]
    #[test]
    fn the_lock_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let p = tmp();
        let _held = acquire_at(&p).unwrap();
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
    }
}
