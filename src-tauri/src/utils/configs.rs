//! Device configuration snapshots and diffs.
//!
//! The most-asked question in network operations is "what changed on this box
//! since it last worked". Snapshots answer it: run the device's config-dump
//! command, store the output timestamped under
//! `%APPDATA%\skiff\configs\<host>\`, and diff any two.
//!
//! Storage is one plain text file per snapshot — no database, no custom
//! format — so the archive stays greppable and usable by other tools (or by
//! the user in a panic at 2 AM) without Skiff involved.

use std::path::{Component, Path, PathBuf};

use serde::Serialize;

use super::known_hosts::KnownHostsError;

/// Reuse the transcript slug + timestamp conventions so all per-host artifacts
/// look alike on disk.
fn slug(s: &str) -> String {
    let out: String = s
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '.' { c } else { '_' })
        .collect();
    // Keeping '.' allows normal hostnames, but a slug that is all dots ("."/"..")
    // would be a path-traversal component. Neutralise those so `configs_dir`
    // can never escape the configs root.
    if out.chars().all(|c| c == '.') {
        "_".repeat(out.len().max(1))
    } else {
        out
    }
}

fn configs_dir(host: &str) -> Result<PathBuf, KnownHostsError> {
    let store = super::known_hosts::store_path()?;
    Ok(store
        .parent()
        .ok_or(KnownHostsError::NoAppDataDir)?
        .join("configs")
        .join(slug(host)))
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotInfo {
    /// Bare filename; also the id for reads. Never a path.
    pub name: String,
    pub bytes: u64,
    pub modified: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotResult {
    pub name: String,
    pub lines: usize,
    /// Lines added/removed vs the previous snapshot; None on the first one.
    pub added: Option<usize>,
    pub removed: Option<usize>,
}

/// Store a new snapshot and report how it differs from the newest previous one.
pub fn save_snapshot(host: &str, content: &str) -> Result<SnapshotResult, KnownHostsError> {
    let dir = configs_dir(host)?;
    std::fs::create_dir_all(&dir).map_err(|source| KnownHostsError::Io {
        path: dir.clone(),
        source,
    })?;
    // A device config dump can hold SNMP communities, pre-shared keys, and other
    // secrets, so keep the per-host snapshot directory owner-only.
    super::platform::restrict_perms(&dir, 0o700);

    // Read the previous snapshot's contents up front: if the new one were
    // ever written over it, a later read would diff the new content against
    // itself and report a bogus 0/0.
    let previous = newest(&dir).map(|p| std::fs::read_to_string(&p).unwrap_or_default());

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let name = write_new_snapshot(&dir, &super::session_log::timestamp_for(now), content)?;

    let (added, removed) = match previous {
        Some(old) => {
            let diff = similar::TextDiff::from_lines(old.as_str(), content);
            let mut a = 0usize;
            let mut r = 0usize;
            for change in diff.iter_all_changes() {
                match change.tag() {
                    similar::ChangeTag::Insert => a += 1,
                    similar::ChangeTag::Delete => r += 1,
                    similar::ChangeTag::Equal => {}
                }
            }
            (Some(a), Some(r))
        }
        None => (None, None),
    };

    Ok(SnapshotResult {
        name,
        lines: content.lines().count(),
        added,
        removed,
    })
}

/// Create `<base>.txt` in `dir` exclusively and owner-only, returning the bare
/// filename used. Snapshot names have one-second resolution, so two snapshots
/// in the same second would otherwise collide: create_new(true) refuses an
/// existing path and a numeric suffix is bumped instead (as captures.rs does),
/// so an earlier snapshot is never clobbered. Mode 0600 at open time keeps a
/// config dump (SNMP communities, PSKs) from ever being group/world-readable.
fn write_new_snapshot(dir: &Path, base: &str, content: &str) -> Result<String, KnownHostsError> {
    use std::io::Write;
    let mut name = format!("{base}.txt");
    let mut n: u32 = 0;
    let mut file = loop {
        let path = dir.join(&name);
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        match opts.open(&path) {
            Ok(f) => break f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && n < 1000 => {
                n += 1;
                name = format!("{base}.{n}.txt");
            }
            Err(source) => return Err(KnownHostsError::Io { path, source }),
        }
    };
    file.write_all(content.as_bytes()).map_err(|source| KnownHostsError::Io {
        path: dir.join(&name),
        source,
    })?;
    Ok(name)
}

fn newest(dir: &PathBuf) -> Option<PathBuf> {
    std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().ends_with(".txt"))
        .max_by_key(|e| e.metadata().and_then(|m| m.modified()).ok())
        .map(|e| e.path())
}

pub fn list_snapshots(host: &str) -> Result<Vec<SnapshotInfo>, KnownHostsError> {
    let dir = match configs_dir(host) {
        Ok(d) if d.exists() => d,
        _ => return Ok(Vec::new()),
    };
    let mut out: Vec<SnapshotInfo> = std::fs::read_dir(&dir)
        .map_err(|source| KnownHostsError::Io { path: dir.clone(), source })?
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().ends_with(".txt"))
        .map(|e| {
            let meta = e.metadata().ok();
            SnapshotInfo {
                name: e.file_name().to_string_lossy().to_string(),
                bytes: meta.as_ref().map(|m| m.len()).unwrap_or(0),
                modified: meta
                    .and_then(|m| m.modified().ok())
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs()),
            }
        })
        .collect();
    out.sort_by(|a, b| b.modified.cmp(&a.modified));
    Ok(out)
}

fn checked(dir: &PathBuf, name: &str) -> Result<PathBuf, KnownHostsError> {
    // The name must be exactly one plain path component. Besides separators and
    // "..", reject ':' — on Windows a drive-relative name like "D:x.txt" has a
    // prefix, and Path::join with a prefixed path REPLACES the base, escaping
    // the configs dir. The single-Normal-component check backs that up.
    let single_normal = matches!(
        Path::new(name).components().collect::<Vec<_>>().as_slice(),
        [Component::Normal(_)]
    );
    if !single_normal
        || name.contains('/')
        || name.contains('\\')
        || name.contains(':')
        || name.contains("..")
        || !name.ends_with(".txt")
    {
        return Err(KnownHostsError::Parse(format!("invalid snapshot name: {name}")));
    }
    Ok(dir.join(name))
}

/// Unified diff between two snapshots, oldest first, for the viewer.
pub fn diff_snapshots(host: &str, older: &str, newer: &str) -> Result<String, KnownHostsError> {
    let dir = configs_dir(host)?;
    let read = |n: &str| -> Result<String, KnownHostsError> {
        let p = checked(&dir, n)?;
        std::fs::read_to_string(&p).map_err(|source| KnownHostsError::Io { path: p, source })
    };
    let old = read(older)?;
    let new = read(newer)?;

    let diff = similar::TextDiff::from_lines(&old, &new);
    Ok(diff
        .unified_diff()
        .context_radius(3)
        .header(older, newer)
        .to_string())
}

pub fn read_snapshot(host: &str, name: &str) -> Result<String, KnownHostsError> {
    let dir = configs_dir(host)?;
    let p = checked(&dir, name)?;
    std::fs::read_to_string(&p).map_err(|source| KnownHostsError::Io { path: p, source })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_accepts_plain_snapshot_names() {
        let dir = PathBuf::from("configs");
        assert_eq!(
            checked(&dir, "20261030-120000.txt").unwrap(),
            dir.join("20261030-120000.txt")
        );
        assert!(checked(&dir, "20261030-120000.1.txt").is_ok());
    }

    #[test]
    fn checked_rejects_escapes() {
        let dir = PathBuf::from("configs");
        for bad in [
            "D:secrets.txt",
            "C:\\x.txt",
            "../x.txt",
            "a/b.txt",
            "a\\b.txt",
            "/abs.txt",
            "x.log",
            "",
            ".txt/..",
        ] {
            assert!(checked(&dir, bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn same_second_snapshots_do_not_overwrite() {
        let dir = std::env::temp_dir().join(format!(
            "skiff-configs-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let a = write_new_snapshot(&dir, "20261030-120000", "one\n").unwrap();
        let b = write_new_snapshot(&dir, "20261030-120000", "two\n").unwrap();
        assert_eq!(a, "20261030-120000.txt");
        assert_eq!(b, "20261030-120000.1.txt");
        assert_eq!(std::fs::read_to_string(dir.join(&a)).unwrap(), "one\n");
        assert_eq!(std::fs::read_to_string(dir.join(&b)).unwrap(), "two\n");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
