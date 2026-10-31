//! Device configuration snapshots and diffs.
//!
//! The most-asked question in network operations is "what changed on this box
//! since it last worked". Snapshots answer it: run the device's config-dump
//! command, store the output timestamped under
//! `%APPDATA%\hawser\configs\<host>\`, and diff any two.
//!
//! Storage is one plain text file per snapshot — no database, no custom
//! format — so the archive stays greppable and usable by other tools (or by
//! the user in a panic at 2 AM) without Hawser involved.

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
            let (a, r) = line_delta(&old, content);
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

/// (lines added, lines removed) going from `old` to `new`.
fn line_delta(old: &str, new: &str) -> (usize, usize) {
    let diff = similar::TextDiff::from_lines(old, new);
    let (mut a, mut r) = (0usize, 0usize);
    for change in diff.iter_all_changes() {
        match change.tag() {
            similar::ChangeTag::Insert => a += 1,
            similar::ChangeTag::Delete => r += 1,
            similar::ChangeTag::Equal => {}
        }
    }
    (a, r)
}

/// Outcome of a "has this box changed since I last looked?" check.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ConfigCheck {
    /// "first" (no earlier snapshot: this one is the baseline), "unchanged"
    /// (identical to the newest snapshot: nothing saved), or "changed".
    pub status: &'static str,
    /// The snapshot saved by this check; None when unchanged.
    pub name: Option<String>,
    /// The newest snapshot before this check, and when it was taken.
    pub previous: Option<String>,
    pub previous_modified: Option<u64>,
    pub added: usize,
    pub removed: usize,
}

/// Compare a fresh capture with the newest stored snapshot, saving it only if
/// it differs. Unlike `save_snapshot` this never stores a duplicate, so it is
/// safe to run on every connect without piling up identical files.
pub fn check_snapshot(host: &str, content: &str) -> Result<ConfigCheck, KnownHostsError> {
    let dir = configs_dir(host)?;
    std::fs::create_dir_all(&dir).map_err(|source| KnownHostsError::Io {
        path: dir.clone(),
        source,
    })?;
    super::platform::restrict_perms(&dir, 0o700);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    check_in(&dir, content, &super::session_log::timestamp_for(now))
}

fn check_in(dir: &PathBuf, content: &str, stamp: &str) -> Result<ConfigCheck, KnownHostsError> {
    let prev = newest(dir).map(|p| {
        let modified = std::fs::metadata(&p)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs());
        let name = p.file_name().map(|n| n.to_string_lossy().to_string());
        (name, modified, std::fs::read_to_string(&p).unwrap_or_default())
    });
    let (previous, previous_modified) = match &prev {
        Some((n, m, _)) => (n.clone(), *m),
        None => (None, None),
    };
    // Line endings and trailing blank lines vary between captures of the same
    // config (exec channels, pagers); they are not a change.
    let norm = |t: &str| t.replace("\r\n", "\n").trim_end().to_string();
    let (status, added, removed) = match &prev {
        None => ("first", 0, 0),
        Some((_, _, old)) if norm(old) == norm(content) => {
            return Ok(ConfigCheck {
                status: "unchanged",
                name: None,
                previous,
                previous_modified,
                added: 0,
                removed: 0,
            })
        }
        Some((_, _, old)) => {
            let (a, r) = line_delta(old, content);
            ("changed", a, r)
        }
    };
    let name = write_new_snapshot(dir, stamp, content)?;
    Ok(ConfigCheck {
        status,
        name: Some(name),
        previous,
        previous_modified,
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

/// Chronological key of a snapshot name "YYYYMMDD-HHMMSS[.n].txt": the stamp,
/// then the numeric same-second suffix (absent = 0). Plain string order would
/// put ".1.txt" before ".txt".
fn name_order(name: &str) -> (String, u32) {
    let stem = name.strip_suffix(".txt").unwrap_or(name);
    match stem.rsplit_once('.') {
        Some((base, n)) if !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) => {
            (base.to_string(), n.parse().unwrap_or(u32::MAX))
        }
        _ => (stem.to_string(), 0),
    }
}

/// Newest snapshot by modified time, ties (same-second writes, coarse mtime
/// filesystems) broken by the name's own chronological order.
fn newest(dir: &PathBuf) -> Option<PathBuf> {
    std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().ends_with(".txt"))
        .max_by_key(|e| {
            (
                e.metadata().and_then(|m| m.modified()).ok(),
                name_order(&e.file_name().to_string_lossy()),
            )
        })
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

    fn tmp_dir() -> PathBuf {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let d = std::env::temp_dir().join(format!("hawser-cfg-test-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn same_second_suffixes_order_after_the_base_name() {
        let mut names = vec![
            "20261031-090000.1.txt",
            "20261031-090000.txt",
            "20261031-085959.txt",
            "20261031-090000.10.txt",
            "20261031-090000.2.txt",
        ];
        names.sort_by_key(|n| name_order(n));
        assert_eq!(
            names,
            [
                "20261031-085959.txt",
                "20261031-090000.txt",
                "20261031-090000.1.txt",
                "20261031-090000.2.txt",
                "20261031-090000.10.txt",
            ]
        );
    }

    #[test]
    fn check_compares_against_the_latest_same_second_snapshot() {
        let d = tmp_dir();
        check_in(&d, "a\n", "20261031-090000").unwrap();
        let second = check_in(&d, "b\n", "20261031-090000").unwrap(); // -> .1.txt
        assert_eq!(second.name.as_deref(), Some("20261031-090000.1.txt"));
        // Force identical mtimes, with the older name made to look newer by
        // nothing but the tie-break: name order must decide.
        let t = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_790_000_000);
        for n in ["20261031-090000.txt", "20261031-090000.1.txt"] {
            std::fs::File::options().write(true).open(d.join(n)).unwrap().set_modified(t).unwrap();
        }
        // Same mtime second: the tie-break must pick .1.txt as newest.
        let third = check_in(&d, "b\n", "20261031-090000").unwrap();
        assert_eq!(third.status, "unchanged");
        assert_eq!(third.previous.as_deref(), Some("20261031-090000.1.txt"));
    }

    #[test]
    fn check_saves_baseline_then_only_real_changes() {
        let d = tmp_dir();
        let first = check_in(&d, "hostname fw1\nntp server 1.1.1.1\n", "20261031-090000").unwrap();
        assert_eq!((first.status, first.previous.as_deref()), ("first", None));
        assert!(first.name.is_some());

        // Same config, different line endings / trailing newline: no new file.
        let same = check_in(&d, "hostname fw1\r\nntp server 1.1.1.1\r\n\r\n", "20261031-100000").unwrap();
        assert_eq!(same.status, "unchanged");
        assert_eq!(same.name, None);
        assert_eq!(same.previous, first.name);
        assert_eq!(std::fs::read_dir(&d).unwrap().count(), 1);

        let changed = check_in(&d, "hostname fw1\nntp server 9.9.9.9\nlogging host 10.0.0.5\n", "20261031-110000").unwrap();
        assert_eq!((changed.status, changed.added, changed.removed), ("changed", 2, 1));
        assert_eq!(changed.previous, first.name);
        assert_eq!(std::fs::read_dir(&d).unwrap().count(), 2);
    }

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
            "hawser-configs-test-{}-{}",
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
