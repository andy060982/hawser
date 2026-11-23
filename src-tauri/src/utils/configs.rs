//! Device configuration snapshots and diffs.
//!
//! The most-asked question in network operations is "what changed on this box
//! since it last worked". Snapshots answer it: run the device's config-dump
//! command, store the output timestamped under
//! `%APPDATA%\hawser\configs\<host>@<endpoint tag>\` (see `artifacts` for
//! why the folder is keyed by endpoint identity, not hostname), and diff any
//! two.
//!
//! Storage is one plain text file per snapshot — no database, no custom
//! format — so the archive stays greppable and usable by other tools (or by
//! the user in a panic at 2 AM) without Hawser involved.

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use serde::Serialize;

use super::artifacts;
use super::known_hosts::KnownHostsError;

/// Prefix of snapshot ids that live in a legacy (hostname-keyed) folder.
const LEGACY_PREFIX: &str = "legacy:";
/// Largest snapshot read back. Captures are capped at 16 MiB.
const MAX_SNAPSHOT_BYTES: u64 = 32 * 1024 * 1024;
/// Wall-clock budget for one diff. Myers/Patience cost grows with N·D, so two
/// large captures that differ almost everywhere could otherwise pin a thread
/// for minutes; past the deadline `similar` returns a coarser (still correct)
/// diff instead.
const DIFF_TIMEOUT: Duration = Duration::from_secs(2);
/// Largest diff text returned to the viewer, which renders one node per line.
const MAX_DIFF_OUT: usize = 2 * 1024 * 1024;

/// The pre-endpoint folder name: the hostname slug exactly as earlier builds
/// wrote it. Kept only to find those folders again.
fn legacy_slug(s: &str) -> String {
    let out: String = s
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '.' { c } else { '_' })
        .collect();
    if out.chars().all(|c| c == '.') {
        "_".repeat(out.len().max(1))
    } else {
        out
    }
}

fn configs_root() -> Result<PathBuf, KnownHostsError> {
    let store = super::known_hosts::store_path()?;
    Ok(store.parent().ok_or(KnownHostsError::NoAppDataDir)?.join("configs"))
}

/// This endpoint's snapshot folder (`configs/<host>@<tag>`, see `artifacts`).
fn configs_dir(endpoint: &str, label: &str) -> Result<PathBuf, KnownHostsError> {
    artifacts::validate_endpoint(endpoint)?;
    Ok(artifacts::endpoint_dir(&configs_root()?, label, endpoint))
}

/// The hostname-keyed folder earlier builds used, if it exists as a real
/// directory. It may hold snapshots of any entry that shared the hostname, so
/// it is only ever listed and read, never used as a baseline.
fn legacy_dir(label: &str) -> Option<PathBuf> {
    let dir = configs_root().ok()?.join(legacy_slug(label));
    match std::fs::symlink_metadata(&dir) {
        Ok(m) if m.is_dir() => Some(dir),
        _ => None,
    }
}

/// One lock per snapshot folder: compare-with-newest and publish must not
/// interleave, or two checks in the same second each compare against the same
/// baseline and both save.
fn dir_lock(dir: &Path) -> Arc<Mutex<()>> {
    static LOCKS: OnceLock<Mutex<HashMap<PathBuf, Arc<Mutex<()>>>>> = OnceLock::new();
    let mut map = LOCKS.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner());
    Arc::clone(map.entry(dir.to_path_buf()).or_default())
}

fn ensure_dir(dir: &Path) -> Result<(), KnownHostsError> {
    std::fs::create_dir_all(dir).map_err(|source| KnownHostsError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    // A device config dump can hold SNMP communities, pre-shared keys, and other
    // secrets, so keep the per-host snapshot directory owner-only.
    super::platform::restrict_perms(dir, 0o700);
    Ok(())
}

fn now_stamp() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    super::session_log::timestamp_for(now)
}

/// Read a snapshot as text. An unreadable previous snapshot is an error, not
/// an empty string: treating it as empty reported every line as added and
/// saved a duplicate.
fn read_text(path: &Path) -> Result<String, KnownHostsError> {
    let bytes = artifacts::read_regular_capped(path, MAX_SNAPSHOT_BYTES).map_err(|source| {
        KnownHostsError::Io { path: path.to_path_buf(), source }
    })?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotInfo {
    /// Snapshot id for reads: a bare filename, or `legacy:<filename>` for one in
    /// the old hostname-keyed folder. Never a path.
    pub name: String,
    pub bytes: u64,
    pub modified: Option<u64>,
    /// Recorded before endpoint keying; may come from another entry that
    /// shared this hostname.
    pub legacy: bool,
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
pub fn save_snapshot(endpoint: &str, label: &str, content: &str) -> Result<SnapshotResult, KnownHostsError> {
    let dir = configs_dir(endpoint, label)?;
    ensure_dir(&dir)?;
    save_in(&dir, content, &now_stamp())
}

fn save_in(dir: &Path, content: &str, stamp: &str) -> Result<SnapshotResult, KnownHostsError> {
    let lock = dir_lock(dir);
    let _held = lock.lock().unwrap_or_else(|e| e.into_inner());
    // Read the previous snapshot's contents up front: if the new one were
    // ever written over it, a later read would diff the new content against
    // itself and report a bogus 0/0.
    let previous = match newest(dir) {
        Some(p) => Some(read_text(&p)?),
        None => None,
    };
    let name = write_new_snapshot(dir, stamp, content)?;

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

/// Line endings and trailing blank lines vary between captures of the same
/// config (exec channels, pagers); they are not a change. Applied to BOTH sides
/// of every comparison: the equality check, the +/- counts and the diff, so a
/// CRLF capture against an LF one is not reported as the whole file changed.
fn norm(t: &str) -> String {
    let mut out = t.replace("\r\n", "\n").trim_end().to_string();
    if !out.is_empty() {
        out.push('\n');
    }
    out
}

fn bounded_line_diff<'a>(old: &'a str, new: &'a str) -> similar::TextDiff<'a, 'a, 'a, str> {
    similar::TextDiff::configure()
        .algorithm(similar::Algorithm::Patience)
        .timeout(DIFF_TIMEOUT)
        .diff_lines(old, new)
}

/// (lines added, lines removed) going from `old` to `new`.
fn line_delta(old: &str, new: &str) -> (usize, usize) {
    let (old, new) = (norm(old), norm(new));
    let diff = bounded_line_diff(&old, &new);
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
///
/// Only this endpoint's own folder is a baseline. A legacy hostname-keyed
/// folder is ignored here (it may be another device's), so the first check
/// after upgrading reports "first".
pub fn check_snapshot(endpoint: &str, label: &str, content: &str) -> Result<ConfigCheck, KnownHostsError> {
    let dir = configs_dir(endpoint, label)?;
    ensure_dir(&dir)?;
    check_in(&dir, content, &now_stamp())
}

fn check_in(dir: &Path, content: &str, stamp: &str) -> Result<ConfigCheck, KnownHostsError> {
    let lock = dir_lock(dir);
    let _held = lock.lock().unwrap_or_else(|e| e.into_inner());
    let prev = match newest(dir) {
        Some(p) => {
            let modified = std::fs::metadata(&p)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs());
            let name = p.file_name().map(|n| n.to_string_lossy().to_string());
            Some((name, modified, read_text(&p)?))
        }
        None => None,
    };
    let (previous, previous_modified) = match &prev {
        Some((n, m, _)) => (n.clone(), *m),
        None => (None, None),
    };
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

/// Publish `<base>.txt` in `dir` without clobbering (a same-second snapshot
/// gets a numeric suffix), owner-only, and only once fully written and synced
/// (see `artifacts::publish_new`), so a full disk or crash can never leave a
/// truncated file to become the next baseline.
fn write_new_snapshot(dir: &Path, base: &str, content: &str) -> Result<String, KnownHostsError> {
    artifacts::publish_new(dir, base, "txt", content.as_bytes()).map_err(|source| KnownHostsError::Io {
        path: dir.join(format!("{base}.txt")),
        source,
    })
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

/// Regular `.txt` snapshot entries of `dir` (no links, no staging files).
fn snapshot_entries(dir: &Path) -> std::io::Result<Vec<std::fs::DirEntry>> {
    Ok(std::fs::read_dir(dir)?
        .flatten()
        .filter(|e| {
            let n = e.file_name();
            let n = n.to_string_lossy();
            n.ends_with(".txt") && !n.starts_with('.')
        })
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .collect())
}

/// Newest snapshot by modified time, ties (same-second writes, coarse mtime
/// filesystems) broken by the name's own chronological order.
fn newest(dir: &Path) -> Option<PathBuf> {
    snapshot_entries(dir)
        .ok()?
        .into_iter()
        .max_by_key(|e| {
            (
                e.metadata().and_then(|m| m.modified()).ok(),
                name_order(&e.file_name().to_string_lossy()),
            )
        })
        .map(|e| e.path())
}

fn infos(dir: &Path, prefix: &str, legacy: bool) -> Result<Vec<SnapshotInfo>, KnownHostsError> {
    Ok(snapshot_entries(dir)
        .map_err(|source| KnownHostsError::Io { path: dir.to_path_buf(), source })?
        .into_iter()
        .map(|e| {
            let meta = e.metadata().ok();
            SnapshotInfo {
                name: format!("{prefix}{}", e.file_name().to_string_lossy()),
                bytes: meta.as_ref().map(|m| m.len()).unwrap_or(0),
                modified: meta
                    .and_then(|m| m.modified().ok())
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs()),
                legacy,
            }
        })
        .collect())
}

/// This endpoint's snapshots plus any in the legacy hostname folder, newest first.
pub fn list_snapshots(endpoint: &str, label: &str) -> Result<Vec<SnapshotInfo>, KnownHostsError> {
    let dir = configs_dir(endpoint, label)?;
    let mut out = if dir.exists() { infos(&dir, "", false)? } else { Vec::new() };
    if let Some(legacy) = legacy_dir(label) {
        out.extend(infos(&legacy, LEGACY_PREFIX, true)?);
    }
    out.sort_by(|a, b| b.modified.cmp(&a.modified));
    Ok(out)
}

fn checked(dir: &Path, name: &str) -> Result<PathBuf, KnownHostsError> {
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

/// Path of a snapshot id: this endpoint's folder, or the legacy one for a
/// `legacy:` id.
fn resolve(endpoint: &str, label: &str, id: &str) -> Result<PathBuf, KnownHostsError> {
    match id.strip_prefix(LEGACY_PREFIX) {
        Some(name) => {
            let dir = legacy_dir(label)
                .ok_or_else(|| KnownHostsError::Parse(format!("no legacy snapshot {name}")))?;
            checked(&dir, name)
        }
        None => checked(&configs_dir(endpoint, label)?, id),
    }
}

/// Unified diff between two snapshots, oldest first, for the viewer.
pub fn diff_snapshots(endpoint: &str, label: &str, older: &str, newer: &str) -> Result<String, KnownHostsError> {
    let old = read_text(&resolve(endpoint, label, older)?)?;
    let new = read_text(&resolve(endpoint, label, newer)?)?;
    Ok(render_diff(&old, &new, older, newer))
}

fn render_diff(old: &str, new: &str, older: &str, newer: &str) -> String {
    let (old, new) = (norm(old), norm(new));
    let diff = bounded_line_diff(&old, &new);
    let mut out = diff.unified_diff().context_radius(3).header(older, newer).to_string();
    if out.len() > MAX_DIFF_OUT {
        let cut = out[..MAX_DIFF_OUT].rfind('\n').map(|i| i + 1).unwrap_or(0);
        let rest = out.len() - cut;
        out.truncate(cut);
        out.push_str(&format!("… diff truncated: {rest} more bytes not shown\n"));
    }
    out
}

pub fn read_snapshot(endpoint: &str, label: &str, name: &str) -> Result<String, KnownHostsError> {
    read_text(&resolve(endpoint, label, name)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("hawser-cfg-test-{}", artifacts::random_hex(8)));
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
    fn line_endings_never_count_as_changes() {
        let d = tmp_dir();
        check_in(&d, "hostname fw1\nntp server 1.1.1.1\nlogging on\n", "20261031-090000").unwrap();
        // CRLF capture with one real change: +1 -1, not the whole file.
        let r = check_in(&d, "hostname fw1\r\nntp server 9.9.9.9\r\nlogging on\r\n", "20261031-100000").unwrap();
        assert_eq!((r.status, r.added, r.removed), ("changed", 1, 1));
        let diff = render_diff("a\nb\nc\n", "a\r\nB\r\nc\r\n\r\n", "old", "new");
        assert_eq!(diff.lines().filter(|l| l.starts_with('+') && !l.starts_with("+++")).count(), 1);
        assert_eq!(diff.lines().filter(|l| l.starts_with('-') && !l.starts_with("---")).count(), 1);
    }

    #[test]
    fn huge_unlike_diffs_finish_and_are_capped() {
        // Entirely different inputs used to run unbounded (minutes in a probe).
        let a: String = (0..20_000).map(|i| format!("a-line {i} {}\n", i * 7)).collect();
        let b: String = (0..20_000).map(|i| format!("b-line {i} {}\n", i * 13)).collect();
        let t = std::time::Instant::now();
        let (added, removed) = line_delta(&a, &b);
        assert_eq!((added, removed), (20_000, 20_000));
        let out = render_diff(&a, &b, "old", "new");
        assert!(t.elapsed() < std::time::Duration::from_secs(30), "took {:?}", t.elapsed());
        assert!(out.len() <= MAX_DIFF_OUT + 100);
        let big: String = (0..200_000).map(|i| format!("line {i}\n")).collect();
        let out = render_diff("", &big, "old", "new");
        assert!(out.len() <= MAX_DIFF_OUT + 100);
        assert!(out.ends_with("more bytes not shown\n"));
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_baseline_is_an_error_not_an_empty_file() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmp_dir();
        let first = check_in(&d, "x\n", "20261031-090000").unwrap();
        let p = d.join(first.name.unwrap());
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::File::open(&p).is_ok() {
            return; // running as root: permissions do not bite
        }
        assert!(check_in(&d, "x\n", "20261031-100000").is_err());
        assert_eq!(std::fs::read_dir(&d).unwrap().count(), 1, "nothing new saved");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn legacy_ids_are_told_apart_from_current_ones() {
        assert_eq!("legacy:20261030-120000.txt".strip_prefix(LEGACY_PREFIX), Some("20261030-120000.txt"));
        // A legacy id never passes as a current-folder name.
        assert!(checked(Path::new("configs"), "legacy:20261030-120000.txt").is_err());
        assert_eq!(legacy_slug("fe80::1"), "fe80__1");
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
