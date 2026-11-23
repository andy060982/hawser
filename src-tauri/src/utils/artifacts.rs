//! On-disk conventions shared by the per-endpoint artifacts: session
//! transcripts, config snapshots and command captures.
//!
//! # Endpoint identity
//!
//! These artifacts used to be keyed by the hostname alone, so two catalogue
//! entries sharing an address (the same RFC1918 IP behind two bastions,
//! `127.0.0.1:2201` vs `:2202`, one box as `admin` and as `readonly`) shared
//! one transcript stream and one config baseline. That let one host's output
//! reach the AI under another host's policy and compared one device's config
//! with another's.
//!
//! They are now keyed by an *endpoint key* the frontend derives from the
//! connection (`src/lib/endpoint.ts`): `host:<id>` for a saved host,
//! `qc:<user>@<host>:<port>` for quick connect, plus `|via:<jump>` when the
//! connection rides a bastion. The key itself never becomes a path: it is
//! hashed to a fixed 16-hex-char tag, and names take the form
//! `<label>@<tag>` where the label is a readable, sanitised hostname.
//!
//! Names written before this scheme carry no `@` (the old slug never produced
//! one), so they are told apart reliably and treated as *legacy*: still listed
//! and readable in the history views, never matched by an endpoint lookup.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::known_hosts::KnownHostsError;

/// Longest endpoint key accepted from the webview.
const MAX_ENDPOINT_LEN: usize = 1024;
/// Hex characters in an endpoint tag (64 bits of SHA-256).
pub const TAG_LEN: usize = 16;
/// Longest readable label kept in front of the tag.
const MAX_LABEL: usize = 64;

/// Reject keys that are empty, oversized or carry control characters. The key
/// is written into transcript headers, so a newline in it could forge a line.
pub fn validate_endpoint(key: &str) -> Result<(), KnownHostsError> {
    if key.is_empty() || key.len() > MAX_ENDPOINT_LEN || key.chars().any(char::is_control) {
        return Err(KnownHostsError::Parse("invalid endpoint identity".into()));
    }
    Ok(())
}

/// Fixed-length filesystem tag for an endpoint key.
pub fn endpoint_tag(key: &str) -> String {
    let digest = Sha256::digest(key.as_bytes());
    digest[..TAG_LEN / 2].iter().map(|b| format!("{b:02x}")).collect()
}

/// `label@tag` → `(label, tag)` when the part after the last `@` is a
/// well-formed tag. Legacy names (no `@`) give None.
pub fn split_tagged(component: &str) -> Option<(&str, &str)> {
    let (label, tag) = component.rsplit_once('@')?;
    let well_formed = tag.len() == TAG_LEN
        && tag.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    well_formed.then_some((label, tag))
}

/// Windows device names, which are reserved with or without an extension.
fn is_windows_reserved(stem: &str) -> bool {
    const RESERVED: [&str; 22] = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    let head = stem.split('.').next().unwrap_or(stem).trim_end_matches(' ');
    RESERVED.iter().any(|r| head.eq_ignore_ascii_case(r))
}

/// A readable path component made from an arbitrary label: ASCII
/// alphanumerics, `-` and `.` kept, everything else `_`, capped in length.
///
/// Applied on every platform so a catalogue that roams between machines names
/// things the same way. Win32 silently strips trailing dots and spaces (so
/// `fw1.` and `fw1` would share a folder) and maps device names like `aux` or
/// `com1.lan` to devices, so both are neutralised.
pub fn safe_component(label: &str) -> String {
    let mut out: String = label
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '.' { c } else { '_' })
        .take(MAX_LABEL)
        .collect();
    // Spaces are already mapped to '_', so a trailing dot is the only thing
    // Win32 would strip.
    if out.ends_with('.') {
        out.pop();
        out.push('_');
    }
    if out.is_empty() || out.chars().all(|c| c == '.' || c == '_') {
        return "_".repeat(out.len().max(1));
    }
    if is_windows_reserved(&out) {
        out.insert(0, '_');
    }
    out
}

/// The folder under `root` for one endpoint: an existing `*@<tag>` folder if
/// there is one (the label part follows the hostname, which can be edited
/// without changing the identity), else `<label>@<tag>`. Not created here.
pub fn endpoint_dir(root: &Path, label: &str, key: &str) -> PathBuf {
    let tag = endpoint_tag(key);
    if let Ok(rd) = std::fs::read_dir(root) {
        let mut found: Vec<String> = rd
            .flatten()
            .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
            .filter_map(|e| e.file_name().to_str().map(str::to_string))
            .filter(|n| split_tagged(n).map(|(_, t)| t == tag).unwrap_or(false))
            .collect();
        found.sort();
        if let Some(n) = found.into_iter().next() {
            return root.join(n);
        }
    }
    root.join(format!("{}@{tag}", safe_component(label)))
}

/// Open `path` for reading only if it is a regular file, never through a
/// symlink or reparse point and never blocking on a FIFO or device.
pub fn open_regular(path: &Path) -> io::Result<File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // O_NONBLOCK only matters for a FIFO, where a plain open would wait
        // for a writer; regular-file reads ignore it.
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        let meta = std::fs::symlink_metadata(path)?;
        if meta.file_type().is_symlink() || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "refusing to read through a link"));
        }
        opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = opts.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a regular file"));
    }
    Ok(file)
}

/// Whole contents of a regular file, refusing anything larger than `cap`.
pub fn read_regular_capped(path: &Path, cap: u64) -> io::Result<Vec<u8>> {
    use std::io::Read;
    let file = open_regular(path)?;
    let mut bytes = Vec::new();
    file.take(cap.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > cap {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "file is larger than the read limit"));
    }
    Ok(bytes)
}

/// Random lowercase hex, for staging-file names and capture ids.
pub fn random_hex(bytes: usize) -> String {
    use rand_core::{OsRng, RngCore};
    let mut buf = vec![0u8; bytes];
    OsRng.fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// Publish `content` as a new file `<base>.<ext>` in `dir` (or `<base>.<n>.<ext>`
/// if that name is taken), returning the bare name used.
///
/// The bytes go to an owner-only staging file first, are synced, and only then
/// appear under the final name, so a crash or a full disk never leaves a
/// partial file where a reader (the next config baseline, say) would take it
/// as complete. The staging file is removed on every failure path.
pub fn publish_new(dir: &Path, base: &str, ext: &str, content: &[u8]) -> io::Result<String> {
    use std::io::Write;
    let tmp = dir.join(format!(".{base}.{}.tmp", random_hex(6)));
    let staged = (|| {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(content)?;
        f.sync_all()
    })();
    if let Err(e) = staged {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    let mut n = 0u32;
    let result = loop {
        let name = if n == 0 { format!("{base}.{ext}") } else { format!("{base}.{n}.{ext}") };
        let target = dir.join(&name);
        // hard_link refuses an existing target atomically, so a same-second
        // name is never clobbered. Filesystems without links (FAT, some SMB
        // shares) fall back to a checked rename.
        match std::fs::hard_link(&tmp, &target) {
            Ok(()) => break Ok(name),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(_) => match std::fs::symlink_metadata(&target) {
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    break std::fs::rename(&tmp, &target).map(|()| name);
                }
                Err(e) => break Err(e),
                Ok(_) => {}
            },
        }
        n += 1;
        if n > 1000 {
            break Err(io::Error::new(io::ErrorKind::AlreadyExists, "no free file name"));
        }
    };
    // After a hard link the staging name is a second link to the same data;
    // after a rename it is already gone. Either way it must not linger.
    let _ = std::fs::remove_file(&tmp);
    #[cfg(unix)]
    if result.is_ok() {
        if let Ok(d) = File::open(dir) {
            let _ = d.sync_all();
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("hawser-artifacts-test-{}", random_hex(8)));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn tags_are_stable_distinct_and_parse_back() {
        let a = endpoint_tag("host:h-1");
        assert_eq!(a.len(), TAG_LEN);
        assert_eq!(a, endpoint_tag("host:h-1"));
        assert_ne!(a, endpoint_tag("host:h-2"));
        // Same address, different port or bastion: different identities.
        assert_ne!(endpoint_tag("qc:admin@10.0.0.1:22"), endpoint_tag("qc:admin@10.0.0.1:2222"));
        assert_ne!(endpoint_tag("host:h-1"), endpoint_tag("host:h-1|via:host:b-1"));
        let name = format!("fw1@{a}");
        assert_eq!(split_tagged(&name), Some(("fw1", a.as_str())));
        assert_eq!(split_tagged("fw1"), None);
        assert_eq!(split_tagged("fw1@xyz"), None);
    }

    #[test]
    fn endpoint_keys_reject_control_characters() {
        assert!(validate_endpoint("host:abc|via:host:def").is_ok());
        assert!(validate_endpoint("").is_err());
        assert!(validate_endpoint("host:a\n=== forged").is_err());
        assert!(validate_endpoint(&"x".repeat(2000)).is_err());
    }

    #[test]
    fn safe_component_neutralises_windows_quirks() {
        assert_eq!(safe_component("fw1.corp.local"), "fw1.corp.local");
        assert_eq!(safe_component("fe80::1"), "fe80__1");
        assert_eq!(safe_component("fw1."), "fw1_");
        assert_eq!(safe_component("aux"), "_aux");
        assert_eq!(safe_component("COM1.lan"), "_COM1.lan");
        assert_eq!(safe_component("console"), "console");
        assert_eq!(safe_component(".."), "__");
        assert_eq!(safe_component(""), "_");
        assert!(safe_component(&"a".repeat(500)).len() <= MAX_LABEL);
    }

    #[test]
    fn endpoint_dir_follows_the_tag_not_the_label() {
        let root = tmp_dir();
        let first = endpoint_dir(&root, "10.0.0.1", "host:h-1");
        std::fs::create_dir_all(&first).unwrap();
        // Hostname edited in the catalogue: same identity, same folder.
        assert_eq!(endpoint_dir(&root, "10.0.0.99", "host:h-1"), first);
        // Same hostname, other identity: its own folder.
        assert_ne!(endpoint_dir(&root, "10.0.0.1", "host:h-2"), first);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn publish_new_never_clobbers_and_leaves_no_staging_file() {
        let d = tmp_dir();
        let a = publish_new(&d, "20261030-120000", "txt", b"one\n").unwrap();
        let b = publish_new(&d, "20261030-120000", "txt", b"two\n").unwrap();
        assert_eq!(a, "20261030-120000.txt");
        assert_eq!(b, "20261030-120000.1.txt");
        assert_eq!(std::fs::read(d.join(&a)).unwrap(), b"one\n");
        assert_eq!(std::fs::read(d.join(&b)).unwrap(), b"two\n");
        let names: Vec<_> = std::fs::read_dir(&d)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(names.len(), 2, "staging files left behind: {names:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn open_regular_refuses_links_and_fifos() {
        let d = tmp_dir();
        std::fs::write(d.join("real.txt"), "x").unwrap();
        std::os::unix::fs::symlink(d.join("real.txt"), d.join("link.txt")).unwrap();
        assert!(open_regular(&d.join("real.txt")).is_ok());
        assert!(open_regular(&d.join("link.txt")).is_err());
        let fifo = d.join("pipe.txt");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        // Must return at once, not wait for a writer.
        assert!(open_regular(&fifo).is_err());
        assert!(read_regular_capped(&d.join("real.txt"), 0).is_err());
        assert_eq!(read_regular_capped(&d.join("real.txt"), 1).unwrap(), b"x");
        let _ = std::fs::remove_dir_all(&d);
    }
}
