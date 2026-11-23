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
//! They are now keyed by an *endpoint identity* bound to where the connection
//! actually goes: `host:<id>=<user>@<host>:<port>` for a saved host,
//! `qc:<user>@<host>:<port>` for quick connect, plus `|via:<same for the
//! bastion>` when the connection rides one. The catalogue id alone was not
//! enough: repointing an entry at another device, or editing its bastion's
//! address or account, kept the key, so the new device inherited the old
//! one's transcript (and its AI context) and config baseline. With the
//! destination in the identity, any such edit starts a new identity and the
//! old artifacts become non-matching history.
//!
//! The backend derives the identity of a live session itself, from the
//! parameters it actually dialled (`dial_identity`, stored on the session), and
//! every config, capture and AI-context lookup made for a live session uses
//! that. The frontend computes the same string (`src/lib/endpoint.ts`, kept in
//! step by shared test vectors) only for lookups with no live session: the
//! replay before a dial and the history of a host that is not connected.
//!
//! The identity never becomes a path: it is hashed to a fixed 16-hex-char tag,
//! and names take the form `<label>@<tag>` where the label is a readable,
//! sanitised hostname.
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

/// The hostname as it enters an identity: trimmed, ASCII-lowercased (DNS
/// names are case-insensitive; non-ASCII is left alone so Rust and JS agree).
fn norm_host(host: &str) -> String {
    host.trim().to_ascii_lowercase()
}

/// A catalogue id usable in an identity: non-empty, and free of the
/// characters the identity format itself uses.
fn valid_catalogue_id(id: &str) -> bool {
    !id.is_empty() && !id.contains(['=', '|', '@']) && !id.chars().any(char::is_control)
}

/// One hop of an identity: `host:<id>=<user>@<host>:<port>` for a catalogue
/// entry, `qc:<user>@<host>:<port>` otherwise.
pub fn hop_identity(catalogue_id: Option<&str>, user: &str, host: &str, port: u16) -> String {
    let dest = format!("{user}@{}:{port}", norm_host(host));
    match catalogue_id.filter(|id| valid_catalogue_id(id)) {
        Some(id) => format!("host:{id}={dest}"),
        None => format!("qc:{dest}"),
    }
}

/// The catalogue ids named by a frontend-supplied identity, (target, jump).
/// Only the ids are taken from it; every destination is re-derived.
fn claimed_ids(claimed: &str) -> (Option<&str>, Option<&str>) {
    fn id(seg: Option<&str>) -> Option<&str> {
        let rest = seg?.strip_prefix("host:")?;
        let id = rest.split('=').next().unwrap_or(rest);
        valid_catalogue_id(id).then_some(id)
    }
    let mut parts = claimed.splitn(2, "|via:");
    let target = id(parts.next());
    let jump = id(parts.next());
    (target, jump)
}

/// The identity of a connection, from the destination it actually dials and,
/// when it rides one, the bastion it actually dials first.
///
/// `claimed` (the frontend's computed identity) contributes only which
/// catalogue entries these are; the user, host and port of every hop come from
/// the dial parameters. A claim whose destinations disagree with the dial
/// therefore cannot pull in another endpoint's artifacts.
pub fn dial_identity(
    claimed: Option<&str>,
    target: (&str, &str, u16),
    jump: Option<(&str, &str, u16)>,
) -> String {
    let (tid, jid) = claimed.filter(|c| validate_endpoint(c).is_ok()).map(claimed_ids).unwrap_or((None, None));
    let (user, host, port) = target;
    let mut out = hop_identity(tid, user, host, port);
    if let Some((ju, jh, jp)) = jump {
        out.push_str("|via:");
        out.push_str(&hop_identity(jid, ju, jh, jp));
    }
    out
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

/// The app-data directory every artifact tree hangs off (`logs`, `configs`,
/// `captures`). Components under it are verified by `real_dir`; the root
/// itself is the platform's per-user application-data folder.
pub fn app_data_root() -> Result<PathBuf, KnownHostsError> {
    let store = super::known_hosts::store_path()?;
    Ok(store.parent().ok_or(KnownHostsError::NoAppDataDir)?.to_path_buf())
}

/// Whether `meta` (from `symlink_metadata`) is a plain directory: not a
/// symlink, and on Windows not a junction or other reparse point either.
fn is_plain_dir(meta: &std::fs::Metadata) -> bool {
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return false;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return false;
        }
    }
    true
}

/// Make sure every component of `dir` below `anchor` is a real directory,
/// never a symlink, junction or other reparse point, creating missing ones
/// when `create` is set (each owner-only on Unix).
///
/// The no-follow open in `open_regular` protects only the final file name. A
/// planted link standing in for an endpoint folder (or for `logs` itself)
/// would otherwise steer every read and write under it to wherever it points.
/// Refused with `NotFound` when a component is missing and `create` is off,
/// and with `InvalidInput` when one is not a plain directory.
///
/// A check, not a handle: a same-user process that swaps a verified folder
/// for a link between this check and the open still wins. The app-data
/// folder is owner-only, so that needs code already running as the user.
pub fn real_dir(anchor: &Path, dir: &Path, create: bool) -> io::Result<()> {
    use std::path::Component;
    let rel = dir
        .strip_prefix(anchor)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "artifact path outside the app-data folder"))?;
    let mut cur = anchor.to_path_buf();
    for c in rel.components() {
        let Component::Normal(part) = c else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "unexpected artifact path component"));
        };
        cur.push(part);
        match std::fs::symlink_metadata(&cur) {
            Ok(m) if is_plain_dir(&m) => {}
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{} is not a plain folder (a link or a file); refusing to use it", cur.display()),
                ))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound && create => {
                let mut b = std::fs::DirBuilder::new();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    b.mode(0o700);
                }
                match b.create(&cur) {
                    Ok(()) => {}
                    // Raced with another creator: re-verify what is there now.
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                        let m = std::fs::symlink_metadata(&cur)?;
                        if !is_plain_dir(&m) {
                            return Err(io::Error::new(io::ErrorKind::InvalidInput, "artifact folder replaced by a link"));
                        }
                    }
                    Err(e) => return Err(e),
                }
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// `real_dir` against the app-data root, as the crate's error type. Ok(false)
/// when the folder does not exist and `create` is off (nothing stored yet).
pub fn verified_dir(dir: &Path, create: bool) -> Result<bool, KnownHostsError> {
    let anchor = app_data_root()?;
    match real_dir(&anchor, dir, create) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound && !create => Ok(false),
        Err(source) => Err(KnownHostsError::Io { path: dir.to_path_buf(), source }),
    }
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
        // shares) fall back to a rename that is itself no-replace: checking
        // for the target and then renaming over it left a window in which a
        // second writer's file was silently replaced.
        match std::fs::hard_link(&tmp, &target) {
            Ok(()) => break Ok(name),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(_) => match rename_noreplace(&tmp, &target) {
                Ok(()) => break Ok(name),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => break Err(e),
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

/// Rename `from` to `to` atomically, failing with `AlreadyExists` instead of
/// replacing a file already at `to`. Where the OS or filesystem offers no such
/// rename, this fails: never a replacing rename.
///
/// The per-folder lock in `configs` is process-local, so two app instances
/// could still publish into one folder at once; this rename keeps either from
/// destroying the other's file, and single-instance enforcement (a later
/// wave) removes the second instance altogether.
pub fn rename_noreplace(from: &Path, to: &Path) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::ffi::OsStrExt;
        let a = std::ffi::CString::new(from.as_os_str().as_bytes())?;
        let b = std::ffi::CString::new(to.as_os_str().as_bytes())?;
        // Through syscall(), not the glibc wrapper: renameat2 only joined
        // glibc in 2.28, and the symbol would stop the app loading on older
        // systems. A kernel or filesystem without RENAME_NOREPLACE reports
        // ENOSYS or EINVAL, which is returned as is (no fallback).
        let r = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                libc::AT_FDCWD,
                a.as_ptr(),
                libc::AT_FDCWD,
                b.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if r == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::ffi::OsStrExt;
        let a = std::ffi::CString::new(from.as_os_str().as_bytes())?;
        let b = std::ffi::CString::new(to.as_os_str().as_bytes())?;
        let r = unsafe { libc::renamex_np(a.as_ptr(), b.as_ptr(), libc::RENAME_EXCL) };
        if r == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_WRITE_THROUGH};
        let wide = |p: &Path| -> Vec<u16> { p.as_os_str().encode_wide().chain(std::iter::once(0)).collect() };
        let (a, b) = (wide(from), wide(to));
        // No MOVEFILE_REPLACE_EXISTING: an existing target fails the move
        // (ERROR_ALREADY_EXISTS / ERROR_FILE_EXISTS, both AlreadyExists).
        let ok = unsafe { MoveFileExW(a.as_ptr(), b.as_ptr(), MOVEFILE_WRITE_THROUGH) };
        if ok != 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = (from, to);
        Err(io::Error::new(io::ErrorKind::Unsupported, "no atomic no-replace rename on this platform"))
    }
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

    /// Shared with src/lib/frontend.test.mjs: the frontend must compute these
    /// exact strings for the same hosts, or offline lookups would miss.
    #[test]
    fn identity_vectors_match_the_frontend() {
        assert_eq!(dial_identity(Some("host:h-1"), ("admin", " FW1.Example.COM ", 22), None), "host:h-1=admin@fw1.example.com:22");
        assert_eq!(
            dial_identity(Some("host:h-1=x@y:1|via:host:b-1=z@w:2"), ("admin", "10.0.0.1", 2222), Some(("jump", "Bastion.lan", 22))),
            "host:h-1=admin@10.0.0.1:2222|via:host:b-1=jump@bastion.lan:22"
        );
        assert_eq!(dial_identity(Some("qc:ignored"), ("root", "Box", 22), None), "qc:root@box:22");
        assert_eq!(dial_identity(None, ("root", "box", 22), Some(("j", "b", 2))), "qc:root@box:22|via:qc:j@b:2");
        assert_eq!(hop_identity(Some("a@b"), "x", "y", 1), "qc:x@y:1");
        // Non-ASCII is not case-folded, exactly like the frontend.
        assert_eq!(hop_identity(Some("h"), "u", "ÄBC", 22), "host:h=u@Äbc:22");
    }

    #[test]
    fn identity_follows_the_dialled_destination() {
        let id = |claim: &str, host: &str, jump: Option<(&str, &str, u16)>| {
            dial_identity(Some(claim), ("admin", host, 22), jump)
        };
        let before = id("host:h-1", "10.0.0.1", None);
        // Repointing the entry at another device: a new identity.
        assert_ne!(before, id("host:h-1", "10.0.0.2", None));
        // Editing the bastion's address or account: a new identity.
        let via = id("host:h-1|via:host:b-1", "10.0.0.1", Some(("ops", "bastion-a", 22)));
        assert_ne!(via, id("host:h-1|via:host:b-1", "10.0.0.1", Some(("ops", "bastion-b", 22))));
        assert_ne!(via, id("host:h-1|via:host:b-1", "10.0.0.1", Some(("root", "bastion-a", 22))));
        assert_ne!(via, id("host:h-1|via:host:b-1", "10.0.0.1", Some(("ops", "bastion-a", 2222))));
        // A claim naming another destination cannot steer the result.
        assert_eq!(id("host:h-1=admin@10.9.9.9:22", "10.0.0.1", None), before);
        // Ids carrying format characters are not trusted as ids.
        assert!(id("host:a@b", "x", None).starts_with("qc:"));
        assert_ne!(endpoint_tag(&before), endpoint_tag(&id("host:h-1", "10.0.0.2", None)));
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

    #[test]
    fn rename_noreplace_never_clobbers() {
        let d = tmp_dir();
        std::fs::write(d.join("a"), "new").unwrap();
        std::fs::write(d.join("b"), "theirs").unwrap();
        let err = rename_noreplace(&d.join("a"), &d.join("b")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(d.join("b")).unwrap(), b"theirs");
        rename_noreplace(&d.join("a"), &d.join("c")).unwrap();
        assert_eq!(std::fs::read(d.join("c")).unwrap(), b"new");
        assert!(!d.join("a").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn real_dir_refuses_symlinked_parents() {
        let anchor = tmp_dir();
        let elsewhere = tmp_dir();
        std::fs::write(elsewhere.join("20261030-120000.txt"), "secret").unwrap();
        // A planted link standing in for an endpoint folder.
        std::fs::create_dir_all(anchor.join("configs")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, anchor.join("configs/fw1@0123456789abcdef")).unwrap();
        let err = real_dir(&anchor, &anchor.join("configs/fw1@0123456789abcdef"), false).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(real_dir(&anchor, &anchor.join("configs/fw1@0123456789abcdef"), true).is_err());
        // A linked root (logs -> elsewhere) is refused the same way.
        std::os::unix::fs::symlink(&elsewhere, anchor.join("logs")).unwrap();
        assert!(real_dir(&anchor, &anchor.join("logs"), true).is_err());
        // Missing and not creating: NotFound. Creating: real folders appear.
        let fresh = anchor.join("captures/x@0123456789abcdef");
        assert_eq!(real_dir(&anchor, &fresh, false).unwrap_err().kind(), io::ErrorKind::NotFound);
        real_dir(&anchor, &fresh, true).unwrap();
        assert!(std::fs::symlink_metadata(&fresh).unwrap().is_dir());
        // Outside the anchor or with `..`: refused.
        assert!(real_dir(&anchor, &elsewhere, true).is_err());
        assert!(real_dir(&anchor, &anchor.join("configs/../logs"), true).is_err());
        let _ = std::fs::remove_dir_all(&anchor);
        let _ = std::fs::remove_dir_all(&elsewhere);
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
