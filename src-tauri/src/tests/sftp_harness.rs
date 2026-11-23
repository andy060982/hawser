//! In-process SFTP server harness for the transfer commit paths (W3's
//! `copy_local_file` / `commit_upload` and `copy_remote_file` /
//! `commit_download`), which no test reached before.
//!
//! A real russh SSH server runs in this process over an in-memory duplex
//! stream; its `sftp` subsystem is russh-sftp's server with a handler that maps
//! the protocol onto a temp directory, with OpenSSH's semantics where they
//! matter here:
//! - SFTPv3 RENAME refuses an existing target (OpenSSH links, then unlinks);
//! - `posix-rename@openssh.com` (when enabled) replaces atomically;
//! - LSTAT reports a symlink as one, STAT and REALPATH follow it.
//!
//! The client side is the app's own: an `SftpConn` built the way
//! `Registry::sftp` builds one (a high-level session plus a raw channel that
//! learns whether the extension is offered), driven through the same
//! functions the transfer commands call.

use super::*;
use russh_sftp::protocol::{
    Attrs, Data, File as SftpFile, FileAttributes, Handle as SftpHandle, Name, OpenFlags, Packet,
    Status, Version,
};
use std::collections::HashMap;
use std::os::unix::fs::{FileExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/* ----------------------------------------------------------- sftp server */

/// russh-sftp server handler over a directory.
struct FsSftp {
    root: PathBuf,
    posix_rename: bool,
    files: HashMap<String, std::fs::File>,
    next: u64,
}

fn ok(id: u32) -> Status {
    Status { id, status_code: StatusCode::Ok, error_message: "Ok".into(), language_tag: "en-US".into() }
}

fn code(e: &std::io::Error) -> StatusCode {
    match e.kind() {
        std::io::ErrorKind::NotFound => StatusCode::NoSuchFile,
        std::io::ErrorKind::PermissionDenied => StatusCode::PermissionDenied,
        _ => StatusCode::Failure,
    }
}

fn attrs_of(m: &std::fs::Metadata) -> FileAttributes {
    use std::os::unix::fs::MetadataExt;
    FileAttributes {
        size: Some(m.len()),
        uid: Some(m.uid()),
        gid: Some(m.gid()),
        // Raw st_mode, type bits included: the client derives the file type
        // (symlink, directory) from them.
        permissions: Some(m.mode()),
        atime: Some(m.atime() as u32),
        mtime: Some(m.mtime() as u32),
        ..Default::default()
    }
}

impl FsSftp {
    fn real(&self, p: &str) -> PathBuf {
        self.root.join(p.trim_start_matches('/'))
    }

    fn server_path(&self, real: &Path) -> String {
        match real.strip_prefix(&self.root) {
            Ok(rest) => format!("/{}", rest.to_string_lossy()),
            Err(_) => real.to_string_lossy().to_string(),
        }
    }

    fn file(&self, h: &str) -> Result<&std::fs::File, StatusCode> {
        self.files.get(h).ok_or(StatusCode::Failure)
    }
}

impl russh_sftp::server::Handler for FsSftp {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn init(&mut self, _: u32, _: HashMap<String, String>) -> Result<Version, Self::Error> {
        let mut v = Version::new();
        if self.posix_rename {
            v.extensions.insert(POSIX_RENAME.to_string(), "1".to_string());
        }
        Ok(v)
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: OpenFlags,
        attrs: FileAttributes,
    ) -> Result<SftpHandle, Self::Error> {
        let mut o = std::fs::OpenOptions::new();
        o.read(pflags.contains(OpenFlags::READ))
            .write(pflags.contains(OpenFlags::WRITE) || pflags.contains(OpenFlags::APPEND))
            .append(pflags.contains(OpenFlags::APPEND))
            .truncate(pflags.contains(OpenFlags::TRUNCATE));
        if pflags.contains(OpenFlags::CREATE) {
            if pflags.contains(OpenFlags::EXCLUDE) {
                o.create_new(true);
            } else {
                o.create(true);
            }
        }
        o.mode(attrs.permissions.map_or(0o644, |m| m & 0o7777));
        let f = o.open(self.real(&filename)).map_err(|e| code(&e))?;
        self.next += 1;
        let handle = format!("h{}", self.next);
        self.files.insert(handle.clone(), f);
        Ok(SftpHandle { id, handle })
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        self.files.remove(&handle);
        Ok(ok(id))
    }

    async fn read(&mut self, id: u32, handle: String, offset: u64, len: u32) -> Result<Data, Self::Error> {
        let f = self.file(&handle)?;
        let mut buf = vec![0u8; len as usize];
        let n = f.read_at(&mut buf, offset).map_err(|e| code(&e))?;
        if n == 0 {
            return Err(StatusCode::Eof);
        }
        buf.truncate(n);
        Ok(Data { id, data: buf })
    }

    async fn write(&mut self, id: u32, handle: String, offset: u64, data: Vec<u8>) -> Result<Status, Self::Error> {
        self.file(&handle)?.write_all_at(&data, offset).map_err(|e| code(&e))?;
        Ok(ok(id))
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let m = std::fs::symlink_metadata(self.real(&path)).map_err(|e| code(&e))?;
        Ok(Attrs { id, attrs: attrs_of(&m) })
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let m = std::fs::metadata(self.real(&path)).map_err(|e| code(&e))?;
        Ok(Attrs { id, attrs: attrs_of(&m) })
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        let m = self.file(&handle)?.metadata().map_err(|e| code(&e))?;
        Ok(Attrs { id, attrs: attrs_of(&m) })
    }

    async fn setstat(&mut self, id: u32, path: String, attrs: FileAttributes) -> Result<Status, Self::Error> {
        if let Some(m) = attrs.permissions {
            std::fs::set_permissions(self.real(&path), std::fs::Permissions::from_mode(m & 0o7777))
                .map_err(|e| code(&e))?;
        }
        Ok(ok(id))
    }

    async fn fsetstat(&mut self, id: u32, handle: String, attrs: FileAttributes) -> Result<Status, Self::Error> {
        if let Some(m) = attrs.permissions {
            self.file(&handle)?
                .set_permissions(std::fs::Permissions::from_mode(m & 0o7777))
                .map_err(|e| code(&e))?;
        }
        Ok(ok(id))
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        std::fs::remove_file(self.real(&filename)).map_err(|e| code(&e))?;
        Ok(ok(id))
    }

    /// SFTPv3 RENAME, as OpenSSH does it: an existing target is refused.
    async fn rename(&mut self, id: u32, oldpath: String, newpath: String) -> Result<Status, Self::Error> {
        let to = self.real(&newpath);
        if std::fs::symlink_metadata(&to).is_ok() {
            return Err(StatusCode::Failure);
        }
        std::fs::rename(self.real(&oldpath), to).map_err(|e| code(&e))?;
        Ok(ok(id))
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let real = std::fs::canonicalize(self.real(&path)).map_err(|e| code(&e))?;
        let shown = self.server_path(&real);
        Ok(Name { id, files: vec![SftpFile::dummy(&shown)] })
    }

    async fn readlink(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let t = std::fs::read_link(self.real(&path)).map_err(|e| code(&e))?;
        Ok(Name { id, files: vec![SftpFile::dummy(t.to_string_lossy().to_string())] })
    }

    async fn extended(&mut self, id: u32, request: String, data: Vec<u8>) -> Result<Packet, Self::Error> {
        if !(self.posix_rename && request == POSIX_RENAME) {
            return Err(StatusCode::OpUnsupported);
        }
        let mut rest = &data[..];
        let mut take = || -> Option<String> {
            let len = u32::from_be_bytes(rest.get(..4)?.try_into().ok()?) as usize;
            let s = String::from_utf8(rest.get(4..4 + len)?.to_vec()).ok()?;
            rest = &rest[4 + len..];
            Some(s)
        };
        let (from, to) = take().zip(take()).ok_or(StatusCode::BadMessage)?;
        // rename(2): replaces an existing target atomically.
        std::fs::rename(self.real(&from), self.real(&to)).map_err(|e| code(&e))?;
        Ok(Packet::Status(ok(id)))
    }
}

/* ------------------------------------------------------------ ssh server */

struct SshServer {
    root: PathBuf,
    posix_rename: bool,
    channels: HashMap<russh::ChannelId, russh::Channel<russh::server::Msg>>,
}

impl russh::server::Handler for SshServer {
    type Error = russh::Error;

    async fn auth_password(&mut self, _: &str, _: &str) -> Result<russh::server::Auth, Self::Error> {
        Ok(russh::server::Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: russh::Channel<russh::server::Msg>,
        reply: russh::server::ChannelOpenHandle,
        _: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        self.channels.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: russh::ChannelId,
        name: &str,
        session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        match (name, self.channels.remove(&channel)) {
            ("sftp", Some(ch)) => {
                session.channel_success(channel)?;
                let handler = FsSftp {
                    root: self.root.clone(),
                    posix_rename: self.posix_rename,
                    files: HashMap::new(),
                    next: 0,
                };
                russh_sftp::server::run(ch.into_stream(), handler).await;
            }
            _ => session.channel_failure(channel)?,
        }
        Ok(())
    }
}

/* ---------------------------------------------------------------- client */

struct TrustAny;

impl client::Handler for TrustAny {
    type Error = SshError;

    async fn check_server_key(&mut self, _: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// A connected SFTP client over a server rooted at `remote`, plus a local
/// scratch folder.
struct Harness {
    conn: SftpConn,
    remote: PathBuf,
    local: PathBuf,
    _ssh: Handle<TrustAny>,
}

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "hawser-sftp-{tag}-{}-{}",
        std::process::id(),
        crate::utils::artifacts::random_hex(4)
    ));
    std::fs::create_dir_all(&d).unwrap();
    // Canonical: macOS's temp dir is behind a symlink, and REALPATH answers
    // are compared with paths under it.
    std::fs::canonicalize(&d).unwrap()
}

async fn harness(posix_rename: bool) -> Harness {
    let remote = scratch("remote");
    let local = scratch("local");
    let (client_io, server_io) = tokio::io::duplex(1 << 20);
    let config = Arc::new(russh::server::Config {
        keys: vec![russh::keys::PrivateKey::random(
            &mut russh::keys::ssh_key::rand_core::UnwrapErr(russh::keys::ssh_key::getrandom::SysRng),
            russh::keys::Algorithm::Ed25519,
        )
        .unwrap()],
        auth_rejection_time: Duration::from_millis(1),
        auth_rejection_time_initial: Some(Duration::ZERO),
        ..Default::default()
    });
    let server = SshServer { root: remote.clone(), posix_rename, channels: HashMap::new() };
    tokio::spawn(async move {
        if let Ok(running) = russh::server::run_stream(config, server_io, server).await {
            let _ = running.await;
        }
    });
    let mut ssh = client::connect_stream(Arc::new(client::Config::default()), client_io, TrustAny)
        .await
        .unwrap();
    let auth = ssh.authenticate_password("u", "p").await.unwrap();
    assert!(matches!(auth, russh::client::AuthResult::Success));

    // As Registry::sftp builds it: the high-level session, then the raw
    // channel that learns whether posix-rename is offered.
    let ch = ssh.channel_open_session().await.unwrap();
    ch.request_subsystem(true, "sftp").await.unwrap();
    let hi = SftpSession::new(ch.into_stream()).await.unwrap();
    let ch = ssh.channel_open_session().await.unwrap();
    ch.request_subsystem(true, "sftp").await.unwrap();
    let raw = RawSftpSession::new(ch.into_stream());
    let version = raw.init().await.unwrap();
    let posix = version.extensions.get(POSIX_RENAME).is_some_and(|v| v == "1");
    assert_eq!(posix, posix_rename);
    Harness { conn: SftpConn { hi, raw: Some(raw), posix_rename: posix }, remote, local, _ssh: ssh }
}

impl Harness {
    async fn upload(&self, local: &str, remote: &str, overwrite: Overwrite) -> Result<(u64, Vec<String>), SshError> {
        let (_tx, rx) = watch::channel(false);
        let mut p = Progress::detached(rx);
        let local = self.local.join(local);
        let done = copy_local_file(&self.conn, &mut p, &local.to_string_lossy(), remote, overwrite).await?;
        Ok((done, p.take_notes()))
    }

    async fn download(&self, remote: &str, local: &str, overwrite: Overwrite) -> Result<u64, SshError> {
        let (_tx, rx) = watch::channel(false);
        let mut p = Progress::detached(rx);
        let local = self.local.join(local);
        copy_remote_file(&self.conn, &mut p, remote, &local.to_string_lossy(), overwrite).await
    }

    fn put_remote(&self, name: &str, body: &[u8], mode: u32) {
        let p = self.remote.join(name);
        std::fs::write(&p, body).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn put_local(&self, name: &str, body: &[u8], mode: u32) {
        let p = self.local.join(name);
        std::fs::write(&p, body).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn remote_body(&self, name: &str) -> Vec<u8> {
        std::fs::read(self.remote.join(name)).unwrap()
    }

    fn mode(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    /// No staging (`.hawserpart`) or backup (`.hawserbak`) file left behind.
    fn assert_clean(dir: &Path) {
        let left: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.ends_with(PART_SUFFIX) || n.ends_with(BAK_SUFFIX))
            .collect();
        assert!(left.is_empty(), "left behind in {}: {left:?}", dir.display());
    }
}

/* ----------------------------------------------------------------- tests */

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_to_a_new_file() {
    for posix in [true, false] {
        let h = harness(posix).await;
        let body = vec![7u8; 300 * 1024]; // several chunks
        h.put_local("new.bin", &body, 0o640);
        let (n, notes) = h.upload("new.bin", "/new.bin", Overwrite::Never).await.unwrap();
        assert_eq!(n, body.len() as u64);
        assert!(notes.is_empty(), "{notes:?}");
        assert_eq!(h.remote_body("new.bin"), body, "posix={posix}");
        // A new file takes the local file's mode.
        assert_eq!(Harness::mode(&h.remote.join("new.bin")), 0o640, "posix={posix}");
        Harness::assert_clean(&h.remote);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_never_refuses_an_existing_file() {
    for posix in [true, false] {
        let h = harness(posix).await;
        h.put_remote("cfg.txt", b"original", 0o600);
        h.put_local("cfg.txt", b"replacement", 0o644);
        let e = h.upload("cfg.txt", "/cfg.txt", Overwrite::Never).await.unwrap_err();
        assert!(e.to_string().contains("already exists"), "{e}");
        assert_eq!(h.remote_body("cfg.txt"), b"original");
        Harness::assert_clean(&h.remote);
    }
}

/// Replace over an existing file: through posix-rename when offered, else the
/// portable path (RENAME refuses the existing target, so the original is moved
/// aside, the new copy put in place, and the backup removed). Either way the
/// file keeps its own permissions.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_replace_over_an_existing_file_keeps_its_mode() {
    for posix in [true, false] {
        let h = harness(posix).await;
        h.put_remote("secret.conf", b"old", 0o600);
        h.put_local("secret.conf", b"new contents", 0o644);
        let (_, notes) = h.upload("secret.conf", "/secret.conf", Overwrite::Replace).await.unwrap();
        assert!(notes.is_empty(), "posix={posix}: {notes:?}");
        assert_eq!(h.remote_body("secret.conf"), b"new contents", "posix={posix}");
        assert_eq!(Harness::mode(&h.remote.join("secret.conf")), 0o600, "posix={posix}");
        Harness::assert_clean(&h.remote);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_over_a_symlink_writes_through_it_or_refuses() {
    for posix in [true, false] {
        let h = harness(posix).await;
        h.put_remote("target.txt", b"before", 0o640);
        std::os::unix::fs::symlink("target.txt", h.remote.join("link.txt")).unwrap();
        h.put_local("link.txt", b"after", 0o644);

        // Never: the link counts as an existing file.
        let e = h.upload("link.txt", "/link.txt", Overwrite::Never).await.unwrap_err();
        assert!(e.to_string().contains("already exists"), "{e}");
        assert_eq!(h.remote_body("target.txt"), b"before");

        // Replace: the target is updated, the link stays a link.
        let (_, notes) = h.upload("link.txt", "/link.txt", Overwrite::Replace).await.unwrap();
        assert!(notes.iter().any(|n| n.contains("symlink")), "{notes:?}");
        assert!(std::fs::symlink_metadata(h.remote.join("link.txt")).unwrap().file_type().is_symlink());
        assert_eq!(h.remote_body("target.txt"), b"after", "posix={posix}");
        assert_eq!(Harness::mode(&h.remote.join("target.txt")), 0o640, "posix={posix}");
        Harness::assert_clean(&h.remote);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_over_a_dangling_symlink_is_refused() {
    let h = harness(true).await;
    std::os::unix::fs::symlink("nowhere.txt", h.remote.join("dangling.txt")).unwrap();
    h.put_local("dangling.txt", b"x", 0o644);
    assert!(h.upload("dangling.txt", "/dangling.txt", Overwrite::Replace).await.is_err());
    assert!(!h.remote.join("nowhere.txt").exists());
    Harness::assert_clean(&h.remote);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn download_over_an_existing_local_file() {
    let h = harness(true).await;
    h.put_remote("log.txt", b"from the server", 0o644);
    h.put_local("log.txt", b"local copy", 0o600);

    // Never: refused at commit, the local file untouched.
    let e = h.download("/log.txt", "log.txt", Overwrite::Never).await.unwrap_err();
    assert!(e.to_string().contains("already exists"), "{e}");
    assert_eq!(std::fs::read(h.local.join("log.txt")).unwrap(), b"local copy");
    Harness::assert_clean(&h.local);

    // Replace: replaced, keeping the local file's own mode.
    let n = h.download("/log.txt", "log.txt", Overwrite::Replace).await.unwrap();
    assert_eq!(n, 15);
    assert_eq!(std::fs::read(h.local.join("log.txt")).unwrap(), b"from the server");
    assert_eq!(Harness::mode(&h.local.join("log.txt")), 0o600);
    Harness::assert_clean(&h.local);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn download_to_a_new_file_takes_the_remote_mode() {
    let h = harness(false).await;
    h.put_remote("run.sh", b"#!/bin/sh\n", 0o750);
    h.download("/run.sh", "run.sh", Overwrite::Never).await.unwrap();
    assert_eq!(std::fs::read(h.local.join("run.sh")).unwrap(), b"#!/bin/sh\n");
    assert_eq!(Harness::mode(&h.local.join("run.sh")), 0o750);
    Harness::assert_clean(&h.local);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn download_never_writes_through_a_local_symlink() {
    let h = harness(true).await;
    h.put_remote("f.txt", b"server", 0o644);
    h.put_local("victim.txt", b"keep", 0o644);
    std::os::unix::fs::symlink(h.local.join("victim.txt"), h.local.join("f.txt")).unwrap();
    assert!(h.download("/f.txt", "f.txt", Overwrite::Replace).await.is_err());
    assert_eq!(std::fs::read(h.local.join("victim.txt")).unwrap(), b"keep");
}

/// A destination that appears after the existence check (another client, a
/// second transfer) is never clobbered under `Never`: the commit itself is the
/// no-replace RENAME.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_commit_never_clobbers_a_file_that_appeared_meanwhile() {
    for posix in [true, false] {
        let h = harness(posix).await;
        h.put_remote(".x.staged.hawserpart", b"staged", 0o644);
        h.put_remote("x", b"appeared", 0o644);
        let (_tx, rx) = watch::channel(false);
        let r = commit_upload(&h.conn, &rx, "/.x.staged.hawserpart", "/x", false).await;
        assert!(matches!(&r, Err(e) if e.to_string().contains("already exists")), "posix={posix}: {:?}", r.err());
        assert_eq!(h.remote_body("x"), b"appeared");
    }
}
