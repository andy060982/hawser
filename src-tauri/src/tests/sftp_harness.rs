//! In-process SFTP server harness for the transfer commit paths (W3's
//! `copy_local_file` / `commit_upload` and `copy_remote_file` /
//! `commit_download`), which no test reached before.
//!
//! A real russh SSH server runs in this process over an in-memory duplex
//! stream; its `sftp` subsystem is russh-sftp's server with a handler that maps
//! the protocol onto a temp directory, with OpenSSH's semantics where they
//! matter here:
//! - SFTPv3 RENAME refuses an existing target (OpenSSH links, then unlinks),
//!   or, in `rename_replaces` mode, replaces it as some servers do;
//! - `posix-rename@openssh.com` (when enabled) replaces atomically;
//! - LSTAT reports a symlink as one, STAT and REALPATH follow it.
//!
//! Faults can be injected per operation (see `Fault`): fail it, delay it
//! before or after it takes effect (a reply that comes too late is a lost
//! reply), or run a hook first (cancel the transfer, plant a file). The
//! server can also refuse the `sftp` subsystem, leaving the channel open.
//!
//! The client side is the app's own: an `SftpConn` from `open_sftp_conn`, as
//! `Registry::sftp` opens it, driven through the same functions the transfer
//! commands call.

use super::*;
use russh_sftp::protocol::{
    Attrs, Data, File as SftpFile, FileAttributes, Handle as SftpHandle, Name, OpenFlags, Packet,
    Status, Version,
};
use std::collections::HashMap;
use std::os::unix::fs::{FileExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicUsize;

/* ---------------------------------------------------------------- faults */

/// What an injected fault does, in order.
#[derive(Clone)]
enum Act {
    /// Run a hook (cancel the transfer, plant or swap a file).
    Run(Arc<dyn Fn() + Send + Sync>),
    /// Wait before the operation takes effect.
    Before(Duration),
    /// Refuse the operation with this status.
    Fail(StatusCode),
    /// Let the operation take effect, then wait this long before replying.
    After(Duration),
}

/// A fault for operation `op` ("open", "close", "read", "write", "lstat",
/// "remove", "rename", "posix-rename") on a path: `rename` matches against
/// "<old> -> <new>", handle operations against the opened path. `path`
/// matches as a substring, or exactly when it starts with '='.
struct Fault {
    op: &'static str,
    path: String,
    times: usize,
    acts: Vec<Act>,
}

type Faults = Arc<std::sync::Mutex<Vec<Fault>>>;

/* ----------------------------------------------------------- sftp server */

/// russh-sftp server handler over a directory.
struct FsSftp {
    root: PathBuf,
    posix_rename: bool,
    rename_replaces: bool,
    files: HashMap<String, (std::fs::File, String)>,
    dirs: HashMap<String, Vec<(String, FileAttributes)>>,
    next: u64,
    faults: Faults,
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
        self.files.get(h).map(|f| &f.0).ok_or(StatusCode::Failure)
    }

    fn path_of(&self, h: &str) -> String {
        self.files.get(h).map(|f| f.1.clone()).unwrap_or_default()
    }

    /// Apply the first matching fault: `Err` refuses the operation; `Ok(d)`
    /// says how long to hold the reply after it took effect.
    async fn fault(&self, op: &str, path: &str) -> Result<Option<Duration>, StatusCode> {
        let acts = {
            let mut faults = self.faults.lock().unwrap();
            let hit = faults.iter_mut().find(|f| {
                f.op == op
                    && f.times > 0
                    && match f.path.strip_prefix('=') {
                        Some(exact) => exact == path,
                        None => path.contains(&f.path),
                    }
            });
            match hit {
                Some(f) => {
                    f.times -= 1;
                    f.acts.clone()
                }
                None => return Ok(None),
            }
        };
        let mut after = None;
        for a in acts {
            match a {
                Act::Run(hook) => hook(),
                Act::Before(d) => tokio::time::sleep(d).await,
                Act::Fail(c) => return Err(c),
                Act::After(d) => after = Some(d),
            }
        }
        Ok(after)
    }
}

async fn hold(after: Option<Duration>) {
    if let Some(d) = after {
        tokio::time::sleep(d).await;
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
        let after = self.fault("open", &filename).await?;
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
        self.files.insert(handle.clone(), (f, filename));
        hold(after).await;
        Ok(SftpHandle { id, handle })
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        let after = self.fault("close", &self.path_of(&handle)).await?;
        self.files.remove(&handle);
        hold(after).await;
        Ok(ok(id))
    }

    async fn read(&mut self, id: u32, handle: String, offset: u64, len: u32) -> Result<Data, Self::Error> {
        let after = self.fault("read", &self.path_of(&handle)).await?;
        hold(after).await;
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
        let after = self.fault("write", &self.path_of(&handle)).await?;
        self.file(&handle)?.write_all_at(&data, offset).map_err(|e| code(&e))?;
        hold(after).await;
        Ok(ok(id))
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let after = self.fault("lstat", &path).await?;
        let m = std::fs::symlink_metadata(self.real(&path)).map_err(|e| code(&e))?;
        hold(after).await;
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
        let after = self.fault("remove", &filename).await?;
        std::fs::remove_file(self.real(&filename)).map_err(|e| code(&e))?;
        hold(after).await;
        Ok(ok(id))
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<SftpHandle, Self::Error> {
        let rd = std::fs::read_dir(self.real(&path)).map_err(|e| code(&e))?;
        let mut names: Vec<(String, FileAttributes)> = rd
            .flatten()
            .filter_map(|e| Some((e.file_name().to_string_lossy().to_string(), attrs_of(&e.metadata().ok()?))))
            .collect();
        names.sort_by(|a, b| a.0.cmp(&b.0));
        self.next += 1;
        let handle = format!("d{}", self.next);
        self.dirs.insert(handle.clone(), names);
        Ok(SftpHandle { id, handle })
    }

    /// Two entries per READDIR, so a listing takes several batches.
    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        let left = self.dirs.get_mut(&handle).ok_or(StatusCode::Failure)?;
        if left.is_empty() {
            return Err(StatusCode::Eof);
        }
        let batch: Vec<_> = left.drain(..left.len().min(2)).collect();
        let files = batch
            .into_iter()
            .map(|(name, attrs)| SftpFile { filename: name.clone(), longname: name, attrs })
            .collect();
        Ok(Name { id, files })
    }

    /// SFTPv3 RENAME, as OpenSSH does it: an existing target is refused —
    /// unless the server is in `rename_replaces` mode.
    async fn rename(&mut self, id: u32, oldpath: String, newpath: String) -> Result<Status, Self::Error> {
        let after = self.fault("rename", &format!("{oldpath} -> {newpath}")).await?;
        let to = self.real(&newpath);
        if !self.rename_replaces && std::fs::symlink_metadata(&to).is_ok() {
            return Err(StatusCode::Failure);
        }
        std::fs::rename(self.real(&oldpath), to).map_err(|e| code(&e))?;
        hold(after).await;
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
        let after = self.fault("posix-rename", &format!("{from} -> {to}")).await?;
        // rename(2): replaces an existing target atomically.
        std::fs::rename(self.real(&from), self.real(&to)).map_err(|e| code(&e))?;
        hold(after).await;
        Ok(Packet::Status(ok(id)))
    }
}

/* ------------------------------------------------------------ ssh server */

/// How the test server behaves.
#[derive(Default, Clone)]
struct Opts {
    posix_rename: bool,
    rename_replaces: bool,
    /// Answer the `sftp` subsystem request with a failure, and leave the
    /// channel open (as some servers do).
    refuse_sftp: bool,
}

/// What the server saw.
#[derive(Default)]
struct Seen {
    channels_opened: AtomicUsize,
    channels_closed: AtomicUsize,
}

struct SshServer {
    root: PathBuf,
    opts: Opts,
    faults: Faults,
    seen: Arc<Seen>,
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
        self.seen.channels_opened.fetch_add(1, Ordering::SeqCst);
        self.channels.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: russh::ChannelId,
        _: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        self.seen.channels_closed.fetch_add(1, Ordering::SeqCst);
        self.channels.remove(&channel);
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: russh::ChannelId,
        name: &str,
        session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        if name != "sftp" || self.opts.refuse_sftp {
            // Refused, and the channel kept open: only the client can free it.
            return session.channel_failure(channel);
        }
        match self.channels.remove(&channel) {
            Some(ch) => {
                session.channel_success(channel)?;
                let handler = FsSftp {
                    root: self.root.clone(),
                    posix_rename: self.opts.posix_rename,
                    rename_replaces: self.opts.rename_replaces,
                    files: HashMap::new(),
                    dirs: HashMap::new(),
                    next: 0,
                    faults: Arc::clone(&self.faults),
                };
                russh_sftp::server::run(ch.into_stream(), handler).await;
            }
            None => session.channel_failure(channel)?,
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
    conn: Arc<SftpConn>,
    remote: PathBuf,
    local: PathBuf,
    faults: Faults,
    seen: Arc<Seen>,
    ssh: Handle<TrustAny>,
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

/// A logged-in SSH connection to a fresh test server.
async fn connect(opts: Opts) -> (Handle<TrustAny>, PathBuf, Faults, Arc<Seen>) {
    let remote = scratch("remote");
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
    let faults: Faults = Arc::default();
    let seen: Arc<Seen> = Arc::default();
    let server = SshServer {
        root: remote.clone(),
        opts,
        faults: Arc::clone(&faults),
        seen: Arc::clone(&seen),
        channels: HashMap::new(),
    };
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
    (ssh, remote, faults, seen)
}

async fn harness_with(opts: Opts) -> Harness {
    let posix = opts.posix_rename;
    let (ssh, remote, faults, seen) = connect(opts).await;
    // As Registry::sftp opens it.
    let conn = open_sftp_conn(&ssh, &AtomicBool::new(false)).await.unwrap();
    assert_eq!(conn.posix_rename, posix);
    Harness { conn: Arc::new(conn), remote, local: scratch("local"), faults, seen, ssh }
}

async fn harness(posix_rename: bool) -> Harness {
    harness_with(Opts { posix_rename, ..Default::default() }).await
}

impl Harness {
    async fn upload(&self, local: &str, remote: &str, overwrite: Overwrite) -> Result<(u64, Vec<String>), SshError> {
        let (_tx, rx) = watch::channel(false);
        self.upload_with(local, remote, overwrite, rx).await
    }

    async fn upload_with(
        &self,
        local: &str,
        remote: &str,
        overwrite: Overwrite,
        cancel: watch::Receiver<bool>,
    ) -> Result<(u64, Vec<String>), SshError> {
        let mut p = Progress::detached(cancel);
        let local = self.local.join(local);
        let done = copy_local_file(&self.conn, &mut p, &local.to_string_lossy(), remote, overwrite).await?;
        Ok((done, p.take_notes()))
    }

    async fn download(&self, remote: &str, local: &str, overwrite: Overwrite) -> Result<u64, SshError> {
        let (_tx, rx) = watch::channel(false);
        self.download_with(remote, local, overwrite, rx).await
    }

    async fn download_with(
        &self,
        remote: &str,
        local: &str,
        overwrite: Overwrite,
        cancel: watch::Receiver<bool>,
    ) -> Result<u64, SshError> {
        let mut p = Progress::detached(cancel);
        let local = self.local.join(local);
        copy_remote_file(&self.conn, &mut p, remote, &local.to_string_lossy(), overwrite).await
    }

    /// Inject a fault (see `Fault`) that fires `times` times.
    fn fault(&self, op: &'static str, path: &str, times: usize, acts: Vec<Act>) {
        self.faults.lock().unwrap().push(Fault { op, path: path.to_string(), times, acts });
    }

    /// The names in the remote root with this suffix.
    fn remote_named(&self, suffix: &str) -> Vec<String> {
        std::fs::read_dir(&self.remote)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.ends_with(suffix))
            .collect()
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

    /// No staging (`.hawserpart`), backup (`.hawserbak`) or probe file left
    /// behind.
    fn assert_clean(dir: &Path) {
        let left: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.ends_with(PART_SUFFIX) || n.ends_with(BAK_SUFFIX) || n.ends_with(PROBE_SUFFIX))
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
        let r = commit_upload(&h.conn, "/.x.staged.hawserpart", "/x", false).await;
        assert!(matches!(&r, Err(e) if e.to_string().contains("already exists")), "posix={posix}: {:?}", r.err());
        assert_eq!(h.remote_body("x"), b"appeared");
    }
}

/* --------------------------------------------------- W3b regression tests */

/// A cancel switch the server's hooks can flip.
fn cancel_switch() -> (Arc<watch::Sender<bool>>, watch::Receiver<bool>) {
    let (tx, rx) = watch::channel(false);
    (Arc::new(tx), rx)
}

fn hook(f: impl Fn() + Send + Sync + 'static) -> Act {
    Act::Run(Arc::new(f))
}

/// P1: a download under `Never` whose destination is created while it streams
/// (here: during the remote CLOSE, after every byte arrived) leaves that file
/// alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn download_never_never_overwrites_a_file_that_appears_late() {
    let h = harness(true).await;
    h.put_remote("late.txt", b"from the server", 0o644);
    let planted = h.local.join("late.txt");
    h.fault("close", "=/late.txt", 1, vec![hook(move || std::fs::write(&planted, "theirs").unwrap())]);
    let e = h.download("/late.txt", "late.txt", Overwrite::Never).await.unwrap_err();
    assert!(e.to_string().contains("already exists"), "{e}");
    assert_eq!(std::fs::read(h.local.join("late.txt")).unwrap(), b"theirs");
    Harness::assert_clean(&h.local);
}

/// P1: a cancel that arrives while the original is being moved aside does not
/// stop the commit halfway: it runs to the end, and the original is replaced
/// (not stranded under `.hawserbak`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_cancel_during_the_commit_lets_it_finish() {
    let h = harness(false).await;
    h.put_remote("cfg.txt", b"old", 0o600);
    h.put_local("cfg.txt", b"new contents", 0o644);
    let (tx, rx) = cancel_switch();
    // The move-aside RENAME (/cfg.txt -> its backup): cancel, then answer late.
    h.fault(
        "rename",
        "/cfg.txt -> ",
        1,
        vec![hook(move || { let _ = tx.send(true); }), Act::After(Duration::from_millis(200))],
    );
    let (_, notes) = h.upload_with("cfg.txt", "/cfg.txt", Overwrite::Replace, rx).await.unwrap();
    assert!(notes.is_empty(), "{notes:?}");
    assert_eq!(h.remote_body("cfg.txt"), b"new contents");
    assert_eq!(Harness::mode(&h.remote.join("cfg.txt")), 0o600);
    Harness::assert_clean(&h.remote);
}

/// P1/item 2: the move-aside's reply is lost (it comes after the stall
/// deadline; russh-sftp drops the waiter, so the late reply is ignored). The
/// commit looks, finds the original at its backup name, and finishes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_recovers_from_a_lost_move_aside_reply() {
    let h = harness(false).await;
    h.put_remote("cfg.txt", b"old", 0o600);
    h.put_local("cfg.txt", b"new contents", 0o644);
    h.fault("rename", "/cfg.txt -> ", 1, vec![Act::After(Duration::from_millis(450))]);
    let r = TEST_STALL
        .scope(Duration::from_millis(300), h.upload("cfg.txt", "/cfg.txt", Overwrite::Replace))
        .await;
    r.unwrap();
    assert_eq!(h.remote_body("cfg.txt"), b"new contents");
    Harness::assert_clean(&h.remote);
}

/// P1/item 2: the move-aside's reply is lost and the channel stays stuck: the
/// error names the backup, where the original really is.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_names_the_backup_when_the_channel_dies_mid_commit() {
    let h = harness(false).await;
    h.put_remote("cfg.txt", b"old", 0o600);
    h.put_local("cfg.txt", b"new contents", 0o644);
    h.fault("rename", "/cfg.txt -> ", 1, vec![Act::After(Duration::from_secs(3))]);
    let e = TEST_STALL
        .scope(Duration::from_millis(300), h.upload("cfg.txt", "/cfg.txt", Overwrite::Replace))
        .await
        .unwrap_err()
        .to_string();
    let bak = h.remote_named(BAK_SUFFIX);
    assert_eq!(bak.len(), 1, "{bak:?}");
    assert!(e.contains(&format!("/{}", bak[0])), "{e}");
    assert_eq!(std::fs::read(h.remote.join(&bak[0])).unwrap(), b"old");
    assert!(sftp_dead(&SshError::TransferStalled(0)));
}

/// Item 2: install and restore both refused after the move-aside: nothing is
/// lost, and the error names both copies.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_failed_install_and_restore_names_both_copies() {
    let h = harness(false).await;
    h.put_remote("cfg.txt", b"old", 0o600);
    h.put_local("cfg.txt", b"new contents", 0o644);
    h.fault("rename", "hawserpart -> /cfg.txt", usize::MAX, vec![Act::Fail(StatusCode::Failure)]);
    h.fault("rename", "hawserbak -> /cfg.txt", usize::MAX, vec![Act::Fail(StatusCode::Failure)]);
    let e = h.upload("cfg.txt", "/cfg.txt", Overwrite::Replace).await.unwrap_err().to_string();
    let (bak, part) = (h.remote_named(BAK_SUFFIX), h.remote_named(PART_SUFFIX));
    assert_eq!((bak.len(), part.len()), (1, 1), "{bak:?} {part:?}");
    assert!(e.contains(&format!("/{}", bak[0])) && e.contains(&format!("/{}", part[0])), "{e}");
    assert_eq!(std::fs::read(h.remote.join(&bak[0])).unwrap(), b"old");
    assert_eq!(std::fs::read(h.remote.join(&part[0])).unwrap(), b"new contents");
}

/// Item 2 (pinned dependency behaviour): a request abandoned before its reply
/// still takes effect on the server, its late reply is ignored, and the same
/// session keeps working.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn russh_sftp_drops_the_waiter_of_an_abandoned_request() {
    let h = harness(false).await;
    h.put_remote("a", b"x", 0o644);
    h.fault("rename", "/a -> /b", 1, vec![Act::After(Duration::from_millis(300))]);
    let r = tokio::time::timeout(Duration::from_millis(50), h.conn.hi.rename("/a", "/b")).await;
    assert!(r.is_err(), "the reply should not have come yet");
    assert!(h.conn.hi.symlink_metadata("/b").await.is_ok());
    assert!(!h.remote.join("a").exists());
    assert!(h.conn.hi.symlink_metadata("/a").await.is_err());
}

/// Item 4: on a server whose plain RENAME replaces, `Never` cannot be
/// guaranteed and fails before anything is written; Replace still works.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_never_fails_on_a_server_whose_rename_replaces() {
    let h = harness_with(Opts { rename_replaces: true, ..Default::default() }).await;
    h.put_local("n.txt", b"new", 0o644);
    let e = h.upload("n.txt", "/n.txt", Overwrite::Never).await.unwrap_err().to_string();
    assert!(e.contains("choose Replace"), "{e}");
    assert!(!h.remote.join("n.txt").exists());
    Harness::assert_clean(&h.remote);
    // The probe is remembered: the commit-time check refuses as well.
    h.put_remote(".n.staged.hawserpart", b"staged", 0o644);
    let r = commit_upload(&h.conn, "/.n.staged.hawserpart", "/n.txt", false).await;
    assert!(matches!(&r, Err(e) if e.to_string().contains("choose Replace")), "{:?}", r.err());
    Harness::assert_clean(&h.remote);

    h.put_remote("n.txt", b"old", 0o640);
    h.upload("n.txt", "/n.txt", Overwrite::Replace).await.unwrap();
    assert_eq!(h.remote_body("n.txt"), b"new");
    assert_eq!(Harness::mode(&h.remote.join("n.txt")), 0o640);
    Harness::assert_clean(&h.remote);
}

/// Item 4: a destination that became a symlink (or a folder) while the upload
/// streamed is neither replaced nor written through.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_refuses_a_destination_that_changed_type_during_the_copy() {
    for posix in [true, false] {
        let h = harness(posix).await;
        h.put_remote("t.txt", b"regular", 0o644);
        h.put_remote("victim.txt", b"keep", 0o644);
        h.put_local("t.txt", b"new", 0o644);
        let root = h.remote.clone();
        h.fault(
            "write",
            "hawserpart",
            1,
            vec![hook(move || {
                std::fs::remove_file(root.join("t.txt")).unwrap();
                std::os::unix::fs::symlink("victim.txt", root.join("t.txt")).unwrap();
            })],
        );
        let e = h.upload("t.txt", "/t.txt", Overwrite::Confirmed).await.unwrap_err().to_string();
        assert!(e.contains("symlink"), "posix={posix}: {e}");
        assert!(std::fs::symlink_metadata(h.remote.join("t.txt")).unwrap().file_type().is_symlink());
        assert_eq!(h.remote_body("victim.txt"), b"keep");
        Harness::assert_clean(&h.remote);

        let root = h.remote.clone();
        h.put_remote("d", b"regular", 0o644);
        h.put_local("d", b"new", 0o644);
        h.fault(
            "write",
            "hawserpart",
            1,
            vec![hook(move || {
                std::fs::remove_file(root.join("d")).unwrap();
                std::fs::create_dir(root.join("d")).unwrap();
            })],
        );
        let e = h.upload("d", "/d", Overwrite::Confirmed).await.unwrap_err().to_string();
        assert!(e.contains("directory"), "posix={posix}: {e}");
        assert!(h.remote.join("d").is_dir());
        Harness::assert_clean(&h.remote);
    }
}

/// Item 5: a cancel that wins after the server created the staging file but
/// before its OPEN reply still removes that file.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_cancelled_before_the_open_reply_leaves_no_staging_file() {
    let h = harness(true).await;
    h.put_local("o.txt", b"body", 0o644);
    let (tx, rx) = cancel_switch();
    h.fault(
        "open",
        "hawserpart",
        1,
        vec![hook(move || { let _ = tx.send(true); }), Act::After(Duration::from_millis(200))],
    );
    let e = h.upload_with("o.txt", "/o.txt", Overwrite::Never, rx).await.unwrap_err();
    assert!(matches!(e, SshError::TransferCancelled), "{e}");
    assert!(!h.remote.join("o.txt").exists());
    Harness::assert_clean(&h.remote);
}

/// Item 5: a download cancelled after its last byte (during the remote CLOSE)
/// is not committed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn download_cancelled_before_the_commit_is_not_committed() {
    let h = harness(true).await;
    h.put_remote("f.txt", b"server", 0o644);
    let (tx, rx) = cancel_switch();
    h.fault("close", "=/f.txt", 1, vec![hook(move || { let _ = tx.send(true); })]);
    let e = h.download_with("/f.txt", "f.txt", Overwrite::Never, rx).await.unwrap_err();
    assert!(matches!(e, SshError::TransferCancelled), "{e}");
    assert!(!h.local.join("f.txt").exists());
    Harness::assert_clean(&h.local);
}

/// Item 6: when the server will not rename at all, the file is written in
/// place, warned about up front, and the complete staged upload is kept until
/// that write has fully succeeded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn in_place_fallback_keeps_the_staged_copy_until_it_succeeds() {
    let h = harness(false).await;
    let body = vec![9u8; 200 * 1024];
    h.put_remote("cfg.bin", b"old", 0o600);
    h.put_local("cfg.bin", &body, 0o644);
    h.fault("rename", "", usize::MAX, vec![Act::Fail(StatusCode::PermissionDenied)]);
    // The in-place write fails partway.
    h.fault("write", "=/cfg.bin", 1, vec![Act::Fail(StatusCode::Failure)]);
    let e = h.upload("cfg.bin", "/cfg.bin", Overwrite::Replace).await.unwrap_err().to_string();
    let part = h.remote_named(PART_SUFFIX);
    assert_eq!(part.len(), 1, "{part:?}");
    assert!(e.contains("may be incomplete") && e.contains(&format!("/{}", part[0])), "{e}");
    assert_eq!(std::fs::read(h.remote.join(&part[0])).unwrap(), body);
    std::fs::remove_file(h.remote.join(&part[0])).unwrap();

    // Without the write fault: done, warned, staging removed.
    let (_, notes) = h.upload("cfg.bin", "/cfg.bin", Overwrite::Replace).await.unwrap();
    assert!(notes.iter().any(|n| n.contains("written in place")), "{notes:?}");
    assert_eq!(h.remote_body("cfg.bin"), body);
    assert_eq!(Harness::mode(&h.remote.join("cfg.bin")), 0o600);
    Harness::assert_clean(&h.remote);
}

/// Item 7: a refused `sftp` subsystem is answered at once, its channel is
/// CLOSED (not left holding a session slot), and the refusal is remembered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_sftp_subsystem_closes_its_channel_and_is_remembered() {
    let (ssh, _remote, _faults, seen) = connect(Opts { refuse_sftp: true, ..Default::default() }).await;
    let refused = AtomicBool::new(false);
    let started = Instant::now();
    let e = open_sftp_conn(&ssh, &refused).await.err().expect("refused");
    assert!(e.to_string().contains("refused"), "{e}");
    assert!(started.elapsed() < Duration::from_secs(5), "waited out a timeout instead of the reply");
    assert!(refused.load(Ordering::SeqCst));
    for _ in 0..50 {
        if seen.channels_closed.load(Ordering::SeqCst) == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(seen.channels_closed.load(Ordering::SeqCst), 1);
    // Asked again (a cache reset, a pane refresh): no new channel.
    assert!(open_sftp_conn(&ssh, &refused).await.is_err());
    assert_eq!(seen.channels_opened.load(Ordering::SeqCst), 1);
}

/// Item 7: the high-level and raw sessions share ONE channel.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sftp_uses_a_single_channel() {
    let h = harness(true).await;
    assert_eq!(h.seen.channels_opened.load(Ordering::SeqCst), 1);
    h.put_remote("x", b"1", 0o644);
    assert!(h.conn.hi.symlink_metadata("/x").await.is_ok());
    assert!(h.conn.raw.lstat("/x").await.is_ok());
    drop(h.ssh);
}

/// Item 10: a listing is read batch by batch and capped while it is read.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listing_is_capped_while_it_is_read() {
    let h = harness(false).await;
    for i in 0..9 {
        h.put_remote(&format!("f{i}"), b"", 0o644);
    }
    let (all, cut) = read_dir_capped(&h.conn, "/", 100).await.unwrap();
    assert_eq!((all.len(), cut), (9, false));
    let (some, cut) = read_dir_capped(&h.conn, "/", 3).await.unwrap();
    assert_eq!((some.len(), cut), (3, true));
}

/// Item 10: a nested file whose read stalls ends the folder transfer with an
/// error that still counts as a dead channel, so the session is reopened.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nested_copy_stall_counts_as_a_dead_channel() {
    let h = harness(true).await;
    std::fs::create_dir_all(h.remote.join("d/sub")).unwrap();
    h.put_remote("d/sub/f.bin", b"data", 0o644);
    h.put_remote("d/sub/g.bin", b"data", 0o644);
    h.fault("read", "/d/sub/", 1, vec![Act::Before(Duration::from_secs(2))]);
    let (_tx, rx) = watch::channel(false);
    let mut p = Progress::detached(rx);
    let local = h.local.join("d").to_string_lossy().to_string();
    let e = TEST_STALL
        .scope(Duration::from_millis(300), download_tree(&h.conn, &mut p, "/d", &local, Overwrite::Never))
        .await
        .unwrap_err();
    assert!(matches!(e, SshError::TreeAborted(_)), "{e}");
    assert!(sftp_dead(&e));
}
