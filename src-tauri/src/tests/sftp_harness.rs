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
//! - `hardlink@openssh.com` (when enabled) is link(2): it refuses an existing
//!   target (FAILURE, as OpenSSH maps EEXIST);
//! - LSTAT reports a symlink as one, STAT and REALPATH follow it.
//!
//! Faults can be injected per operation (see `Fault`): fail it, delay it
//! before or after it takes effect (a reply that comes too late is a lost
//! reply), lose its reply outright, defer its effect until after later
//! requests were answered (a server working on requests concurrently), or run
//! a hook first (cancel the transfer, plant a file). The server can also
//! refuse the `sftp` subsystem, leaving the channel open, or stall it: stop
//! reading the channel, so the SSH window and every buffer fill and the
//! client's sends park (see `relay`).
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
    /// Take effect, but never send the reply; later requests are still
    /// answered.
    LoseReply,
    /// RENAME and hardlink only: lose the reply, and take effect only this
    /// long after the request — after later requests on the channel were
    /// answered.
    Defer(Duration),
}

/// What a matching fault asks of an operation that goes ahead.
#[derive(Default)]
struct Hit {
    /// Hold the reply this long after taking effect.
    after: Option<Duration>,
    /// Take effect this long from now, in the background (see `Act::Defer`).
    defer: Option<Duration>,
}

/// A fault for operation `op` ("open", "close", "read", "write", "lstat",
/// "remove", "rename", "posix-rename", "hardlink") on a path: the two-path
/// operations match against "<old> -> <new>", handle operations against the
/// opened path. `path`
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
    hardlink: bool,
    rename_replaces: bool,
    files: HashMap<String, (std::fs::File, String)>,
    dirs: HashMap<String, Vec<(String, FileAttributes)>>,
    next: u64,
    faults: Faults,
    seen: Arc<Seen>,
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

    /// Apply the first matching fault to request `id`: `Err` refuses the
    /// operation; `Ok` says how it goes ahead.
    async fn fault(&self, op: &str, path: &str, id: u32) -> Result<Hit, StatusCode> {
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
                None => return Ok(Hit::default()),
            }
        };
        let mut hit = Hit::default();
        for a in acts {
            match a {
                Act::Run(hook) => hook(),
                Act::Before(d) => tokio::time::sleep(d).await,
                Act::Fail(c) => return Err(c),
                Act::After(d) => hit.after = Some(d),
                Act::LoseReply => {
                    self.seen.lost_replies.lock().unwrap().insert(id);
                }
                Act::Defer(d) => {
                    self.seen.lost_replies.lock().unwrap().insert(id);
                    hit.defer = Some(d);
                }
            }
        }
        Ok(hit)
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
        if self.hardlink {
            v.extensions.insert(HARDLINK.to_string(), "1".to_string());
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
        let after = self.fault("open", &filename, id).await?.after;
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
        let after = self.fault("close", &self.path_of(&handle), id).await?.after;
        self.files.remove(&handle);
        hold(after).await;
        Ok(ok(id))
    }

    async fn read(&mut self, id: u32, handle: String, offset: u64, len: u32) -> Result<Data, Self::Error> {
        let after = self.fault("read", &self.path_of(&handle), id).await?.after;
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
        let after = self.fault("write", &self.path_of(&handle), id).await?.after;
        self.file(&handle)?.write_all_at(&data, offset).map_err(|e| code(&e))?;
        hold(after).await;
        Ok(ok(id))
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let after = self.fault("lstat", &path, id).await?.after;
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
        let after = self.fault("remove", &filename, id).await?.after;
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
        let hit = self.fault("rename", &format!("{oldpath} -> {newpath}"), id).await?;
        let (from, to, replaces) = (self.real(&oldpath), self.real(&newpath), self.rename_replaces);
        let rename = move || -> Result<(), StatusCode> {
            if !replaces && std::fs::symlink_metadata(&to).is_ok() {
                return Err(StatusCode::Failure);
            }
            std::fs::rename(&from, &to).map_err(|e| code(&e))
        };
        if let Some(d) = hit.defer {
            tokio::spawn(async move {
                tokio::time::sleep(d).await;
                let _ = rename();
            });
            return Ok(ok(id));
        }
        rename()?;
        hold(hit.after).await;
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
        let link = match request.as_str() {
            POSIX_RENAME if self.posix_rename => false,
            HARDLINK if self.hardlink => true,
            _ => return Err(StatusCode::OpUnsupported),
        };
        let mut rest = &data[..];
        let mut take = || -> Option<String> {
            let len = u32::from_be_bytes(rest.get(..4)?.try_into().ok()?) as usize;
            let s = String::from_utf8(rest.get(4..4 + len)?.to_vec()).ok()?;
            rest = &rest[4 + len..];
            Some(s)
        };
        let (from, to) = take().zip(take()).ok_or(StatusCode::BadMessage)?;
        if link {
            // link(2), as OpenSSH's sftp-server serves it: never replaces.
            let hit = self.fault("hardlink", &format!("{from} -> {to}"), id).await?;
            let (a, b) = (self.real(&from), self.real(&to));
            let link = move || std::fs::hard_link(&a, &b).map_err(|e| code(&e));
            if let Some(d) = hit.defer {
                tokio::spawn(async move {
                    tokio::time::sleep(d).await;
                    let _ = link();
                });
                return Ok(Packet::Status(ok(id)));
            }
            link()?;
            hold(hit.after).await;
            return Ok(Packet::Status(ok(id)));
        }
        let after = self.fault("posix-rename", &format!("{from} -> {to}"), id).await?.after;
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
    /// Offer `hardlink@openssh.com`.
    hardlink: bool,
    rename_replaces: bool,
    /// Answer the `sftp` subsystem request with a failure, and leave the
    /// channel open (as some servers do).
    refuse_sftp: bool,
}

/// What the server saw, and how its SFTP channel behaves.
#[derive(Default)]
struct Seen {
    channels_opened: AtomicUsize,
    channels_closed: AtomicUsize,
    /// Request ids whose reply is never sent (see `Act::LoseReply`).
    lost_replies: std::sync::Mutex<std::collections::HashSet<u32>>,
    /// The subsystem stopped reading its channel (see `relay`).
    stalled: AtomicBool,
    unstalled: tokio::sync::Notify,
}

impl Seen {
    fn stall(&self) {
        self.stalled.store(true, Ordering::SeqCst);
    }

    fn unstall(&self) {
        self.stalled.store(false, Ordering::SeqCst);
        self.unstalled.notify_waiters();
    }
}

/// Carry an SFTP channel to and from the server's SFTP handler, dropping
/// lost replies, and not reading the channel at all while `stalled`: the
/// russh server then stops reading the connection, the client's SSH window
/// and queues fill, and its sends park, as on a wedged sftp-server.
async fn relay(ch: russh::ChannelStream<russh::server::Msg>, srv: tokio::io::DuplexStream, seen: Arc<Seen>) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let (mut ch_r, mut ch_w) = tokio::io::split(ch);
    let (mut srv_r, mut srv_w) = tokio::io::split(srv);
    let seen_up = Arc::clone(&seen);
    let requests = async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            loop {
                let resumed = seen_up.unstalled.notified();
                if !seen_up.stalled.load(Ordering::SeqCst) {
                    break;
                }
                resumed.await;
            }
            let n = match ch_r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if srv_w.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
        let _ = srv_w.shutdown().await;
    };
    let replies = async move {
        let mut first = true;
        loop {
            let mut len = [0u8; 4];
            if srv_r.read_exact(&mut len).await.is_err() {
                break;
            }
            let mut f = len.to_vec();
            f.resize(4 + u32::from_be_bytes(len) as usize, 0);
            if srv_r.read_exact(&mut f[4..]).await.is_err() {
                break;
            }
            // Every reply but the VERSION carries its request id.
            if !std::mem::take(&mut first) && f.len() >= 9 {
                let id = u32::from_be_bytes([f[5], f[6], f[7], f[8]]);
                if seen.lost_replies.lock().unwrap().remove(&id) {
                    continue;
                }
            }
            if ch_w.write_all(&f).await.is_err() {
                break;
            }
        }
        let _ = ch_w.shutdown().await;
    };
    tokio::join!(requests, replies);
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
                    hardlink: self.opts.hardlink,
                    rename_replaces: self.opts.rename_replaces,
                    files: HashMap::new(),
                    dirs: HashMap::new(),
                    next: 0,
                    faults: Arc::clone(&self.faults),
                    seen: Arc::clone(&self.seen),
                };
                let (srv, relayed) = tokio::io::duplex(1 << 20);
                tokio::spawn(relay(ch.into_stream(), relayed, Arc::clone(&self.seen)));
                russh_sftp::server::run(srv, handler).await;
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

/// Trusts any key, and records the negotiated algorithms like ClientHandler.
struct Recording {
    algos: Algos,
}

impl client::Handler for Recording {
    type Error = SshError;

    async fn check_server_key(&mut self, _: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn kex_done(
        &mut self,
        _: Option<&[u8]>,
        names: &russh::Names,
        _: &mut client::Session,
    ) -> Result<(), Self::Error> {
        record_negotiated(&self.algos, names);
        Ok(())
    }
}

/// W5: the status bar shows what the key exchange really negotiated.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn negotiated_algorithms_are_recorded() {
    let algos: Algos = Arc::default();
    let opts = Opts::default();
    let (_ssh, _remote, _faults, _seen) = connect_with(opts, Recording { algos: Arc::clone(&algos) }).await;
    let got = algos.lock().unwrap().clone().expect("kex_done recorded nothing");
    // The test server's only host key is Ed25519, so that is what was used.
    assert_eq!(got.host_key, "ssh-ed25519");
    assert!(!got.kex.is_empty() && got.kex != "none", "{got:?}");
    assert!(!got.cipher.is_empty() && got.cipher != "none", "{got:?}");
    let json = serde_json::to_value(&got).unwrap();
    assert!(json.get("hostKey").is_some(), "{json}");
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
    connect_with(opts, TrustAny).await
}

/// `connect`, with the client handler supplied.
async fn connect_with<H>(opts: Opts, handler: H) -> (Handle<H>, PathBuf, Faults, Arc<Seen>)
where
    H: client::Handler<Error = SshError> + Send + 'static,
{
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
    let mut ssh = client::connect_stream(Arc::new(client::Config::default()), client_io, handler)
        .await
        .unwrap();
    let auth = ssh.authenticate_password("u", "p").await.unwrap();
    assert!(matches!(auth, russh::client::AuthResult::Success));
    (ssh, remote, faults, seen)
}

async fn harness_with(opts: Opts) -> Harness {
    let (posix, link) = (opts.posix_rename, opts.hardlink);
    let (ssh, remote, faults, seen) = connect(opts).await;
    // As Registry::sftp opens it.
    let conn = open_sftp_conn(&ssh, &AtomicBool::new(false)).await.unwrap();
    assert_eq!((conn.posix_rename, conn.hardlink), (posix, link), "extensions as advertised");
    Harness { conn: Arc::new(conn), remote, local: scratch("local"), faults, seen, ssh }
}

async fn harness(posix_rename: bool) -> Harness {
    harness_with(Opts { posix_rename, ..Default::default() }).await
}

/// Every combination of the two OpenSSH extensions a commit can use.
fn extension_sets() -> [Opts; 4] {
    [(false, false), (true, false), (false, true), (true, true)]
        .map(|(posix_rename, hardlink)| Opts { posix_rename, hardlink, ..Default::default() })
}

fn label(o: &Opts) -> String {
    format!("posix={} hardlink={}", o.posix_rename, o.hardlink)
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
    for opts in extension_sets() {
        let posix = label(&opts);
        let h = harness_with(opts).await;
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
    for opts in extension_sets() {
        let which = label(&opts);
        let h = harness_with(opts).await;
        h.put_remote("cfg.txt", b"original", 0o600);
        h.put_local("cfg.txt", b"replacement", 0o644);
        let e = h.upload("cfg.txt", "/cfg.txt", Overwrite::Never).await.unwrap_err();
        assert!(e.to_string().contains("already exists"), "{which}: {e}");
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
    for opts in extension_sets() {
        let posix = label(&opts);
        let h = harness_with(opts).await;
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
    assert!(matches!(e, SshError::ChannelLost(_)), "{e}");
    assert!(sftp_dead(&e));
}

/* --------------------------------------------------- W3c regression tests */

/// Wait up to `limit` for `cond`.
async fn eventually(limit: Duration, cond: impl Fn() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < limit {
        if cond() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    cond()
}

/// Item 2: the move-aside's reply is lost and the server performs it only
/// AFTER answering the follow-up LSTAT (which then says "no backup"). That
/// is no proof the move failed: nothing is deleted, and the error names both
/// the backup and the staged copy — where everything really ends up.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_lost_move_aside_not_yet_done_keeps_and_names_everything() {
    let h = harness(false).await;
    h.put_remote("cfg.txt", b"old", 0o600);
    h.put_local("cfg.txt", b"new contents", 0o644);
    h.fault("rename", "/cfg.txt -> ", 1, vec![Act::Defer(Duration::from_millis(900))]);
    let e = TEST_STALL
        .scope(Duration::from_millis(300), h.upload("cfg.txt", "/cfg.txt", Overwrite::Replace))
        .await
        .unwrap_err();
    assert!(sftp_dead(&e), "{e}");
    let e = e.to_string();
    let part = h.remote_named(PART_SUFFIX);
    assert_eq!(part.len(), 1, "the staged copy was kept: {part:?}");
    assert!(e.contains(&format!("/{}", part[0])) && e.contains(BAK_SUFFIX), "{e}");
    // The deferred move lands: the original is exactly where the error said.
    assert!(eventually(Duration::from_secs(3), || h.remote_named(BAK_SUFFIX).len() == 1).await);
    let bak = h.remote_named(BAK_SUFFIX);
    assert!(e.contains(&format!("/{}", bak[0])), "{e}");
    assert_eq!(std::fs::read(h.remote.join(&bak[0])).unwrap(), b"old");
    assert_eq!(std::fs::read(h.remote.join(&part[0])).unwrap(), b"new contents");
}

/// Item 2: an install whose reply is lost and that the server performs only
/// later: the staged copy is not deleted under it, and the error names it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_lost_install_not_yet_done_keeps_the_staged_copy() {
    let h = harness(false).await;
    h.put_local("n.txt", b"new", 0o644);
    h.fault("rename", "hawserpart -> /n.txt", 1, vec![Act::Defer(Duration::from_millis(900))]);
    let e = TEST_STALL
        .scope(Duration::from_millis(300), h.upload("n.txt", "/n.txt", Overwrite::Never))
        .await
        .unwrap_err();
    assert!(sftp_dead(&e), "{e}");
    let part = h.remote_named(PART_SUFFIX);
    assert_eq!(part.len(), 1, "{part:?}");
    assert!(e.to_string().contains(&format!("/{}", part[0])), "{e}");
    // The rename still lands, with the complete upload.
    assert!(eventually(Duration::from_secs(3), || h.remote.join("n.txt").exists()).await);
    assert_eq!(h.remote_body("n.txt"), b"new");
    Harness::assert_clean(&h.remote);
}

/// Item 4: replacing, a re-check of the destination that FAILS refuses (it
/// does not carry on as if the file were fine).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_replace_refuses_when_the_recheck_fails() {
    for posix in [true, false] {
        let h = harness(posix).await;
        h.put_remote("t.txt", b"regular", 0o644);
        h.put_local("t.txt", b"new", 0o644);
        let faults = Arc::clone(&h.faults);
        // The first LSTAT passes; the re-check after the copy fails.
        h.fault(
            "write",
            "hawserpart",
            1,
            vec![hook(move || {
                faults.lock().unwrap().push(Fault {
                    op: "lstat",
                    path: "=/t.txt".into(),
                    times: 1,
                    acts: vec![Act::Fail(StatusCode::Failure)],
                })
            })],
        );
        let e = h.upload("t.txt", "/t.txt", Overwrite::Confirmed).await.unwrap_err().to_string();
        assert!(e.contains("could not check") && e.contains("not replacing"), "posix={posix}: {e}");
        assert_eq!(h.remote_body("t.txt"), b"regular");
        Harness::assert_clean(&h.remote);
    }
}

/// Item 4: a link that takes the destination's place between the first
/// install attempt and the move-aside is seen by the re-check right before
/// the move, and is neither moved nor replaced.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_replace_rechecks_right_before_the_move_aside() {
    let h = harness(false).await;
    h.put_remote("t.txt", b"regular", 0o644);
    h.put_remote("victim.txt", b"keep", 0o644);
    h.put_local("t.txt", b"new", 0o644);
    let root = h.remote.clone();
    h.fault(
        "rename",
        "hawserpart -> /t.txt",
        1,
        vec![
            hook(move || {
                std::fs::remove_file(root.join("t.txt")).unwrap();
                std::os::unix::fs::symlink("victim.txt", root.join("t.txt")).unwrap();
            }),
            Act::Fail(StatusCode::Failure),
        ],
    );
    let e = h.upload("t.txt", "/t.txt", Overwrite::Confirmed).await.unwrap_err().to_string();
    assert!(e.contains("symlink") && e.contains("not replacing"), "{e}");
    assert!(std::fs::symlink_metadata(h.remote.join("t.txt")).unwrap().file_type().is_symlink());
    assert_eq!(h.remote_body("victim.txt"), b"keep");
    Harness::assert_clean(&h.remote);
}

/// Item 4: a folder swapped in between that re-check and the move-aside is
/// moved, recognised under its backup name, and put back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_replace_puts_back_a_folder_moved_aside_by_a_race() {
    let h = harness(false).await;
    h.put_remote("t.txt", b"regular", 0o644);
    h.put_local("t.txt", b"new", 0o644);
    let root = h.remote.clone();
    h.fault(
        "rename",
        "/t.txt -> ",
        1,
        vec![hook(move || {
            std::fs::remove_file(root.join("t.txt")).unwrap();
            std::fs::create_dir(root.join("t.txt")).unwrap();
            std::fs::write(root.join("t.txt/inside"), "keep").unwrap();
        })],
    );
    let e = h.upload("t.txt", "/t.txt", Overwrite::Confirmed).await.unwrap_err().to_string();
    assert!(e.contains("changed while it was being replaced") && e.contains("put back"), "{e}");
    assert_eq!(h.remote_body("t.txt/inside"), b"keep");
    Harness::assert_clean(&h.remote);
}

/// Item 6: the in-place warning reaches the UI as a progress event BEFORE the
/// destination is opened for truncation, not only with the final notes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn in_place_warning_is_shown_before_the_destination_is_truncated() {
    let h = harness(false).await;
    h.put_remote("cfg.bin", b"old", 0o600);
    h.put_local("cfg.bin", b"new body", 0o644);
    h.fault("rename", "", usize::MAX, vec![Act::Fail(StatusCode::PermissionDenied)]);
    let (_tx, rx) = watch::channel(false);
    let mut p = Progress::detached(rx);
    let log = p.record();
    let warned_first = Arc::new(AtomicBool::new(false));
    let (log2, flag) = (Arc::clone(&log), Arc::clone(&warned_first));
    // The in-place OPEN (with TRUNCATE) of the destination itself.
    h.fault(
        "open",
        "=/cfg.bin",
        1,
        vec![hook(move || {
            let seen = log2.lock().unwrap().iter().any(|ev| {
                ev.note.as_deref().is_some_and(|n| n.contains("written in place"))
            });
            flag.store(seen, Ordering::SeqCst);
        })],
    );
    let local = h.local.join("cfg.bin").to_string_lossy().to_string();
    copy_local_file(&h.conn, &mut p, &local, "/cfg.bin", Overwrite::Replace).await.unwrap();
    assert!(warned_first.load(Ordering::SeqCst), "no warning event before the truncating open");
    assert!(p.take_notes().iter().any(|n| n.contains("written in place")));
    assert_eq!(h.remote_body("cfg.bin"), b"new body");
    // Shown once, then cleared from later events.
    let events = log.lock().unwrap();
    assert_eq!(events.iter().filter(|ev| ev.note.is_some()).count(), 1);
    assert!(events.last().unwrap().note.is_none());
}

/// Item 7/P2: a stalled subsystem (the server stopped reading the channel,
/// so the mux's writer parks inside its SSH send). Evicting the connection
/// stops every mux task at once, even with a straggler still holding it; the
/// CLOSE is not given up on while the peer stays stuck past any grace
/// period, so the channel is freed, and a replacement opens.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn evicting_a_stalled_channel_frees_it_and_a_replacement_opens() {
    let Harness { conn, seen, ssh, .. } = harness(false).await;
    let slot = Mutex::new(Some(Arc::clone(&conn)));
    let handle = conn
        .raw
        .open("/big", OpenFlags::CREATE | OpenFlags::WRITE, FileAttributes::default())
        .await
        .unwrap()
        .handle;
    seen.stall();
    // Far more than the SSH window plus every buffer on the way.
    let chunk = vec![0u8; 200 * 1024];
    let writes = (0..100u64).map(|i| conn.raw.write(handle.clone(), i * chunk.len() as u64, chunk.clone()));
    let r = tokio::time::timeout(Duration::from_millis(800), futures_util::future::join_all(writes)).await;
    assert!(r.is_err(), "a stalled server answered");
    assert_eq!(conn.mux.running(), 4);

    // The cache evicts it while a straggler (this test) still holds it.
    assert!(forget_sftp(&slot, &conn, &SshError::TransferStalled(1)).await);
    assert!(slot.lock().await.is_none());
    assert!(
        eventually(Duration::from_secs(1), || conn.mux.running() == 0).await,
        "{} mux task(s) still running",
        conn.mux.running()
    );

    // The peer stays stuck past any grace period, then recovers: the CLOSE,
    // queued behind everything else, still goes out.
    tokio::time::sleep(EXEC_CLOSE_GRACE + Duration::from_millis(500)).await;
    seen.unstall();
    assert!(
        eventually(Duration::from_secs(15), || seen.channels_closed.load(Ordering::SeqCst) == 1).await,
        "the stalled channel was never closed"
    );
    let fresh = open_sftp_conn(&ssh, &AtomicBool::new(false)).await.unwrap();
    assert!(fresh.hi.symlink_metadata("/").await.is_ok());
    assert_eq!(seen.channels_opened.load(Ordering::SeqCst), 2);
    // The straggler fails fast instead of waiting out a timeout.
    let late = tokio::time::timeout(Duration::from_secs(2), conn.hi.symlink_metadata("/")).await;
    assert!(matches!(late, Ok(Err(_))), "{late:?}");
    // Dropping a connection stops its mux the same way.
    let fresh = Arc::new(fresh);
    let running = Arc::clone(&fresh.mux.live);
    drop(fresh);
    assert!(eventually(Duration::from_secs(1), || running.load(Ordering::SeqCst) == 0).await);
    assert!(eventually(Duration::from_secs(5), || seen.channels_closed.load(Ordering::SeqCst) == 2).await);
}

/// P2: a straggler failing on an old, already replaced channel must not evict
/// the healthy replacement; only the cached instance that failed is dropped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failure_on_an_old_channel_does_not_evict_its_replacement() {
    let h = harness(true).await;
    let dead = SshError::TransferStalled(1);
    let old = Arc::clone(&h.conn);
    let slot = Mutex::new(Some(Arc::clone(&old)));
    // An error that is not a dead channel never evicts.
    assert!(!forget_sftp(&slot, &old, &SshError::PartialTransfer("x exists".into())).await);
    assert!(slot.lock().await.is_some());
    // The first failure evicts it, and a replacement is opened.
    assert!(forget_sftp(&slot, &old, &dead).await);
    let new = Arc::new(open_sftp_conn(&h.ssh, &AtomicBool::new(false)).await.unwrap());
    *slot.lock().await = Some(Arc::clone(&new));
    // A second operation on the old channel fails later: the replacement stays.
    assert!(!forget_sftp(&slot, &old, &dead).await);
    assert!(Arc::ptr_eq(slot.lock().await.as_ref().unwrap(), &new));
    assert!(new.hi.symlink_metadata("/").await.is_ok(), "the replacement was shut down");
    // Its own death does evict it.
    assert!(forget_sftp(&slot, &new, &dead).await);
    assert!(slot.lock().await.is_none());
}

/// Item 10/P2: an in-place fallback whose write loses its reply ends with a
/// path-rich error that still counts as a dead channel: a folder transfer
/// stops there (no second file is attempted) and the session is evicted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn in_place_failure_on_a_dead_channel_stops_the_tree_and_evicts() {
    let h = harness(false).await;
    std::fs::create_dir(h.remote.join("d")).unwrap();
    std::fs::create_dir(h.local.join("d")).unwrap();
    for f in ["a.bin", "b.bin"] {
        h.put_remote(&format!("d/{f}"), b"old", 0o644);
        h.put_local(&format!("d/{f}"), b"new body", 0o644);
        // The in-place write's reply never comes.
        h.fault("write", &format!("=/d/{f}"), 1, vec![Act::LoseReply]);
    }
    h.fault("rename", "", usize::MAX, vec![Act::Fail(StatusCode::PermissionDenied)]);
    let (_tx, rx) = watch::channel(false);
    let mut p = Progress::detached(rx);
    let local = h.local.join("d").to_string_lossy().to_string();
    let e = TEST_STALL
        .scope(Duration::from_millis(300), upload_tree(&h.conn, &mut p, &local, "/d", Overwrite::Replace))
        .await
        .unwrap_err();
    assert!(matches!(e, SshError::ChannelLost(_)) && sftp_dead(&e), "{e}");
    // The failed file and "the rest was skipped": nothing else was tried.
    assert!(e.to_string().contains("2 item(s) not transferred"), "{e}");
    let parts: Vec<String> = std::fs::read_dir(h.remote.join("d"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.ends_with(PART_SUFFIX))
        .collect();
    assert_eq!(parts.len(), 1, "a second file was attempted: {parts:?}");
    // A single file's in-place failure is dead too, and names its staged copy.
    let mut p = Progress::detached(watch::channel(false).1);
    h.put_local("c.bin", b"new body", 0o644);
    h.put_remote("c.bin", b"old", 0o644);
    h.fault("write", "=/c.bin", 1, vec![Act::LoseReply]);
    let one = h.local.join("c.bin").to_string_lossy().to_string();
    let e = TEST_STALL
        .scope(Duration::from_millis(300), copy_local_file(&h.conn, &mut p, &one, "/c.bin", Overwrite::Replace))
        .await
        .unwrap_err();
    assert!(sftp_dead(&e) && e.to_string().contains(PART_SUFFIX), "{e}");
    // ...so the cache drops the session.
    let slot = Mutex::new(Some(Arc::clone(&h.conn)));
    assert!(forget_sftp(&slot, &h.conn, &e).await);
}

/* --------------------------------------------------- W3d regression tests */

/// Plant `body` at `name` in `root` while the staged upload is being written
/// (after every up-front check): a file that arrives "late".
fn plant_during_staging(h: &Harness, name: &str, body: &'static str) {
    let late = h.remote.join(name);
    h.fault("write", "hawserpart", 1, vec![hook(move || std::fs::write(&late, body).unwrap())]);
}

/// W3d item 1, hardlink path: on a server whose plain RENAME REPLACES, a
/// file that appears at the destination during a `Never` upload is still
/// never clobbered: the commit is link(2), which the server's kernel refuses
/// atomically. A free destination is committed by the link alone (RENAME is
/// refused outright here), leaving no staging name behind.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_never_hardlink_commit_never_clobbers_a_late_file() {
    let h = harness_with(Opts { hardlink: true, rename_replaces: true, ..Default::default() }).await;
    h.put_local("n.txt", b"new", 0o640);
    plant_during_staging(&h, "n.txt", "theirs");
    let e = h.upload("n.txt", "/n.txt", Overwrite::Never).await.unwrap_err();
    assert!(e.to_string().contains("already exists"), "{e}");
    assert_eq!(h.remote_body("n.txt"), b"theirs");
    Harness::assert_clean(&h.remote);

    h.fault("rename", "", usize::MAX, vec![Act::Fail(StatusCode::PermissionDenied)]);
    let (_, notes) = h.upload("n.txt", "/m.txt", Overwrite::Never).await.unwrap();
    assert!(notes.is_empty(), "{notes:?}");
    assert_eq!(h.remote_body("m.txt"), b"new");
    assert_eq!(Harness::mode(&h.remote.join("m.txt")), 0o640);
    Harness::assert_clean(&h.remote);
}

/// W3d item 1, no-extension path: SFTPv3 RENAME, which (on a compliant
/// server, as OpenSSH) refuses an existing target: a late file is kept, a
/// free destination is committed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_never_without_hardlink_commits_by_rename() {
    let h = harness(false).await;
    assert!(!h.conn.hardlink);
    h.put_local("n.txt", b"new", 0o644);
    plant_during_staging(&h, "n.txt", "theirs");
    let e = h.upload("n.txt", "/n.txt", Overwrite::Never).await.unwrap_err();
    assert!(e.to_string().contains("already exists"), "{e}");
    assert_eq!(h.remote_body("n.txt"), b"theirs");
    Harness::assert_clean(&h.remote);
    h.upload("n.txt", "/m.txt", Overwrite::Never).await.unwrap();
    assert_eq!(h.remote_body("m.txt"), b"new");
    Harness::assert_clean(&h.remote);
}

/// W3d item 1: a link refused with the destination free (a filesystem
/// without hard links) falls back to RENAME; one refused because something
/// is there is "already exists", with no RENAME attempted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_never_link_refused_for_another_reason_falls_back_to_rename() {
    for status in [StatusCode::OpUnsupported, StatusCode::PermissionDenied, StatusCode::Failure] {
        let h = harness_with(Opts { hardlink: true, ..Default::default() }).await;
        h.put_local("n.txt", b"new", 0o644);
        h.fault("hardlink", "-> /n.txt", 1, vec![Act::Fail(status)]);
        h.upload("n.txt", "/n.txt", Overwrite::Never).await.unwrap();
        assert_eq!(h.remote_body("n.txt"), b"new", "{status:?}");
        Harness::assert_clean(&h.remote);
    }
}

/// W3d item 2: a lost LINK reply. Made or not, the link only adds a name, so
/// the staged upload is still there: nothing is deleted, and the error names
/// both paths and says what was seen. (a) The link was made and the reply
/// lost; (b) the server makes it only after answering the follow-up LSTATs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_never_lost_link_reply_keeps_and_names_both_paths() {
    for deferred in [false, true] {
        let h = harness_with(Opts { hardlink: true, ..Default::default() }).await;
        h.put_local("n.txt", b"new", 0o644);
        let act = if deferred { Act::Defer(Duration::from_millis(900)) } else { Act::LoseReply };
        h.fault("hardlink", "-> /n.txt", 1, vec![act]);
        let e = TEST_STALL
            .scope(Duration::from_millis(300), h.upload("n.txt", "/n.txt", Overwrite::Never))
            .await
            .unwrap_err();
        assert!(matches!(e, SshError::ChannelLost(_)) && sftp_dead(&e), "deferred={deferred}: {e}");
        let e = e.to_string();
        let part = h.remote_named(PART_SUFFIX);
        assert_eq!(part.len(), 1, "deferred={deferred}: the staged upload must be kept: {part:?}");
        assert!(e.contains(&format!("/{}", part[0])) && e.contains("/n.txt"), "{e}");
        if deferred {
            assert!(e.contains("does not exist yet"), "{e}");
            assert!(eventually(Duration::from_secs(3), || h.remote.join("n.txt").exists()).await);
        } else {
            assert!(e.contains("most likely went through"), "{e}");
        }
        assert_eq!(h.remote_body("n.txt"), b"new");
        assert_eq!(std::fs::read(h.remote.join(&part[0])).unwrap(), b"new");
    }
}

/// W3d item 6: during the `Never` commit, a stalled step — the link itself,
/// or the LSTAT that follows a refused link or RENAME — is `ChannelLost`
/// naming the staged upload (so a tree stops and the session is evicted),
/// never an ordinary refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_never_commit_stall_is_channel_lost() {
    for (link, stall_the_link) in [(true, true), (true, false), (false, false)] {
        let h = harness_with(Opts { hardlink: link, ..Default::default() }).await;
        h.put_local("n.txt", b"new", 0o644);
        let op = if link { "hardlink" } else { "rename" };
        if stall_the_link {
            h.fault(op, "-> /n.txt", 1, vec![Act::Before(Duration::from_secs(2))]);
        } else {
            let faults = Arc::clone(&h.faults);
            h.fault(
                op,
                "-> /n.txt",
                1,
                vec![
                    hook(move || {
                        faults.lock().unwrap().push(Fault {
                            op: "lstat",
                            path: "=/n.txt".into(),
                            times: 1,
                            acts: vec![Act::Before(Duration::from_secs(2))],
                        })
                    }),
                    Act::Fail(StatusCode::Failure),
                ],
            );
        }
        let e = TEST_STALL
            .scope(Duration::from_millis(300), h.upload("n.txt", "/n.txt", Overwrite::Never))
            .await
            .unwrap_err();
        let which = format!("link={link} stall_the_link={stall_the_link}");
        assert!(matches!(e, SshError::ChannelLost(_)), "{which}: {e}");
        let part = h.remote_named(PART_SUFFIX);
        assert_eq!(part.len(), 1, "{which}: {part:?}");
        assert!(e.to_string().contains(&format!("/{}", part[0])), "{which}: {e}");
        let slot = Mutex::new(Some(Arc::clone(&h.conn)));
        assert!(forget_sftp(&slot, &h.conn, &e).await, "{which}: not evicted");
    }
}

/// W3d item 1 (restore): after a failed replace, the original is put back by
/// a hard link, so a file that appeared at the destination meanwhile is not
/// overwritten even though this server's RENAME replaces. Nothing is lost,
/// and the error names where each copy is.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_restore_by_hardlink_never_clobbers_a_late_file() {
    let h = harness_with(Opts { hardlink: true, rename_replaces: true, ..Default::default() }).await;
    h.put_remote("cfg.txt", b"old", 0o600);
    h.put_local("cfg.txt", b"new contents", 0o644);
    let root = h.remote.clone();
    h.fault(
        "rename",
        "hawserpart -> /cfg.txt",
        usize::MAX,
        vec![
            hook(move || {
                // Once the original is aside, someone else writes the name.
                let aside = std::fs::read_dir(&root)
                    .unwrap()
                    .flatten()
                    .any(|e| e.file_name().to_string_lossy().ends_with(BAK_SUFFIX));
                if aside {
                    std::fs::write(root.join("cfg.txt"), "theirs").unwrap();
                }
            }),
            Act::Fail(StatusCode::Failure),
        ],
    );
    let e = h.upload("cfg.txt", "/cfg.txt", Overwrite::Replace).await.unwrap_err().to_string();
    let (bak, part) = (h.remote_named(BAK_SUFFIX), h.remote_named(PART_SUFFIX));
    assert_eq!((bak.len(), part.len()), (1, 1), "{bak:?} {part:?}");
    assert!(e.contains(&format!("/{}", bak[0])) && e.contains(&format!("/{}", part[0])), "{e}");
    assert_eq!(h.remote_body("cfg.txt"), b"theirs");
    assert_eq!(std::fs::read(h.remote.join(&bak[0])).unwrap(), b"old");
    assert_eq!(std::fs::read(h.remote.join(&part[0])).unwrap(), b"new contents");
}

/// W3d item 4: the confirmed in-place fallback never OPENs with TRUNCATE
/// unless an LSTAT has just SUCCEEDED and shown a regular file. Here LSTAT is
/// denied (as a server could deny it while allowing OPEN): refused, the file
/// untouched, no in-place warning, and the staged upload kept and named.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn in_place_replace_refuses_when_its_lstat_fails() {
    for status in [StatusCode::PermissionDenied, StatusCode::OpUnsupported, StatusCode::Failure] {
        let h = harness(false).await;
        h.put_remote("cfg.bin", b"old", 0o600);
        h.put_local("cfg.bin", b"new body", 0o644);
        let faults = Arc::clone(&h.faults);
        // The move-aside is refused (so the upload falls back to in place),
        // and from then on LSTAT of the destination fails.
        h.fault(
            "rename",
            "/cfg.bin -> ",
            1,
            vec![
                hook(move || {
                    faults.lock().unwrap().push(Fault {
                        op: "lstat",
                        path: "=/cfg.bin".into(),
                        times: usize::MAX,
                        acts: vec![Act::Fail(status)],
                    })
                }),
                Act::Fail(StatusCode::PermissionDenied),
            ],
        );
        h.fault("rename", "", usize::MAX, vec![Act::Fail(StatusCode::PermissionDenied)]);
        let opened = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&opened);
        h.fault("open", "=/cfg.bin", usize::MAX, vec![hook(move || flag.store(true, Ordering::SeqCst))]);
        let (_tx, rx) = watch::channel(false);
        let mut p = Progress::detached(rx);
        let local = h.local.join("cfg.bin").to_string_lossy().to_string();
        let e = copy_local_file(&h.conn, &mut p, &local, "/cfg.bin", Overwrite::Confirmed)
            .await
            .unwrap_err()
            .to_string();
        assert!(!opened.load(Ordering::SeqCst), "{status:?}: the destination was opened");
        assert_eq!(h.remote_body("cfg.bin"), b"old");
        assert!(!p.take_notes().iter().any(|n| n.contains("written in place")), "{status:?}");
        let part = h.remote_named(PART_SUFFIX);
        assert_eq!(part.len(), 1, "{part:?}");
        assert!(e.contains("could not check") && e.contains(&format!("/{}", part[0])), "{status:?}: {e}");
    }
}

/// Whether two remote names are the same file (one inode, two names).
fn same_inode(a: &Path, b: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let (a, b) = (std::fs::metadata(a).unwrap(), std::fs::metadata(b).unwrap());
    (a.dev(), a.ino()) == (b.dev(), b.ino())
}

/// W3e item 1: a `Never` upload committed by hard link on a server that
/// denies REMOVE (OpenSSH `-P remove`). (a) Every REMOVE of a staging name is
/// denied: the staging name is renamed to a fresh throwaway name (whose
/// REMOVE is denied too), and the upload succeeds with a WARNING that names
/// the leftover, says it is a second name for the same file, and says it must
/// be deleted manually. (b) Only the original staging name's REMOVE is
/// denied: the rename to a throwaway name and its REMOVE clean up, silently.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_never_hardlink_with_remove_denied_never_leaves_a_silent_second_name() {
    let h = harness_with(Opts { hardlink: true, ..Default::default() }).await;
    h.put_local("n.txt", b"new", 0o644);
    h.fault("remove", "hawserpart", usize::MAX, vec![Act::Fail(StatusCode::PermissionDenied)]);
    let renamed = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&renamed);
    h.fault("rename", "hawserpart -> ", 1, vec![hook(move || flag.store(true, Ordering::SeqCst))]);
    let (_, notes) = h.upload("n.txt", "/n.txt", Overwrite::Never).await.unwrap();
    assert!(renamed.load(Ordering::SeqCst), "the throwaway RENAME was not tried");
    assert_eq!(h.remote_body("n.txt"), b"new");
    let part = h.remote_named(PART_SUFFIX);
    assert_eq!(part.len(), 1, "{part:?}");
    assert!(same_inode(&h.remote.join(&part[0]), &h.remote.join("n.txt")));
    let left = format!("/{}", part[0]);
    assert!(
        notes.iter().any(|n| n.contains(&left)
            && n.contains("SECOND NAME FOR THE SAME FILE")
            && n.contains("deleted manually")),
        "{notes:?}"
    );

    let h = harness_with(Opts { hardlink: true, ..Default::default() }).await;
    h.put_local("n.txt", b"new", 0o644);
    h.fault("remove", "hawserpart", 1, vec![Act::Fail(StatusCode::PermissionDenied)]);
    let (_, notes) = h.upload("n.txt", "/n.txt", Overwrite::Never).await.unwrap();
    assert!(notes.is_empty(), "{notes:?}");
    assert_eq!(h.remote_body("n.txt"), b"new");
    Harness::assert_clean(&h.remote);
}

/// W3e item 2: the install is refused after the move-aside, the original is
/// hard-linked back, and the backup name cannot be removed (REMOVE denied,
/// even after a rename to a throwaway name). The upload stops there: no
/// in-place write (its truncating OPEN would change the backup too), and the
/// error names both names and says they are the same file. Nothing is lost.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_restore_by_hardlink_with_backup_remove_denied_never_writes_in_place() {
    let h = harness_with(Opts { hardlink: true, ..Default::default() }).await;
    h.put_remote("cfg.txt", b"old", 0o600);
    h.put_local("cfg.txt", b"new contents", 0o644);
    h.fault("rename", "hawserpart -> /cfg.txt", usize::MAX, vec![Act::Fail(StatusCode::Failure)]);
    h.fault("remove", "hawserbak", usize::MAX, vec![Act::Fail(StatusCode::PermissionDenied)]);
    let opened = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&opened);
    h.fault("open", "=/cfg.txt", usize::MAX, vec![hook(move || flag.store(true, Ordering::SeqCst))]);
    let (_tx, rx) = watch::channel(false);
    let mut p = Progress::detached(rx);
    let local = h.local.join("cfg.txt").to_string_lossy().to_string();
    let e = copy_local_file(&h.conn, &mut p, &local, "/cfg.txt", Overwrite::Replace)
        .await
        .unwrap_err()
        .to_string();
    assert!(!opened.load(Ordering::SeqCst), "the destination was opened for an in-place write");
    assert!(!p.take_notes().iter().any(|n| n.contains("written in place")));
    assert_eq!(h.remote_body("cfg.txt"), b"old");
    let (bak, part) = (h.remote_named(BAK_SUFFIX), h.remote_named(PART_SUFFIX));
    assert_eq!((bak.len(), part.len()), (1, 1), "{bak:?} {part:?}");
    assert!(same_inode(&h.remote.join(&bak[0]), &h.remote.join("cfg.txt")));
    assert!(
        e.contains(&format!("/{}", bak[0]))
            && e.contains("/cfg.txt")
            && e.contains("SAME FILE")
            && e.contains(&format!("/{}", part[0])),
        "{e}"
    );
    assert_eq!(std::fs::read(h.remote.join(&part[0])).unwrap(), b"new contents");
}

/// W3e item 3: a folder upload cancelled while the in-place fallback's LSTAT
/// of the destination is pending ends as CANCELLED (not as a failed file in
/// a partial transfer). The destination is untouched and the staged copy
/// dropped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tree_cancel_during_the_in_place_check_is_cancelled() {
    let h = harness(false).await;
    std::fs::create_dir(h.remote.join("d")).unwrap();
    std::fs::create_dir(h.local.join("d")).unwrap();
    h.put_remote("d/a.bin", b"old", 0o644);
    h.put_local("d/a.bin", b"new body", 0o644);
    let (tx, rx) = cancel_switch();
    let faults = Arc::clone(&h.faults);
    // The move-aside is refused (so the upload falls back to in place); the
    // next LSTAT of the destination is the in-place check: cancel during it.
    h.fault(
        "rename",
        "/d/a.bin -> ",
        1,
        vec![
            hook(move || {
                let tx = Arc::clone(&tx);
                faults.lock().unwrap().push(Fault {
                    op: "lstat",
                    path: "=/d/a.bin".into(),
                    times: 1,
                    acts: vec![
                        hook(move || {
                            let _ = tx.send(true);
                        }),
                        Act::Before(Duration::from_millis(500)),
                    ],
                })
            }),
            Act::Fail(StatusCode::PermissionDenied),
        ],
    );
    h.fault("rename", "", usize::MAX, vec![Act::Fail(StatusCode::PermissionDenied)]);
    let mut p = Progress::detached(rx);
    let local = h.local.join("d").to_string_lossy().to_string();
    let e = upload_tree(&h.conn, &mut p, &local, "/d", Overwrite::Replace).await.unwrap_err();
    assert!(matches!(e, SshError::TransferCancelled), "{e}");
    assert_eq!(std::fs::read(h.remote.join("d/a.bin")).unwrap(), b"old");
    Harness::assert_clean(&h.remote.join("d"));
}

/// W3d item 5: both sessions leave while the mux's writer is parked inside
/// an SSH send (the server stopped reading) and its readers inside the full
/// queue — none of them could see the sessions go. Dropping both ends stops
/// the mux anyway: every task ends (the count reaches 0) while the `SftpMux`
/// itself is still held, and the CLOSE goes out once the peer reads again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mux_stops_when_both_sessions_leave_while_its_writer_is_parked() {
    use tokio::io::AsyncWriteExt as _;
    let (ssh, _remote, _faults, seen) = connect(Opts::default()).await;
    let (r, w, early) = open_sftp_channel(&ssh, &AtomicBool::new(false)).await.unwrap();
    let (mut hi, raw, mux) = spawn_sftp_mux(r, w, early);
    seen.stall();
    // WRITE-shaped frames, far more than the SSH window plus every buffer.
    let body = 200 * 1024;
    let mut frame = Vec::with_capacity(4 + body);
    frame.extend_from_slice(&(body as u32).to_be_bytes());
    frame.push(6);
    frame.resize(4 + body, 0);
    let flood = async {
        for _ in 0..200 {
            if hi.write_all(&frame).await.is_err() {
                break;
            }
        }
    };
    assert!(
        tokio::time::timeout(Duration::from_millis(1500), flood).await.is_err(),
        "a stalled server took everything"
    );
    assert_eq!(mux.running(), 4);
    drop(hi);
    drop(raw);
    assert!(
        eventually(Duration::from_secs(2), || mux.running() == 0).await,
        "{} mux task(s) still running after both sessions left",
        mux.running()
    );
    seen.unstall();
    assert!(
        eventually(Duration::from_secs(15), || seen.channels_closed.load(Ordering::SeqCst) == 1).await,
        "the channel was never closed"
    );
    drop(mux);
}
