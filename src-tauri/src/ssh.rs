//! SSH transport, PTY I/O, and SFTP, built on russh (pure Rust — no libssh2 or
//! OpenSSL system dependency, so the Windows build needs no vcpkg).

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

/// Process-wide monotonic counter for unique host-key approval ids. `Instant`
/// elapsed-since-now is ~0 and collides across concurrent connections; a
/// counter never repeats within a run.
static HOSTKEY_SEQ: AtomicU64 = AtomicU64::new(0);
use std::time::{Duration, Instant};

use dashmap::DashMap;
use russh::client::{self, Handle};
use crate::utils::known_hosts::{self, HostKeyStatus};
use crate::utils::session_log::SessionLog;
use russh::{ChannelMsg, ChannelWriteHalf};
use russh_sftp::client::{RawSftpSession, SftpSession};
use russh_sftp::protocol::{FileType, StatusCode};
use serde::Serialize;
use tauri::{AppHandle, Emitter};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{oneshot, watch, Mutex};

use crate::credentials;

/// How long a host-key prompt waits for a human before giving up. Long enough
/// to read a fingerprint off a phone, short enough that a forgotten dialog does
/// not pin a connection task forever.
const HOST_KEY_PROMPT_TIMEOUT: Duration = Duration::from_secs(120);

/// Connect-stage deadlines. Each bounds machine time only: a stage's clock is
/// paused while a host-key or password dialog waits for the human (see
/// `HumanWait`), so a slow reader is never cut off by them.
///
/// TCP connect: the SYN/ACK round trip (per address tried by the resolver), or
/// for a jump target the bastion's own connect to it (direct-tcpip open).
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// The server's SSH identification line plus the whole key exchange. A port
/// that accepts TCP but never speaks SSH (a TLS service, a tarpit) ends here.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
/// Every authentication round trip together (password, keyboard-interactive
/// rounds, each agent identity).
const AUTH_TIMEOUT: Duration = Duration::from_secs(60);
/// Opening the session channel and the server's replies to the PTY and shell
/// requests.
const CHANNEL_SETUP_TIMEOUT: Duration = Duration::from_secs(20);
/// How long closing an exec channel, or disconnecting a throwaway connection,
/// may take before it is abandoned.
const EXEC_CLOSE_GRACE: Duration = Duration::from_secs(2);
/// After the shell's EOF, how long to wait for its exit status or channel close
/// before treating the shell as gone. OpenSSH sends both at once.
const SHELL_EOF_GRACE: Duration = Duration::from_secs(2);

/// Minimum gap between progress events for one transfer. At 64 KB chunks an
/// unthrottled emit would fire ~16k times per gigabyte; the IPC bridge and
/// React would both spend more time on bookkeeping than on the transfer.
const PROGRESS_INTERVAL: Duration = Duration::from_millis(100);

const CHUNK: usize = 64 * 1024;

/// A transfer step (one chunk read or written, one commit rename) that makes
/// no progress for this long fails the file as stalled, so a black-holed link
/// can never leave a row "active" forever. russh-sftp's own per-request
/// timeout normally fires first; this also covers local I/O and the copy loop.
const TRANSFER_STALL_TIMEOUT: Duration = Duration::from_secs(60);

/// Opening the auxiliary raw SFTP channel (see `Registry::sftp`).
const SFTP_SETUP_TIMEOUT: Duration = Duration::from_secs(10);

/// Most entries one directory listing returns; the rest are reported as
/// truncated. A broken or hostile server cannot grow client memory without
/// limit by streaming READDIR batches forever.
const MAX_LIST_ENTRIES: usize = 200_000;

#[derive(Debug, thiserror::Error)]
pub enum SshError {
    #[error("no open session {0}")]
    NoSession(String),
    #[error("session {0} has no shell channel")]
    NoShell(String),
    #[error("session {0} is disconnected")]
    Disconnected(String),
    #[error("authentication failed for {0}")]
    AuthFailed(String),
    #[error("host key for {host} was rejected")]
    HostKeyRejected { host: String },
    #[error("no answer to the host key prompt for {host}")]
    HostKeyTimeout { host: String },
    #[error(
        "host key for {host} CHANGED (known_hosts line {line}). This is either a rebuilt \
         server or an interception attempt. Hawser will not connect until the old entry is \
         removed by hand."
    )]
    ChangedHostKey { host: String, line: usize },
    #[error("{0}")]
    PartialTransfer(String),
    /// A folder transfer stopped early because its SFTP channel died.
    #[error("{0}")]
    TreeAborted(String),
    /// A connect stage ran past its deadline (see the `*_TIMEOUT` constants).
    #[error("{host}: {stage} timed out after {secs}s")]
    Timeout { host: String, stage: &'static str, secs: u64 },
    /// The server answered the shell request with a refusal.
    #[error(
        "{host} refused to start a shell (the account may be SFTP-only or have no login \
         shell)"
    )]
    ShellRefused { host: String },
    /// The session ended before the server answered the PTY and shell
    /// requests. `output` is what it printed first (often the only reason
    /// given: an expired account, a forced command).
    #[error("{}", shell_ended_early_text(.host, .output))]
    ShellEndedEarly { host: String, output: String },
    #[error("{0}")]
    Connect(String),
    /// The tab that started this connect was closed before it finished.
    #[error("connection {0} was cancelled")]
    Cancelled(String),
    /// A transfer stopped by `transfer_cancel`.
    #[error("transfer cancelled")]
    TransferCancelled,
    /// A transfer step made no progress for `TRANSFER_STALL_TIMEOUT`.
    #[error("transfer stalled: no progress for {0}s")]
    TransferStalled(u64),
    #[error(transparent)]
    KnownHosts(#[from] crate::utils::known_hosts::KnownHostsError),
    #[error(transparent)]
    Credential(#[from] credentials::CredError),
    #[error(transparent)]
    Russh(#[from] russh::Error),
    #[error(transparent)]
    Sftp(#[from] russh_sftp::client::error::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// `SshError::ShellEndedEarly`'s text: the server's output, then the reason
/// on a line of its own.
fn shell_ended_early_text(host: &str, output: &str) -> String {
    let sep = if output.is_empty() || output.ends_with('\n') { "" } else { "\r\n" };
    format!("{output}{sep}{host} closed the session before the shell started")
}

/* ------------------------------------------------------------------ payloads */

/// Serialised to the frontend. Mirrors `FileEntry` in src/types.ts — change the
/// two together.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileEntry {
    pub name: String,
    /// "file" | "directory" | "symlink"
    pub kind: &'static str,
    pub size: u64,
    /// Unix epoch seconds, or null when the server omits mtime.
    pub modified: Option<u32>,
    pub mode: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DirListing {
    pub path: String,
    pub entries: Vec<FileEntry>,
    /// The server listed more than `MAX_LIST_ENTRIES`; only that many are here.
    pub truncated: bool,
}

/// What a finished `sftp_get`/`sftp_put` reports. Mirrors `TransferOutcome`
/// in src/types.ts.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferOutcome {
    pub bytes: u64,
    /// Things the user should know although the transfer succeeded: a write
    /// that went through a symlink, or a non-atomic in-place fallback.
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferProgress {
    pub session_id: String,
    /// The frontend's id for this transfer: the queue row is matched on it,
    /// so two transfers of the same source never update each other's row.
    pub transfer_id: String,
    /// The transfer's ROOT source path — what the queue row is keyed on. Equal
    /// to `file_path` for a single file; for a folder, the folder, so per-file
    /// events land on the folder's row (bytes are then cumulative for the tree).
    pub root: String,
    pub file_path: String,
    pub bytes_transferred: u64,
    /// 0 when the server declines to report a size; the UI must treat that as
    /// indeterminate rather than dividing by zero.
    pub total_bytes: u64,
    pub direction: &'static str,
    pub done: bool,
}

/// One file a recursive transfer could not move, pushed on `sftp://failure` so
/// the UI can show the FULL list (not just the first failure) and offer a retry.
/// Single-file transfers don't emit this — their error propagates as the row's
/// own error, which is already the real reason.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferFailure {
    pub session_id: String,
    /// The transfer's id (see `TransferProgress::transfer_id`).
    pub transfer_id: String,
    /// The transfer's ROOT source path (local for upload, remote for download) —
    /// the value the queue row is keyed on, so the UI attributes this correctly.
    pub root: String,
    pub name: String,
    /// Both sides, so the UI can rebuild a retry job for exactly this file.
    pub local: String,
    pub remote: String,
    pub reason: String,
    pub direction: &'static str,
}

/// Connection lifecycle, pushed to the frontend on `ssh://status`.
///
/// Without this the UI has no way to learn a session died: the tab keeps its
/// "connected" dot, the status bar keeps claiming a live link, and the first
/// hint of trouble is a keystroke that goes nowhere.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionStatusEvent {
    pub session_id: String,
    /// "connected" | "disconnected" | "error"
    pub status: &'static str,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostKeyRequest {
    pub request_id: String,
    pub host: String,
    /// The peer address the socket actually connected to, for a direct
    /// connection. Empty when the connection rides a jump host: the bastion
    /// resolved and dialled the name, so no local address is meaningful (see
    /// `via`).
    pub ip: String,
    pub port: u16,
    /// Who is asking (catalogue name, user@host:port, bastion). Backend-derived
    /// from the dial, except the display name.
    #[serde(flatten)]
    pub origin: PromptOrigin,
    pub key_type: String,
    /// OpenSSH-style SHA256 fingerprint — the exact string `ssh-keygen -lf`
    /// prints, so it can be compared against an out-of-band source verbatim.
    pub fingerprint: String,
}

/// One active local port-forward, as reported to the UI.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ForwardInfo {
    pub id: String,
    pub session_id: String,
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
    /// "local" (ssh -L) or "socks" (ssh -D).
    pub kind: &'static str,
}

/// Bastion to tunnel through, resolved by the frontend from the catalogue.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JumpParams {
    pub host_id: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth: String,
    pub key_path: Option<String>,
    /// Catalogue display name, for prompts only.
    #[serde(default)]
    pub name: Option<String>,
}

/// Which connection a prompt belongs to, shown in the host-key and auth
/// dialogs apart from anything the server wrote. `target` and `via` come from
/// the parameters actually dialled; only `name` is the frontend's label.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PromptOrigin {
    /// Catalogue name of the host, when it has one.
    pub host_name: Option<String>,
    /// `user@host:port` of the machine asking.
    pub target: String,
    /// `user@host:port` (or name) of the bastion this connection rides, if any.
    pub via: Option<String>,
}

impl PromptOrigin {
    fn new(name: Option<&str>, username: &str, host: &str, port: u16, via: Option<String>) -> Self {
        let name = name.map(str::trim).filter(|n| !n.is_empty()).map(str::to_string);
        PromptOrigin { host_name: name, target: endpoint_label(username, host, port), via }
    }
}

/// `user@host:port`, bracketing an IPv6 literal.
fn endpoint_label(username: &str, host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("{username}@[{host}]:{port}")
    } else {
        format!("{username}@{host}:{port}")
    }
}

/* ---------------------------------------------------------------- deadlines */

/// Time spent waiting on a human (host-key or auth dialog) during one connect
/// attempt. Stage deadlines subtract it, so they bound only machine time.
#[derive(Clone, Default)]
pub(crate) struct HumanWait(Arc<std::sync::Mutex<HumanWaitState>>);

#[derive(Default)]
struct HumanWaitState {
    open: u32,
    since: Option<Instant>,
    total: Duration,
}

/// Held while a dialog is open; dropping it resumes the stage clocks.
pub(crate) struct HumanWaitGuard(HumanWait);

impl HumanWait {
    pub(crate) fn enter(&self) -> HumanWaitGuard {
        let mut s = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if s.open == 0 {
            s.since = Some(Instant::now());
        }
        s.open += 1;
        drop(s);
        HumanWaitGuard(self.clone())
    }

    /// (total waited so far, including an open wait; whether one is open now)
    fn waited(&self) -> (Duration, bool) {
        let s = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let open = s.since.map(|t| t.elapsed()).unwrap_or_default();
        (s.total + open, s.open > 0)
    }
}

impl Drop for HumanWaitGuard {
    fn drop(&mut self) {
        let mut s = self.0 .0.lock().unwrap_or_else(|e| e.into_inner());
        s.open = s.open.saturating_sub(1);
        if s.open == 0 {
            if let Some(t) = s.since.take() {
                s.total += t.elapsed();
            }
        }
    }
}

/// Run `fut` under `limit` of machine time: the clock does not run while a
/// human prompt is open (`wait`). Times out with a `Timeout` naming the stage.
async fn within<F: std::future::Future>(
    wait: &HumanWait,
    limit: Duration,
    host: &str,
    stage: &'static str,
    fut: F,
) -> Result<F::Output, SshError> {
    let start = Instant::now();
    tokio::pin!(fut);
    loop {
        let (waited, open) = wait.waited();
        let wake = if open {
            // Re-check periodically; the deadline moves out while a human reads.
            Instant::now() + Duration::from_millis(250)
        } else {
            start + limit + waited
        };
        tokio::select! {
            out = &mut fut => return Ok(out),
            _ = tokio::time::sleep_until(wake.into()) => {
                let (waited, open) = wait.waited();
                if !open && Instant::now() >= start + limit + waited {
                    return Err(SshError::Timeout {
                        host: host.to_string(),
                        stage,
                        secs: limit.as_secs(),
                    });
                }
            }
        }
    }
}

/* ------------------------------------------------------------ kill switch */

/// Ends one connect attempt's transports for real.
///
/// russh spawns its session task inside `connect_stream`, and that task owns
/// the socket. Dropping the connect future (a deadline, a cancel) drops only
/// the task's JoinHandle, which detaches it; and during key exchange the task
/// does not poll the channel that would tell it its caller is gone, so it can
/// sit on a stalled peer forever. Every stream handed to russh is therefore
/// wrapped in `Killable`: firing the switch makes the stream's next poll fail,
/// waking the parked task, which then unwinds and drops the socket. The host-key
/// handler (which runs in that task and may be parked on a dialog) also stops
/// waiting when it fires.
#[derive(Clone, Default)]
pub(crate) struct Kill(Arc<KillInner>);

#[derive(Default)]
struct KillInner {
    fired: AtomicBool,
    /// One pair of wakers PER stream. A ProxyJump attempt wraps two streams
    /// (the bastion's TCP socket and the target's direct-tcpip channel) in the
    /// same switch, each polled by its own russh task; a single shared waker
    /// kept only the last registrant, so `fire` could wake the target while
    /// the bastion's parked flush slept on.
    streams: std::sync::Mutex<Vec<Arc<StreamWakers>>>,
    notify: tokio::sync::Notify,
}

#[derive(Default)]
struct StreamWakers {
    read: futures_util::task::AtomicWaker,
    write: futures_util::task::AtomicWaker,
}

impl Kill {
    pub(crate) fn fire(&self) {
        self.0.fired.store(true, Ordering::SeqCst);
        let streams = match self.0.streams.lock() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        };
        for w in streams {
            w.read.wake();
            w.write.wake();
        }
        self.0.notify.notify_waiters();
    }

    /// A fresh waker pair for one stream, woken by every later `fire`.
    fn register_stream(&self) -> Arc<StreamWakers> {
        let w = Arc::new(StreamWakers::default());
        match self.0.streams.lock() {
            Ok(mut g) => g.push(Arc::clone(&w)),
            Err(p) => p.into_inner().push(Arc::clone(&w)),
        }
        w
    }

    pub(crate) fn fired(&self) -> bool {
        self.0.fired.load(Ordering::SeqCst)
    }

    /// Resolves once the switch has fired.
    async fn wait(&self) {
        loop {
            let notified = self.0.notify.notified();
            tokio::pin!(notified);
            // Registered before the check, so a fire in between is not missed.
            notified.as_mut().enable();
            if self.fired() {
                return;
            }
            notified.await;
        }
    }
}

/// Fires its `Kill` when dropped, unless disarmed. A connect attempt holds one
/// from its first dial: any exit that does not hand the transport to a
/// registered session (an error, a deadline, the future being dropped by a
/// cancel) kills every stream the attempt created.
pub(crate) struct KillGuard {
    kill: Kill,
    armed: bool,
}

impl KillGuard {
    pub(crate) fn new() -> Self {
        Self { kill: Kill::default(), armed: true }
    }

    pub(crate) fn kill(&self) -> Kill {
        self.kill.clone()
    }

    /// The transports now belong to a registered session.
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for KillGuard {
    fn drop(&mut self) {
        if self.armed {
            self.kill.fire();
        }
    }
}

/// A stream whose I/O fails once its `Kill` fires (see `Kill`).
pub(crate) struct Killable<S> {
    inner: S,
    kill: Kill,
    wakers: Arc<StreamWakers>,
}

impl<S> Killable<S> {
    pub(crate) fn new(inner: S, kill: Kill) -> Self {
        let wakers = kill.register_stream();
        Self { inner, kill, wakers }
    }
}

fn killed_error() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "connection attempt abandoned")
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for Killable<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.wakers.read.register(cx.waker());
        if self.kill.fired() {
            return std::task::Poll::Ready(Err(killed_error()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Killable<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.wakers.write.register(cx.waker());
        if self.kill.fired() {
            return std::task::Poll::Ready(Err(killed_error()));
        }
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.wakers.write.register(cx.waker());
        if self.kill.fired() {
            return std::task::Poll::Ready(Err(killed_error()));
        }
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // Killed: do not wait on a peer that stopped reading; dropping the
        // stream closes it.
        if self.kill.fired() {
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Host-key algorithms to offer, pinned ones first (as OpenSSH orders them):
/// a host pinned as ECDSA that later also offers Ed25519 keeps signing with the
/// pinned key instead of being refused as CHANGED. Only algorithms russh
/// implements are offered; an RSA pin covers all three RSA signature names.
///
/// The pinned block is in russh's own strength order (Ed25519, ECDSA,
/// rsa-sha2-512/256, then SHA-1 `ssh-rsa`), not file order: with an RSA pin
/// and an Ed25519 pin, a server offering both must get Ed25519, never SHA-1.
/// SHA-1 `ssh-rsa` is therefore always the last pinned algorithm.
fn preferred_host_key_order(pinned: &[russh::keys::Algorithm]) -> Vec<russh::keys::Algorithm> {
    use russh::keys::Algorithm;
    let defaults: &[Algorithm] = &russh::Preferred::DEFAULT.key;
    let rsa_pinned = pinned.iter().any(|a| matches!(a, Algorithm::Rsa { .. }));
    let is_pinned = |a: &Algorithm| match a {
        Algorithm::Rsa { .. } => rsa_pinned,
        other => pinned.contains(other),
    };
    let mut out: Vec<Algorithm> = defaults.iter().filter(|a| is_pinned(a)).cloned().collect();
    for alg in defaults {
        if !out.contains(alg) {
            out.push(alg.clone());
        }
    }
    out
}

/// keepalive interval and how many may go unanswered. russh ends the link when
/// MORE than `KEEPALIVE_MAX` intervals pass without a reply, i.e. after
/// `KEEPALIVE_INTERVAL * (KEEPALIVE_MAX + 1)`: 45s here.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
const KEEPALIVE_MAX: usize = 2;

fn keepalive_timeout() -> Duration {
    KEEPALIVE_INTERVAL * (KEEPALIVE_MAX as u32 + 1)
}

/// Client config for one hop: keepalives (what makes a dropped link
/// detectable; see `KEEPALIVE_MAX`) and the host-key algorithm order for that
/// host.
fn hop_config(host: &str, port: u16) -> Arc<client::Config> {
    let pinned = known_hosts::pinned_algorithms(host, port);
    let mut preferred = russh::Preferred::default();
    preferred.key = std::borrow::Cow::Owned(preferred_host_key_order(&pinned));
    Arc::new(client::Config {
        keepalive_interval: Some(KEEPALIVE_INTERVAL),
        keepalive_max: KEEPALIVE_MAX,
        nodelay: true,
        preferred,
        ..client::Config::default()
    })
}

/// Dial TCP under `TCP_CONNECT_TIMEOUT` and return the stream with the peer
/// address it actually connected to (the resolver may try several).
async fn dial_tcp(host: &str, port: u16) -> Result<(tokio::net::TcpStream, String), SshError> {
    let stream = match tokio::time::timeout(
        TCP_CONNECT_TIMEOUT,
        tokio::net::TcpStream::connect((host, port)),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return Err(SshError::Connect(format!("could not connect to {host}:{port}: {e}")))
        }
        Err(_) => {
            return Err(SshError::Timeout {
                host: format!("{host}:{port}"),
                stage: "TCP connect",
                secs: TCP_CONNECT_TIMEOUT.as_secs(),
            })
        }
    };
    let _ = stream.set_nodelay(true);
    let ip = stream
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| host.to_string());
    Ok((stream, ip))
}

/// SSH identification + key exchange over `stream`, under `limit` of machine
/// time (`HANDSHAKE_TIMEOUT` outside tests).
///
/// The stream goes to russh wrapped in `Killable`. On any failure here — the
/// deadline included — the switch is fired, so russh's already-spawned
/// session task unwinds and the socket closes instead of outliving the
/// attempt (see `Kill`). The caller's `KillGuard` covers the future being
/// dropped mid-way (a cancel).
async fn handshake<H, S>(
    config: Arc<client::Config>,
    stream: S,
    handler: H,
    wait: &HumanWait,
    host: &str,
    limit: Duration,
    kill: &Kill,
) -> Result<Handle<H>, SshError>
where
    H: client::Handler<Error = SshError> + Send + 'static,
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let stream = Killable::new(stream, kill.clone());
    let r = within(
        wait,
        limit,
        host,
        "SSH handshake (no SSH banner, or the key exchange stalled)",
        client::connect_stream(config, stream, handler),
    )
    .await
    .and_then(|r| r);
    if r.is_err() {
        kill.fire();
    }
    r
}

/* -------------------------------------------------------------- host keys */

/// Bridges the async Handler to a human decision in the UI.
///
/// `check_server_key` runs inside russh's connection task and cannot block, so
/// it parks on a oneshot while the frontend shows a dialog. The matching sender
/// is handed back by the `host_key_respond` command.
#[derive(Default)]
pub struct HostKeyPrompts {
    /// request id -> (owning session id + connect generation, answer channel).
    /// The session id lets a closed tab drop its own prompts instead of leaving
    /// them on screen; the generation lets a newer connect for the same tab
    /// drop only the prompts of the attempt it superseded.
    pending: DashMap<String, (PromptOwner, oneshot::Sender<bool>)>,
}

impl HostKeyPrompts {
    /// Resolve a prompt. Returns false if the id is unknown — a stale dialog
    /// answered after a timeout, which is not an error worth surfacing.
    pub fn respond(&self, request_id: &str, accept: bool) -> bool {
        match self.pending.remove(request_id) {
            Some((_, (_, tx))) => tx.send(accept).is_ok(),
            None => false,
        }
    }

    fn cancel(&self, request_id: &str) {
        self.pending.remove(request_id);
    }

    /// Drop every prompt raised for `session_id`, returning their request ids so
    /// the UI can be told to close them. Dropping the sender rejects the key,
    /// which aborts that in-flight connect.
    pub fn cancel_session(&self, session_id: &str) -> Vec<String> {
        cancel_matching(&self.pending, |o| o.0 == session_id)
    }

    fn cancel_attempt(&self, session_id: &str, ticket: u64) -> Vec<String> {
        cancel_matching(&self.pending, |o| o.0 == session_id && o.1 == ticket)
    }
}

/// (session id, connect generation) that raised a prompt.
type PromptOwner = (String, u64);

/// Remove all pending prompts whose owner matches from a prompt map,
/// returning their request ids.
fn cancel_matching<T>(
    pending: &DashMap<String, (PromptOwner, oneshot::Sender<T>)>,
    matches: impl Fn(&PromptOwner) -> bool,
) -> Vec<String> {
    let ids: Vec<String> = pending
        .iter()
        .filter(|e| matches(&e.value().0))
        .map(|e| e.key().clone())
        .collect();
    // remove_if: an id is never reused, but stay exact anyway.
    ids.into_iter()
        .filter(|id| pending.remove_if(id, |_, v| matches(&v.0)).is_some())
        .collect()
}

/// Register a prompt and show it, atomically with respect to
/// `cancel_for_session`.
///
/// The entry's shard lock is held from insert until the emit has returned, and
/// the sweep must take that same lock to see or remove the entry. So a sweep
/// lands either wholly BEFORE the registration — the watch sender it follows
/// is already dropped, `cancelled()` sees it, and nothing is emitted — or
/// wholly AFTER the emit, so its `prompt-closed` always follows the prompt in
/// the UI's event order. Without this, a cancel between the check and the emit
/// left a dialog no backend task would ever resolve.
///
/// Returns `None` (with nothing left registered) when cancelled or when the
/// emit fails. `emit` must not touch `pending`.
fn register_and_emit<T>(
    pending: &DashMap<String, (PromptOwner, oneshot::Sender<T>)>,
    request_id: &str,
    owner: PromptOwner,
    cancelled: impl FnOnce() -> bool,
    emit: impl FnOnce() -> bool,
) -> Option<oneshot::Receiver<T>> {
    let (tx, rx) = oneshot::channel();
    let guard = pending.entry(request_id.to_string()).insert((owner, tx));
    let shown = !cancelled() && emit();
    drop(guard);
    if shown {
        Some(rx)
    } else {
        pending.remove(request_id);
        None
    }
}

/// `register_and_emit`, with the stage clocks paused FIRST: the deadline that
/// races a prompt may run on another worker (a host-key check runs in russh's
/// own task), and pausing only after the emit left a gap in which it could fire
/// and close a dialog the user had just been shown. The guard comes back with
/// the receiver and must be held until the answer arrives.
fn raise_prompt<T>(
    wait: &HumanWait,
    pending: &DashMap<String, (PromptOwner, oneshot::Sender<T>)>,
    request_id: &str,
    owner: PromptOwner,
    cancelled: impl FnOnce() -> bool,
    emit: impl FnOnce() -> bool,
) -> Option<(HumanWaitGuard, oneshot::Receiver<T>)> {
    let human = wait.enter();
    register_and_emit(pending, request_id, owner, cancelled, emit).map(|rx| (human, rx))
}

/// Payload of `ssh://prompt-closed`: a host-key or auth prompt that no longer
/// has anyone waiting on it (timed out, or its tab was closed), so the dialog
/// queue can drop it instead of showing a stale question.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PromptClosed {
    pub request_id: String,
}

pub fn emit_prompt_closed(app: &AppHandle, request_id: &str) {
    let _ = app.emit(
        "ssh://prompt-closed",
        PromptClosed { request_id: request_id.to_string() },
    );
}

/* ------------------------------------------- keyboard-interactive auth prompts */

/// One field of a keyboard-interactive challenge shown to the user. The prompt
/// that asks for the password is answered with the stored password entirely in
/// the backend, so the password never crosses IPC (the "secrets never cross IPC
/// outward" invariant); `echo: false` fields (a hidden OTP) are masked in the UI.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthPromptField {
    pub prompt: String,
    pub echo: bool,
}

/// A keyboard-interactive challenge raised to the UI on `ssh://auth-prompt`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthPromptRequest {
    pub request_id: String,
    pub session_id: String,
    pub name: String,
    pub instruction: String,
    pub prompts: Vec<AuthPromptField>,
    /// Which connection is asking, apart from the server-written text above.
    #[serde(flatten)]
    pub origin: PromptOrigin,
    /// "password" for Hawser's own up-front password prompt (no server text),
    /// "challenge" for a keyboard-interactive round written by the server.
    pub kind: &'static str,
    /// When true, the dialog offers a "save to the OS vault" checkbox. Only set
    /// for the up-front "no saved password" prompt — never for a live server
    /// challenge (an OTP or token code is single-use and must not be stored).
    pub offer_save: bool,
}

/// The user's answer to an auth prompt: one typed response per shown prompt,
/// plus whether they asked to save the password to the OS vault.
#[derive(Debug, Default)]
pub struct AuthAnswer {
    pub answers: Vec<zeroize::Zeroizing<String>>,
    pub save: bool,
}

/// Same oneshot bridge as `HostKeyPrompts`, but the answer is the typed
/// responses (one per echo prompt shown) plus the save choice. Resolved by
/// `auth_prompt_respond`.
#[derive(Default)]
pub struct AuthPrompts {
    /// request id -> (owning session id, answer channel); see HostKeyPrompts.
    pending: DashMap<String, (PromptOwner, oneshot::Sender<AuthAnswer>)>,
}

impl AuthPrompts {
    /// Resolve a pending auth prompt with the user's typed answers and save choice.
    pub fn respond(
        &self,
        request_id: &str,
        answers: Vec<zeroize::Zeroizing<String>>,
        save: bool,
    ) -> bool {
        match self.pending.remove(request_id) {
            Some((_, (_, tx))) => tx.send(AuthAnswer { answers, save }).is_ok(),
            None => false,
        }
    }

    /// Drop every prompt raised for `session_id` (see HostKeyPrompts). The
    /// waiting auth then fails as cancelled, so nothing is sent.
    pub fn cancel_session(&self, session_id: &str) -> Vec<String> {
        cancel_matching(&self.pending, |o| o.0 == session_id)
    }

    fn cancel_attempt(&self, session_id: &str, ticket: u64) -> Vec<String> {
        cancel_matching(&self.pending, |o| o.0 == session_id && o.1 == ticket)
    }

    /// Drop the pending sender for a request. The waiting `request_auth_answers`
    /// then sees its receiver error and returns `AuthFailed("cancelled")`, which
    /// aborts the whole authentication — so NO answer (and therefore no stored
    /// password for the hidden prompts) is ever sent. This is what "Cancel" must
    /// do; answering with an empty vector would still send the password.
    pub fn cancel(&self, request_id: &str) {
        self.pending.remove(request_id);
    }
}

static AUTH_PROMPT_SEQ: AtomicU64 = AtomicU64::new(0);
const AUTH_PROMPT_TIMEOUT: Duration = Duration::from_secs(120);

/// Host key policy.
///
/// russh's default handler rejects every key, and the tempting "fix" is to
/// return `Ok(true)` — which silently disables the one check that detects a
/// man-in-the-middle. Instead:
///
///   * known and matching  -> accept silently
///   * known and DIFFERENT -> refuse outright, no prompt. A changed key is the
///     one case where a click-through is genuinely dangerous, and OpenSSH
///     refuses here too. Clearing it should require deliberate manual action.
///   * unknown             -> ask a human, showing the SHA256 fingerprint, and
///     record the answer in known_hosts on acceptance (trust on first use).
struct ClientHandler {
    host: String,
    /// The peer address the TCP socket connected to, shown alongside the
    /// hostname so the user can see *which* machine answered. Empty for a
    /// target reached through a jump host (the bastion dialled it; see
    /// `origin.via`).
    ip: String,
    port: u16,
    /// Who is asking, for the dialog (name, user@host:port, bastion).
    origin: PromptOrigin,
    app: AppHandle,
    prompts: Arc<HostKeyPrompts>,
    /// The tab and connect generation this connection belongs to, so closing
    /// the tab (or a newer connect for it) can drop the prompt.
    owner: PromptOwner,
    /// Closes (sender dropped) when the tab is closed mid-connect. Host-key
    /// checks run in russh's own session task, which outlives the cancelled
    /// connect future, so the handler must look itself before prompting.
    cancel: watch::Receiver<()>,
    /// Pauses the connect-stage deadlines while the dialog is open.
    wait: HumanWait,
    /// Why the transport ended, filled by `disconnected` for the output pump.
    death: DeathNote,
    /// The attempt's kill switch: a parked host-key check gives up when it
    /// fires (see `Kill`).
    kill: Kill,
}

/// Where `ClientHandler::disconnected` leaves the reason a transport died.
type DeathNote = Arc<std::sync::Mutex<Option<String>>>;

impl ClientHandler {
    fn cancelled(&self) -> bool {
        self.cancel.has_changed().is_err()
    }
}

/// The key a host-key decision is made on. Hawser pins plain public keys; a
/// certificate is judged by the key it embeds, exactly as that raw key would
/// be (the CA signature earns no extra trust and no exemption).
fn presented_key(presented: &russh::keys::PublicKeyOrCertificate) -> russh::keys::PublicKey {
    match presented {
        russh::keys::PublicKeyOrCertificate::PublicKey { key, .. } => key.clone(),
        russh::keys::PublicKeyOrCertificate::Certificate(cert) => {
            russh::keys::ssh_key::PublicKey::new(cert.public_key().clone(), "")
        }
    }
}

/// What to do with a presented host key, before any human is involved.
#[derive(Debug)]
enum KeyVerdict {
    /// Pinned and matching: accept silently.
    Accept,
    /// Changed, revoked, or the store could not be read: refuse, never prompt.
    Refuse(SshError),
    /// First use: ask a human.
    Ask,
}

/// The tri-state mapping that is the whole security property:
///   Trusted -> accept silently
///   Changed / Revoked -> refuse, never prompt
///   Unknown -> ask a human
///   store error -> refuse (fail closed, not a trust prompt)
fn key_verdict(host: &str, port: u16, key: &russh::keys::PublicKey, store: &std::path::Path) -> KeyVerdict {
    match known_hosts::classify(host, port, key, store) {
        Ok(HostKeyStatus::Trusted) => KeyVerdict::Accept,
        Ok(HostKeyStatus::Changed { line }) | Ok(HostKeyStatus::Revoked { line }) => {
            KeyVerdict::Refuse(SshError::ChangedHostKey { host: host.to_string(), line })
        }
        Ok(HostKeyStatus::Unknown) => KeyVerdict::Ask,
        Err(e) => KeyVerdict::Refuse(SshError::KnownHosts(e)),
    }
}

/// How a host-key dialog ended.
#[derive(Debug, PartialEq, Eq)]
enum PromptEnd {
    Accepted,
    Rejected,
    /// The sender was dropped: the tab closed, or a newer connect swept it.
    Dropped,
    TimedOut,
}

async fn await_host_key_answer(rx: oneshot::Receiver<bool>, limit: Duration) -> PromptEnd {
    match tokio::time::timeout(limit, rx).await {
        Ok(Ok(true)) => PromptEnd::Accepted,
        Ok(Ok(false)) => PromptEnd::Rejected,
        Ok(Err(_)) => PromptEnd::Dropped,
        Err(_) => PromptEnd::TimedOut,
    }
}

/// `settle_host_key` off the async runtime: trusting a key takes the
/// known_hosts file lock (a bounded wait, see `known_hosts::trust_at`), which
/// must never block a russh worker. Gives up with the attempt when `kill`
/// fires; the blocking call itself then finishes within its lock bound.
async fn settle_host_key_off_runtime(
    end: PromptEnd,
    host: &str,
    port: u16,
    key: &russh::keys::PublicKey,
    store: &std::path::Path,
    kill: &Kill,
) -> Result<bool, SshError> {
    if end != PromptEnd::Accepted {
        return settle_host_key(&end, host, port, key, store);
    }
    let (h, k, s) = (host.to_string(), key.clone(), store.to_path_buf());
    let task = tokio::task::spawn_blocking(move || settle_host_key(&end, &h, port, &k, &s));
    tokio::select! {
        r = task => r.map_err(|e| SshError::Connect(format!("recording the host key failed: {e}")))?,
        _ = kill.wait() => Err(SshError::Cancelled(host.to_string())),
    }
}

/// Turn a dialog's end into the handler's answer. Only an explicit accept
/// trusts the key, and only after the store re-check in `trust_at` (under its
/// lock) still sees the host as unknown or already pinned to this key.
fn settle_host_key(
    end: &PromptEnd,
    host: &str,
    port: u16,
    key: &russh::keys::PublicKey,
    store: &std::path::Path,
) -> Result<bool, SshError> {
    match end {
        PromptEnd::Accepted => {
            known_hosts::trust_at(host, port, key, store)?;
            Ok(true)
        }
        PromptEnd::Rejected | PromptEnd::Dropped => {
            Err(SshError::HostKeyRejected { host: host.to_string() })
        }
        PromptEnd::TimedOut => Err(SshError::HostKeyTimeout { host: host.to_string() }),
    }
}

impl client::Handler for ClientHandler {
    type Error = SshError;

    async fn check_server_key(
        &mut self,
        presented: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let server_public_key = presented_key(presented);
        let server_public_key = &server_public_key;
        let store = known_hosts::ensure_store()?;
        match key_verdict(&self.host, self.port, server_public_key, &store) {
            KeyVerdict::Accept => return Ok(true),
            KeyVerdict::Refuse(e) => return Err(e),
            KeyVerdict::Ask => {}
        }

        let request_id = format!(
            "hk-{}-{}",
            self.host,
            HOSTKEY_SEQ.fetch_add(1, Ordering::Relaxed)
        );
        let fingerprint = server_public_key
            .fingerprint(russh::keys::HashAlg::Sha256)
            .to_string();

        let request = HostKeyRequest {
            request_id: request_id.clone(),
            host: self.host.clone(),
            ip: self.ip.clone(),
            port: self.port,
            origin: self.origin.clone(),
            key_type: server_public_key.algorithm().to_string(),
            fingerprint,
        };
        let mut was_cancelled = false;
        let raised = raise_prompt(
            &self.wait,
            &self.prompts.pending,
            &request_id,
            self.owner.clone(),
            || {
                was_cancelled = self.cancelled() || self.kill.fired();
                was_cancelled
            },
            || self.app.emit("ssh://host-key-prompt", request).is_ok(),
        );
        let Some((human, rx)) = raised else {
            return Err(if was_cancelled {
                SshError::Cancelled(self.owner.0.clone())
            } else {
                SshError::HostKeyRejected { host: self.host.clone() }
            });
        };

        let end = tokio::select! {
            end = await_host_key_answer(rx, HOST_KEY_PROMPT_TIMEOUT) => end,
            // The attempt was abandoned (cancel or deadline): drop the dialog
            // and let russh's task unwind.
            _ = self.kill.wait() => {
                self.prompts.cancel(&request_id);
                emit_prompt_closed(&self.app, &request_id);
                return Err(SshError::Cancelled(self.owner.0.clone()));
            }
        };
        drop(human);
        match end {
            // Sender dropped: the tab was closed (or the attempt swept). The
            // sweep already emitted prompt-closed after our prompt; repeat it
            // so a close always follows the prompt even on a path that missed
            // it (the UI ignores a close for an id it no longer holds).
            PromptEnd::Dropped => emit_prompt_closed(&self.app, &request_id),
            PromptEnd::TimedOut => {
                self.prompts.cancel(&request_id);
                emit_prompt_closed(&self.app, &request_id);
            }
            PromptEnd::Accepted | PromptEnd::Rejected => {}
        }
        // Trust on first use, recorded so the next connection is silent. Same
        // store the check above read — writing anywhere else would mean
        // re-prompting forever.
        settle_host_key_off_runtime(end, &self.host, self.port, server_public_key, &store, &self.kill)
            .await
    }

    async fn disconnected(
        &mut self,
        reason: client::DisconnectReason<Self::Error>,
    ) -> Result<(), Self::Error> {
        let (note, out) = match reason {
            client::DisconnectReason::ReceivedDisconnect(info) => {
                let msg = info.message.trim();
                (
                    if msg.is_empty() {
                        "the server closed the connection".to_string()
                    } else {
                        format!("the server closed the connection: {msg}")
                    },
                    Ok(()),
                )
            }
            client::DisconnectReason::Error(e) => (death_reason(&e), Err(e)),
        };
        if let Ok(mut slot) = self.death.lock() {
            slot.get_or_insert(note);
        }
        out
    }
}

/// User-facing wording for a transport that ended with an error.
fn death_reason(e: &SshError) -> String {
    match e {
        SshError::Russh(russh::Error::KeepaliveTimeout) => format!(
            "no reply to keepalives for {}s (the network path or VPN dropped)",
            keepalive_timeout().as_secs()
        ),
        SshError::Russh(russh::Error::InactivityTimeout) => "closed after inactivity".into(),
        SshError::Russh(russh::Error::IO(io)) => format!("connection lost: {io}"),
        SshError::Io(io) => format!("connection lost: {io}"),
        SshError::Russh(russh::Error::HUP) | SshError::Russh(russh::Error::Disconnect) => {
            "the connection was closed".into()
        }
        other => format!("connection lost: {other}"),
    }
}

/* -------------------------------------------------------------- session */

pub struct Session {
    handle: Handle<ClientHandler>,
    /// Write half of the interactive shell channel. Split from the Channel so
    /// the read half can be owned by a pump task while writes and window-change
    /// requests still work — `into_stream()` would consume the Channel and take
    /// `window_change` with it, leaving no way to resize.
    shell: Arc<Mutex<Option<ChannelWriteHalf<client::Msg>>>>,
    sftp: Mutex<Option<Arc<SftpConn>>>,
    /// The server refused the `sftp` subsystem on this connection. Remembered
    /// so a pane refresh or cache reset does not open (and spend a session
    /// slot on) a channel the server will refuse again.
    sftp_refused: AtomicBool,
    /// The bastion connection, when this session rides a jump host. Held so it
    /// is not dropped (that closes the tunnel under the target session's feet),
    /// and disconnected explicitly on teardown.
    jump: Option<Handle<ClientHandler>>,
    /// Cleared when the shell or transport ends. Checked before every write so
    /// input into a dead session fails loudly instead of vanishing into a
    /// closed channel, and by `forward_start` to refuse a dead transport.
    alive: AtomicBool,
    /// Endpoint identity derived from what this connection actually dialled
    /// (see `utils::artifacts::dial_identity`). Keys the transcript, and every
    /// config, capture and AI-context lookup made for this session.
    endpoint: String,
    /// The connect that produced this session. Forwards record it so that the
    /// end of this session tears down its own forwards and never a newer
    /// connection's for the same tab.
    generation: u64,
}

impl Session {
    /// Mark the session dead and send SSH_MSG_DISCONNECT on the target and then
    /// the bastion. Best-effort: on a link that is already gone each send errors
    /// harmlessly. This closes the transport and every channel on it, including
    /// an in-flight SFTP transfer, whose next read or write then fails.
    async fn close(&self, why: &str) {
        self.alive.store(false, Ordering::SeqCst);
        let _ = self.handle.disconnect(russh::Disconnect::ByApplication, why, "").await;
        if let Some(jh) = self.jump.as_ref() {
            let _ = jh.disconnect(russh::Disconnect::ByApplication, why, "").await;
        }
    }
}

#[derive(Default)]
pub struct Registry {
    /// Shared with the output pumps, which end their own generation's forwards
    /// when the shell or transport ends.
    sessions: Arc<DashMap<String, Arc<Session>>>,
    /// Output-pump task per session, so disconnect can stop it — otherwise the
    /// pump keeps an Arc<Session> (hence the SSH Handle) alive and blocks on
    /// `read_half.wait()` forever after the tab is "closed".
    pumps: DashMap<String, tokio::task::JoinHandle<()>>,
    /// Active local/SOCKS forwards, keyed by forward id. See `Forward`.
    forwards: Arc<DashMap<String, Forward>>,
    /// Connects still in flight, session id -> generation. `remove` deletes the
    /// entry, which is how closing a tab mid-connect cancels it: the connect
    /// checks its generation at each step and before registering, and tears its
    /// own transport down instead of leaving a logged-in shell no tab owns.
    ///
    /// Each entry also holds the sender of a `watch` channel. Removing the entry
    /// drops it, which interrupts the connect at whatever await it is parked on
    /// (see `connect`) and tells the russh handlers to stop prompting.
    connecting: DashMap<String, (u64, watch::Sender<()>)>,
    /// In-flight key installs (`copy_id`), op id -> cancel sender.
    copy_ids: DashMap<String, (u64, watch::Sender<()>)>,
    /// Cancels that arrived for an op id not registered yet (the editor's
    /// cancel IPC overtook its install IPC), op id -> when. An install that
    /// registers under such an id stops before it dials. Pruned after
    /// `COPY_ID_CANCEL_TTL`.
    copy_id_cancels: DashMap<String, Instant>,
    /// Running transfers and early cancels, under ONE lock (see
    /// `TransferTable`).
    transfers: std::sync::Mutex<TransferTable>,
}

/// Running transfers and the cancels that arrived before their transfer
/// registered. One lock for both: with two maps, a cancel could find no
/// transfer, the transfer then register (finding no marker), and the cancel
/// then leave its marker behind — a cancel that stopped nothing.
#[derive(Default)]
struct TransferTable {
    /// Transfer id -> (registration seq, cancel sender).
    running: std::collections::HashMap<String, (u64, watch::Sender<bool>)>,
    /// Transfer id -> when the early cancel came, pruned after
    /// `COPY_ID_CANCEL_TTL`.
    early_cancels: std::collections::HashMap<String, Instant>,
}

/// How long an early `copy_id_cancel` is remembered (see `copy_id_cancels`).
const COPY_ID_CANCEL_TTL: Duration = Duration::from_secs(120);

/// Generation counter for `Registry::connecting`.
static CONNECT_SEQ: AtomicU64 = AtomicU64::new(1);
static COPY_ID_SEQ: AtomicU64 = AtomicU64::new(0);
static TRANSFER_SEQ: AtomicU64 = AtomicU64::new(0);

/// Everything needed to tear a forward down *completely*.
///
/// Aborting only the listener stops new connections but leaves already-
/// established tunnels carrying traffic — a user who "stopped" a forward would
/// still be leaking through the live ones. So each forward also owns the
/// handles of the per-connection tunnel tasks it has spawned; tearing the
/// forward down ends those too.
struct Forward {
    info: ForwardInfo,
    /// `Session::generation` of the transport this forward tunnels over.
    generation: u64,
    listener: tokio::task::JoinHandle<()>,
    tunnels: TunnelHandles,
}

/// Join handles for the live per-connection tunnel tasks under one forward.
/// `JoinHandle` rather than `AbortHandle` so teardown can *await* completion,
/// not just request cancellation. A plain `std::sync::Mutex` (never held across
/// an `.await`) is enough — pushes happen in the accept loop, and the whole set
/// is drained on teardown.
type TunnelHandles = Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>>;

/// Accept one connection. An accept error (EMFILE under fd pressure, a client
/// that reset mid-handshake) is transient — the listener itself is still good —
/// so back off briefly and report "nothing this time" instead of letting the
/// caller's loop exit and silently kill a forward that stays listed as active.
async fn accept_or_retry(
    listener: &tokio::net::TcpListener,
) -> Option<(tokio::net::TcpStream, std::net::SocketAddr)> {
    match listener.accept().await {
        Ok(pair) => Some(pair),
        Err(e) => {
            eprintln!("hawser: forward accept failed (retrying): {e}");
            tokio::time::sleep(Duration::from_millis(100)).await;
            None
        }
    }
}

/// Record a newly spawned tunnel task, pruning handles for tunnels that have
/// already finished so a long-lived forward's set does not grow without bound.
fn track_tunnel(tunnels: &TunnelHandles, handle: tokio::task::JoinHandle<()>) {
    if let Ok(mut v) = tunnels.lock() {
        v.retain(|h| !h.is_finished());
        v.push(handle);
    }
}

/// Remove and return all currently-tracked tunnel handles, so the caller can
/// abort and await them without holding the lock across `.await`.
fn take_tunnels(tunnels: &TunnelHandles) -> Vec<tokio::task::JoinHandle<()>> {
    match tunnels.lock() {
        Ok(mut v) => std::mem::take(&mut *v),
        Err(_) => Vec::new(),
    }
}

/// Tear one forward down, in the only order that leaves nothing behind: stop
/// the listener and WAIT for it, so it can no longer accept and register a new
/// tunnel; only then take, abort and await every tunnel it registered.
async fn teardown_forward(fw: Forward) {
    fw.listener.abort();
    let _ = fw.listener.await;
    let tunnels = take_tunnels(&fw.tunnels);
    for h in &tunnels {
        h.abort();
    }
    for h in tunnels {
        let _ = h.await;
    }
}

/// Tear down forwards already removed from the map, in a way the caller being
/// aborted cannot interrupt.
///
/// Every listener is aborted first, synchronously (`abort()` never waits), so
/// none can outlive this call even if it is cut off at its first await. The
/// ordered joins then run in a detached task that owns every handle: dropping
/// the awaiting caller (the pump aborted by a reconnect or tab close) leaves
/// that task running to completion instead of detaching half-joined
/// listeners and tunnels that no registry sweep can find any more.
async fn teardown_forwards(fws: Vec<Forward>) {
    if fws.is_empty() {
        return;
    }
    for fw in &fws {
        fw.listener.abort();
    }
    let joiner = tokio::spawn(async move {
        for fw in fws {
            teardown_forward(fw).await;
        }
    });
    let _ = joiner.await;
}

/// Remove every forward that matches from the map, for teardown.
fn take_forwards(
    forwards: &DashMap<String, Forward>,
    matches: impl Fn(&Forward) -> bool,
) -> Vec<Forward> {
    let ids: Vec<String> = forwards
        .iter()
        .filter(|e| matches(e.value()))
        .map(|e| e.key().clone())
        .collect();
    ids.into_iter()
        .filter_map(|id| forwards.remove_if(&id, |_, f| matches(f)).map(|(_, f)| f))
        .collect()
}

/// Everything a connect needs, as the frontend asked for it.
pub struct ConnectSpec {
    pub session_id: String,
    /// Vault id of the credential (the host's own id, or the one it borrows).
    pub host_id: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub cols: u32,
    pub rows: u32,
    pub startup_commands: Vec<String>,
    pub auth: String,
    pub key_path: Option<String>,
    pub jump: Option<JumpParams>,
    /// A quick-connect password, used once and wiped on drop.
    pub one_shot_password: Option<zeroize::Zeroizing<String>>,
    /// The frontend's computed endpoint identity. Only its catalogue ids are
    /// used; destinations come from the dial (utils::artifacts::dial_identity).
    pub endpoint: Option<String>,
    /// Catalogue display name, for prompts only.
    pub label: Option<String>,
    /// A quick-connect host that is not in the catalogue: never offer to save
    /// a typed password for it (nothing could ever delete that vault entry).
    pub ephemeral: bool,
}

/// Prompt context shared by one hop's authentication.
struct PromptCtx<'a> {
    app: &'a AppHandle,
    auth_prompts: &'a Arc<AuthPrompts>,
    owner: PromptOwner,
    origin: PromptOrigin,
    wait: HumanWait,
    /// Offer "save to the vault" on the up-front password prompt.
    offer_save: bool,
}

/// One hop's authentication parameters.
struct AuthSpec<'a> {
    host_id: &'a str,
    host: &'a str,
    port: u16,
    username: &'a str,
    auth: &'a str,
    key_path: Option<&'a str>,
    /// The ONE secret snapshot `authorize_stored_password` read and authorized
    /// for this destination (or the one-shot password). `authenticate` never
    /// reads the vault again, so what was checked is exactly what is sent.
    secret: Option<zeroize::Zeroizing<String>>,
}

/// Open the shell channel, ask for a PTY and a shell, and wait for the
/// server's replies to both. russh's request calls only enqueue; the replies
/// arrive on the channel as Success/Failure, in request order. Anything else
/// that arrives first is returned for the pump to replay.
///
/// A refused PTY is reported (the shell may still work, as with OpenSSH's
/// "PTY allocation request failed"); a refused shell is an error.
///
/// A session that ends before both replies (an expired account, a forced
/// command that prints and exits) fails with what it printed, followed by the
/// diagnostic: that output is usually the only explanation the user gets.
///
/// Startup input is NOT sent here: it goes out only once the output pump is
/// reading (see `send_startup`).
async fn open_shell<H: client::Handler>(
    handle: &Handle<H>,
    host: &str,
    cols: u32,
    rows: u32,
) -> Result<(russh::ChannelReadHalf, ChannelWriteHalf<client::Msg>, Vec<ChannelMsg>, bool), SshError>
{
    let channel = handle.channel_open_session().await?;
    let (mut read_half, write_half) = channel.split();
    write_half
        .request_pty(true, "xterm-256color", cols, rows, 0, 0, &[])
        .await?;
    write_half.request_shell(true).await?;
    let mut early = Vec::new();
    let mut replies: Vec<bool> = Vec::with_capacity(2);
    while replies.len() < 2 {
        match read_half.wait().await {
            Some(ChannelMsg::Success) => replies.push(true),
            Some(ChannelMsg::Failure) => replies.push(false),
            Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => {
                return Err(SshError::ShellEndedEarly {
                    host: host.to_string(),
                    output: early_output(&early),
                })
            }
            Some(other) => early.push(other),
        }
    }
    if !replies[1] {
        return Err(SshError::ShellRefused { host: host.to_string() });
    }
    Ok((read_half, write_half, early, replies[0]))
}

/// Cap on the early output carried in a `ShellEndedEarly` error.
const EARLY_OUTPUT_CAP: usize = 16 * 1024;

/// The terminal text of messages buffered before the shell started, decoded as
/// the pump would (stdout and stderr), capped at `EARLY_OUTPUT_CAP` bytes.
fn early_output(early: &[ChannelMsg]) -> String {
    let mut bytes: Vec<u8> = Vec::new();
    for m in early {
        if let ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } = m {
            let room = EARLY_OUTPUT_CAP.saturating_sub(bytes.len());
            bytes.extend_from_slice(&data[..data.len().min(room)]);
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

/// The startup commands as the lines `send_startup` types, blanks dropped.
fn startup_lines(commands: &[String]) -> Vec<String> {
    commands
        .iter()
        .map(|c| c.trim())
        .filter(|c| !c.is_empty())
        .map(|c| format!("{c}\n"))
        .collect()
}

/// The shell writer, held exclusively. Taken by `connect` BEFORE the session
/// is registered (so before any user keystroke can reach it) and handed to
/// `send_startup`, so the first user input always lands after the startup
/// lines, never ahead of a `tmux attach`.
type ShellGuard = tokio::sync::OwnedMutexGuard<Option<ChannelWriteHalf<client::Msg>>>;

/// Ctrl-U: discards the shell's current input line.
const KILL_LINE: &[u8] = b"\x15";

/// Send the startup commands as shell input. Called only once the output pump
/// is reading: a shell that prints a lot at login (an MOTD, a tmux attach)
/// fills russh's per-channel receive queue, and russh then blocks delivering
/// that output — so it never processes the window adjustment that a write
/// waiting for send credit needs. With nobody reading, connect hung forever.
///
/// Holds the shell writer (taken before registration, see `ShellGuard`) for
/// the whole batch, and gives up after `limit` (the session stays up; only the
/// remaining startup lines are skipped). A line cut off part-way is never left
/// for the user's typing to extend: `report` is told first, then the writer is
/// kept until a Ctrl-U has discarded the partial line (or the session ends).
async fn send_startup(
    mut guard: ShellGuard,
    commands: &[String],
    limit: Duration,
    report: impl FnOnce(&SshError),
) -> Result<(), SshError> {
    let lines = startup_lines(commands);
    if lines.is_empty() {
        return Ok(());
    }
    let Some(w) = guard.as_mut() else { return Ok(()) };
    let mut mid_line = false;
    let send = async {
        for line in &lines {
            mid_line = true;
            w.data(line.as_bytes()).await?;
            mid_line = false;
        }
        Ok::<(), SshError>(())
    };
    let r = match tokio::time::timeout(limit, send).await {
        Ok(r) => r,
        Err(_) => Err(SshError::Connect(format!(
            "the server took no input for {}s",
            limit.as_secs()
        ))),
    };
    if let Err(e) = &r {
        report(e);
        if mid_line {
            // Unbounded on purpose: user input queued behind this lock would
            // wait on the same send window anyway, and must not go out first.
            let _ = w.data(KILL_LINE).await;
        }
    }
    r
}

/// One live session, resolved from the registry once. Its endpoint identity
/// and every operation run through it belong to the same connection, even if
/// a reconnect replaces the tab's registry entry in between.
pub struct SessionRef {
    id: String,
    session: Arc<Session>,
}

impl SessionRef {
    /// The endpoint identity this connection dialled (see `Session::endpoint`).
    pub fn endpoint(&self) -> &str {
        &self.session.endpoint
    }
}

impl Registry {
    /// The endpoint identity of a live session (see `Session::endpoint`).
    pub fn endpoint_of(&self, id: &str) -> Result<String, SshError> {
        Ok(self.get(id)?.endpoint.clone())
    }

    /// Resolve a live session once, for a caller that needs its identity and
    /// an operation on the same connection (see `SessionRef`).
    pub fn session(&self, id: &str) -> Result<SessionRef, SshError> {
        Ok(SessionRef { id: id.to_string(), session: self.get(id)? })
    }

    fn get(&self, id: &str) -> Result<Arc<Session>, SshError> {
        self.sessions
            .get(id)
            .map(|r| Arc::clone(r.value()))
            .ok_or_else(|| SshError::NoSession(id.to_string()))
    }

    /// Close a tab's connection: cancel a connect still in flight for it, then
    /// tear down whatever is registered (see `teardown_registered`).
    pub async fn remove(&self, id: &str) {
        // Cancel a connect that has not registered yet (see `connecting`).
        self.connecting.remove(id);
        self.teardown_registered(id).await;
    }

    /// Tear a registered session down for real: stop the pump, send an SSH
    /// disconnect to the target and the bastion so the transports actually
    /// close (Handle's Drop does NOT close them), and sweep the session's
    /// forwards. Leaves `connecting` alone, so a reconnect can hold its ticket
    /// across this teardown (a tab closed meanwhile then cancels it).
    ///
    /// Teardown is awaited to completion before returning: `abort()` only
    /// *requests* cancellation, so returning as soon as abort was issued could
    /// report "disconnected" while the pump was still mid-poll, still holding
    /// its `Arc<Session>`.
    async fn teardown_registered(&self, id: &str) {
        let session = self.sessions.remove(id).map(|(_, s)| s);

        // Stop the output pump first, and WAIT for it to unwind, so it has
        // dropped its Arc<Session> before we send the disconnect below.
        if let Some((_, pump)) = self.pumps.remove(id) {
            pump.abort();
            let _ = pump.await;
        }

        if let Some(session) = session {
            session.close("closed by user").await;
        }

        // A forward's transport is this session; with it gone the listener
        // would sit accepting connections it can never tunnel, forever.
        teardown_forwards(take_forwards(&self.forwards, |f| f.info.session_id == id)).await;
    }

    /// Whether connect `ticket` for `id` is still wanted (no
    /// disconnect arrived for it since it started).
    fn still_wanted(&self, id: &str, ticket: u64) -> bool {
        self.connecting.get(id).is_some_and(|g| g.0 == ticket)
    }

    /// Open a connection, authenticate, and start an interactive shell.
    ///
    /// A stored password is read from the OS vault once, authorized for this
    /// destination, held in a zeroizing buffer, and dropped as soon as
    /// authentication returns. It is never a parameter, never logged, and never
    /// sent to the webview.
    ///
    /// Returns the endpoint identity the connection dialled (see
    /// `Session::endpoint`), so the caller keys follow-up work by what was
    /// actually dialled rather than by the catalogue as it stands afterwards.
    pub async fn connect(
        &self,
        app: AppHandle,
        prompts: Arc<HostKeyPrompts>,
        auth_prompts: Arc<AuthPrompts>,
        spec: ConnectSpec,
    ) -> Result<String, SshError> {
        let session_id = spec.session_id.clone();
        let ticket = CONNECT_SEQ.fetch_add(1, Ordering::Relaxed);
        let (cancel_tx, cancel_rx) = watch::channel(());
        // Take the ticket FIRST, before tearing down the previous connection:
        // a tab closed during that teardown then removes our ticket and this
        // connect stops before it dials, instead of prompting for a closed tab.
        let superseded = self.connecting.insert(session_id.clone(), (ticket, cancel_tx));
        let sweep = |owner_ticket: u64| {
            let closed = prompts
                .cancel_attempt(&session_id, owner_ticket)
                .into_iter()
                .chain(auth_prompts.cancel_attempt(&session_id, owner_ticket));
            for request_id in closed {
                emit_prompt_closed(&app, &request_id);
            }
        };
        // Dropping the superseded attempt's sender cancels it; its prompts (a
        // host-key check parks in russh's own task, which outlives that
        // attempt) are dropped here so they do not linger beside ours.
        if let Some((old_ticket, _old_tx)) = superseded {
            sweep(old_ticket);
        }

        // A reconnect reuses the session id. Tear the previous connection down:
        // replacing the map entry alone would leave its transport alive
        // (forward listeners hold their own Arc<Session>) and its forwards
        // still listed under this id. Not raced against cancellation: a
        // teardown cut off half-way would drop a session without disconnecting.
        if self.sessions.contains_key(&session_id) || self.pumps.contains_key(&session_id) {
            self.teardown_registered(&session_id).await;
        }

        let result = if !self.still_wanted(&session_id, ticket) {
            Err(SshError::Cancelled(session_id.clone()))
        } else {
            let mut closed = cancel_rx.clone();
            // Race the whole connect against cancellation. `still_wanted`
            // checks between stages are not enough: a disconnect during the
            // TCP/kex handshake or authentication must stop it there, before a
            // password is sent or a new prompt raised. Dropping the future
            // drops every Handle it owns, which ends those transports.
            tokio::select! {
                biased;
                _ = closed.changed() => Err(SshError::Cancelled(session_id.clone())),
                r = self.connect_inner(
                    app.clone(), Arc::clone(&prompts), Arc::clone(&auth_prompts), spec, ticket,
                    cancel_rx,
                ) => r,
            }
        };
        // Clear our in-flight marker, but only if it is still ours.
        self.connecting.remove_if(&session_id, |_, g| g.0 == ticket);
        // A failed or cancelled attempt leaves no prompt behind: one registered
        // in the poll that raced a sweep would otherwise be orphaned (its
        // timeout cleanup lived in the dropped future). Swept by generation,
        // so a newer connect's prompts for this tab are left alone.
        if result.is_err() {
            sweep(ticket);
        }
        result
    }

    async fn connect_inner(
        &self,
        app: AppHandle,
        prompts: Arc<HostKeyPrompts>,
        auth_prompts: Arc<AuthPrompts>,
        spec: ConnectSpec,
        ticket: u64,
        cancel: watch::Receiver<()>,
    ) -> Result<String, SshError> {
        let ConnectSpec {
            session_id,
            host_id,
            host,
            port,
            username,
            cols,
            rows,
            startup_commands,
            auth,
            key_path,
            jump,
            one_shot_password,
            endpoint,
            label,
            ephemeral,
        } = spec;
        let (session_id, host, username) = (session_id.as_str(), host.as_str(), username.as_str());

        // Before dialing anything, refuse to send a saved password to a
        // destination the catalogue never bound it to (both the target and any
        // jump host). This fails fast, before we even connect to the requested
        // host, so a compromised frontend cannot use the connection itself as an
        // exfiltration channel for another host's stored secret. The snapshot
        // it authorized is what authentication later uses.
        let target_secret = match one_shot_password {
            Some(p) => {
                authorize_stored_password(&auth, &host_id, host, port, username, true).await?;
                Some(p)
            }
            None => authorize_stored_password(&auth, &host_id, host, port, username, false).await?,
        };
        let jump_secret = match jump.as_ref() {
            Some(j) => authorize_stored_password(&j.auth, &j.host_id, &j.host, j.port, &j.username, false).await?,
            None => None,
        };

        // Endpoint identity from the parameters actually dialled below, not
        // from the claim: the claim only says which catalogue entries these are.
        let endpoint = crate::utils::artifacts::dial_identity(
            endpoint.as_deref(),
            (username, host, port),
            jump.as_ref().map(|j| (j.username.as_str(), j.host.as_str(), j.port)),
        );

        let owner: PromptOwner = (session_id.to_string(), ticket);
        let wait = HumanWait::default();
        let death: DeathNote = Arc::default();
        // Fires on every exit that does not register a session, including this
        // future being dropped by a cancel: no russh task or socket from this
        // attempt survives it (see `Kill`).
        let mut guard = KillGuard::new();
        let kill = guard.kill();
        let via = jump.as_ref().map(|j| {
            let ep = endpoint_label(&j.username, &j.host, j.port);
            match j.name.as_deref().map(str::trim).filter(|n| !n.is_empty()) {
                Some(n) => format!("{n} ({ep})"),
                None => ep,
            }
        });
        let target_origin = PromptOrigin::new(label.as_deref(), username, host, port, via);

        // With a jump host: dial the bastion, authenticate there, then open a
        // direct-tcpip channel to the real target and run the SSH handshake
        // over that stream — exactly what OpenSSH's ProxyJump does. The
        // bastion's own host key is checked and prompted like any other.
        let (mut handle, jump_handle) = match jump {
            Some(j) => {
                let (tcp, jump_ip) = dial_tcp(&j.host, j.port).await?;
                let jump_origin =
                    PromptOrigin::new(j.name.as_deref(), &j.username, &j.host, j.port, None);
                let jump_handler = ClientHandler {
                    host: j.host.clone(),
                    ip: jump_ip,
                    port: j.port,
                    origin: jump_origin.clone(),
                    app: app.clone(),
                    prompts: Arc::clone(&prompts),
                    owner: owner.clone(),
                    cancel: cancel.clone(),
                    wait: wait.clone(),
                    death: Arc::default(),
                    kill: kill.clone(),
                };
                let jlabel = format!("{}:{}", j.host, j.port);
                let mut jh = handshake(
                    hop_config(&j.host, j.port), tcp, jump_handler, &wait, &jlabel, HANDSHAKE_TIMEOUT, &kill,
                )
                .await?;
                let jctx = PromptCtx {
                    app: &app,
                    auth_prompts: &auth_prompts,
                    owner: owner.clone(),
                    origin: jump_origin,
                    wait: wait.clone(),
                    offer_save: true,
                };
                let jspec = AuthSpec {
                    host_id: &j.host_id,
                    host: &j.host,
                    port: j.port,
                    username: &j.username,
                    auth: &j.auth,
                    key_path: j.key_path.as_deref(),
                    secret: jump_secret,
                };
                within(&wait, AUTH_TIMEOUT, &jlabel, "authentication", authenticate(&mut jh, jspec, &jctx))
                    .await??;
                if !self.still_wanted(session_id, ticket) {
                    let _ = jh
                        .disconnect(russh::Disconnect::ByApplication, "cancelled", "")
                        .await;
                    return Err(SshError::Cancelled(session_id.to_string()));
                }

                // The bastion resolves and dials the target itself, so there
                // is no local address to show; the prompt says "via" instead.
                let tunnel = within(
                    &wait,
                    TCP_CONNECT_TIMEOUT,
                    &format!("{host}:{port}"),
                    "the bastion's connection to the target",
                    jh.channel_open_direct_tcpip(host, port as u32, "127.0.0.1", 0),
                )
                .await??;
                let handler = ClientHandler {
                    host: host.to_string(),
                    ip: String::new(),
                    port,
                    origin: target_origin.clone(),
                    app: app.clone(),
                    prompts,
                    owner: owner.clone(),
                    cancel: cancel.clone(),
                    wait: wait.clone(),
                    death: Arc::clone(&death),
                    kill: kill.clone(),
                };
                let h = handshake(
                    hop_config(host, port),
                    tunnel.into_stream(),
                    handler,
                    &wait,
                    &format!("{host}:{port}"),
                    HANDSHAKE_TIMEOUT,
                    &kill,
                )
                .await?;
                (h, Some(jh))
            }
            None => {
                let (tcp, ip) = dial_tcp(host, port).await?;
                let handler = ClientHandler {
                    host: host.to_string(),
                    ip,
                    port,
                    origin: target_origin.clone(),
                    app: app.clone(),
                    prompts,
                    owner: owner.clone(),
                    cancel: cancel.clone(),
                    wait: wait.clone(),
                    death: Arc::clone(&death),
                    kill: kill.clone(),
                };
                let h = handshake(
                    hop_config(host, port), tcp, handler, &wait, &format!("{host}:{port}"),
                    HANDSHAKE_TIMEOUT, &kill,
                )
                .await?;
                (h, None)
            }
        };

        let ctx = PromptCtx {
            app: &app,
            auth_prompts: &auth_prompts,
            owner,
            origin: target_origin,
            wait: wait.clone(),
            offer_save: !ephemeral,
        };
        let aspec = AuthSpec {
            host_id: &host_id,
            host,
            port,
            username,
            auth: &auth,
            key_path: key_path.as_deref(),
            secret: target_secret,
        };
        let hlabel = format!("{host}:{port}");
        within(&wait, AUTH_TIMEOUT, &hlabel, "authentication", authenticate(&mut handle, aspec, &ctx))
            .await??;

        // Interactive shell on its own channel. "Connected" only once the
        // server has accepted the shell request.
        let (read_half, write_half, early, pty_ok) = within(
            &wait,
            CHANNEL_SETUP_TIMEOUT,
            &hlabel,
            "shell setup",
            open_shell(&handle, host, cols, rows),
        )
        .await??;

        // The tab may have been closed during any of the awaits above (a slow
        // handshake, a host-key or password dialog). Stop before the startup
        // commands run on the remote and before anything is registered.
        if !self.still_wanted(session_id, ticket) {
            let _ = handle
                .disconnect(russh::Disconnect::ByApplication, "cancelled", "")
                .await;
            if let Some(jh) = jump_handle.as_ref() {
                let _ = jh
                    .disconnect(russh::Disconnect::ByApplication, "cancelled", "")
                    .await;
            }
            return Err(SshError::Cancelled(session_id.to_string()));
        }

        let session = Arc::new(Session {
            handle,
            shell: Arc::new(Mutex::new(Some(write_half))),
            sftp: Mutex::new(None),
            sftp_refused: AtomicBool::new(false),
            jump: jump_handle,
            alive: AtomicBool::new(true),
            endpoint,
            generation: ticket,
        });

        // Output pump. Spawned now so its JoinHandle can be registered
        // atomically below, but it emits nothing until it is handed its
        // transcript, which happens only after a successful registration: a
        // cancelled or superseded attempt creates no transcript file and
        // writes nothing into a tab a newer connect owns.
        //
        // The startup commands go with it: the pump sends them once it is
        // reading (see `send_startup`). Written as input rather than via
        // request_exec so they degrade gracefully: a missing command shows
        // "command not found" in a working shell, where a failed exec would
        // close the channel and look like a broken connection. Order is the
        // user's: a `tmux new-session` first means every later line runs
        // inside tmux, which is usually what is wanted.
        //
        // The writer is taken for the startup batch HERE, before registration
        // exposes the session to `write`: nothing else can hold it yet (the
        // session is not registered), and from the moment it is, a keystroke
        // or paste queues behind the startup lines instead of racing them.
        let (go_tx, go_rx) = oneshot::channel::<Option<SessionLog>>();
        let startup_guard = if startup_lines(&startup_commands).is_empty() {
            None
        } else {
            Some(Arc::clone(&session.shell).lock_owned().await)
        };
        let pump = tokio::spawn(run_pump(
            app.clone(),
            session_id.to_string(),
            Arc::clone(&session),
            read_half,
            early,
            go_rx,
            death,
            Arc::clone(&self.forwards),
            startup_commands,
            startup_guard,
        ));

        // Register only while our ticket is still current, holding the
        // `connecting` entry (a shard lock, no await) so a concurrent
        // `remove()` — which deletes that entry first — either runs before us
        // (we see no ticket and do not register) or after us (it finds and
        // tears down what we registered). Never `remove()` by id here: a newer
        // connect may own this id now, and that would cancel or tear down ITS
        // session instead of ours.
        //
        // The transcript is created and announced under that same entry lock:
        // a close or superseding connect right after registration has to take
        // the lock to remove or replace the entry, so it cannot slip in between
        // registering and the file being created (which would leave the new
        // owner's tab showing this attempt's "logging to"). Creating the file
        // is one small local open; the emits only queue events.
        let topic = format!("ssh://{session_id}");
        let mut pump = Some(pump);
        let registered = match self.connecting.get(session_id) {
            Some(g) if g.0 == ticket => {
                self.sessions
                    .insert(session_id.to_string(), Arc::clone(&session));
                if let Some(p) = pump.take() {
                    self.pumps.insert(session_id.to_string(), p);
                }
                // Transcript. Degraded to None rather than propagated: losing
                // a log must never take down a working connection.
                let log = SessionLog::create_for(Some(&session.endpoint), host, username).ok();
                if let Some(l) = log.as_ref() {
                    let _ = app.emit(
                        &topic,
                        format!("\x1b[38;5;244mlogging to {}\x1b[0m\r\n", l.path().display()),
                    );
                }
                if !pty_ok {
                    let _ = app.emit(
                        &topic,
                        "\x1b[38;2;242;178;92mthe server refused a terminal (PTY); line editing and \
                         full-screen programs may not work\x1b[0m\r\n"
                            .to_string(),
                    );
                }
                drop(g);
                Some(log)
            }
            _ => None,
        };
        let Some(log) = registered else {
            // Superseded or cancelled: tear down only this attempt's own
            // resources. Detached, because the cancel that brought us here also
            // makes `connect`'s select drop this future at its next await — an
            // inline teardown would be cut off half-way. The pump never got its
            // go signal, so it has emitted nothing.
            //
            // The kill guard goes with it and fires once the disconnect has
            // had a moment to reach the server, so the transport ends either
            // way. Bounded: a window-blocked transport may never take the
            // disconnect at all.
            if let Some(p) = pump.take() {
                p.abort();
            }
            session.alive.store(false, Ordering::SeqCst);
            tokio::spawn(async move {
                let _ = tokio::time::timeout(Duration::from_secs(2), session.close("cancelled")).await;
                tokio::time::sleep(Duration::from_millis(250)).await;
                drop(guard);
            });
            return Err(SshError::Cancelled(session_id.to_string()));
        };
        // Registered: the session owns its transports now, and its own
        // teardown (`Session::close`) ends them.
        guard.disarm();
        let _ = go_tx.send(log);

        Ok(session.endpoint.clone())
    }

    /* ------------------------------------------------------------ phase 1 */

    /// Raw terminal input straight to the PTY.
    ///
    /// Bytes, not a string: arrow keys arrive as "\x1b[A", Ctrl+C as 0x03, and
    /// a paste as one block. Anything that re-encodes on the way through breaks
    /// every full-screen program that relies on raw mode.
    pub async fn write(&self, session_id: &str, data: &[u8]) -> Result<(), SshError> {
        let session = self.get(session_id)?;
        // A write to a channel whose transport has gone is silently discarded by
        // russh, which is how a dead session managed to look alive.
        if !session.alive.load(Ordering::Relaxed) {
            return Err(SshError::Disconnected(session_id.to_string()));
        }
        let guard = session.shell.lock().await;
        let shell = guard
            .as_ref()
            .ok_or_else(|| SshError::NoShell(session_id.to_string()))?;
        shell.data(data).await?;
        Ok(())
    }

    /// Forward a window-size change as a real SSH `window-change` request.
    /// Without it the remote keeps drawing to the old geometry and full-screen
    /// programs wrap at the wrong column.
    ///
    /// Note: russh has no `request_pty_size`; `window_change` is the method, and
    /// it takes pixel dimensions too (0 means "unspecified", which every server
    /// accepts).
    pub async fn resize(&self, session_id: &str, cols: u32, rows: u32) -> Result<(), SshError> {
        let session = self.get(session_id)?;
        if !session.alive.load(Ordering::Relaxed) {
            return Err(SshError::Disconnected(session_id.to_string()));
        }
        let guard = session.shell.lock().await;
        let shell = guard
            .as_ref()
            .ok_or_else(|| SshError::NoShell(session_id.to_string()))?;
        shell.window_change(cols, rows, 0, 0).await?;
        Ok(())
    }

    /* --------------------------------------------------------------- sftp */

    /// The SFTP subsystem rides the existing SSH connection rather than opening
    /// a second one, and starts lazily: a session that only uses the terminal
    /// never pays for it. Cached because channel setup costs a round trip.
    ///
    /// Two subsystem channels: russh-sftp's high-level session (streaming file
    /// I/O) and a raw one for what the high-level API cannot do — a listing
    /// read batch by batch (so it can be capped) and `posix-rename@openssh.com`
    /// (an atomic replace). A server that refuses the second channel still
    /// gets every operation, without those two refinements.
    async fn sftp(&self, session_id: &str) -> Result<Arc<SftpConn>, SshError> {
        let session = self.get(session_id)?;
        if !session.alive.load(Ordering::Relaxed) {
            return Err(SshError::Disconnected(session_id.to_string()));
        }
        let mut guard = session.sftp.lock().await;
        if let Some(existing) = guard.as_ref() {
            return Ok(Arc::clone(existing));
        }

        let conn = Arc::new(open_sftp_conn(&session.handle, &session.sftp_refused).await?);
        *guard = Some(Arc::clone(&conn));
        Ok(conn)
    }

    /// Forget the cached SFTP session if `r` failed because its channel is gone
    /// or stopped answering (the sftp-server process exited, was killed or
    /// hangs while the SSH transport stayed up). Without this every later file
    /// operation reuses the dead session and fails until the whole tab is
    /// reconnected; with it the next call reopens the subsystem.
    async fn check_sftp<T>(&self, session_id: &str, r: Result<T, SshError>) -> Result<T, SshError> {
        if let Err(e) = &r {
            if sftp_dead(e) {
                if let Ok(session) = self.get(session_id) {
                    *session.sftp.lock().await = None;
                }
            }
        }
        r
    }

    pub async fn list_dir(&self, session_id: &str, path: &str) -> Result<DirListing, SshError> {
        let first = self.list_dir_once(session_id, path).await;
        if matches!(&first, Err(e) if sftp_dead(e)) {
            // A dead cached channel is dropped by check_sftp; one retry then
            // runs on a fresh subsystem, so the pane recovers by itself.
            let cleared = match self.get(session_id) {
                Ok(s) => s.sftp.lock().await.is_none(),
                Err(_) => false,
            };
            if cleared {
                return self.list_dir_once(session_id, path).await;
            }
        }
        first
    }

    async fn list_dir_once(&self, session_id: &str, path: &str) -> Result<DirListing, SshError> {
        let r = match self.sftp(session_id).await {
            Ok(sftp) => list_dir_with(&sftp, path).await,
            Err(e) => Err(e),
        };
        self.check_sftp(session_id, r).await
    }

    /// Whether anything is at a remote path — the overwrite guard asks before
    /// a transfer clobbers something already there. LSTAT, so a symlink (even
    /// a dangling one) counts as present. Only a definite "no such file" is
    /// `false`; any other failure (a dead channel, a timeout, permission
    /// denied) is an error, never a silent "not there".
    pub async fn sftp_exists(&self, session_id: &str, path: &str) -> Result<bool, SshError> {
        let sftp = self.sftp(session_id).await?;
        let r = match sftp.hi.symlink_metadata(path).await {
            Ok(_) => Ok(true),
            Err(e) if sftp_status(&e) == Some(StatusCode::NoSuchFile) => Ok(false),
            Err(e) => Err(SshError::from(e)),
        };
        self.check_sftp(session_id, r).await
    }

    /// Rename a remote file or directory. SFTP rename is not a copy — it is
    /// the server's own rename, atomic where the filesystem allows.
    pub async fn sftp_rename(&self, session_id: &str, from: &str, to: &str) -> Result<(), SshError> {
        let sftp = self.sftp(session_id).await?;
        let r = sftp.hi.rename(from, to).await.map_err(SshError::from);
        self.check_sftp(session_id, r).await
    }

    /// Delete a remote file, or an EMPTY remote directory.
    ///
    /// Deliberately not recursive: `rm -rf` semantics from a GUI click is how
    /// production directories die. A non-empty directory fails with the
    /// server's error and the UI says so; recursive delete stays a deliberate
    /// terminal act.
    pub async fn sftp_delete(&self, session_id: &str, path: &str, is_dir: bool) -> Result<(), SshError> {
        let sftp = self.sftp(session_id).await?;
        let r = if is_dir {
            sftp.hi.remove_dir(path).await
        } else {
            sftp.hi.remove_file(path).await
        };
        self.check_sftp(session_id, r.map_err(SshError::from)).await
    }

    /// Create a remote directory.
    pub async fn sftp_mkdir(&self, session_id: &str, path: &str) -> Result<(), SshError> {
        let sftp = self.sftp(session_id).await?;
        let r = sftp.hi.create_dir(path).await.map_err(SshError::from);
        self.check_sftp(session_id, r).await
    }

    /* ------------------------------------------------------------ phase 2 */

    /// Register a transfer under the frontend's id so `transfer_cancel` can
    /// reach it. A cancel that overtook this call (the user cancelled a row
    /// whose command had not started yet) stops it before any byte moves.
    fn transfer_begin(&self, transfer_id: &str) -> Result<(u64, watch::Receiver<bool>), SshError> {
        let seq = TRANSFER_SEQ.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = watch::channel(false);
        let mut t = self.transfers.lock().unwrap_or_else(|p| p.into_inner());
        if t.running.contains_key(transfer_id) {
            return Err(SshError::PartialTransfer(format!(
                "transfer id {transfer_id} is already running"
            )));
        }
        if t.early_cancels.remove(transfer_id).is_some() {
            return Err(SshError::TransferCancelled);
        }
        t.running.insert(transfer_id.to_string(), (seq, tx));
        Ok((seq, rx))
    }

    fn transfer_end(&self, transfer_id: &str, seq: u64) {
        let mut t = self.transfers.lock().unwrap_or_else(|p| p.into_inner());
        if t.running.get(transfer_id).is_some_and(|v| v.0 == seq) {
            t.running.remove(transfer_id);
        }
    }

    /// Cancel a running transfer (`sftp_get`/`sftp_put` with the same id). Its
    /// copy loop stops at the next chunk and removes its staging files on both
    /// sides while the connection is still up. An id with no transfer
    /// registered yet is remembered, so that transfer stops as it starts. A
    /// transfer already committing its file is not interrupted (see
    /// `commit_upload`): it finishes and reports what really happened.
    pub fn transfer_cancel(&self, transfer_id: &str) {
        let now = Instant::now();
        let mut t = self.transfers.lock().unwrap_or_else(|p| p.into_inner());
        t.early_cancels
            .retain(|_, at| now.duration_since(*at) < COPY_ID_CANCEL_TTL);
        match t.running.get(transfer_id) {
            Some(e) => {
                let _ = e.1.send(true);
            }
            None => {
                t.early_cancels.insert(transfer_id.to_string(), now);
            }
        }
    }

    /// Download, streamed and reporting byte-accurate progress.
    ///
    /// Streaming rather than read-to-end is not only about memory: it is what
    /// makes progress reportable at all. Chunks are 64 KB; events are throttled
    /// to one per PROGRESS_INTERVAL across the whole transfer, with a
    /// guaranteed final event so the UI always lands on 100%.
    ///
    /// `overwrite` is enforced when each file is committed, not only when the
    /// user was asked: a file that appeared at the destination meanwhile is
    /// never replaced under `Overwrite::Never`.
    pub async fn download(
        &self,
        app: &AppHandle,
        session_id: &str,
        transfer_id: &str,
        remote: &str,
        local: &str,
        overwrite: Overwrite,
    ) -> Result<TransferOutcome, SshError> {
        let (seq, cancel) = self.transfer_begin(transfer_id)?;
        let r = match self.sftp(session_id).await {
            Ok(sftp) => {
                let mut p = Progress::new(app, session_id, transfer_id, remote, "download", cancel);
                download_tree(&sftp, &mut p, remote, local, overwrite).await.map(|bytes| {
                    TransferOutcome { bytes, notes: p.take_notes() }
                })
            }
            Err(e) => Err(e),
        };
        self.transfer_end(transfer_id, seq);
        self.check_sftp(session_id, r).await
    }

    /// Upload, same streaming, reporting and overwrite contract, directory-aware.
    pub async fn upload(
        &self,
        app: &AppHandle,
        session_id: &str,
        transfer_id: &str,
        local: &str,
        remote: &str,
        overwrite: Overwrite,
    ) -> Result<TransferOutcome, SshError> {
        let (seq, cancel) = self.transfer_begin(transfer_id)?;
        let r = match self.sftp(session_id).await {
            Ok(sftp) => {
                let mut p = Progress::new(app, session_id, transfer_id, local, "upload", cancel);
                upload_tree(&sftp, &mut p, local, remote, overwrite).await.map(|bytes| {
                    TransferOutcome { bytes, notes: p.take_notes() }
                })
            }
            Err(e) => Err(e),
        };
        self.transfer_end(transfer_id, seq);
        self.check_sftp(session_id, r).await
    }
}

impl Registry {
    /// Start a local forward: listen on 127.0.0.1:local_port, and for every
    /// connection open a direct-tcpip channel to remote_host:remote_port over
    /// the session's SSH transport — `ssh -L`, in app form.
    ///
    /// Binds 127.0.0.1 only, never 0.0.0.0: a forward into a management VLAN
    /// must not turn the operator's workstation into an open relay for
    /// whatever else is on the office network.
    pub async fn forward_start(
        &self,
        session_id: &str,
        local_port: u16,
        remote_host: &str,
        remote_port: u16,
    ) -> Result<ForwardInfo, SshError> {
        let session = self.get(session_id)?;
        if !session.alive.load(Ordering::Relaxed) {
            return Err(SshError::Disconnected(session_id.to_string()));
        }

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", local_port)).await?;
        // Port 0 means "pick one"; report what was actually bound.
        let bound = listener.local_addr()?.port();

        let info = ForwardInfo {
            id: format!("fw-{session_id}-{bound}"),
            session_id: session_id.to_string(),
            local_port: bound,
            remote_host: remote_host.to_string(),
            remote_port,
            kind: "local",
        };

        let sess = Arc::clone(&session);
        let rhost = remote_host.to_string();
        let tunnels: TunnelHandles = Arc::new(std::sync::Mutex::new(Vec::new()));
        let tunnels_loop = Arc::clone(&tunnels);
        let task = tokio::spawn(async move {
            loop {
                let Some((mut tcp, peer)) = accept_or_retry(&listener).await else { continue };
                // The channel open is awaited in the per-connection task, not
                // here: the server confirms it only once its own connect to the
                // target completes, so a blackholed target would otherwise stall
                // every other client of this forward for the remote TCP timeout.
                let sess = Arc::clone(&sess);
                let rhost = rhost.clone();
                let h = tokio::spawn(async move {
                    let Ok(channel) = sess
                        .handle
                        .channel_open_direct_tcpip(
                            rhost,
                            remote_port as u32,
                            peer.ip().to_string(),
                            peer.port() as u32,
                        )
                        .await
                    else {
                        // Remote refused (nothing listening there, or policy).
                        // Drop this client; the listener stays up.
                        return;
                    };
                    let mut stream = channel.into_stream();
                    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut stream).await;
                });
                track_tunnel(&tunnels_loop, h);
            }
        });

        self.insert_forward(&session, Forward {
            info: info.clone(),
            generation: session.generation,
            listener: task,
            tunnels,
        })
        .await?;
        Ok(info)
    }

    /// Register a forward, then make sure its session is still the live one.
    ///
    /// The bind above awaits, and the tab can close (or the shell end) meanwhile:
    /// that teardown swept this session's forwards before ours existed, so a
    /// forward inserted now would hold its port and stay listed forever. The
    /// teardowns clear the session (map entry or `alive`) BEFORE sweeping, so
    /// re-checking after the insert is enough: either we see it gone and roll
    /// back, or the sweep runs after our insert and takes this forward too.
    ///
    /// Ids are `<kind>-<session>-<port>`, so re-creating a forward on a port
    /// whose old listener died yields the same id; tear the old entry down
    /// rather than let `insert` silently detach its tunnels.
    async fn insert_forward(&self, session: &Arc<Session>, fw: Forward) -> Result<(), SshError> {
        let id = fw.info.id.clone();
        let sid = fw.info.session_id.clone();
        if let Some(old) = self.forwards.insert(id.clone(), fw) {
            teardown_forwards(vec![old]).await;
        }
        let live = self
            .sessions
            .get(&sid)
            .is_some_and(|s| Arc::ptr_eq(s.value(), session))
            && session.alive.load(Ordering::SeqCst);
        if !live {
            if let Some((_, ours)) =
                self.forwards.remove_if(&id, |_, f| f.generation == session.generation)
            {
                teardown_forwards(vec![ours]).await;
            }
            return Err(SshError::Disconnected(sid));
        }
        Ok(())
    }

    /// Stop one forward: its listener first, then every live tunnel, so no
    /// traffic keeps flowing after the user stops it (see `teardown_forward`).
    pub async fn forward_stop(&self, forward_id: &str) {
        if let Some((_, fw)) = self.forwards.remove(forward_id) {
            teardown_forwards(vec![fw]).await;
        }
    }

    /// Start a SOCKS5 proxy (`ssh -D`): every connection made through it is
    /// tunnelled over this session and egresses from the REMOTE side. Point a
    /// browser's proxy at it and you are browsing from the server's network —
    /// the standard way to reach web UIs on an isolated management VLAN.
    ///
    /// Deliberately minimal SOCKS5: no-auth only (it binds 127.0.0.1, the
    /// boundary is the machine), CONNECT only (BIND and UDP-associate are
    /// refused with the proper reply code). That subset is what browsers and
    /// curl actually use.
    pub async fn forward_start_socks(
        &self,
        session_id: &str,
        local_port: u16,
    ) -> Result<ForwardInfo, SshError> {
        let session = self.get(session_id)?;
        if !session.alive.load(Ordering::Relaxed) {
            return Err(SshError::Disconnected(session_id.to_string()));
        }

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", local_port)).await?;
        let bound = listener.local_addr()?.port();

        let info = ForwardInfo {
            id: format!("socks-{session_id}-{bound}"),
            session_id: session_id.to_string(),
            local_port: bound,
            remote_host: "(dynamic)".into(),
            remote_port: 0,
            kind: "socks",
        };

        let sess = Arc::clone(&session);
        let tunnels: TunnelHandles = Arc::new(std::sync::Mutex::new(Vec::new()));
        let tunnels_loop = Arc::clone(&tunnels);
        let task = tokio::spawn(async move {
            loop {
                let Some((tcp, peer)) = accept_or_retry(&listener).await else { continue };
                let sess = Arc::clone(&sess);
                let h = tokio::spawn(async move {
                    let _ = socks5_serve(sess, tcp, peer).await;
                });
                track_tunnel(&tunnels_loop, h);
            }
        });

        self.insert_forward(&session, Forward {
            info: info.clone(),
            generation: session.generation,
            listener: task,
            tunnels,
        })
        .await?;
        Ok(info)
    }

    pub fn forwards_list(&self, session_id: Option<&str>) -> Vec<ForwardInfo> {
        self.forwards
            .iter()
            .map(|e| e.value().info.clone())
            .filter(|f| session_id.is_none_or(|sid| f.session_id == sid))
            .collect()
    }

    /// Install a public key (ssh-copy-id) over a throwaway connection, under
    /// the same stage deadlines as a connect, and cancellable by `op_id` with
    /// `copy_id_cancel` (the editor closed, or the user gave up). A cancelled
    /// install leaves no prompt behind.
    #[allow(clippy::too_many_arguments)]
    pub async fn copy_id_run(
        &self,
        app: AppHandle,
        prompts: Arc<HostKeyPrompts>,
        auth_prompts: Arc<AuthPrompts>,
        op_id: Option<&str>,
        host: &str,
        port: u16,
        username: &str,
        password: zeroize::Zeroizing<String>,
        public_key: &str,
    ) -> Result<(), SshError> {
        let seq = COPY_ID_SEQ.fetch_add(1, Ordering::Relaxed);
        let session_id = format!("install-key-{seq}");
        let op = op_id.map(str::to_string).unwrap_or_else(|| session_id.clone());
        let (tx, rx) = watch::channel(());
        // A second install under the same op id supersedes (cancels) the first.
        // Registered, and checked against an early cancel, under the entry's
        // lock and before anything dials, so a cancel either lands in
        // `copy_id_cancels` first (seen here) or finds this entry.
        if !self.copy_id_register(&op, seq, tx) {
            return Err(SshError::Cancelled(op));
        }
        let mut closed = rx.clone();
        let result = tokio::select! {
            biased;
            _ = closed.changed() => Err(SshError::Cancelled(op.clone())),
            r = copy_id(
                app.clone(), Arc::clone(&prompts), Arc::clone(&auth_prompts), &session_id, rx,
                host, port, username, password, public_key,
            ) => r,
        };
        self.copy_ids.remove_if(&op, |_, v| v.0 == seq);
        if result.is_err() {
            let swept = prompts
                .cancel_session(&session_id)
                .into_iter()
                .chain(auth_prompts.cancel_session(&session_id));
            for request_id in swept {
                emit_prompt_closed(&app, &request_id);
            }
        }
        result
    }

    /// Register install `seq` under `op`, unless a cancel for `op` already
    /// arrived (then false, and nothing is registered).
    fn copy_id_register(&self, op: &str, seq: u64, tx: watch::Sender<()>) -> bool {
        let entry = self.copy_ids.entry(op.to_string());
        if self.copy_id_cancels.remove(op).is_some() {
            return false;
        }
        entry.insert((seq, tx));
        true
    }

    /// Cancel a `copy_id_run`. An id with no install registered yet is
    /// remembered, so the install it belongs to stops as soon as it starts.
    pub fn copy_id_cancel(&self, op_id: &str) {
        let now = Instant::now();
        self.copy_id_cancels
            .retain(|_, at| now.duration_since(*at) < COPY_ID_CANCEL_TTL);
        // Under the entry lock, the mirror of `copy_id_run`'s registration.
        match self.copy_ids.entry(op_id.to_string()) {
            dashmap::Entry::Occupied(e) => {
                e.remove();
            }
            dashmap::Entry::Vacant(_) => {
                self.copy_id_cancels.insert(op_id.to_string(), now);
            }
        }
    }
}

impl SessionRef {
    /// Run one command on a fresh exec channel and capture its output.
    ///
    /// Exec, not the interactive shell: capturing through the user's live
    /// terminal would splatter a full config dump across whatever they were
    /// doing. A separate channel keeps the capture invisible and gives a clean
    /// EOF to stop at. The trade-off is that some appliances only speak
    /// interactive shells and refuse exec — those fail here with the server's
    /// own error, which the UI surfaces as "this device may not support
    /// command capture".
    ///
    /// On a `SessionRef` rather than the registry, so the output always comes
    /// from the connection whose identity the caller files it under.
    pub async fn exec_capture(&self, command: &str, timeout_secs: u64) -> Result<ExecOutput, SshError> {
        let session = &self.session;
        if !session.alive.load(Ordering::Relaxed) {
            return Err(SshError::Disconnected(self.id.clone()));
        }

        let mut channel = session.handle.channel_open_session().await?;
        channel.exec(true, command).await?;
        let run = run_exec(&mut channel, 16 * 1024 * 1024, Duration::from_secs(timeout_secs)).await;
        if !run.close_sent {
            // The close did not get out within its grace (a full outbound
            // queue). This is the user's live session, so the channel must not
            // simply be dropped: russh would then never send its close, and the
            // command (`tail -f`, a pager waiting for input) would keep running
            // and hold a channel slot until the whole session ends. The close
            // stays queued here and goes out as soon as the transport drains;
            // it fails (and the task ends) when the session ends.
            tokio::spawn(async move {
                let _ = channel.close().await;
            });
        }
        exec_verdict(run, timeout_secs)
    }
}

/// What a capture printed, the two streams kept apart: stderr (a login-shell
/// `setlocale` warning, MOTD noise) must never become part of a saved config.
#[derive(Debug, Default)]
pub struct ExecOutput {
    pub stdout: String,
    pub stderr: String,
}

impl ExecOutput {
    /// Both streams for a human-read capture file, stderr labelled.
    pub fn labelled(&self) -> String {
        if self.stderr.trim().is_empty() {
            return self.stdout.clone();
        }
        let sep = if self.stdout.is_empty() || self.stdout.ends_with('\n') { "" } else { "\n" };
        format!("{}{sep}--- stderr ---\n{}", self.stdout, self.stderr)
    }
}

/// A short stderr excerpt for an error message, or "".
fn stderr_hint(err: &[u8]) -> String {
    let (clean, _) = crate::utils::session_log::strip_ansi(err);
    let text = String::from_utf8_lossy(&clean);
    let text = text.trim();
    if text.is_empty() {
        return String::new();
    }
    let short: String = text.chars().take(300).collect();
    format!(": {short}")
}

/// Judge a finished exec run (see `exec_capture`).
///
/// Don't pass off a partial or failed capture as a valid snapshot:
///  - refused     -> the server answered the exec request with a failure
///  - timed out   -> we have no idea if the config finished printing
///  - truncated   -> hit the size cap mid-dump
///  - unconfirmed -> the channel/transport ended before the server confirmed
///    the run (EOF, then a status or close)
///  - killed / exit != 0 -> the command itself reported failure (a missing
///    status after EOF + close is tolerated: much network gear never sends one
///    over exec)
fn exec_verdict(run: ExecRun, timeout_secs: u64) -> Result<ExecOutput, SshError> {
    if run.refused {
        return Err(SshError::PartialTransfer(
            "the device refused to run the command over an exec channel (it may only \
             support interactive shells)"
                .into(),
        ));
    }
    if run.timed_out {
        return Err(SshError::PartialTransfer(if run.eof {
            format!(
                "device ended its output but never confirmed completion within \
                 {timeout_secs}s; output discarded"
            )
        } else {
            format!("capture timed out after {timeout_secs}s; output discarded")
        }));
    }
    if run.truncated {
        return Err(SshError::PartialTransfer(
            "capture exceeded 16 MiB; output discarded".into(),
        ));
    }
    if !run.confirmed {
        return Err(SshError::PartialTransfer(
            "connection ended before the capture completed; output discarded".into(),
        ));
    }
    if let Some(sig) = run.signal {
        return Err(SshError::PartialTransfer(format!(
            "capture command was killed by signal {sig}{}",
            stderr_hint(&run.err)
        )));
    }
    if let Some(code) = run.exit_status {
        if code != 0 {
            return Err(SshError::PartialTransfer(format!(
                "capture command exited with status {code}{}",
                stderr_hint(&run.err)
            )));
        }
    }
    let (out, _) = crate::utils::session_log::strip_ansi(&run.out);
    let (err, _) = crate::utils::session_log::strip_ansi(&run.err);
    Ok(ExecOutput {
        stdout: String::from_utf8_lossy(&out).to_string(),
        stderr: String::from_utf8_lossy(&err).to_string(),
    })
}

/// How an exec channel's run ended, as far as the server confirmed it.
#[derive(Default)]
struct ExecRun {
    /// stdout.
    out: Vec<u8>,
    /// stderr (extended data), kept apart from stdout.
    err: Vec<u8>,
    exit_status: Option<u32>,
    /// Name of the signal that killed the command (`exit-signal`).
    signal: Option<String>,
    eof: bool,
    truncated: bool,
    timed_out: bool,
    /// The server answered the exec request with CHANNEL_FAILURE.
    refused: bool,
    /// The server confirmed the run finished: EOF, then an exit status/signal
    /// or a channel close (in either order). A transport that drops, or a
    /// close with no EOF first, is NOT confirmation.
    confirmed: bool,
    /// Our CHANNEL_CLOSE went out within `EXEC_CLOSE_GRACE`.
    close_sent: bool,
}

/// Collect an exec channel's output under `deadline`, then close the channel.
///
/// Do not stop at EOF: OpenSSH sends the exit status AFTER EOF (when it reaps
/// the child), while other stacks send it before — so the run ends when the
/// second of {EOF, status/signal} arrives, or on close after EOF. No short
/// post-EOF grace: that passed off a command that closed its output and then
/// failed as success. A device that EOFs but never confirms now times out.
///
/// The exec request must have been sent with want_reply: a CHANNEL_FAILURE
/// reply (the device refuses exec but leaves the channel open) ends the run at
/// once as `refused` instead of waiting out the deadline.
async fn run_exec(
    channel: &mut russh::Channel<client::Msg>,
    cap: usize,
    deadline: Duration,
) -> ExecRun {
    let mut run = ExecRun::default();
    let collect = async {
        // These commands read no stdin. Send our EOF (like `ssh host cmd
        // </dev/null`) so stacks that wait for the peer's EOF before closing
        // do. Inside the deadline: on a stalled transport even queueing it
        // can wait.
        let _ = channel.eof().await;
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { ref data } => run.out.extend_from_slice(data),
                ChannelMsg::ExtendedData { ref data, .. } => run.err.extend_from_slice(data),
                ChannelMsg::ExitStatus { exit_status } => run.exit_status = Some(exit_status),
                ChannelMsg::ExitSignal { signal_name, .. } => {
                    run.signal = Some(format!("{signal_name:?}"))
                }
                ChannelMsg::Failure if !run.eof && run.out.is_empty() => {
                    run.refused = true;
                    return;
                }
                ChannelMsg::Eof => run.eof = true,
                ChannelMsg::Close => {
                    run.confirmed = run.eof;
                    return;
                }
                _ => {}
            }
            // A runaway command (`tail -f`) must not eat RAM until the
            // deadline.
            if run.out.len() + run.err.len() > cap {
                run.truncated = true;
                return;
            }
            if run.eof && (run.exit_status.is_some() || run.signal.is_some()) {
                run.confirmed = true;
                return;
            }
        }
        // wait() == None: the session ended with no close — unconfirmed.
    };
    run.timed_out = tokio::time::timeout(deadline, collect).await.is_err();
    // A plain russh Channel sends no CHANNEL_CLOSE on drop; without this a
    // timed-out exec would leak a channel on the user's live session. Bounded
    // like the rest: a stalled transport must not hold the caller past it
    // (`exec_capture` then keeps the close queued; see there).
    run.close_sent = matches!(
        tokio::time::timeout(EXEC_CLOSE_GRACE, channel.close()).await,
        Ok(Ok(()))
    );
    run
}

/// Read the vault slot for `host_id` and authorize what it holds for this
/// destination. Returns the ONE snapshot that `authenticate` will use, so the
/// secret that was checked is exactly the secret that is sent: re-reading at
/// send time let a password saved during the handshake (after a NotFound
/// here) go to an unchecked destination.
///
/// Only stored password auth transmits the vault secret to the server. Key auth
/// uses the vault entry as a local key passphrase (it decrypts the key here and
/// is never sent), and agent auth / a one-shot password carry no stored secret —
/// so those are exempt from the binding check. When a stored password exists
/// for `host_id`, the destination must match a connection the user actually
/// saved for that credential (its own record, or one that borrows it via
/// `credentialId`); otherwise a compromised frontend could pair the id with an
/// attacker's host and read the secret off the wire.
///
/// The vault read and the binding check happen together, under the lock every
/// credential save and delete holds (utils::hosts::read_authorized), so the
/// secret returned is always checked against ITS OWN binding — never a
/// replacement secret against the previous binding mid-save. The read runs on
/// the blocking pool: it is a keychain call that can show a prompt.
async fn authorize_stored_password(
    auth: &str,
    host_id: &str,
    host: &str,
    port: u16,
    username: &str,
    one_shot: bool,
) -> Result<Option<zeroize::Zeroizing<String>>, SshError> {
    use crate::utils::hosts::{Dest, StoredSecret};
    // Ids in a reserved vault namespace (the AI provider key lives at `ai:…`)
    // are never host credentials: refuse them for every auth method, so no
    // host id can address — and send, or use as a passphrase — that secret.
    if credentials::is_reserved_id(host_id) {
        return Err(SshError::AuthFailed(format!(
            "refusing to use '{host_id}' as a host credential: it is a reserved vault id"
        )));
    }
    if let Err(e) = credentials::validate_id(host_id) {
        return Err(SshError::AuthFailed(format!("refusing to use '{host_id}' as a host credential: {e}")));
    }
    if one_shot || auth == "agent" {
        return Ok(None);
    }
    // A key passphrase is used locally and never transmitted: no binding.
    let check_binding = auth != "key";
    let dest = Dest { host: host.to_string(), port, username: username.to_string() };
    let id = host_id.to_string();
    let read = tokio::task::spawn_blocking(move || {
        crate::utils::hosts::read_authorized(&id, &dest, check_binding)
    })
    .await
    .map_err(|e| SshError::Connect(format!("vault read task failed: {e}")))?;
    // No saved secret for this id → nothing to leak (a password is then asked
    // for). Only a definite NotFound counts as "no secret": any other vault
    // error (a locked keyring, a dismissed unlock prompt) fails CLOSED and is
    // reported as the vault problem it is.
    match read.map_err(|e| vault_error(host_id, e))? {
        StoredSecret::None => Ok(None),
        StoredSecret::Authorized(secret) => Ok(Some(secret)),
        StoredSecret::Unbound => Err(SshError::AuthFailed(format!(
            "refusing to send the saved credential '{host_id}' to {host}:{port} as {username}: \
             it is not an authorized saved destination for that credential"
        ))),
        StoredSecret::Poisoned => Err(SshError::AuthFailed(format!(
            "the saved credential '{host_id}' is not used: an earlier save of it failed half-way, \
             so it may not match where it is allowed to go. Save the password again."
        ))),
    }
}

/// A vault read that failed for a reason other than "nothing saved".
fn vault_error(host_id: &str, e: credentials::CredError) -> SshError {
    SshError::Connect(format!(
        "could not read the saved credential for '{host_id}' from the OS vault (it may be \
         locked, or the unlock prompt was dismissed): {e}"
    ))
}

/// The RSA signature hash to use, asked of the server only when an RSA key is
/// actually offered: russh waits up to 1s for EXT_INFO, which much network gear
/// never sends, and every non-RSA login used to pay that.
///
/// Returns (hash, retry with SHA-1 on failure). With no EXT_INFO the server's
/// support is unknown, so rsa-sha2-256 is tried first (modern OpenSSH refuses
/// SHA-1) and ssh-rsa second (old stacks only know SHA-1), as russh's docs
/// suggest. A server that sent EXT_INFO without rsa-sha2 gets SHA-1 directly.
#[derive(Default)]
struct RsaHash(Option<(Option<russh::keys::HashAlg>, bool)>);

impl RsaHash {
    async fn get(
        &mut self,
        handle: &Handle<ClientHandler>,
    ) -> Result<(Option<russh::keys::HashAlg>, bool), SshError> {
        if let Some(v) = self.0 {
            return Ok(v);
        }
        let v = match handle.best_supported_rsa_hash().await? {
            Some(h) => (h, false),
            None => (Some(russh::keys::HashAlg::Sha256), true),
        };
        self.0 = Some(v);
        Ok(v)
    }
}

/// Shared between the target connection and a jump-host connection so the
/// bastion supports the same three methods as any other host.
async fn authenticate(
    handle: &mut Handle<ClientHandler>,
    spec: AuthSpec<'_>,
    ctx: &PromptCtx<'_>,
) -> Result<(), SshError> {
    let AuthSpec { host_id, host, port, username, auth, key_path, secret } = spec;
    let authed = match auth {
        // Private key file. The vault entry for this host, if present, is the
        // key's passphrase — one vault slot per host, meaning either
        // "password" or "key passphrase" depending on the auth method.
        "key" => {
            let path = key_path.ok_or_else(|| {
                SshError::AuthFailed(format!("{username}: no key file configured"))
            })?;
            let key = russh::keys::load_secret_key(path, secret.as_ref().map(|p| p.as_str()))
                .map_err(|e| SshError::AuthFailed(format!("could not load key {path}: {e}")))?;
            drop(secret);
            let key = Arc::new(key);
            if key.algorithm().is_rsa() {
                // RSA needs the strongest hash the server advertises.
                let (hash, retry_sha1) = RsaHash::default().get(handle).await?;
                let first = handle
                    .authenticate_publickey(
                        username,
                        russh::keys::PrivateKeyWithHashAlg::new(Arc::clone(&key), hash),
                    )
                    .await?;
                if retry_sha1 && !matches!(first, russh::client::AuthResult::Success) {
                    handle
                        .authenticate_publickey(
                            username,
                            russh::keys::PrivateKeyWithHashAlg::new(key, None),
                        )
                        .await?
                } else {
                    first
                }
            } else {
                handle
                    .authenticate_publickey(
                        username,
                        russh::keys::PrivateKeyWithHashAlg::new(key, None),
                    )
                    .await?
            }
        }

        // Running SSH agent(s). Keys never leave the agent; it only signs.
        "agent" => match agent_auth(handle, username).await? {
            Some(result) => result,
            None => return Err(SshError::AuthFailed(format!("{username}: {NO_AGENT}"))),
        },

        // Password (default): the one-shot password or the authorized vault
        // snapshot, else asked for.
        //
        // On failure, keyboard-interactive is tried with the same secret.
        // That fallback is what makes TACACS+-fronted network gear work:
        // many appliances advertise ONLY keyboard-interactive and then ask a
        // single hidden "Password:" question. Users should not need to know
        // which of the two dances their firewall does.
        _ => {
            // Held in Zeroizing so it is wiped on EVERY exit path, including a
            // failed `?` or a cancellation.
            // A password the user typed AND asked to save, held until we know it
            // actually authenticated — never persist a wrong guess.
            let mut save_typed: Option<zeroize::Zeroizing<String>> = None;
            let pw: zeroize::Zeroizing<String> = match secret {
                Some(s) => s,
                // No saved password and none supplied for this connect: ask
                // for it. The prompt is hidden (masked), and the typed password
                // comes INWARD via auth_prompt_respond — no stored secret is
                // ever emitted outward.
                None => {
                    let offer_save = ctx.offer_save && !host_id.is_empty();
                    let answer = request_auth_answers(
                        ctx,
                        "password",
                        "",
                        "",
                        vec![AuthPromptField { prompt: "Password:".into(), echo: false }],
                        offer_save,
                    )
                    .await?;
                    let typed = answer.answers.into_iter().next().unwrap_or_default();
                    if answer.save && offer_save {
                        save_typed = Some(typed.clone());
                    }
                    typed
                }
            };
            let first = handle.authenticate_password(username, pw.as_str()).await?;
            let result = if matches!(first, russh::client::AuthResult::Success) {
                first
            } else {
                // partial_success means the password itself was accepted and the
                // server wants a second factor (AuthenticationMethods
                // password,keyboard-interactive) — so an unlabelled hidden prompt
                // that follows is NOT the password.
                let password_accepted = matches!(
                    first,
                    russh::client::AuthResult::Failure { partial_success: true, .. }
                );
                keyboard_interactive_with_password(
                    handle,
                    username,
                    pw.as_str(),
                    password_accepted,
                    ctx,
                )
                .await?
            };
            // Persist a freshly-typed password only now that it has authenticated,
            // and only if the user opted in. A vault-write failure must not fail an
            // otherwise-good session, so it is logged, not propagated.
            if matches!(result, russh::client::AuthResult::Success) {
                if let Some(secret) = &save_typed {
                    // Secret and binding as one unit (utils::hosts::save_credential):
                    // a failed binding write restores the previous secret. On the
                    // blocking pool: keychain calls can show a prompt.
                    let (id, user, secret) = (host_id.to_string(), username.to_string(), secret.clone());
                    let owner = crate::utils::hosts::Dest { host: host.to_string(), port, username: username.to_string() };
                    let saved = tokio::task::spawn_blocking(move || {
                        crate::utils::hosts::save_credential(&id, &user, secret.as_str(), &owner, None)
                    })
                    .await
                    .unwrap_or_else(|e| Err(e.to_string()));
                    if let Err(e) = saved {
                        eprintln!("hawser: could not save password for {host_id}: {e}");
                    }
                }
            }
            result
        }
    };

    if !matches!(authed, russh::client::AuthResult::Success) {
        return Err(SshError::AuthFailed(username.to_string()));
    }
    Ok(())
}

#[cfg(windows)]
const NO_AGENT: &str = "no SSH agent reachable (tried the Windows OpenSSH agent service and \
                        Pageant), or no key it holds was accepted";
#[cfg(not(windows))]
const NO_AGENT: &str = "no SSH agent reachable through $SSH_AUTH_SOCK, or no key it holds \
                        was accepted";

/// True if a keyboard-interactive prompt's text asks for the account password
/// (as opposed to an OTP / verification code, which PAM also sends hidden).
fn looks_like_password_prompt(prompt: &str) -> bool {
    let t = prompt.to_lowercase();
    [
        "password", "passphrase", "passwort", "mot de passe", "contraseña", "senha",
        "пароль", "密码", "パスワード", "비밀번호",
    ]
    .iter()
    .any(|w| t.contains(w))
}

/// True if a prompt asks for a second factor: an OTP, token or verification
/// code. Checked BEFORE the password test and overrides it — "One-time
/// password:" contains "password", and a lone hidden "Verification code:" must
/// not be read as the TACACS+ unlabelled password question. Sending the
/// reusable password to an OTP verifier both fails auth and leaks it there.
fn looks_like_otp_prompt(prompt: &str) -> bool {
    let lower = prompt.to_lowercase();
    // Ignore whatever names the account: "Password for root@shipping-db:" or
    // "Password for jpinto@REALM:" must not read as a PIN/OTP prompt because a
    // username or host happens to contain one of the short stems.
    let t = lower.split(" for ").next().unwrap_or(&lower);
    // Distinctive phrases, matched as substrings (incl. localized OTP wording;
    // the password list above is localized, so a localized "one-time
    // password" would otherwise be read as the account password).
    const PHRASES: &[&str] = &[
        "one-time", "one time", "onetime", "verification", "passcode", "two-factor",
        "two factor", "second factor", "factor", "faktor", "authenticator", "yubikey",
        "security key", "einmal", "bestätigung", "ワンタイム", "一次性", "动态", "验证码",
        "驗證碼", "認証コード", "確認コード", "일회용", "인증", "одноразов", "код ",
        "un solo uso", "uso único", "usage unique", "código", "codice", "monouso",
    ];
    // Short stems, matched only as whole words.
    const WORDS: &[&str] = &[
        "otp", "code", "token", "pin", "mfa", "2fa", "duo", "verify", "oath", "sms",
        "response", "digit", "digits", "challenge", "код",
    ];
    PHRASES.iter().any(|p| t.contains(p))
        || t
            .split(|c: char| !c.is_alphanumeric())
            .any(|w| WORDS.contains(&w))
}

/// Which prompts of one keyboard-interactive round get the password, in the
/// backend. At most one per auth attempt (`password_used`), and only a hidden
/// prompt that reads like a password — or, in the first round, a lone hidden
/// prompt when the password has not already been accepted (the TACACS+ single
/// unlabelled question). A prompt that reads like a second factor never does.
/// Every other prompt, hidden or not, goes to the user.
fn password_slots(
    prompts: &[(String, bool)],
    first_round: bool,
    password_used: bool,
    password_accepted: bool,
) -> Vec<bool> {
    let mut used = password_used;
    let lone_hidden = first_round
        && !password_accepted
        && prompts.len() == 1
        && !prompts[0].1
        && !looks_like_otp_prompt(&prompts[0].0);
    prompts
        .iter()
        .map(|(text, echo)| {
            if used || *echo {
                return false;
            }
            if lone_hidden || (looks_like_password_prompt(text) && !looks_like_otp_prompt(text)) {
                used = true;
                true
            } else {
                false
            }
        })
        .collect()
}

/// Keyboard-interactive auth.
///
/// The hidden prompt asking for the password (the common TACACS+/RADIUS single
/// "Password:" question) is answered with the password on hand, in the backend
/// — so the password never crosses IPC. Every other prompt (an OTP, a token or
/// verification code — which PAM often sends HIDDEN — or a security question)
/// is surfaced to the user through the UI via `request_auth_answers`, masked
/// when the server asked for no echo, and the typed replies are merged back in
/// prompt order.
async fn keyboard_interactive_with_password(
    handle: &mut Handle<ClientHandler>,
    username: &str,
    password: &str,
    password_accepted: bool,
    ctx: &PromptCtx<'_>,
) -> Result<russh::client::AuthResult, SshError> {
    use russh::client::KeyboardInteractiveAuthResponse as Kb;

    let mut reply = handle
        .authenticate_keyboard_interactive_start(username, None)
        .await?;

    let mut password_used = false;
    // A server may send several rounds; cap them so a misbehaving one cannot
    // loop us forever.
    for round in 0..5 {
        match reply {
            Kb::Success => return Ok(russh::client::AuthResult::Success),
            Kb::Failure { remaining_methods, partial_success } => {
                return Ok(russh::client::AuthResult::Failure {
                    remaining_methods,
                    partial_success,
                })
            }
            Kb::InfoRequest { name, instructions, prompts } => {
                // The password answers only the prompt that asks for it (see
                // password_slots); everything else — an OTP, a token or
                // verification code, a security question — is a live challenge
                // the stored password can't answer, so ask the user through the
                // UI. The password itself never crosses IPC.
                //
                // `password` is borrowed from the caller's Zeroizing buffer.
                // Residual (documented, upstream-bounded): russh 0.63's
                // `..._respond` takes the answers `Vec<String>` by value into its
                // internal message queue, so that one transient plaintext copy
                // lives inside russh for the round-trip and cannot be zeroized
                // here — no additional copy is retained on Hawser's side.
                let shape: Vec<(String, bool)> =
                    prompts.iter().map(|p| (p.prompt.clone(), p.echo)).collect();
                let slots = password_slots(&shape, round == 0, password_used, password_accepted);
                if slots.iter().any(|b| *b) {
                    password_used = true;
                }
                let ask: Vec<AuthPromptField> = prompts
                    .iter()
                    .zip(&slots)
                    .filter(|(_, auto)| !**auto)
                    .map(|(p, _)| AuthPromptField { prompt: p.prompt.clone(), echo: p.echo })
                    .collect();
                let mut typed = if ask.is_empty() {
                    Vec::new().into_iter()
                } else {
                    request_auth_answers(ctx, "challenge", &name, &instructions, ask, false)
                        .await?
                        .answers
                        .into_iter()
                };
                // Merge back in prompt order: password slots get the password,
                // the rest take the user's answers in the order they were shown.
                let answers: Vec<String> = slots
                    .iter()
                    .map(|auto| {
                        if *auto {
                            password.to_string()
                        } else {
                            typed.next().map(|t| t.to_string()).unwrap_or_default()
                        }
                    })
                    .collect();
                reply = handle
                    .authenticate_keyboard_interactive_respond(answers)
                    .await?;
            }
        }
    }
    Err(SshError::AuthFailed(format!(
        "{username}: keyboard-interactive did not converge after 5 rounds"
    )))
}

/// Raise a keyboard-interactive challenge to the UI and park on a oneshot until
/// the user answers (or a timeout). Only the prompts the password does not
/// answer are sent out; the returned vector is one typed answer per prompt
/// shown, in order.
async fn request_auth_answers(
    ctx: &PromptCtx<'_>,
    kind: &'static str,
    name: &str,
    instruction: &str,
    fields: Vec<AuthPromptField>,
    offer_save: bool,
) -> Result<AuthAnswer, SshError> {
    let (app, auth_prompts, session_id) = (ctx.app, ctx.auth_prompts, ctx.owner.0.as_str());
    let request_id = format!(
        "auth-{}-{}",
        session_id,
        AUTH_PROMPT_SEQ.fetch_add(1, Ordering::Relaxed)
    );
    let request = AuthPromptRequest {
        request_id: request_id.clone(),
        session_id: session_id.to_string(),
        name: name.to_string(),
        instruction: instruction.to_string(),
        prompts: fields,
        origin: ctx.origin.clone(),
        kind,
        offer_save,
    };
    // No cancellation check here: this runs inside the connect future, which
    // the cancel select drops at its next await. A sweep that ran just before
    // this registration is followed by connect()'s own post-cancel sweep, which
    // then closes the prompt — after it was emitted (see register_and_emit).
    // The stage deadlines stop before the prompt is shown and do not run
    // while the human types.
    let Some((_human, rx)) = raise_prompt(
        &ctx.wait,
        &auth_prompts.pending,
        &request_id,
        ctx.owner.clone(),
        || false,
        || app.emit("ssh://auth-prompt", request).is_ok(),
    ) else {
        // The dialog will never be shown, so nothing will ever resolve this
        // request; register_and_emit has already dropped the pending entry.
        return Err(SshError::AuthFailed(
            "could not raise the interactive auth prompt".into(),
        ));
    };

    match tokio::time::timeout(AUTH_PROMPT_TIMEOUT, rx).await {
        Ok(Ok(answer)) => Ok(answer),
        // Sender dropped (dialog cancelled, or the tab's prompts swept) —
        // abort auth cleanly, and make sure a close follows the prompt.
        Ok(Err(_)) => {
            emit_prompt_closed(app, &request_id);
            Err(SshError::AuthFailed("interactive auth cancelled".into()))
        }
        Err(_) => {
            auth_prompts.cancel(&request_id);
            emit_prompt_closed(app, &request_id);
            Err(SshError::AuthFailed("interactive auth prompt timed out".into()))
        }
    }
}

/// ssh-copy-id, in one call: connect with a password, append a public key to
/// the server's authorized_keys, disconnect. Turns "generate a key" into
/// "generate and it works" without the copy/paste/assemble ritual.
///
/// A throwaway connection, not a Registry session — no shell, no pump, no tab.
/// The password is one-shot and never stored. The host-key check still runs
/// (first-time hosts prompt exactly as a normal connect would).
///
/// POSIX-sh only: it does the mkdir/grep-dedup/append/chmod dance a Unix host
/// understands. Network appliances (PAN-OS, IOS) manage keys through their own
/// config and are out of scope here — the UI offers the copyable command for
/// those.
#[allow(clippy::too_many_arguments)]
/// Validate a public key for `copy_id` and return its single trimmed line.
///
/// It must parse as one OpenSSH public key line (so an empty paste, a private
/// key or arbitrary text is refused), and it must be safe inside the
/// single-quoted remote script: no quote, no line break, no control
/// character, and no leading '-' (which `grep` would take as an option).
fn validate_public_key(public_key: &str) -> Result<String, String> {
    let key = public_key.trim();
    if key.is_empty() {
        return Err("no public key given".into());
    }
    if key.contains('\n') || key.contains('\r') {
        return Err("the public key must be a single line".into());
    }
    if key.starts_with('-') {
        return Err("the public key cannot start with '-'".into());
    }
    if key.contains('\'') || key.chars().any(|c| c.is_control()) {
        return Err("public key contains illegal characters".into());
    }
    russh::keys::ssh_key::PublicKey::from_openssh(key)
        .map_err(|e| format!("not an OpenSSH public key line ({e})"))?;
    Ok(key.to_string())
}

/// Quote `s` as one POSIX-shell single-quoted word.
fn sh_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// The exec command for a key install: `exec sh -s`, which every login shell
/// (sh, bash, zsh, fish, csh, tcsh) runs the same way because it contains
/// nothing any of them interprets. The script and the key go to that `sh` on
/// stdin (`copy_id_script`), so the login shell never sees the key: csh and
/// tcsh history-expand a `!` even inside single quotes, and a key comment may
/// hold `!`, `$` or backticks.
const COPY_ID_COMMAND: &str = "exec sh -s";

/// The POSIX sh script `COPY_ID_COMMAND` reads on stdin, for a key already
/// passed through `validate_public_key` (one line, no `'`), which makes it a
/// safe single-quoted sh word.
///
/// One brace group, so sh has parsed all of it before anything runs (nothing
/// in it reads stdin, and nothing could read a later line as input). `-e`
/// keeps grep from reading the key as an option.
///
/// grep -qxF: only append if the exact line is not already present, so running
/// this twice does not duplicate the key. The chain is conjunctive:
/// HAWSER_KEY_OK is printed only if every step — including the append —
/// actually succeeded. A file whose last line has no trailing newline gets one
/// first (as ssh-copy-id does); otherwise the key is glued onto that line, grep
/// never sees it as its own line, and "success" is reported for a key sshd
/// cannot parse.
fn copy_id_script(key: &str) -> String {
    let k = sh_single_quote(key);
    format!(
        "{{\n\
         mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys \\\n\
         && {{ [ ! -s ~/.ssh/authorized_keys ] || [ -z \"$(tail -c 1 ~/.ssh/authorized_keys)\" ] \\\n\
               || printf '\\n' >> ~/.ssh/authorized_keys; }} \\\n\
         && {{ grep -qxF -e {k} ~/.ssh/authorized_keys || printf '%s\\n' {k} >> ~/.ssh/authorized_keys; }} \\\n\
         && chmod 600 ~/.ssh/authorized_keys && echo HAWSER_KEY_OK\n\
         }}\n"
    )
}

async fn copy_id(
    app: AppHandle,
    prompts: Arc<HostKeyPrompts>,
    auth_prompts: Arc<AuthPrompts>,
    session_id: &str,
    cancel: watch::Receiver<()>,
    host: &str,
    port: u16,
    username: &str,
    password: zeroize::Zeroizing<String>,
    public_key: &str,
) -> Result<(), SshError> {
    // Checked before anything dials: an empty, multi-line or non-key text
    // would otherwise be appended to authorized_keys and reported "installed".
    let key = validate_public_key(public_key).map_err(SshError::AuthFailed)?;
    let key = key.as_str();

    // Same stage deadlines as a normal connect; the host-key check and any
    // keyboard-interactive challenge pause them while the user reads.
    let wait = HumanWait::default();
    let owner: PromptOwner = (session_id.to_string(), 0);
    let origin = PromptOrigin::new(None, username, host, port, None);
    // As for a connect: whatever ends this install (an error, a deadline, a
    // cancel dropping this future, or success) ends its transport too.
    let guard = KillGuard::new();
    let kill = guard.kill();
    let (tcp, ip) = dial_tcp(host, port).await?;
    let handler = ClientHandler {
        host: host.to_string(),
        ip,
        port,
        origin: origin.clone(),
        app: app.clone(),
        prompts,
        owner: owner.clone(),
        cancel,
        wait: wait.clone(),
        death: Arc::default(),
        kill: kill.clone(),
    };
    let hlabel = format!("{host}:{port}");
    let mut handle =
        handshake(hop_config(host, port), tcp, handler, &wait, &hlabel, HANDSHAKE_TIMEOUT, &kill).await?;

    // Password (with keyboard-interactive fallback), one-shot. host_id "" is
    // never consulted because the one-shot password is supplied.
    let ctx = PromptCtx {
        app: &app,
        auth_prompts: &auth_prompts,
        owner,
        origin,
        wait: wait.clone(),
        offer_save: false,
    };
    let spec = AuthSpec {
        host_id: "",
        host,
        port,
        username,
        auth: "password",
        key_path: None,
        secret: Some(password),
    };
    within(&wait, AUTH_TIMEOUT, &hlabel, "authentication", authenticate(&mut handle, spec, &ctx))
        .await??;

    // See copy_id_script.
    let script = copy_id_script(key);

    let mut channel = within(
        &wait,
        CHANNEL_SETUP_TIMEOUT,
        &hlabel,
        "opening a session channel",
        handle.channel_open_session(),
    )
    .await??;
    within(
        &wait,
        CHANNEL_SETUP_TIMEOUT,
        &hlabel,
        "starting the install command",
        channel.exec(true, COPY_ID_COMMAND),
    )
    .await??;
    // The script on stdin; run_exec then sends EOF, which ends it.
    within(
        &wait,
        CHANNEL_SETUP_TIMEOUT,
        &hlabel,
        "sending the install script",
        channel.data(script.as_bytes()),
    )
    .await??;
    // A timeout is a failure, not a silent success: don't judge the run by
    // whatever partial output happened to arrive before the clock ran out.
    let run = run_exec(&mut channel, 1024 * 1024, Duration::from_secs(20)).await;
    let completed = !run.timed_out && !run.truncated && run.confirmed && run.signal.is_none();
    let exit_status = run.exit_status;
    let mut out = run.out;
    out.extend_from_slice(&run.err);

    // Three signals must agree before we claim the key is installed:
    //   - the command actually finished within the timeout,
    //   - any exit status it reported was 0 (missing status is tolerated, as
    //     some servers close the channel without sending one — the marker below
    //     is the primary positive proof), and
    //   - the conjunctive `&&` chain printed its end marker, which it only does
    //     if every step (including the append) succeeded.
    // Deciding on the marker alone let a non-zero exit or a truncated/timed-out
    // run be reported as success.
    let marker = String::from_utf8_lossy(&out).contains("HAWSER_KEY_OK");
    let exit_ok = exit_status.map_or(true, |code| code == 0);
    // A throwaway connection: close it properly rather than just dropping it.
    // Bounded (a transport that stopped taking messages would hold this
    // forever); the kill guard then ends the transport regardless.
    let _ = tokio::time::timeout(
        EXEC_CLOSE_GRACE,
        handle.disconnect(russh::Disconnect::ByApplication, "key installed", ""),
    )
    .await;
    drop(guard);
    if completed && exit_ok && marker {
        Ok(())
    } else {
        Err(SshError::AuthFailed(format!(
            "install did not confirm success (completed={completed}, exit={exit_status:?}): {}",
            String::from_utf8_lossy(&out).chars().take(200).collect::<String>()
        )))
    }
}

/// Try every identity each reachable SSH agent offers.
///
/// Returns `Ok(None)` when no agent is reachable or no key was accepted —
/// distinct from an SSH-level error, so the caller can produce a message that
/// says what to actually do (start the agent, add a key) rather than a generic
/// failure. An error from one agent does not stop the next being tried.
/// Windows tries the OpenSSH agent service first (the one Windows ships), then
/// Pageant for the PuTTY crowd; elsewhere the one agent is $SSH_AUTH_SOCK.
async fn agent_auth(
    handle: &mut Handle<ClientHandler>,
    username: &str,
) -> Result<Option<russh::client::AuthResult>, SshError> {
    use russh::keys::agent::client::AgentClient;

    let mut rsa = RsaHash::default();
    let mut tried = 0usize;
    let mut errors: Vec<String> = Vec::new();

    #[cfg(windows)]
    {
        if let Ok(mut agent) =
            AgentClient::connect_named_pipe(r"\\.\pipe\openssh-ssh-agent").await
        {
            match try_agent_identities(&mut agent, handle, username, &mut rsa, &mut tried).await {
                Ok(Some(r)) => return Ok(Some(r)),
                Ok(None) => {}
                Err(e) => errors.push(format!("OpenSSH agent: {}", auth_detail(e))),
            }
        }
        // russh makes connect_pageant fallible; a missing Pageant is just "no
        // agent".
        if let Ok(mut pageant) = AgentClient::connect_pageant().await {
            match try_agent_identities(&mut pageant, handle, username, &mut rsa, &mut tried).await {
                Ok(Some(r)) => return Ok(Some(r)),
                Ok(None) => {}
                Err(e) => errors.push(format!("Pageant: {}", auth_detail(e))),
            }
        }
    }

    #[cfg(not(windows))]
    {
        // $SSH_AUTH_SOCK — set by ssh-agent, gnome-keyring, 1Password, etc.
        if let Ok(mut agent) = AgentClient::connect_env().await {
            match try_agent_identities(&mut agent, handle, username, &mut rsa, &mut tried).await {
                Ok(Some(r)) => return Ok(Some(r)),
                Ok(None) => {}
                Err(e) => errors.push(format!("agent: {}", auth_detail(e))),
            }
        }
    }

    if errors.is_empty() {
        Ok(None)
    } else {
        Err(SshError::AuthFailed(format!("{username}: {}", errors.join("; "))))
    }
}

/// Offer each identity a connected agent holds to the server, signing with the
/// agent. Returns `Ok(Some(..))` on the first accepted key, `Ok(None)` if the
/// agent holds no accepted key, and an error if it cannot list its keys. `tried` counts attempts
/// across agents, for the MaxAuthTries hint.
async fn try_agent_identities(
    agent: &mut russh::keys::agent::client::AgentClient<
        impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    >,
    handle: &mut Handle<ClientHandler>,
    username: &str,
    rsa: &mut RsaHash,
    tried: &mut usize,
) -> Result<Option<russh::client::AuthResult>, SshError> {
    // A reachable agent that cannot list its keys is reported as that, not
    // folded into "no agent, or no key accepted".
    let identities = agent.request_identities().await.map_err(|e| {
        SshError::AuthFailed(format!("could not list the agent's keys: {e}"))
    })?;
    for identity in identities {
        // AgentIdentity is a key or a certificate; publickey auth wants the
        // underlying PublicKey.
        let key = identity.public_key().into_owned();
        let (hashes, is_rsa): (Vec<Option<russh::keys::HashAlg>>, bool) =
            if key.algorithm().is_rsa() {
                let (h, retry_sha1) = rsa.get(handle).await?;
                (if retry_sha1 { vec![h, None] } else { vec![h] }, true)
            } else {
                (vec![None], false)
            };
        for hash in hashes {
            *tried += 1;
            let result = handle
                .authenticate_publickey_with(username, key.clone(), hash, agent)
                .await
                .map_err(|e| agent_error(e, *tried))?;
            if matches!(result, russh::client::AuthResult::Success) {
                return Ok(Some(result));
            }
            if !is_rsa {
                break;
            }
        }
    }
    Ok(None)
}

/// The detail of an auth error, without `AuthFailed`'s "authentication failed
/// for" prefix (the caller adds its own context once).
fn auth_detail(e: SshError) -> String {
    match e {
        SshError::AuthFailed(m) => m,
        other => other.to_string(),
    }
}

/// Wording for an agent-auth error. A server that drops the connection mid-way
/// has almost always hit its MaxAuthTries limit with a well-stocked agent.
fn agent_error(e: russh::AgentAuthError, tried: usize) -> SshError {
    let text = e.to_string();
    // `Send`: the session task is gone, i.e. the server hung up.
    let dropped = matches!(&e, russh::AgentAuthError::Send(_));
    if dropped {
        SshError::AuthFailed(format!(
            "the server closed the connection after {tried} key attempts (it probably limits \
             attempts, MaxAuthTries). Remove keys from the agent, or use a key file for this \
             host"
        ))
    } else {
        SshError::AuthFailed(format!("agent signing failed: {text}"))
    }
}

/// True if `meta` describes a symlink or (on Windows) any reparse point such as
/// a junction or mount point. `symlink_metadata().is_symlink()` alone misses
/// NTFS junctions, which are reparse points but not "symlinks" — and a junction
/// redirects a directory just as effectively, so a download must refuse it too.
fn is_link_or_reparse(meta: &std::fs::Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        return meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0;
    }
    #[cfg(not(target_os = "windows"))]
    false
}

/// Refuse if any component of `target` *below* the trusted `root` already exists
/// on disk as a symlink or reparse point.
///
/// `safe_local_component` guarantees each name is a plain component, so `target`
/// is structurally `root/comp1/comp2/...` and cannot use `..` or an absolute
/// path to escape. The one remaining escape is an *existing local link* planted
/// at one of those positions: a server tree containing `logs/` will silently
/// write into `/etc` if `root/logs` is already a symlink to it, because
/// `create_dir_all` and `File::create` follow links. Checking each existing
/// level before we create or write closes that hole.
///
/// The trusted `root` itself (the folder the user picked) and its real ancestors
/// are not re-checked — only the region built from server-supplied names is.
/// The attacker here is the remote server choosing names, not a concurrent local
/// process, so a check-then-create window is not a meaningful TOCTOU race.
fn reject_link_in_subtree(root: &std::path::Path, target: &std::path::Path) -> Result<(), SshError> {
    let rel = match target.strip_prefix(root) {
        Ok(rel) => rel,
        // A target that is not under root is itself an escape; refuse rather
        // than silently checking nothing.
        Err(_) => {
            return Err(SshError::PartialTransfer(format!(
                "refusing to write outside the destination: {}",
                target.display()
            )))
        }
    };
    let mut cur = root.to_path_buf();
    for comp in rel.components() {
        cur.push(comp);
        match std::fs::symlink_metadata(&cur) {
            Ok(meta) if is_link_or_reparse(&meta) => {
                return Err(SshError::PartialTransfer(format!(
                    "refusing to follow a link in the download path: {}",
                    cur.display()
                )))
            }
            // Missing (will be created as a real dir/file) or a real entry: fine.
            _ => {}
        }
    }
    Ok(())
}

/// True for Windows reserved device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9),
/// matched case-insensitively and ignoring any extension — `NUL.txt` is still
/// the NUL device. Creating such a file fails with a confusing OS error, so we
/// reject the name up front and report it as skipped instead.
fn is_windows_reserved(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name);
    const RESERVED: [&str; 22] = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    RESERVED.iter().any(|r| stem.eq_ignore_ascii_case(r))
}

/* ------------------------------------------------------------ sftp plumbing */

/// A session's SFTP channel (see `open_sftp_conn`).
pub struct SftpConn {
    /// The high-level session: file handles, metadata, renames.
    hi: SftpSession,
    /// A raw session over the SAME channel, for listings read batch by batch
    /// (so they can be capped) and `posix-rename@openssh.com`.
    raw: RawSftpSession,
    /// The server advertised `posix-rename@openssh.com` version 1.
    posix_rename: bool,
    /// Whether this server's plain RENAME replaces an existing target, once
    /// probed (see `rename_replaces`).
    rename_replaces: std::sync::Mutex<Option<bool>>,
}

/// Open the `sftp` subsystem on a fresh session channel and wait for the
/// server's answer. A refusal (or no answer) CLOSES the channel — dropping it
/// would leave it open on the server, holding one of its session slots — and
/// a refusal is remembered in `refused`, so the connection does not ask again.
async fn open_sftp_channel<H: client::Handler>(
    handle: &Handle<H>,
    refused: &AtomicBool,
) -> Result<(russh::ChannelReadHalf, ChannelWriteHalf<client::Msg>, Vec<u8>), SshError> {
    if refused.load(Ordering::SeqCst) {
        return Err(SshError::Connect("the server refused the SFTP subsystem on this connection".into()));
    }
    let mut channel = tokio::time::timeout(SFTP_SETUP_TIMEOUT, handle.channel_open_session())
        .await
        .map_err(|_| SshError::Connect("opening the SFTP channel timed out".into()))??;
    let mut early = Vec::new();
    let answer = tokio::time::timeout(SFTP_SETUP_TIMEOUT, async {
        channel.request_subsystem(true, "sftp").await?;
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Success) => return Ok(true),
                Some(ChannelMsg::Failure) => return Ok(false),
                // Some servers start talking before the reply is processed.
                Some(ChannelMsg::Data { data }) => early.extend_from_slice(&data),
                Some(ChannelMsg::Close | ChannelMsg::Eof) | None => {
                    return Err(SshError::Connect("the SFTP channel closed before it started".into()))
                }
                Some(_) => {}
            }
        }
    })
    .await;
    match answer {
        Ok(Ok(true)) => {
            let (r, w) = channel.split();
            Ok((r, w, early))
        }
        other => {
            let _ = tokio::time::timeout(EXEC_CLOSE_GRACE, channel.close()).await;
            Err(match other {
                Ok(Ok(_)) => {
                    refused.store(true, Ordering::SeqCst);
                    SshError::Connect("the server refused the SFTP subsystem".into())
                }
                Ok(Err(e)) => e,
                Err(_) => SshError::Connect(format!(
                    "the server did not answer the SFTP subsystem request within {}s",
                    SFTP_SETUP_TIMEOUT.as_secs()
                )),
            })
        }
    }
}

/// Open a session's SFTP channel: ONE subsystem channel shared by the
/// high-level session and a raw one (see `spawn_sftp_mux`), so a server that
/// allows one SFTP channel per connection still gets capped listings and
/// posix-rename, and no second channel ever holds a session slot.
async fn open_sftp_conn<H: client::Handler>(
    handle: &Handle<H>,
    refused: &AtomicBool,
) -> Result<SftpConn, SshError> {
    let (r, w, early) = open_sftp_channel(handle, refused).await?;
    let (hi_io, raw_io) = spawn_sftp_mux(r, w, early);
    let setup = async {
        let hi = SftpSession::new(hi_io).await?;
        let raw = RawSftpSession::new(raw_io);
        let version = raw.init().await?;
        Ok::<_, SshError>((hi, raw, version))
    };
    let (hi, raw, version) = tokio::time::timeout(SFTP_SETUP_TIMEOUT, setup)
        .await
        .map_err(|_| SshError::Connect("the SFTP server did not answer its INIT".into()))??;
    let posix_rename = version.extensions.get(POSIX_RENAME).is_some_and(|v| v == "1");
    Ok(SftpConn { hi, raw, posix_rename, rename_replaces: std::sync::Mutex::new(None) })
}

/// Largest SFTP packet the mux relays (the protocol's own limits are far
/// lower; anything bigger is a broken stream).
const MUX_MAX_PACKET: usize = 4 << 20;
const SSH_FXP_INIT: u8 = 1;
const SSH_FXP_VERSION: u8 = 2;

/// Two SFTP client sessions over one subsystem channel.
///
/// Each session talks to its own in-memory stream. Every request it sends
/// gets a fresh request id on the wire, remembered with the session and the
/// id it used; each reply is routed back with its original id. Only the first
/// session's INIT goes to the server; the second is answered with a copy of
/// the server's VERSION. A reply for a request its session gave up on is
/// delivered and ignored by that session, as a late reply on a private
/// channel would be.
///
/// The channel is CLOSED (not just dropped, which sends nothing) when both
/// sessions are gone or the server ends it; either way both sessions then see
/// end-of-stream and fail fast (see `sftp_dead`).
fn spawn_sftp_mux(
    mut read: russh::ChannelReadHalf,
    write: ChannelWriteHalf<client::Msg>,
    early: Vec<u8>,
) -> (tokio::io::DuplexStream, tokio::io::DuplexStream) {
    use tokio::io::AsyncWriteExt as _;
    struct Routes {
        next: u32,
        pending: std::collections::HashMap<u32, (usize, u32)>,
        version: Option<Vec<u8>>,
        raw_waiting: bool,
    }
    let routes = Arc::new(std::sync::Mutex::new(Routes {
        next: 1,
        pending: std::collections::HashMap::new(),
        version: None,
        raw_waiting: false,
    }));
    let write = Arc::new(write);
    let (hi_app, hi_mux) = tokio::io::duplex(1 << 20);
    let (raw_app, raw_mux) = tokio::io::duplex(1 << 20);
    let (hi_r, hi_w) = tokio::io::split(hi_mux);
    let (raw_r, raw_w) = tokio::io::split(raw_mux);
    // Frames from either session, in the order they were completed.
    let (up_tx, mut up_rx) = tokio::sync::mpsc::channel::<(usize, Vec<u8>)>(64);
    // The second session's INIT, answered by the downstream task.
    let (init_tx, mut init_rx) = tokio::sync::mpsc::channel::<()>(1);

    async fn frame<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> Option<Vec<u8>> {
        let mut len = [0u8; 4];
        r.read_exact(&mut len).await.ok()?;
        let n = u32::from_be_bytes(len) as usize;
        if n == 0 || n > MUX_MAX_PACKET {
            return None;
        }
        let mut f = vec![0u8; 4 + n];
        f[..4].copy_from_slice(&len);
        r.read_exact(&mut f[4..]).await.ok()?;
        Some(f)
    }
    for (ep, mut r) in [(0usize, Box::new(hi_r) as Box<dyn tokio::io::AsyncRead + Unpin + Send>), (1, Box::new(raw_r))] {
        let tx = up_tx.clone();
        tokio::spawn(async move {
            while let Some(f) = frame(&mut r).await {
                if tx.send((ep, f)).await.is_err() {
                    break;
                }
            }
        });
    }
    drop(up_tx);

    // Upstream: one writer, so two sessions' packets never interleave.
    let up_routes = Arc::clone(&routes);
    let up_write = Arc::clone(&write);
    tokio::spawn(async move {
        while let Some((ep, mut f)) = up_rx.recv().await {
            if f[4] == SSH_FXP_INIT {
                if ep == 0 {
                    if up_write.data(&f[..]).await.is_err() {
                        break;
                    }
                } else {
                    let _ = init_tx.try_send(());
                }
                continue;
            }
            if f.len() < 9 {
                continue;
            }
            let orig = u32::from_be_bytes([f[5], f[6], f[7], f[8]]);
            let wire = {
                let mut r = up_routes.lock().unwrap_or_else(|p| p.into_inner());
                let mut id = r.next;
                while r.pending.contains_key(&id) {
                    id = id.wrapping_add(1);
                }
                r.next = id.wrapping_add(1);
                r.pending.insert(id, (ep, orig));
                id
            };
            f[5..9].copy_from_slice(&wire.to_be_bytes());
            if up_write.data(&f[..]).await.is_err() {
                break;
            }
        }
        // Both sessions gone (or the channel broke): end the channel.
        let _ = tokio::time::timeout(EXEC_CLOSE_GRACE, up_write.close()).await;
    });

    // Downstream: route each reply to its session.
    tokio::spawn(async move {
        let mut outs = [hi_w, raw_w];
        let mut buf = early;
        'run: loop {
            // Every complete frame in the buffer.
            loop {
                if buf.len() < 4 {
                    break;
                }
                let n = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
                if n == 0 || n > MUX_MAX_PACKET {
                    break 'run;
                }
                if buf.len() < 4 + n {
                    break;
                }
                let mut f: Vec<u8> = buf.drain(..4 + n).collect();
                if f[4] == SSH_FXP_VERSION {
                    let raw_waiting = {
                        let mut r = routes.lock().unwrap_or_else(|p| p.into_inner());
                        r.version = Some(f.clone());
                        std::mem::take(&mut r.raw_waiting)
                    };
                    if raw_waiting {
                        let _ = outs[1].write_all(&f).await;
                    }
                    let _ = outs[0].write_all(&f).await;
                    continue;
                }
                if f.len() < 9 {
                    continue;
                }
                let wire = u32::from_be_bytes([f[5], f[6], f[7], f[8]]);
                let route = routes.lock().unwrap_or_else(|p| p.into_inner()).pending.remove(&wire);
                if let Some((ep, orig)) = route {
                    f[5..9].copy_from_slice(&orig.to_be_bytes());
                    // A session that is gone just misses its reply.
                    let _ = outs[ep].write_all(&f).await;
                }
            }
            tokio::select! {
                msg = read.wait() => match msg {
                    Some(ChannelMsg::Data { data }) => buf.extend_from_slice(&data),
                    Some(ChannelMsg::Eof | ChannelMsg::Close) | None => break 'run,
                    Some(_) => {}
                },
                Some(()) = init_rx.recv() => {
                    let version = {
                        let mut r = routes.lock().unwrap_or_else(|p| p.into_inner());
                        let v = r.version.clone();
                        if v.is_none() {
                            r.raw_waiting = true;
                        }
                        v
                    };
                    if let Some(v) = version {
                        let _ = outs[1].write_all(&v).await;
                    }
                }
            }
        }
        // The server ended the stream: both sessions see EOF, and the channel
        // is closed from our side too.
        for o in outs.iter_mut() {
            let _ = o.shutdown().await;
        }
        drop(outs);
        let _ = tokio::time::timeout(EXEC_CLOSE_GRACE, write.close()).await;
    });
    (hi_app, raw_app)
}

const POSIX_RENAME: &str = "posix-rename@openssh.com";

/// The SFTP status code inside `e`, if it is a status reply.
fn sftp_status(e: &russh_sftp::client::error::Error) -> Option<StatusCode> {
    match e {
        russh_sftp::client::error::Error::Status(st) => Some(st.status_code),
        _ => None,
    }
}

/// Whether `e` means the SFTP channel itself is gone or not answering (rather
/// than one operation failing), so the cached session must be reopened and a
/// tree walk must stop instead of timing out on every remaining file.
fn sftp_dead(e: &SshError) -> bool {
    use russh_sftp::client::error::Error as SftpErr;
    fn dead(e: &SftpErr) -> bool {
        matches!(e, SftpErr::UnexpectedBehavior(_) | SftpErr::IO(_) | SftpErr::Timeout)
    }
    match e {
        SshError::Sftp(s) => dead(s),
        SshError::TransferStalled(_) | SshError::TreeAborted(_) => true,
        // Errors from an SFTP `File` (AsyncRead/AsyncWrite) arrive as io::Error
        // carrying the SFTP error inside.
        SshError::Io(io) => {
            io.kind() == std::io::ErrorKind::TimedOut
                || io
                    .get_ref()
                    .and_then(|inner| inner.downcast_ref::<SftpErr>())
                    .is_some_and(dead)
        }
        _ => false,
    }
}

/// Read one remote directory, at most `cap` entries ("." and ".." left out).
/// Returns the entries and whether the listing was cut off.
async fn read_dir_capped(
    sftp: &SftpConn,
    path: &str,
    cap: usize,
) -> Result<(Vec<(String, russh_sftp::protocol::FileAttributes)>, bool), SshError> {
    let raw = &sftp.raw;
    let handle = raw.opendir(path).await?.handle;
    let mut out = Vec::new();
    let mut truncated = false;
    let result = loop {
        match raw.readdir(handle.as_str()).await {
            Ok(name) => {
                for f in name.files {
                    if f.filename == "." || f.filename == ".." {
                        continue;
                    }
                    if out.len() >= cap {
                        truncated = true;
                        break;
                    }
                    out.push((f.filename, f.attrs));
                }
                if truncated {
                    break Ok(());
                }
            }
            Err(e) if sftp_status(&e) == Some(StatusCode::Eof) => break Ok(()),
            Err(e) => break Err(e),
        }
    };
    let _ = raw.close(handle).await;
    result?;
    Ok((out, truncated))
}

async fn list_dir_with(sftp: &SftpConn, path: &str) -> Result<DirListing, SshError> {
    // Resolve first so the pane shows the real location: the server may
    // return something different for ".", "~", or a symlinked directory.
    let canonical = sftp
        .hi
        .canonicalize(path)
        .await
        .unwrap_or_else(|_| path.to_string());

    let mut entries = vec![FileEntry {
        name: "..".into(),
        kind: "directory",
        size: 0,
        modified: None,
        mode: String::new(),
    }];

    let (listed, truncated) = read_dir_capped(sftp, &canonical, MAX_LIST_ENTRIES).await?;
    for (name, meta) in listed {
        let kind = match meta.file_type() {
            FileType::Dir => "directory",
            FileType::Symlink => "symlink",
            _ => "file",
        };
        entries.push(FileEntry {
            name,
            kind,
            size: meta.size.unwrap_or(0),
            modified: meta.mtime,
            mode: mode_string(meta.permissions, kind),
        });
    }

    Ok(DirListing { path: canonical, entries, truncated })
}

/// `posix-rename@openssh.com`: rename that atomically REPLACES an existing
/// target (POSIX rename(2) semantics), unlike SFTPv3 RENAME.
async fn posix_rename(raw: &RawSftpSession, from: &str, to: &str) -> Result<(), SshError> {
    fn put(buf: &mut Vec<u8>, s: &str) {
        buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
        buf.extend_from_slice(s.as_bytes());
    }
    let mut data = Vec::with_capacity(8 + from.len() + to.len());
    put(&mut data, from);
    put(&mut data, to);
    match raw.extended(POSIX_RENAME, data).await? {
        russh_sftp::protocol::Packet::Status(st) if st.status_code == StatusCode::Ok => Ok(()),
        russh_sftp::protocol::Packet::Status(st) => {
            Err(SshError::Sftp(russh_sftp::client::error::Error::Status(st)))
        }
        _ => Err(SshError::Sftp(russh_sftp::client::error::Error::UnexpectedPacket)),
    }
}

/* ---------------------------------------------------------- transfer policy */

/// What a transfer may do to a file already at its destination. Chosen by the
/// frontend's overwrite prompt, carried through IPC (retries included), and
/// enforced when each file is COMMITTED: a destination that appears after the
/// prompt is never clobbered under `Never`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Overwrite {
    /// Refuse to replace anything (the default, and the choice for a
    /// destination that did not exist when the user was asked).
    Never,
    /// Replace an existing file.
    Replace,
    /// The user was asked about this existing destination and agreed.
    Confirmed,
}

impl Overwrite {
    /// Parse the IPC value; a missing value is `Never`.
    pub fn parse(v: Option<&str>) -> Result<Self, String> {
        match v.unwrap_or("never") {
            "never" => Ok(Self::Never),
            "replace" => Ok(Self::Replace),
            "confirmed" => Ok(Self::Confirmed),
            other => Err(format!("unknown overwrite policy: {other}")),
        }
    }

    fn allows_replace(self) -> bool {
        !matches!(self, Self::Never)
    }
}

fn already_exists(path: &str) -> SshError {
    SshError::PartialTransfer(format!("{path} already exists; not overwriting it"))
}

/// Run one transfer step under the transfer's cancel switch and the stall
/// deadline.
async fn step<T, E: Into<SshError>>(
    cancel: &watch::Receiver<bool>,
    fut: impl std::future::Future<Output = Result<T, E>>,
) -> Result<T, SshError> {
    let mut rx = cancel.clone();
    if *rx.borrow() {
        return Err(SshError::TransferCancelled);
    }
    let cancelled = async move {
        loop {
            if rx.changed().await.is_err() {
                // Sender gone: nobody can cancel any more.
                std::future::pending::<()>().await;
            }
            if *rx.borrow() {
                return;
            }
        }
    };
    let stall = stall_timeout();
    tokio::select! {
        biased;
        _ = cancelled => Err(SshError::TransferCancelled),
        r = tokio::time::timeout(stall, fut) => match r {
            Ok(r) => r.map_err(Into::into),
            Err(_) => Err(SshError::TransferStalled(stall.as_secs())),
        },
    }
}

#[cfg(test)]
tokio::task_local! {
    /// A test's shorter stall deadline (see `stall_timeout`).
    static TEST_STALL: Duration;
}

/// How long one transfer step may make no progress: `TRANSFER_STALL_TIMEOUT`,
/// or a test's own (the SFTP harness drops and delays replies).
fn stall_timeout() -> Duration {
    #[cfg(test)]
    if let Ok(d) = TEST_STALL.try_with(|d| *d) {
        return d;
    }
    TRANSFER_STALL_TIMEOUT
}

/// A cancel switch that never fires: for the steps of a commit, which must
/// run to the end once started (see `commit_upload`).
fn uncancellable() -> watch::Receiver<bool> {
    watch::channel(false).1
}

/// Run `fut` as its own task and wait for it, so it runs to completion even
/// if the caller stops waiting: a commit that has moved the original aside
/// must get to put something back.
async fn shielded<T: Send + 'static>(
    fut: impl std::future::Future<Output = T> + Send + 'static,
) -> Result<T, SshError> {
    #[cfg(test)]
    let fut = TEST_STALL.scope(stall_timeout(), fut);
    tokio::spawn(fut)
        .await
        .map_err(|e| SshError::PartialTransfer(format!("the commit task failed: {e}")))
}

/// Remove a remote staging or probe file, best effort and bounded, never
/// cancelled: called on the way out of a failed or cancelled transfer.
async fn remove_remote_quietly(sftp: &SftpConn, path: &str) {
    let _ = step(&uncancellable(), sftp.hi.remove_file(path)).await;
}

/// Whether anything is at `path` on the server (LSTAT: a link counts). Only a
/// definite "no such file" is `false`.
async fn remote_present(sftp: &SftpConn, path: &str) -> Result<bool, SshError> {
    match step(&uncancellable(), sftp.hi.symlink_metadata(path)).await {
        Ok(_) => Ok(true),
        Err(SshError::Sftp(e)) if sftp_status(&e) == Some(StatusCode::NoSuchFile) => Ok(false),
        Err(e) => Err(e),
    }
}

/* ------------------------------------------------------------- progress */

/// Throttled progress for one whole transfer (a file, or every file of a
/// tree). One clock for the whole transfer: a 100k-file tree must not send
/// two IPC events per file.
struct Progress<'a> {
    /// None only in tests that drive a transfer without a Tauri app.
    app: Option<&'a AppHandle>,
    payload: TransferProgress,
    last: Option<Instant>,
    /// Bytes of files already completed in this transfer.
    base: u64,
    /// The current file's size (single-file transfers only).
    file_total: u64,
    /// Part of a folder transfer: the row's total is unknown, so never report
    /// one file's size (or completion) as the tree's.
    tree: bool,
    cancel: watch::Receiver<bool>,
    notes: Vec<String>,
    notes_dropped: usize,
}

const MAX_NOTES: usize = 20;

impl<'a> Progress<'a> {
    fn new(
        app: &'a AppHandle,
        session_id: &str,
        transfer_id: &str,
        root: &str,
        direction: &'static str,
        cancel: watch::Receiver<bool>,
    ) -> Self {
        Self {
            app: Some(app),
            payload: TransferProgress {
                session_id: session_id.to_string(),
                transfer_id: transfer_id.to_string(),
                root: root.to_string(),
                file_path: root.to_string(),
                bytes_transferred: 0,
                total_bytes: 0,
                direction,
                done: false,
            },
            last: None,
            base: 0,
            file_total: 0,
            tree: false,
            cancel,
            notes: Vec::new(),
            notes_dropped: 0,
        }
    }

    fn cancelled(&self) -> bool {
        *self.cancel.borrow()
    }

    /// A transfer with nobody to report to (the SFTP harness tests).
    #[cfg(test)]
    fn detached(cancel: watch::Receiver<bool>) -> Progress<'static> {
        Progress {
            app: None,
            payload: TransferProgress {
                session_id: String::new(),
                transfer_id: String::new(),
                root: String::new(),
                file_path: String::new(),
                bytes_transferred: 0,
                total_bytes: 0,
                direction: "upload",
                done: false,
            },
            last: None,
            base: 0,
            file_total: 0,
            tree: false,
            cancel,
            notes: Vec::new(),
            notes_dropped: 0,
        }
    }

    fn emit(&mut self) {
        self.last = Some(Instant::now());
        if let Some(app) = self.app {
            let _ = app.emit("sftp://progress", self.payload.clone());
        }
    }

    /// A file starts. A single file emits at once, so the row gets its
    /// denominator; a tree file does not (see the struct comment).
    fn start_file(&mut self, file_path: &str, total: u64) {
        self.payload.file_path = file_path.to_string();
        self.file_total = total;
        self.payload.total_bytes = if self.tree { 0 } else { total };
        self.payload.bytes_transferred = self.base;
        if !self.tree {
            self.emit();
        }
    }

    fn tick(&mut self, file_bytes: u64) {
        if self.last.is_some_and(|t| t.elapsed() < PROGRESS_INTERVAL) {
            return;
        }
        self.payload.bytes_transferred = self.base + file_bytes;
        self.emit();
    }

    /// A file completed. A single file always emits its final event, so the
    /// UI never stalls at 97%; a tree file only counts toward the total.
    fn finish_file(&mut self, file_bytes: u64) {
        self.base += file_bytes;
        if self.tree {
            self.tick(0);
            return;
        }
        self.payload.bytes_transferred = self.base;
        if self.payload.total_bytes == 0 {
            self.payload.total_bytes = file_bytes;
        }
        self.payload.done = true;
        self.emit();
    }

    /// The tree finished: one unthrottled event with the final count.
    fn finish_tree(&mut self) {
        self.payload.bytes_transferred = self.base;
        self.emit();
    }

    fn note(&mut self, text: String) {
        if self.notes.len() < MAX_NOTES {
            self.notes.push(text);
        } else {
            self.notes_dropped += 1;
        }
    }

    fn take_notes(&mut self) -> Vec<String> {
        let mut notes = std::mem::take(&mut self.notes);
        if self.notes_dropped > 0 {
            notes.push(format!("…and {} more like these", self.notes_dropped));
        }
        notes
    }

    fn failure(&self, name: &str, local: &str, remote: &str, reason: String) {
        let Some(app) = self.app else { return };
        let _ = app.emit(
            "sftp://failure",
            TransferFailure {
                session_id: self.payload.session_id.clone(),
                transfer_id: self.payload.transfer_id.clone(),
                root: self.payload.root.clone(),
                name: name.to_string(),
                local: local.to_string(),
                remote: remote.to_string(),
                reason,
                direction: self.payload.direction,
            },
        );
    }
}

/* ------------------------------------------------------------ tree walks */

/// A tree's tally. `dead`: the walk stopped because the SFTP channel stopped
/// answering, which `sftp_dead` must still see so the cached session is
/// dropped (a `PartialTransfer` would hide it, and the next transfer would
/// reuse the stalled channel).
fn partial_summary(total: u64, failed: &[String], dead: bool) -> SshError {
    let text = format!(
        "copied {} bytes; {} item(s) not transferred — first: {}",
        total,
        failed.len(),
        failed[0]
    );
    if dead {
        SshError::TreeAborted(text)
    } else {
        SshError::PartialTransfer(text)
    }
}

async fn download_tree(
    sftp: &Arc<SftpConn>,
    p: &mut Progress<'_>,
    remote: &str,
    local: &str,
    overwrite: Overwrite,
) -> Result<u64, SshError> {
    // A directory recurses; a file copies directly. Walking the tree
    // iteratively (a worklist, not async recursion) keeps this a plain
    // function with no Box::pin ceremony.
    let is_dir = step(&p.cancel, sftp.hi.metadata(remote))
        .await
        .map(|m| m.file_type().is_dir())
        .unwrap_or(false);

    // Single file: the frontend built `local` from the server's name, so
    // verify its final component has not been used to escape the target.
    let last = std::path::Path::new(local)
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_default();
    if !safe_local_component(&last) {
        return Err(SshError::PartialTransfer(format!(
            "refusing to write unsafe filename: {last}"
        )));
    }
    if !is_dir {
        p.tree = false;
        return copy_remote_file(sftp, p, remote, local, overwrite).await;
    }
    p.tree = true;

    // Everything from `local` downward is built from server-chosen names and
    // is therefore untrusted; the folder that CONTAINS `local` is the one the
    // user actually picked and is the trust boundary. Any pre-existing symlink
    // or junction below it must not be followed. (`local` always has a parent
    // here: `safe_local_component` above rejected an empty final component.)
    let root = std::path::Path::new(local)
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .to_path_buf();

    let mut failed: Vec<String> = Vec::new();
    let mut dead = false;
    // Bound the walk so a malicious or misconfigured server advertising a
    // pathologically deep/wide tree cannot grow the worklist without limit.
    const MAX_DIRS: usize = 50_000;
    let mut visited = 0usize;
    let mut dirs = vec![(remote.to_string(), local.to_string())];
    'walk: while let Some((rdir, ldir)) = dirs.pop() {
        if p.cancelled() {
            return Err(SshError::TransferCancelled);
        }
        visited += 1;
        // The root failing is a real error; a subdirectory failing is one
        // more item in the tally, like an unreadable file (see below).
        let is_root = visited == 1;
        if visited > MAX_DIRS {
            let reason = format!(
                "directory limit ({MAX_DIRS}) reached — tree too large; remainder skipped"
            );
            // Empty paths: not retryable — a retry would re-run the whole tree.
            p.failure("(tree)", "", "", reason.clone());
            failed.push(reason);
            break;
        }
        // Refuse to descend into (or create under) a linked ancestor before
        // create_dir_all can follow it outside the destination.
        if let Err(e) = reject_link_in_subtree(&root, std::path::Path::new(&ldir)) {
            failed.push(format!("{ldir}: {e}"));
            continue;
        }
        let dir_name = rdir.rsplit('/').next().unwrap_or(&rdir).to_string();
        let listing = match tokio::fs::create_dir_all(&ldir).await {
            Err(e) if is_root => return Err(e.into()),
            Err(e) => Err(SshError::from(e)),
            Ok(()) => step(&p.cancel, read_dir_capped(sftp, &rdir, MAX_LIST_ENTRIES)).await,
        };
        let (listing, truncated) = match listing {
            Ok(l) => l,
            Err(SshError::TransferCancelled) => return Err(SshError::TransferCancelled),
            Err(e) if is_root || sftp_dead(&e) => return Err(e),
            Err(e) => {
                p.failure(&dir_name, &ldir, &rdir, format!("{e}"));
                failed.push(format!("{rdir}: {e}"));
                continue;
            }
        };
        if truncated {
            let reason = format!("listing cut off at {MAX_LIST_ENTRIES} entries; the rest was skipped");
            p.failure(&dir_name, "", &rdir, reason.clone());
            failed.push(format!("{rdir}: {reason}"));
        }
        for (name, meta) in listing {
            let rpath = format!("{}/{}", rdir.trim_end_matches('/'), name);
            // The server chose this name; refuse anything that is not a
            // plain component before it becomes a local path.
            if !safe_local_component(&name) {
                let reason = format!("{name} (unsafe name, skipped)");
                p.failure(&name, "", &rpath, reason.clone());
                failed.push(reason);
                continue;
            }
            let lpath = std::path::Path::new(&ldir)
                .join(&name)
                .to_string_lossy()
                .to_string();
            let ft = meta.file_type();
            if ft.is_dir() {
                dirs.push((rpath, lpath));
            } else if ft.is_symlink() {
                // A symlink in a tree walk is skipped, not followed: SFTP
                // open() on a dir-symlink fails, and following file links
                // can duplicate or even loop. Recorded so the user learns
                // it was left behind rather than silently missing it.
                // Emitted with an empty local path so it is NOT retryable:
                // a retry would copy it as a plain file, following the link
                // the walk deliberately refused to follow.
                p.failure(&name, "", &rpath, "symlink, skipped".into());
                failed.push(format!("{rpath} (symlink, skipped)"));
            } else {
                // One unreadable file must not abort the other 499: keep
                // walking, collect what failed, report the tally at the end.
                match copy_remote_file(sftp, p, &rpath, &lpath, overwrite).await {
                    Ok(_) => {}
                    Err(SshError::TransferCancelled) => return Err(SshError::TransferCancelled),
                    Err(e) => {
                        p.failure(&name, &lpath, &rpath, format!("{e}"));
                        failed.push(format!("{rpath}: {e}"));
                        if sftp_dead(&e) {
                            // Every remaining file would wait out the same
                            // timeout on a channel that is gone.
                            failed.push("the SFTP session stopped responding; the rest was skipped".into());
                            dead = true;
                            break 'walk;
                        }
                    }
                }
            }
        }
    }
    p.finish_tree();
    if failed.is_empty() {
        Ok(p.base)
    } else {
        Err(partial_summary(p.base, &failed, dead))
    }
}

async fn upload_tree(
    sftp: &Arc<SftpConn>,
    p: &mut Progress<'_>,
    local: &str,
    remote: &str,
    overwrite: Overwrite,
) -> Result<u64, SshError> {
    let is_dir = tokio::fs::metadata(local)
        .await
        .map(|m| m.is_dir())
        .unwrap_or(false);

    if !is_dir {
        p.tree = false;
        return copy_local_file(sftp, p, local, remote, overwrite).await;
    }
    p.tree = true;

    let mut failed: Vec<String> = Vec::new();
    let mut dead = false;
    const MAX_DIRS: usize = 50_000;
    let mut visited = 0usize;
    let mut dirs = vec![(local.to_string(), remote.to_string())];
    'walk: while let Some((ldir, rdir)) = dirs.pop() {
        if p.cancelled() {
            return Err(SshError::TransferCancelled);
        }
        visited += 1;
        let is_root = visited == 1;
        if visited > MAX_DIRS {
            let reason = format!(
                "directory limit ({MAX_DIRS}) reached — tree too large; remainder skipped"
            );
            // Empty paths: not retryable — a retry would re-run the whole tree.
            p.failure("(tree)", "", "", reason.clone());
            failed.push(reason);
            break;
        }
        // create_dir on an existing directory is an error over SFTP; ignore
        // it so re-uploading into a partially-present tree just works.
        match step(&p.cancel, sftp.hi.create_dir(rdir.clone())).await {
            Err(SshError::TransferCancelled) => return Err(SshError::TransferCancelled),
            Err(e) if sftp_dead(&e) => return Err(e),
            _ => {}
        }
        // An unreadable SUBdirectory (another user's 0700 dir, a macOS
        // TCC-protected folder) is one more failed item, not the end of the
        // whole tree; only the root failing is fatal.
        let dir_name = std::path::Path::new(&ldir)
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_else(|| ldir.clone());
        let mut rd = match tokio::fs::read_dir(&ldir).await {
            Ok(rd) => rd,
            Err(e) if is_root => return Err(e.into()),
            Err(e) => {
                p.failure(&dir_name, &ldir, &rdir, format!("{e}"));
                failed.push(format!("{ldir}: {e}"));
                continue;
            }
        };
        loop {
            let entry = match rd.next_entry().await {
                Ok(Some(entry)) => entry,
                Ok(None) => break,
                Err(e) => {
                    failed.push(format!("{ldir}: {e}"));
                    break;
                }
            };
            let name = entry.file_name().to_string_lossy().to_string();
            let lpath = entry.path().to_string_lossy().to_string();
            let rpath = format!("{}/{}", rdir.trim_end_matches('/'), name);
            let ft = match entry.file_type().await {
                Ok(ft) => ft,
                Err(e) => {
                    p.failure(&name, &lpath, &rpath, format!("{e}"));
                    failed.push(format!("{lpath}: {e}"));
                    continue;
                }
            };
            if ft.is_dir() {
                dirs.push((lpath, rpath));
            } else if ft.is_symlink() {
                // Empty local path: NOT retryable. A retry would open the
                // path as a plain file and upload whatever the link points
                // at (e.g. ~/.ssh/id_ed25519) — the very thing the walk
                // refused to do.
                p.failure(&name, "", &rpath, "symlink, skipped".into());
                failed.push(format!("{lpath} (symlink, skipped)"));
            } else {
                match copy_local_file(sftp, p, &lpath, &rpath, overwrite).await {
                    Ok(_) => {}
                    Err(SshError::TransferCancelled) => return Err(SshError::TransferCancelled),
                    Err(e) => {
                        p.failure(&name, &lpath, &rpath, format!("{e}"));
                        failed.push(format!("{lpath}: {e}"));
                        if sftp_dead(&e) {
                            failed.push("the SFTP session stopped responding; the rest was skipped".into());
                            dead = true;
                            break 'walk;
                        }
                    }
                }
            }
        }
    }
    p.finish_tree();
    if failed.is_empty() {
        Ok(p.base)
    } else {
        Err(partial_summary(p.base, &failed, dead))
    }
}

/* ------------------------------------------------------------ local names */

/// Reject a remote-supplied name that could escape the local target directory.
///
/// A malicious or compromised server controls the filenames it lists, and on
/// download those names become LOCAL path components. A name like
/// `..\Windows\evil` — or an absolute path, which `Path::join` uses to
/// REPLACE the base entirely — would write outside the folder the user chose.
/// This is the scp/zip-slip class; the defense is to accept only plain file
/// names as path components.
///
/// The Windows-only hazards are checked on Windows only: on macOS and Linux
/// `aux.c`, `con.h` or `report.` are ordinary, legal names.
fn safe_local_component(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains('\0')
        && !(cfg!(windows) && !windows_name_ok(name))
}

/// The Windows rules: no ':' (drive letters, alternate data streams), no
/// reserved device name, and no trailing '.' or ' ' — Win32 strips those, so
/// `report` and `report.` in one server tree would silently write one file.
fn windows_name_ok(name: &str) -> bool {
    !name.contains(':')
        && !is_windows_reserved(name)
        && !name.ends_with('.')
        && !name.ends_with(' ')
}

/// The longest file name (in bytes) the staging names below may produce.
const NAME_MAX: usize = 255;

/// A hidden staging name beside `name`: `.<name>.<tag><suffix>`, with `name`
/// shortened (at a character boundary) so the whole stays within `NAME_MAX`
/// bytes — a 250-byte file name must still transfer.
fn staging_name(name: &str, tag: &str, suffix: &str) -> String {
    let room = NAME_MAX.saturating_sub(2 + tag.len() + suffix.len());
    let mut end = name.len().min(room);
    while end > 0 && !name.is_char_boundary(end) {
        end -= 1;
    }
    format!(".{}.{tag}{suffix}", &name[..end])
}

const PART_SUFFIX: &str = ".hawserpart";
const BAK_SUFFIX: &str = ".hawserbak";

/// The remote sibling `dir/<staging name>` for `remote`.
fn remote_staging(remote: &str, suffix: &str) -> String {
    let (dir, name) = match remote.rfind('/') {
        Some(i) => (&remote[..=i], &remote[i + 1..]),
        None => ("", remote),
    };
    format!("{dir}{}", staging_name(name, &crate::utils::artifacts::random_hex(6), suffix))
}

/// Create a fresh local staging file beside `dest`: exclusive (an existing
/// file or a planted symlink at that name fails the create instead of being
/// followed), with a random name, and owner-only (0600) on Unix while it
/// streams. Created in the folder that will hold `dest`, so the commit is a
/// same-directory rename.
async fn create_local_staging(
    dest: &std::path::Path,
) -> Result<(std::path::PathBuf, tokio::fs::File), SshError> {
    let dir = match dest.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => std::path::PathBuf::from("."),
    };
    let name = dest
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let mut last_err = None;
    for _ in 0..8 {
        let tmp = dir.join(staging_name(&name, &crate::utils::artifacts::random_hex(6), PART_SUFFIX));
        let mut opts = tokio::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        opts.mode(0o600);
        match opts.open(&tmp).await {
            Ok(f) => return Ok((tmp, f)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => last_err = Some(e),
            Err(e) => return Err(e.into()),
        }
    }
    Err(last_err.map(SshError::from).unwrap_or_else(|| {
        SshError::PartialTransfer("could not create a staging file".into())
    }))
}

/* ------------------------------------------------------- download commit */

/// What `CommitFs::kind` sees at a path (without following a link).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalKind {
    File,
    Dir,
    /// A symlink, junction, device…: never moved aside or replaced.
    Other,
}

/// The file operations `commit_download` uses, so tests can fail any one.
trait CommitFs {
    fn rename(&self, from: &std::path::Path, to: &std::path::Path) -> std::io::Result<()>;
    fn rename_noreplace(&self, from: &std::path::Path, to: &std::path::Path) -> std::io::Result<()>;
    fn hard_link(&self, from: &std::path::Path, to: &std::path::Path) -> std::io::Result<()>;
    fn remove(&self, p: &std::path::Path) -> std::io::Result<()>;
    fn kind(&self, p: &std::path::Path) -> Option<LocalKind>;
}

struct RealFs;

impl CommitFs for RealFs {
    fn rename(&self, from: &std::path::Path, to: &std::path::Path) -> std::io::Result<()> {
        std::fs::rename(from, to)
    }
    fn rename_noreplace(&self, from: &std::path::Path, to: &std::path::Path) -> std::io::Result<()> {
        crate::utils::artifacts::rename_noreplace(from, to)
    }
    fn hard_link(&self, from: &std::path::Path, to: &std::path::Path) -> std::io::Result<()> {
        std::fs::hard_link(from, to)
    }
    fn remove(&self, p: &std::path::Path) -> std::io::Result<()> {
        std::fs::remove_file(p)
    }
    fn kind(&self, p: &std::path::Path) -> Option<LocalKind> {
        let m = std::fs::symlink_metadata(p).ok()?;
        Some(if is_link_or_reparse(&m) {
            LocalKind::Other
        } else if m.is_dir() {
            LocalKind::Dir
        } else if m.is_file() {
            LocalKind::File
        } else {
            LocalKind::Other
        })
    }
}

/// Put `from` at `to` only if nothing is there, atomically: a no-replace
/// rename, or where the filesystem has none (an old kernel, some network
/// shares) a hard link — which cannot replace either — and then dropping the
/// old name. `AlreadyExists` if something is at `to`; `Unsupported` if this
/// filesystem offers neither. Never a check followed by a replacing rename.
fn place_noreplace(fs: &dyn CommitFs, from: &std::path::Path, to: &std::path::Path) -> std::io::Result<()> {
    use std::io::ErrorKind;
    let e1 = match fs.rename_noreplace(from, to) {
        Ok(()) => return Ok(()),
        Err(e) if e.kind() == ErrorKind::AlreadyExists => return Err(e),
        Err(e) => e,
    };
    match fs.hard_link(from, to) {
        Ok(()) => {
            // The content is at `to`; a leftover second name is harmless.
            let _ = fs.remove(from);
            Ok(())
        }
        Err(e) if e.kind() == ErrorKind::AlreadyExists => Err(e),
        Err(e2) => Err(std::io::Error::new(ErrorKind::Unsupported, format!("{e1}; {e2}"))),
    }
}

/// Move a finished download from its staging file `tmp` to `dest`. On
/// success, an optional note for the user (a backup that could not be
/// removed).
///
/// Never destroys both copies: on every failure either the original is still
/// at `dest` or the error says where it went, and the downloaded copy stays at
/// `tmp` (named in the error) unless the policy refused it.
///
/// - `replace == false`: placed with `place_noreplace`. A file at `dest` (even
///   one created after the user was asked) is never clobbered; the staged
///   copy is then removed. A filesystem with no atomic no-replace fails the
///   download instead (choose Replace there).
/// - `replace == true`: an atomic rename over `dest`. If the platform refuses
///   (Windows: something holds the file open), the original — if it is still
///   a regular file — is moved aside to `bak`, the new copy put in place
///   (never over something that appeared meanwhile), and the backup dropped;
///   if putting the new copy in place fails, the original is moved back, never
///   over anything either, or both copies are kept and named.
fn commit_download(
    fs: &dyn CommitFs,
    tmp: &std::path::Path,
    dest: &std::path::Path,
    bak: &std::path::Path,
    replace: bool,
) -> Result<Option<String>, String> {
    use std::io::ErrorKind;
    let (t, d, b) = (tmp.display(), dest.display(), bak.display());
    if !replace {
        return match place_noreplace(fs, tmp, dest) {
            Ok(()) => Ok(None),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                let _ = fs.remove(tmp);
                Err(format!("{d} already exists; not overwriting it"))
            }
            Err(e) => Err(format!(
                "this folder's filesystem cannot add a file without possibly overwriting one ({e}), \
                 so Hawser can't guarantee {d} is not overwritten; choose Replace to download \
                 anyway. The downloaded copy was kept at {t}"
            )),
        };
    }
    let e1 = match fs.rename(tmp, dest) {
        Ok(()) => return Ok(None),
        Err(e) => e,
    };
    // Checked again right before the move-aside: only a regular file is ever
    // moved aside (a folder or link that appeared during the copy is not).
    match fs.kind(dest) {
        None => {
            return Err(format!(
                "could not move the download into place ({e1}); the downloaded copy was kept at {t}"
            ))
        }
        Some(LocalKind::File) => {}
        Some(_) => {
            return Err(format!(
                "{d} is no longer a regular file; not replacing it ({e1}). The downloaded copy \
                 was kept at {t}"
            ))
        }
    }
    if let Err(e2) = fs.rename_noreplace(dest, bak).or_else(|e| {
        if e.kind() == ErrorKind::AlreadyExists {
            Err(e)
        } else {
            fs.rename(dest, bak)
        }
    }) {
        return Err(format!(
            "could not replace {d} ({e1}; moving it aside failed: {e2}); the original is \
             untouched and the downloaded copy was kept at {t}"
        ));
    }
    // Something swapped in between the check and the move: put it back.
    if fs.kind(bak) != Some(LocalKind::File) {
        return match place_noreplace(fs, bak, dest) {
            Ok(()) => Err(format!(
                "{d} changed while it was being replaced; it was left as it was and the \
                 downloaded copy kept at {t}"
            )),
            Err(e) => Err(format!(
                "{d} changed while it was being replaced and could not be put back ({e}): it \
                 is at {b}, and the downloaded copy at {t}"
            )),
        };
    }
    let installed = match place_noreplace(fs, tmp, dest) {
        Err(e) if e.kind() == ErrorKind::Unsupported => fs.rename(tmp, dest),
        r => r,
    };
    match installed {
        Ok(()) => match fs.remove(bak) {
            Ok(()) => Ok(None),
            Err(e) => Ok(Some(format!(
                "{d} was replaced, but its previous version could not be removed ({e}) and was \
                 left at {b}"
            ))),
        },
        Err(e3) => match place_noreplace(fs, bak, dest) {
            Ok(()) => Err(format!(
                "could not replace {d} ({e3}); the original was restored and the downloaded \
                 copy was kept at {t}"
            )),
            Err(e4) => Err(format!(
                "could not replace {d} ({e3}) or restore it without overwriting anything ({e4}): \
                 the original is at {b} and the downloaded copy at {t}"
            )),
        },
    }
}

/* ---------------------------------------------------------- file copies */

/// Copy one remote file to a local path, streaming with progress.
async fn copy_remote_file(
    sftp: &Arc<SftpConn>,
    p: &mut Progress<'_>,
    remote: &str,
    local: &str,
    overwrite: Overwrite,
) -> Result<u64, SshError> {
    // Never write THROUGH an existing symlink at the destination: a
    // server-controlled tree must not use a pre-placed link to redirect a
    // download outside the folder the user chose.
    let existing = tokio::fs::symlink_metadata(local).await.ok();
    if let Some(meta) = existing.as_ref() {
        if meta.file_type().is_symlink() {
            return Err(SshError::PartialTransfer(format!(
                "refusing to overwrite a symlink: {local}"
            )));
        }
        if meta.is_dir() {
            return Err(SshError::PartialTransfer(format!(
                "{local} is a folder here; refusing to replace it with a file"
            )));
        }
        if !overwrite.allows_replace() {
            return Err(already_exists(local));
        }
    }

    let rmeta = step(&p.cancel, sftp.hi.metadata(remote)).await.ok();
    let total = rmeta.as_ref().and_then(|m| m.size).unwrap_or(0);
    let mut src = step(&p.cancel, sftp.hi.open(remote)).await?;

    // Stream to a fresh staging file beside the destination, then commit it
    // with a rename. A failed, cancelled or interrupted transfer therefore
    // never destroys the existing file or leaves a truncated partial in its
    // place.
    let dest = std::path::PathBuf::from(local);
    let staged = create_local_staging(&dest).await;
    let (tmp, mut dst) = match staged {
        Ok(s) => s,
        Err(e) => {
            let _ = src.close().await;
            return Err(e);
        }
    };
    p.start_file(remote, total);
    let copy_result: Result<u64, SshError> = async {
        let mut buf = vec![0u8; CHUNK];
        let mut done = 0u64;
        loop {
            let n = step(&p.cancel, src.read(&mut buf)).await?;
            if n == 0 {
                break;
            }
            step(&p.cancel, dst.write_all(&buf[..n])).await?;
            done += n as u64;
            p.tick(done);
        }
        step(&p.cancel, dst.flush()).await?;
        Ok(done)
    }
    .await;
    drop(dst);

    // Close the remote read handle explicitly. Dropping the SFTP `File` does NOT
    // send SSH_FXP_CLOSE, so a recursive download of a large tree would leak one
    // server-side handle per file and eventually exhaust the server's limit.
    // Best-effort and bounded: a close failure must not fail an otherwise-
    // complete transfer.
    let _ = tokio::time::timeout(stall_timeout(), src.close()).await;

    let done = match copy_result {
        Ok(done) => done,
        Err(e) => {
            // Leave the original untouched; drop the partial staging file.
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(e);
        }
    };

    // The staging file is 0600 while it streams. It ends with the mode of
    // the file it replaces (a 0600 secret stays 0600), or for a new file the
    // remote file's permission bits (setuid/setgid/sticky dropped), as `scp
    // -p` would. Unix only: Windows has no POSIX mode.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = existing
            .as_ref()
            .filter(|m| m.is_file())
            .map(|m| m.permissions().mode() & 0o7777)
            .or_else(|| rmeta.as_ref().and_then(|m| m.permissions).map(|m| m & 0o777))
            .unwrap_or(0o644);
        let _ = tokio::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode)).await;
    }

    // Last point a cancel applies (a cancel that came during the close or the
    // chmod above): the commit below is not interrupted.
    if p.cancelled() {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(SshError::TransferCancelled);
    }

    let bak = dest.with_file_name(staging_name(
        &dest.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default(),
        &crate::utils::artifacts::random_hex(6),
        BAK_SUFFIX,
    ));
    let replace = overwrite.allows_replace();
    let (t2, d2) = (tmp.clone(), dest.clone());
    let committed = tokio::task::spawn_blocking(move || commit_download(&RealFs, &t2, &d2, &bak, replace))
        .await
        .map_err(|e| SshError::PartialTransfer(format!("download commit failed: {e}")))?;
    if let Some(note) = committed.map_err(SshError::PartialTransfer)? {
        p.note(note);
    }
    p.finish_file(done);
    Ok(done)
}

/// The local file's permission bits, for a new remote file. Unix only — the
/// Windows metadata carries no POSIX mode.
fn local_mode(meta: Option<&std::fs::Metadata>) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.map(|m| m.permissions().mode() & 0o777)
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        None
    }
}

/// What is at an upload's destination before it starts.
enum RemoteDest {
    Missing,
    /// STAT was refused (write-only drop boxes): it may or may not exist.
    Unknown,
    File(russh_sftp::protocol::FileAttributes),
}

/// How a staged upload's commit ended.
enum UploadCommit {
    /// In place, with an optional note (a backup left behind).
    Done(Option<String>),
    /// The server would not rename the staged copy into place, and the
    /// original (if any) is still at the destination: write in place instead.
    /// The complete staged copy is still at its staging name.
    InPlace,
}

/// Stream the local file into an already-open remote handle.
async fn stream_up(
    p: &mut Progress<'_>,
    src: &mut tokio::fs::File,
    dst: &mut russh_sftp::client::fs::File,
) -> Result<u64, SshError> {
    let mut buf = vec![0u8; CHUNK];
    let mut done = 0u64;
    loop {
        let n = step(&p.cancel, src.read(&mut buf)).await?;
        if n == 0 {
            break;
        }
        step(&p.cancel, dst.write_all(&buf[..n])).await?;
        done += n as u64;
        p.tick(done);
    }
    Ok(done)
}

/// Copy one local file to a remote path, streaming with progress.
///
/// The normal path writes a hidden staging file beside the destination and
/// renames it into place (`posix-rename@openssh.com` when the server has it:
/// an atomic replace with no moment where the file is missing). Two fallbacks
/// write the destination IN PLACE, non-atomically, with a note to the user:
/// the folder is not writable (only the file is), or the server will not
/// rename. In place keeps the file's owner, ACLs and hard links; the price is
/// that an interrupted transfer leaves it truncated.
async fn copy_local_file(
    sftp: &Arc<SftpConn>,
    p: &mut Progress<'_>,
    local: &str,
    remote: &str,
    overwrite: Overwrite,
) -> Result<u64, SshError> {
    use russh_sftp::protocol::{FileAttributes, OpenFlags};
    let local_meta = tokio::fs::metadata(local).await.ok();
    let total = local_meta.as_ref().map(|m| m.len()).unwrap_or(0);

    // What is there now. LSTAT, so a symlink is seen as one: renaming over a
    // link would replace the LINK with a plain file and never update what it
    // points at. Only a definite "no such file" means new; a refused STAT
    // (write-only drop boxes: SFTPGo upload-only users, ProFTPD <Limit READ>,
    // appliances answering a generic failure) leaves it UNKNOWN: still upload,
    // but never replace. Any other failure aborts.
    let lstat = step(&p.cancel, sftp.hi.symlink_metadata(remote)).await;
    let classify = |r: Result<FileAttributes, SshError>, path: &str| -> Result<RemoteDest, SshError> {
        match r {
            Ok(m) if m.file_type().is_dir() => Err(SshError::PartialTransfer(format!(
                "{path} is a directory on the server; refusing to replace it with a file"
            ))),
            Ok(m) => Ok(RemoteDest::File(m)),
            Err(SshError::Sftp(e)) => match sftp_status(&e) {
                Some(StatusCode::NoSuchFile) => Ok(RemoteDest::Missing),
                Some(StatusCode::PermissionDenied | StatusCode::Failure | StatusCode::OpUnsupported) => {
                    Ok(RemoteDest::Unknown)
                }
                _ => Err(SshError::PartialTransfer(format!(
                    "could not check whether {path} already exists ({e}); not overwriting it"
                ))),
            },
            Err(e) => Err(e),
        }
    };
    let (target, dest) = match lstat {
        Ok(m) if m.file_type().is_symlink() => {
            // Write THROUGH the link, as `cp` does — but only with the user's
            // say-so: the frontend asked about this name (a link, even a
            // dangling one, counts as existing).
            if !overwrite.allows_replace() {
                return Err(already_exists(remote));
            }
            let real = step(&p.cancel, sftp.hi.canonicalize(remote)).await.map_err(|e| {
                SshError::PartialTransfer(format!(
                    "{remote} is a symlink whose target could not be resolved ({e}); not \
                     replacing it"
                ))
            })?;
            let dest = classify(step(&p.cancel, sftp.hi.metadata(real.clone())).await, &real)?;
            if matches!(dest, RemoteDest::Missing) {
                return Err(SshError::PartialTransfer(format!(
                    "{remote} is a symlink to {real}, which does not exist; not replacing it"
                )));
            }
            p.note(format!("{remote} is a symlink: wrote through it to {real}"));
            (real, dest)
        }
        other => (remote.to_string(), classify(other, remote)?),
    };
    if matches!(dest, RemoteDest::File(_)) && !overwrite.allows_replace() {
        return Err(already_exists(&target));
    }
    let replace = matches!(dest, RemoteDest::File(_)) && overwrite.allows_replace();

    // The rename replaces the remote inode, so its mode must be carried over
    // explicitly: an overwritten file keeps its own permissions (a 0600 secret
    // must not become 0644, a deploy script must keep +x); a new file takes the
    // local file's mode where the platform has one; an unknown destination
    // takes the server's default.
    let (mode, preserve_required) = match &dest {
        RemoteDest::File(m) => (m.permissions.map(|p| p & 0o7777), m.permissions.is_some()),
        RemoteDest::Missing => (local_mode(local_meta.as_ref()), false),
        RemoteDest::Unknown => (None, false),
    };

    // Never: a commit by plain RENAME is only no-clobber on a server whose
    // RENAME refuses an existing target. Found out before any byte moves (and
    // checked again at the commit).
    if !replace && rename_replaces(sftp, &target).await == Some(true) {
        return Err(cannot_guarantee_noclobber(&target));
    }

    let mut src = tokio::fs::File::open(local).await?;
    p.start_file(local, total);

    // Stage. EXCLUDE: never open something already at the staging name.
    let tmp = remote_staging(&target, PART_SUFFIX);
    let attrs = FileAttributes { permissions: mode, ..Default::default() };
    let opened = step(
        &p.cancel,
        sftp.hi.open_with_flags_and_attributes(
            tmp.clone(),
            OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE,
            attrs,
        ),
    )
    .await;
    let mut dst = match opened {
        Ok(f) => f,
        Err(SshError::Sftp(e)) if sftp_status(&e) == Some(StatusCode::PermissionDenied) => {
            // The folder is not writable, only (perhaps) the file.
            let why = "the folder is not writable";
            p.note(in_place_warning(&target, why));
            let done = write_in_place(sftp, p, &mut src, &target, replace, mode)
                .await
                .map_err(|e| in_place_failed(&target, why, e, None))?;
            p.finish_file(done);
            return Ok(done);
        }
        Err(e) => {
            // No status reply (a cancel, a stall): the server may have created
            // the staging file before the answer was given up on.
            if !matches!(&e, SshError::Sftp(russh_sftp::client::error::Error::Status(_))) {
                remove_remote_quietly(sftp, &tmp).await;
            }
            return Err(e);
        }
    };

    let staged: Result<u64, SshError> = async {
        let done = stream_up(p, &mut src, &mut dst).await?;
        if let Some(m) = mode {
            let set = step(
                &p.cancel,
                dst.set_metadata(FileAttributes { permissions: Some(m), ..Default::default() }),
            )
            .await;
            // FSETSTAT may be denied or unsupported. Retry by path (SETSTAT; the
            // staging file is our own), then accept it if the permission bits
            // match. Otherwise, for an overwrite, fail BEFORE the rename so the
            // original (and its permissions) stays. Special bits are not
            // compared: servers/kernels routinely strip setuid/setgid.
            if set.is_err() && preserve_required {
                let _ = step(
                    &p.cancel,
                    sftp.hi.set_metadata(
                        tmp.clone(),
                        FileAttributes { permissions: Some(m), ..Default::default() },
                    ),
                )
                .await;
                let actual = step(&p.cancel, sftp.hi.metadata(tmp.clone()))
                    .await
                    .ok()
                    .and_then(|md| md.permissions)
                    .map(|p| p & 0o777);
                if actual != Some(m & 0o777) {
                    return Err(SshError::PartialTransfer(format!(
                        "could not preserve the permissions ({m:o}) of {target}; left it unchanged"
                    )));
                }
            }
        }
        // shutdown (not just flush) closes the remote handle, which must happen
        // before the rename and also avoids leaking the SFTP handle.
        step(&p.cancel, dst.shutdown()).await?;
        // The last point a cancel applies: the commit below runs to its end.
        if p.cancelled() {
            return Err(SshError::TransferCancelled);
        }
        Ok(done)
    }
    .await;

    let done = match staged {
        Ok(done) => done,
        Err(e) => {
            // Close explicitly so it completes before the staging file is
            // removed (some servers cannot delete an open file). Leave the
            // original untouched; drop the partial staging file. Bounded, and
            // run even after a cancel: the connection is still up.
            let _ = tokio::time::timeout(stall_timeout(), dst.shutdown()).await;
            remove_remote_quietly(sftp, &tmp).await;
            return Err(e);
        }
    };

    // Replacing: what is at the destination now must still be what the user
    // agreed to replace. A link or folder that took its place during the copy
    // is neither replaced nor followed.
    if replace {
        match step(&uncancellable(), sftp.hi.symlink_metadata(target.clone())).await {
            Ok(m) if m.file_type().is_symlink() || m.file_type().is_dir() => {
                remove_remote_quietly(sftp, &tmp).await;
                return Err(SshError::PartialTransfer(format!(
                    "{target} became a {} during the upload; not replacing it",
                    if m.file_type().is_dir() { "directory" } else { "symlink" }
                )));
            }
            _ => {}
        }
    }

    // The commit runs as its own task: neither a cancel nor the caller going
    // away can stop it halfway (with the original moved aside).
    let commit = {
        let (sftp, tmp, target) = (Arc::clone(sftp), tmp.clone(), target.clone());
        shielded(async move { commit_upload(&sftp, &tmp, &target, replace).await }).await?
    };
    match commit? {
        UploadCommit::Done(note) => {
            if let Some(note) = note {
                p.note(note);
            }
            p.finish_file(done);
            Ok(done)
        }
        UploadCommit::InPlace => {
            // The complete upload stays at `tmp` until the in-place write has
            // fully succeeded.
            let why = "the server would not rename the uploaded copy into place";
            p.note(in_place_warning(&target, why));
            use tokio::io::AsyncSeekExt;
            step(&p.cancel, src.seek(std::io::SeekFrom::Start(0)))
                .await
                .map_err(|e| in_place_failed(&target, why, e, Some(&tmp)))?;
            p.start_file(local, total);
            let done = write_in_place(sftp, p, &mut src, &target, replace, mode)
                .await
                .map_err(|e| in_place_failed(&target, why, e, Some(&tmp)))?;
            if step(&uncancellable(), sftp.hi.remove_file(tmp.clone())).await.is_err() {
                p.note(format!("{target}: the uploaded copy staged at {tmp} could not be removed"));
            }
            p.finish_file(done);
            Ok(done)
        }
    }
}

/// The note given BEFORE an in-place write starts.
fn in_place_warning(target: &str, why: &str) -> String {
    format!(
        "{target}: {why}, so the file is written in place (not atomic: an interrupted \
         transfer leaves it incomplete)"
    )
}

/// An in-place write that failed: say the file may be incomplete, and where
/// the complete upload is if one was staged.
fn in_place_failed(target: &str, why: &str, e: SshError, staged: Option<&str>) -> SshError {
    let kept = staged
        .map(|t| format!("; the complete upload is kept on the server at {t}"))
        .unwrap_or_default();
    SshError::PartialTransfer(format!(
        "{target} was being written in place ({why}) and may be incomplete: {e}{kept}"
    ))
}

fn cannot_guarantee_noclobber(target: &str) -> SshError {
    SshError::PartialTransfer(format!(
        "this server's rename replaces existing files, so Hawser can't guarantee {target} is \
         not overwritten; choose Replace to upload anyway"
    ))
}

/// The folder part of a remote path, with its trailing '/' ("" for a bare
/// name).
fn remote_parent(path: &str) -> &str {
    match path.rfind('/') {
        Some(i) => &path[..=i],
        None => "",
    }
}

const PROBE_SUFFIX: &str = ".hawserprobe";

/// Whether this server's plain RENAME replaces an existing target, found once
/// per session: create two scratch files beside `target` and RENAME one onto
/// the other. SFTPv3 says RENAME refuses an existing target (OpenSSH links,
/// then unlinks); some servers replace instead, and on those a plain RENAME is
/// no "never overwrite" commit. `None`: it could not be found out (the folder
/// is not writable, the channel failed); not remembered.
async fn rename_replaces(sftp: &SftpConn, target: &str) -> Option<bool> {
    use russh_sftp::protocol::{FileAttributes, OpenFlags};
    if let Some(v) = *sftp.rename_replaces.lock().unwrap_or_else(|p| p.into_inner()) {
        return Some(v);
    }
    let never = uncancellable();
    let stem = format!("{}hawser", remote_parent(target));
    let (a, b) = (remote_staging(&stem, PROBE_SUFFIX), remote_staging(&stem, PROBE_SUFFIX));
    let mut made = Vec::new();
    for path in [&a, &b] {
        let created = step(
            &never,
            sftp.hi.open_with_flags_and_attributes(
                path.clone(),
                OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE,
                FileAttributes::default(),
            ),
        )
        .await;
        match created {
            Ok(mut f) => {
                let _ = step(&never, f.shutdown()).await;
                made.push(path.clone());
            }
            Err(_) => {
                for m in &made {
                    remove_remote_quietly(sftp, m).await;
                }
                return None;
            }
        }
    }
    let verdict = match step(&never, sftp.hi.rename(a.clone(), b.clone())).await {
        Ok(()) => Some(true),
        Err(e) if sftp_dead(&e) => None,
        Err(_) => Some(false),
    };
    if verdict != Some(true) {
        remove_remote_quietly(sftp, &a).await;
    }
    remove_remote_quietly(sftp, &b).await;
    if let Some(v) = verdict {
        *sftp.rename_replaces.lock().unwrap_or_else(|p| p.into_inner()) = Some(v);
    }
    verdict
}

/// After an install rename whose reply never came (`e`): it happened if the
/// staged copy is gone.
async fn after_lost_install(
    sftp: &SftpConn,
    tmp: &str,
    target: &str,
    e: SshError,
) -> Result<UploadCommit, SshError> {
    match remote_present(sftp, tmp).await {
        Ok(false) => Ok(UploadCommit::Done(None)),
        Ok(true) => {
            remove_remote_quietly(sftp, tmp).await;
            Err(e)
        }
        Err(_) => Err(SshError::PartialTransfer(format!(
            "the connection failed while putting the upload in place ({e}); {target} holds \
             either its old or its new version, and if not the new one, the new copy is at {tmp}"
        ))),
    }
}

/// Drop the backup of a replaced file; a note if it could not be.
async fn remove_backup(sftp: &SftpConn, bak: &str, target: &str) -> Option<String> {
    match step(&uncancellable(), sftp.hi.remove_file(bak)).await {
        Ok(()) => None,
        Err(e) => Some(format!(
            "{target} was replaced, but its previous version could not be removed ({e}) and was \
             left at {bak}"
        )),
    }
}

/// Put a staged upload at `target`. See `copy_local_file`, which runs this as
/// a shielded task: none of its steps can be cancelled.
///
/// - `replace == false`: a plain RENAME, on a server whose RENAME refuses an
///   existing target (`rename_replaces`), so a file that appeared since the
///   check is never replaced. A server that replaces, or one that cannot be
///   probed, fails the upload: no check-then-rename.
/// - `replace == true`: `posix-rename@openssh.com` (atomic replace) where
///   offered; else a RENAME (which replaces on some servers); else the
///   original is moved ASIDE (never deleted), the new copy put in place and
///   the backup dropped. Every error after the move-aside names the backup.
///   The original is moved back only by a RENAME known to refuse an existing
///   target; otherwise both copies are kept and named.
///
/// A step whose reply is lost (the channel stalled or died) is followed by a
/// look at the server to learn whether it happened. The staging file is
/// removed on failure unless the error names it; on `InPlace` it is kept.
async fn commit_upload(sftp: &SftpConn, tmp: &str, target: &str, replace: bool) -> Result<UploadCommit, SshError> {
    let never = uncancellable();
    if !replace {
        match rename_replaces(sftp, target).await {
            Some(false) => {}
            Some(true) => {
                remove_remote_quietly(sftp, tmp).await;
                return Err(cannot_guarantee_noclobber(target));
            }
            None => {
                remove_remote_quietly(sftp, tmp).await;
                return Err(SshError::PartialTransfer(format!(
                    "could not check whether this server's rename overwrites existing files, so \
                     Hawser can't guarantee {target} is not overwritten; choose Replace to \
                     upload anyway"
                )));
            }
        }
        return match step(&never, sftp.hi.rename(tmp, target)).await {
            Ok(()) => Ok(UploadCommit::Done(None)),
            Err(e) if sftp_dead(&e) => after_lost_install(sftp, tmp, target, e).await,
            Err(_) => match remote_present(sftp, target).await {
                Ok(true) => {
                    remove_remote_quietly(sftp, tmp).await;
                    Err(already_exists(target))
                }
                Ok(false) => Ok(UploadCommit::InPlace),
                Err(e) => {
                    remove_remote_quietly(sftp, tmp).await;
                    Err(e)
                }
            },
        };
    }
    if sftp.posix_rename {
        match step(&never, posix_rename(&sftp.raw, tmp, target)).await {
            Ok(()) => return Ok(UploadCommit::Done(None)),
            Err(e) if sftp_dead(&e) => return after_lost_install(sftp, tmp, target, e).await,
            // Refused (a policy, a filesystem quirk): try the portable way.
            Err(_) => {}
        }
    }
    // Some servers' RENAME does replace.
    match step(&never, sftp.hi.rename(tmp, target)).await {
        Ok(()) => return Ok(UploadCommit::Done(None)),
        Err(e) if sftp_dead(&e) => return after_lost_install(sftp, tmp, target, e).await,
        Err(_) => {}
    }
    // Move the original ASIDE (never delete it) before putting the new one in
    // place, so a second failure or a dropped connection cannot destroy it
    // with nothing to recover.
    let bak = remote_staging(target, BAK_SUFFIX);
    match step(&never, sftp.hi.rename(target, bak.clone())).await {
        Ok(()) => {}
        Err(e) if sftp_dead(&e) => match remote_present(sftp, &bak).await {
            // The reply was lost, but the move happened: carry on.
            Ok(true) => {}
            Ok(false) => {
                remove_remote_quietly(sftp, tmp).await;
                return Err(e);
            }
            Err(_) => {
                return Err(SshError::PartialTransfer(format!(
                    "the connection failed while moving {target} aside ({e}): if {target} is \
                     missing, the original is at {bak}; the new copy is at {tmp}"
                )))
            }
        },
        // Cannot even move the original: the server does not rename here.
        Err(_) => return Ok(UploadCommit::InPlace),
    }
    // The original is at `bak`: every error from here names it.
    let e = match step(&never, sftp.hi.rename(tmp, target)).await {
        Ok(()) => return Ok(UploadCommit::Done(remove_backup(sftp, &bak, target).await)),
        Err(e) => e,
    };
    if sftp_dead(&e) && matches!(remote_present(sftp, tmp).await, Ok(false)) {
        // The reply was lost, but the new copy went in.
        return Ok(UploadCommit::Done(remove_backup(sftp, &bak, target).await));
    }
    if rename_replaces(sftp, target).await != Some(false) {
        return Err(SshError::PartialTransfer(format!(
            "could not put the upload in place ({e}), and this server's rename may overwrite, so \
             the original was not moved back automatically: it is at {bak}, and the new copy \
             at {tmp}"
        )));
    }
    match step(&never, sftp.hi.rename(bak.clone(), target)).await {
        Ok(()) if !sftp_dead(&e) => Ok(UploadCommit::InPlace),
        Ok(()) => {
            remove_remote_quietly(sftp, tmp).await;
            Err(SshError::PartialTransfer(format!(
                "could not put the upload in place ({e}); the original {target} was restored"
            )))
        }
        Err(e2) => Err(SshError::PartialTransfer(format!(
            "could not replace {target} ({e}) or restore it ({e2}): the original is at {bak}, \
             and the new copy at {tmp}"
        ))),
    }
}

/// The non-atomic fallback: write `target` itself. `replace` truncates an
/// existing regular file (re-checked first: a link is never followed, a
/// folder never touched); otherwise the create is exclusive, so an existing
/// file is never touched, and a failed write removes the file it created.
async fn write_in_place(
    sftp: &SftpConn,
    p: &mut Progress<'_>,
    src: &mut tokio::fs::File,
    target: &str,
    replace: bool,
    mode: Option<u32>,
) -> Result<u64, SshError> {
    use russh_sftp::protocol::{FileAttributes, OpenFlags};
    let (flags, attrs) = if replace {
        match step(&p.cancel, sftp.hi.symlink_metadata(target)).await {
            Ok(m) if m.file_type().is_symlink() || m.file_type().is_dir() => {
                return Err(SshError::PartialTransfer(format!(
                    "{target} is now a {}; not writing into it",
                    if m.file_type().is_dir() { "directory" } else { "symlink" }
                )));
            }
            _ => {}
        }
        // An existing file keeps its own mode, owner and ACLs.
        (OpenFlags::WRITE | OpenFlags::TRUNCATE, FileAttributes::default())
    } else {
        (
            OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE,
            FileAttributes { permissions: mode, ..Default::default() },
        )
    };
    let mut dst = match step(&p.cancel, sftp.hi.open_with_flags_and_attributes(target, flags, attrs)).await {
        Ok(f) => f,
        Err(SshError::Sftp(e))
            if !replace && sftp_status(&e) == Some(StatusCode::Failure) =>
        {
            // OpenSSH reports EEXIST on an exclusive create as a generic
            // failure; say what it most likely means.
            return Err(SshError::PartialTransfer(format!(
                "could not create {target} ({e}); it may already exist, so it was not overwritten"
            )));
        }
        Err(e) => return Err(e),
    };
    let r = stream_up(p, src, &mut dst).await;
    let closed = step(&uncancellable(), dst.shutdown()).await;
    let r = r.and_then(|done| closed.map(|_| done));
    if r.is_err() && !replace {
        // Ours (the create was exclusive) and incomplete.
        remove_remote_quietly(sftp, target).await;
    }
    r
}

/// One SOCKS5 CONNECT conversation, then a bidirectional pump.
async fn socks5_serve(
    session: Arc<Session>,
    mut tcp: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
) -> Result<(), SshError> {
    use tokio::io::AsyncReadExt as _;
    use tokio::io::AsyncWriteExt as _;

    // Greeting: VER, NMETHODS, methods[...]. Reply: no-auth (0x00).
    let mut head = [0u8; 2];
    tcp.read_exact(&mut head).await?;
    if head[0] != 5 {
        return Ok(()); // not SOCKS5; drop silently
    }
    let mut methods = vec![0u8; head[1] as usize];
    tcp.read_exact(&mut methods).await?;
    tcp.write_all(&[5, 0]).await?;

    // Request: VER, CMD, RSV, ATYP, addr..., port.
    let mut req = [0u8; 4];
    tcp.read_exact(&mut req).await?;
    let host = match req[3] {
        1 => {
            let mut b = [0u8; 4];
            tcp.read_exact(&mut b).await?;
            std::net::Ipv4Addr::from(b).to_string()
        }
        3 => {
            let mut len = [0u8; 1];
            tcp.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            tcp.read_exact(&mut name).await?;
            String::from_utf8_lossy(&name).to_string()
        }
        4 => {
            let mut b = [0u8; 16];
            tcp.read_exact(&mut b).await?;
            std::net::Ipv6Addr::from(b).to_string()
        }
        _ => {
            // Address type not supported.
            let _ = tcp.write_all(&[5, 8, 0, 1, 0, 0, 0, 0, 0, 0]).await;
            return Ok(());
        }
    };
    let mut pb = [0u8; 2];
    tcp.read_exact(&mut pb).await?;
    let port = u16::from_be_bytes(pb);

    if req[1] != 1 {
        // Only CONNECT; refuse BIND/UDP with "command not supported".
        let _ = tcp.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await;
        return Ok(());
    }

    match session
        .handle
        .channel_open_direct_tcpip(host, port as u32, peer.ip().to_string(), peer.port() as u32)
        .await
    {
        Ok(channel) => {
            tcp.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            let mut stream = channel.into_stream();
            let _ = tokio::io::copy_bidirectional(&mut tcp, &mut stream).await;
        }
        Err(_) => {
            // Host unreachable from the remote side.
            let _ = tcp.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0]).await;
        }
    }
    Ok(())
}

/// The shell's output pump: emits on the per-session topic TerminalPane
/// subscribes to, appends to the transcript, and — when the shell or the
/// transport ends — reports why and ends this session generation (its forwards
/// and its transport), so nothing keeps tunnelling over a session the tab shows
/// as disconnected. stderr (ExtendedData) is interleaved into the same stream,
/// which is what a real terminal does — separating it would reorder output.
///
/// Waits for `go` before emitting anything: see `connect_inner`.
#[allow(clippy::too_many_arguments)]
async fn run_pump(
    app: AppHandle,
    sid: String,
    session: Arc<Session>,
    mut read_half: russh::ChannelReadHalf,
    early: Vec<ChannelMsg>,
    go: oneshot::Receiver<Option<SessionLog>>,
    death: DeathNote,
    forwards: Arc<DashMap<String, Forward>>,
    startup: Vec<String>,
    startup_guard: Option<ShellGuard>,
) {
    let Ok(mut log) = go.await else { return };
    let topic = format!("ssh://{sid}");
    // Startup input goes out concurrently with this loop, never before it:
    // see `send_startup`. Aborted with the pump (the guard's drop), so it
    // never outlives the session's reader.
    let _startup = startup_guard.map(|guard| {
        let session = Arc::clone(&session);
        let (app, topic) = (app.clone(), topic.clone());
        AbortOnDrop(tokio::spawn(async move {
            let report = |e: &SshError| {
                if session.alive.load(Ordering::SeqCst) {
                    let _ = app.emit(
                        &topic,
                        format!("\x1b[38;2;242;178;92mstartup commands not sent: {e}\x1b[0m\r\n"),
                    );
                }
            };
            let _ = send_startup(guard, &startup, CHANNEL_SETUP_TIMEOUT, report).await;
        }))
    });
    // Incomplete UTF-8 tails carried to the next chunk, one per stream: a
    // packet boundary can split a multi-byte character, and decoding each chunk
    // alone would print two U+FFFD for one real character.
    let mut pending_out: Vec<u8> = Vec::new();
    let mut pending_err: Vec<u8> = Vec::new();
    let mut early = early.into_iter();
    let mut eof = false;
    let mut exit: Option<String> = None;
    let mut transport_gone = false;

    loop {
        let msg = match early.next() {
            Some(m) => m,
            None => {
                // After EOF, OpenSSH sends the exit status and the close at
                // once; a stack that sends neither must not leave the tab
                // looking connected to a shell that is gone.
                let next = if eof {
                    match tokio::time::timeout(SHELL_EOF_GRACE, read_half.wait()).await {
                        Ok(m) => m,
                        Err(_) => break,
                    }
                } else {
                    read_half.wait().await
                };
                match next {
                    Some(m) => m,
                    None => {
                        // The transport itself went away — keepalive failure,
                        // reset, a dropped route — unless the shell had ended.
                        transport_gone = !eof && exit.is_none();
                        break;
                    }
                }
            }
        };
        match msg {
            ChannelMsg::Data { ref data } | ChannelMsg::ExtendedData { ref data, .. } => {
                // Logged before display, so anything that reaches the screen is
                // already durable if the app dies next.
                if let Some(l) = log.as_mut() {
                    l.append(data);
                }
                let pending = if matches!(msg, ChannelMsg::Data { .. }) {
                    &mut pending_out
                } else {
                    &mut pending_err
                };
                let text = decode_utf8_stream(pending, data);
                if !text.is_empty() {
                    let _ = app.emit(&topic, text);
                }
            }
            // EOF alone is not the end: the exit status usually follows it.
            ChannelMsg::Eof => {
                eof = true;
                if exit.is_some() {
                    break;
                }
            }
            ChannelMsg::Close => break,
            ChannelMsg::ExitStatus { exit_status } => {
                exit = Some(if exit_status == 0 {
                    "shell exited".to_string()
                } else {
                    format!("shell exited with status {exit_status}")
                });
                if eof {
                    break;
                }
            }
            ChannelMsg::ExitSignal { signal_name, .. } => {
                exit = Some(format!("shell was killed by signal {signal_name:?}"));
                if eof {
                    break;
                }
            }
            _ => {}
        }
    }

    session.alive.store(false, Ordering::SeqCst);

    // Distinguishes a clean logout from a link that died under us: one is
    // expected, the other means "your VPN dropped" or "the firewall timed you
    // out". The cause of a dead transport is recorded by the handler's
    // `disconnected`, which runs in russh's task; give it a moment to land.
    let reason = if transport_gone {
        let mut note = None;
        for _ in 0..10 {
            note = death.lock().ok().and_then(|mut d| d.take());
            if note.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        note.unwrap_or_else(|| "connection lost".to_string())
    } else {
        exit.unwrap_or_else(|| "session closed".to_string())
    };

    if let Some(l) = log.as_mut() {
        l.footer(&reason);
    }
    let _ = app.emit(
        &topic,
        format!("\r\n\x1b[38;2;242;178;92m\u{25cf} disconnected\x1b[0m {reason}\r\n"),
    );
    let _ = app.emit(
        "ssh://status",
        SessionStatusEvent {
            session_id: sid.clone(),
            status: "disconnected",
            detail: reason,
        },
    );

    // The shell is gone, so the session is over (as with `ssh`): end THIS
    // generation's forwards — never a newer connection's for the same tab —
    // and its transport. The registry entry stays (dead) until the tab is
    // closed or reconnected, so later calls fail as "disconnected".
    let generation = session.generation;
    teardown_forwards(take_forwards(&forwards, |f| {
        f.info.session_id == sid && f.generation == generation
    }))
    .await;
    session.close("session ended").await;
}


/// Aborts its task when dropped (a JoinHandle's drop only detaches it).
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Streaming UTF-8 decode: append `data` to `pending`, return every complete
/// character, and keep an incomplete trailing sequence (at most 3 bytes) in
/// `pending` for the next chunk. Only genuinely invalid bytes become U+FFFD.
pub(crate) fn decode_utf8_stream(pending: &mut Vec<u8>, data: &[u8]) -> String {
    pending.extend_from_slice(data);
    let mut out = String::new();
    loop {
        match std::str::from_utf8(pending) {
            Ok(s) => {
                out.push_str(s);
                pending.clear();
                return out;
            }
            Err(e) => {
                let valid = e.valid_up_to();
                // The prefix up to valid_up_to() is valid UTF-8 by definition.
                out.push_str(std::str::from_utf8(&pending[..valid]).unwrap_or_default());
                match e.error_len() {
                    // Incomplete sequence at the end: wait for the rest.
                    None => {
                        pending.drain(..valid);
                        return out;
                    }
                    Some(n) => {
                        out.push('\u{FFFD}');
                        pending.drain(..valid + n);
                    }
                }
            }
        }
    }
}

/// Render POSIX permission bits as `drwxr-xr-x`.
fn mode_string(permissions: Option<u32>, kind: &str) -> String {
    let Some(bits) = permissions else {
        return String::new();
    };
    let lead = match kind {
        "directory" => 'd',
        "symlink" => 'l',
        _ => '-',
    };
    // `special` is the setuid / setgid / sticky bit for this triad, shown in the
    // execute slot as ls does: lowercase when x is also set, uppercase when not.
    let rwx = |shift: u32, special: u32, set: char| {
        let v = (bits >> shift) & 0b111;
        let x = v & 0b001 != 0;
        let exec = match (bits & special != 0, x) {
            (true, true) => set,
            (true, false) => set.to_ascii_uppercase(),
            (false, true) => 'x',
            (false, false) => '-',
        };
        format!(
            "{}{}{}",
            if v & 0b100 != 0 { 'r' } else { '-' },
            if v & 0b010 != 0 { 'w' } else { '-' },
            exec,
        )
    };
    format!(
        "{lead}{}{}{}",
        rwx(6, 0o4000, 's'),
        rwx(3, 0o2000, 's'),
        rwx(0, 0o1000, 't')
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_traversal_and_absolute_names() {
        assert!(safe_local_component("report.txt"));
        assert!(safe_local_component("id_ed25519.pub"));
        assert!(!safe_local_component(".."));
        assert!(!safe_local_component("."));
        assert!(!safe_local_component(""));
        assert!(!safe_local_component("../etc/passwd"));
        assert!(!safe_local_component("..\\Windows\\evil"));
        assert!(!safe_local_component("sub/dir"));
        // Drive-relative on Windows; an ordinary name elsewhere.
        assert_eq!(safe_local_component("C:evil"), !cfg!(windows));
        assert_eq!(safe_local_component("app-2026-10-30T10:15:00.log"), !cfg!(windows));
    }

    #[test]
    fn mode_string_shows_special_bits() {
        use super::mode_string;
        assert_eq!(mode_string(Some(0o755), "file"), "-rwxr-xr-x");
        assert_eq!(mode_string(Some(0o1777), "directory"), "drwxrwxrwt");
        assert_eq!(mode_string(Some(0o4755), "file"), "-rwsr-xr-x");
        assert_eq!(mode_string(Some(0o2750), "directory"), "drwxr-s---");
        assert_eq!(mode_string(Some(0o4644), "file"), "-rwSr--r--");
        assert_eq!(mode_string(Some(0o1666), "file"), "-rw-rw-rwT");
        assert_eq!(mode_string(None, "file"), "");
    }

    #[test]
    fn utf8_stream_carries_split_characters() {
        use super::decode_utf8_stream;
        let mut pending = Vec::new();
        let text = "a\u{4e2d}b\u{1F600}";
        let bytes = text.as_bytes();
        // Split inside the 3-byte CJK char and inside the 4-byte emoji.
        let mut out = String::new();
        out += &decode_utf8_stream(&mut pending, &bytes[..2]);
        out += &decode_utf8_stream(&mut pending, &bytes[2..6]);
        out += &decode_utf8_stream(&mut pending, &bytes[6..]);
        assert_eq!(out, text);
        assert!(pending.is_empty());
        // Genuinely invalid bytes still become U+FFFD and do not stall output.
        assert_eq!(decode_utf8_stream(&mut pending, b"x\xffy"), "x\u{FFFD}y");
        assert!(pending.is_empty());
    }

    #[test]
    fn kbd_interactive_password_only_answers_password_prompts() {
        use super::password_slots;
        let p = |t: &str, echo: bool| (t.to_string(), echo);
        // TACACS+-style lone unlabelled hidden prompt in round 1: the password.
        assert_eq!(password_slots(&[p("Enter:", false)], true, false, false), vec![true]);
        // Password + hidden OTP in one round: only the password slot.
        assert_eq!(
            password_slots(&[p("Password:", false), p("Verification code:", false)], true, false, false),
            vec![true, false]
        );
        // OTP in a later round after the password was used: ask the user.
        assert_eq!(password_slots(&[p("Verification code:", false)], false, true, false), vec![false]);
        // After password auth returned partial_success, a lone hidden prompt is
        // the second factor, not the password.
        assert_eq!(password_slots(&[p("Verification code:", false)], true, false, true), vec![false]);
        // Echo prompts never get the password.
        assert_eq!(password_slots(&[p("Password:", true)], true, false, false), vec![false]);
        // A lone hidden second-factor prompt in round 1 is NOT the TACACS+
        // unlabelled password question.
        assert_eq!(password_slots(&[p("Verification code:", false)], true, false, false), vec![false]);
        assert_eq!(password_slots(&[p("Enter PASSCODE:", false)], true, false, false), vec![false]);
        // "One-time password" names a password but is an OTP, in any round.
        assert_eq!(password_slots(&[p("One-time password:", false)], true, false, false), vec![false]);
        assert_eq!(password_slots(&[p("One-time password:", false)], false, false, true), vec![false]);
        assert_eq!(
            password_slots(&[p("Password:", false), p("OTP password:", false)], true, false, false),
            vec![true, false]
        );
        // Usernames / hosts containing a short stem are still password prompts
        // (FreeBSD / OpenPAM "Password for %u@%h:").
        assert_eq!(password_slots(&[p("Password for root@shipping-db:", false)], true, false, false), vec![true]);
        assert_eq!(password_slots(&[p("Password for jpinto@host:", false)], false, false, false), vec![true]);
        assert_eq!(password_slots(&[p("Password for unicode@otpbox:", false)], false, false, false), vec![true]);
        // Short stems as whole words, and localized one-time passwords.
        assert_eq!(password_slots(&[p("Enter PIN:", false)], true, false, false), vec![false]);
        assert_eq!(password_slots(&[p("OTP:", false)], true, false, false), vec![false]);
        assert_eq!(password_slots(&[p("Einmalpasswort:", false)], false, false, false), vec![false]);
        assert_eq!(password_slots(&[p("ワンタイムパスワード:", false)], false, false, false), vec![false]);
    }

    // The prompt must stay locked while it is emitted, so a concurrent
    // cancel_for_session cannot remove it between the cancellation check and
    // the emit (it would then emit prompt-closed BEFORE the prompt). A
    // cancellation seen at registration leaves nothing registered.
    #[test]
    fn prompt_registration_is_atomic_with_cancel_sweep() {
        use super::{cancel_matching, register_and_emit, PromptOwner};
        use dashmap::{try_result::TryResult, DashMap};
        use tokio::sync::oneshot;

        let pending: DashMap<String, (PromptOwner, oneshot::Sender<bool>)> = DashMap::new();
        let owner = |t: u64| -> PromptOwner { ("s1".to_string(), t) };
        let mut locked_during_emit = false;
        let rx = register_and_emit(&pending, "hk-1", owner(1), || false, || {
            locked_during_emit = matches!(pending.try_get_mut("hk-1"), TryResult::Locked);
            true
        });
        assert!(locked_during_emit, "sweep could interleave between check and emit");
        assert!(rx.is_some());
        // A sweep after the emit removes it (and the caller emits prompt-closed).
        // A superseded attempt's sweep (generation 2) leaves generation 1 alone.
        assert!(cancel_matching(&pending, |o| o.0 == "s1" && o.1 == 2).is_empty());
        assert_eq!(cancel_matching(&pending, |o| o.0 == "s1"), vec!["hk-1".to_string()]);

        // Cancelled at registration: never emitted, nothing left behind.
        let mut emitted = false;
        let rx = register_and_emit(&pending, "hk-2", owner(1), || true, || {
            emitted = true;
            true
        });
        assert!(rx.is_none() && !emitted && pending.is_empty());

        // Emit failure also leaves nothing registered.
        assert!(register_and_emit(&pending, "hk-3", owner(1), || false, || false).is_none());
        assert!(pending.is_empty());
    }

    #[test]
    fn rejects_windows_reserved_names() {
        assert!(is_windows_reserved("CON"));
        assert!(is_windows_reserved("nul")); // case-insensitive
        assert!(is_windows_reserved("NUL.txt")); // extension ignored
        assert!(is_windows_reserved("COM1"));
        assert!(is_windows_reserved("LPT9"));
        // Refused as download names on Windows only (see the test below).
        assert_eq!(safe_local_component("CON"), !cfg!(windows));
        // Names that merely start with a reserved stem are fine everywhere.
        assert!(safe_local_component("console.log"));
        assert!(safe_local_component("com10"));
        assert!(safe_local_component("nullable.rs"));
    }

    // A pre-existing local symlink in the download subtree is the escape #4
    // guards against: `create_dir_all`/`File::create` would follow it out of the
    // chosen folder. Symlink creation is a Unix-only primitive in std, so this
    // test is gated to Unix; the Windows reparse-point path shares the code.
    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_ancestor_in_subtree() {
        use std::fs;
        let base = std::env::temp_dir().join(format!("hawser-symtest-{}", std::process::id()));
        let root = base.join("root");
        let outside = base.join("outside");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&outside).unwrap();

        // A plain, real subtree is accepted (nothing created yet — check is
        // purely about existing links).
        assert!(reject_link_in_subtree(&root, &root.join("a").join("b.txt")).is_ok());

        // Plant `root/link` -> `outside`, then a target that routes through it.
        let link = root.join("link");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        let via_link = link.join("evil.txt");
        assert!(reject_link_in_subtree(&root, &via_link).is_err());

        // A target outside root entirely is also refused.
        assert!(reject_link_in_subtree(&root, &outside.join("x")).is_err());

        let _ = fs::remove_dir_all(&base);
    }

    /* ---------------------------------------------- host-key policy (W2) */

    const ED_A: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ1EeRn1nUZ6oQiaSmrlPONbjg1FxJtr35MXzTndFYIe";
    const ED_B: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHveLo5tgiTjyNgc98zwmigaaw1vJ/1IN9KDWqa0Z43a";
    const ECDSA: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBI/gPg4KkOG52SzCdcnggcQk7DG6z1OLSfSAi2LTGk4OFnDnYrkNsxVIWtt/KArpW70Gac7c1im2IEx4u8Bs0MI=";
    /// The raw host key a CA signed into `HOST_CERT` (ssh-keygen -s ca -h).
    const CERT_HOST_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN9i5YuRG3Q+ur8Jb5GHlc8PHma3/lZIDJ8w28uSpVEx";
    const HOST_CERT: &str = "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIB+h46eQH0FJHc7hx2tNtaxZ1fDOJGco3BuHG1HzpT/HAAAAIN9i5YuRG3Q+ur8Jb5GHlc8PHma3/lZIDJ8w28uSpVExAAAAAAAAAAAAAAACAAAAC2hhd3Nlci10ZXN0AAAAEAAAAAxjZXJ0LmV4YW1wbGUAAAAAAAAAAP//////////AAAAAAAAAAAAAAAAAAAAMwAAAAtzc2gtZWQyNTUxOQAAACA8sSKaRahTgUwI22aO8wihmUdkNFGaozzeUvs1SAGyjgAAAFMAAAALc3NoLWVkMjU1MTkAAABAXQZ2JLfK29r9OIjDZKy3ubiIfFzB4005BDVGGpMoKFgo1PrvBFHsynEvqzl4NeGZ1hBNNelCdUanRtM5aPjIAA==";

    fn key(s: &str) -> russh::keys::PublicKey {
        russh::keys::PublicKey::from_openssh(s).unwrap()
    }

    fn raw(s: &str) -> russh::keys::PublicKeyOrCertificate {
        russh::keys::PublicKeyOrCertificate::PublicKey { key: key(s), hash_alg: None }
    }

    fn cert() -> russh::keys::PublicKeyOrCertificate {
        russh::keys::PublicKeyOrCertificate::Certificate(
            russh::keys::Certificate::from_openssh(HOST_CERT).unwrap(),
        )
    }

    /// A known_hosts file holding `body`, in a directory unique to the test.
    struct Store(std::path::PathBuf);
    impl Store {
        fn new(tag: &str, body: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("hawser-ssh-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("known_hosts"), body).unwrap();
            Store(dir)
        }
        fn path(&self) -> std::path::PathBuf {
            self.0.join("known_hosts")
        }
        fn verdict(&self, host: &str, presented: &russh::keys::PublicKeyOrCertificate) -> KeyVerdict {
            key_verdict(host, 22, &presented_key(presented), &self.path())
        }
        fn text(&self) -> String {
            std::fs::read_to_string(self.path()).unwrap()
        }
    }
    impl Drop for Store {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn trusted_key_connects_silently() {
        let store = Store::new("trusted", &format!("fw01 {ED_A}\n"));
        assert!(matches!(store.verdict("fw01", &raw(ED_A)), KeyVerdict::Accept));
        // Host names are case-insensitive.
        assert!(matches!(store.verdict("FW01", &raw(ED_A)), KeyVerdict::Accept));
    }

    #[test]
    fn changed_or_revoked_key_is_refused_without_a_prompt() {
        // Same algorithm, different key.
        let store = Store::new("changed", &format!("fw01 {ED_B}\n"));
        assert!(matches!(
            store.verdict("fw01", &raw(ED_A)),
            KeyVerdict::Refuse(SshError::ChangedHostKey { line: 1, .. })
        ));
        // Different algorithm for a pinned host is CHANGED too, not first use.
        let store = Store::new("changed-alg", &format!("# pinned\nfw01 {ECDSA}\n"));
        assert!(matches!(
            store.verdict("fw01", &raw(ED_A)),
            KeyVerdict::Refuse(SshError::ChangedHostKey { line: 2, .. })
        ));
        // Revoked beats a matching trust line.
        let store = Store::new("revoked", &format!("fw01 {ED_A}\n@revoked * {ED_A}\n"));
        assert!(matches!(
            store.verdict("fw01", &raw(ED_A)),
            KeyVerdict::Refuse(SshError::ChangedHostKey { line: 2, .. })
        ));
        // An unreadable store fails closed rather than prompting.
        let missing = key_verdict(
            "fw01",
            22,
            &key(ED_A),
            std::path::Path::new("/nonexistent/hawser/known_hosts"),
        );
        assert!(matches!(missing, KeyVerdict::Refuse(SshError::KnownHosts(_))));
    }

    #[tokio::test]
    async fn unknown_key_rejected_timed_out_or_cancelled_is_refused() {
        let store = Store::new("unknown", "");
        let k = key(ED_A);
        assert!(matches!(store.verdict("new01", &raw(ED_A)), KeyVerdict::Ask));

        // Rejected by the user.
        let (tx, rx) = oneshot::channel();
        tx.send(false).unwrap();
        let end = await_host_key_answer(rx, Duration::from_secs(5)).await;
        assert_eq!(end, PromptEnd::Rejected);
        assert!(matches!(
            settle_host_key(&end, "new01", 22, &k, &store.path()),
            Err(SshError::HostKeyRejected { .. })
        ));

        // Cancelled: the tab closed, so the sender was dropped.
        let (tx, rx) = oneshot::channel::<bool>();
        drop(tx);
        let end = await_host_key_answer(rx, Duration::from_secs(5)).await;
        assert_eq!(end, PromptEnd::Dropped);
        assert!(matches!(
            settle_host_key(&end, "new01", 22, &k, &store.path()),
            Err(SshError::HostKeyRejected { .. })
        ));

        // Nobody answered in time.
        let (_tx, rx) = oneshot::channel::<bool>();
        let end = await_host_key_answer(rx, Duration::from_millis(20)).await;
        assert_eq!(end, PromptEnd::TimedOut);
        assert!(matches!(
            settle_host_key(&end, "new01", 22, &k, &store.path()),
            Err(SshError::HostKeyTimeout { .. })
        ));

        // None of those recorded anything: the host is still unknown.
        assert_eq!(store.text(), "");
        assert!(matches!(store.verdict("new01", &raw(ED_A)), KeyVerdict::Ask));

        // Only an explicit accept pins it, after which it connects silently.
        let (tx, rx) = oneshot::channel();
        tx.send(true).unwrap();
        let end = await_host_key_answer(rx, Duration::from_secs(5)).await;
        assert!(settle_host_key(&end, "new01", 22, &k, &store.path()).unwrap());
        assert!(matches!(store.verdict("new01", &raw(ED_A)), KeyVerdict::Accept));
    }

    #[test]
    fn certificate_follows_the_raw_key_policy() {
        let c = cert();
        // Its embedded key is what is judged.
        assert_eq!(presented_key(&c).key_data(), key(CERT_HOST_KEY).key_data());

        let pinned = Store::new("cert-pinned", &format!("cert.example {CERT_HOST_KEY}\n"));
        assert!(matches!(pinned.verdict("cert.example", &c), KeyVerdict::Accept));

        let changed = Store::new("cert-changed", &format!("cert.example {ED_A}\n"));
        assert!(matches!(
            changed.verdict("cert.example", &c),
            KeyVerdict::Refuse(SshError::ChangedHostKey { .. })
        ));

        let revoked = Store::new(
            "cert-revoked",
            &format!("cert.example {CERT_HOST_KEY}\n@revoked * {CERT_HOST_KEY}\n"),
        );
        assert!(matches!(
            revoked.verdict("cert.example", &c),
            KeyVerdict::Refuse(SshError::ChangedHostKey { .. })
        ));

        // The CA signature earns no trust: unknown is still a prompt.
        let unknown = Store::new("cert-unknown", "");
        assert!(matches!(unknown.verdict("cert.example", &c), KeyVerdict::Ask));
    }

    // Two tabs approving DIFFERENT unknown keys for one host at once, through
    // the handler's own settle path: exactly one is pinned, the other refused.
    #[test]
    fn concurrent_trusts_of_different_keys_leave_one_pinned_key() {
        for round in 0..10 {
            let store = Store::new(&format!("race-{round}"), "");
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let spawn = |k: &'static str| {
                let (b, p) = (Arc::clone(&barrier), store.path());
                std::thread::spawn(move || {
                    b.wait();
                    settle_host_key(&PromptEnd::Accepted, "race01", 22, &key(k), &p).is_ok()
                })
            };
            let (a, b) = (spawn(ED_A), spawn(ED_B));
            let oks = [a.join().unwrap(), b.join().unwrap()];
            assert_eq!(oks.iter().filter(|o| **o).count(), 1);
            let lines = store.text().lines().filter(|l| l.starts_with("race01 ")).count();
            assert_eq!(lines, 1, "exactly one key pinned");
        }
    }

    #[test]
    fn pinned_host_key_algorithms_are_offered_first() {
        use russh::keys::{Algorithm, EcdsaCurve, HashAlg};
        let defaults: Vec<Algorithm> = russh::Preferred::DEFAULT.key.to_vec();

        // Nothing pinned: russh's own order.
        assert_eq!(preferred_host_key_order(&[]), defaults);

        // ECDSA pinned: offered before Ed25519, every default still offered once.
        let p256 = Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 };
        let order = preferred_host_key_order(&[p256.clone()]);
        assert_eq!(order[0], p256);
        assert_eq!(order[1], Algorithm::Ed25519);
        assert_eq!(order.len(), defaults.len());

        // An RSA pin covers all three RSA signature names, strongest first.
        let order = preferred_host_key_order(&[Algorithm::Rsa { hash: None }]);
        assert_eq!(
            &order[..3],
            &[
                Algorithm::Rsa { hash: Some(HashAlg::Sha512) },
                Algorithm::Rsa { hash: Some(HashAlg::Sha256) },
                Algorithm::Rsa { hash: None },
            ]
        );

        // Something russh does not implement is never advertised.
        let order = preferred_host_key_order(&[Algorithm::Dsa, Algorithm::Ed25519]);
        assert!(!order.contains(&Algorithm::Dsa));
        assert_eq!(order[0], Algorithm::Ed25519);

        // From the store: the pinned ECDSA key comes first.
        let store = Store::new("algs", &format!("fw01 {ECDSA}\n"));
        let pinned = known_hosts::pinned_algorithms_at("fw01", 22, &store.path());
        assert_eq!(preferred_host_key_order(&pinned)[0], p256);

        // RSA pinned on the first line, Ed25519 later: a server offering
        // Ed25519 and SHA-1 ssh-rsa must get Ed25519. SHA-1 is the last pinned
        // algorithm, after every pinned non-SHA-1 one, and still ahead of the
        // unpinned ones (it may be the only thing an old pinned host signs).
        let order = preferred_host_key_order(&[Algorithm::Rsa { hash: None }, Algorithm::Ed25519]);
        assert_eq!(
            &order[..4],
            &[
                Algorithm::Ed25519,
                Algorithm::Rsa { hash: Some(HashAlg::Sha512) },
                Algorithm::Rsa { hash: Some(HashAlg::Sha256) },
                Algorithm::Rsa { hash: None },
            ]
        );
        assert_eq!(order[4], p256, "unpinned algorithms follow the pinned block");
        assert_eq!(order.len(), defaults.len());
        for pinned in [
            vec![Algorithm::Rsa { hash: None }, p256.clone()],
            vec![Algorithm::Rsa { hash: Some(HashAlg::Sha256) }, Algorithm::Ed25519, p256.clone()],
        ] {
            let order = preferred_host_key_order(&pinned);
            let sha1 = order.iter().position(|a| *a == Algorithm::Rsa { hash: None }).unwrap();
            for a in pinned.iter().filter(|a| **a != Algorithm::Rsa { hash: None }) {
                assert!(order.iter().position(|o| o == a).unwrap() < sha1, "SHA-1 ahead of {a:?}");
            }
        }
    }

    #[tokio::test]
    async fn stage_deadline_excludes_time_waiting_on_a_human() {
        // Machine time alone runs out.
        let wait = HumanWait::default();
        let r = within(&wait, Duration::from_millis(50), "h", "stage", tokio::time::sleep(Duration::from_millis(400))).await;
        assert!(matches!(r, Err(SshError::Timeout { stage: "stage", .. })));

        // The same work with a dialog open for most of it finishes in time.
        let wait = HumanWait::default();
        let guard = wait.enter();
        let release = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            drop(guard);
        });
        let r = within(&wait, Duration::from_millis(150), "h", "stage", tokio::time::sleep(Duration::from_millis(350))).await;
        assert!(r.is_ok(), "prompt time counted against the deadline");
        release.await.unwrap();
    }

    #[test]
    fn prompt_origin_names_the_dialled_endpoint() {
        let o = PromptOrigin::new(Some(" fw-prod "), "admin", "10.0.0.1", 22, Some("bastion".into()));
        assert_eq!(o.host_name.as_deref(), Some("fw-prod"));
        assert_eq!(o.target, "admin@10.0.0.1:22");
        assert_eq!(o.via.as_deref(), Some("bastion"));
        assert_eq!(PromptOrigin::new(Some(""), "u", "::1", 2222, None).target, "u@[::1]:2222");
    }

    #[test]
    fn keepalive_wording_states_the_real_timeout() {
        // russh ends the link after MORE than KEEPALIVE_MAX silent intervals.
        assert_eq!(keepalive_timeout(), Duration::from_secs(45));
        let text = death_reason(&SshError::Russh(russh::Error::KeepaliveTimeout));
        assert!(text.contains("45s"), "{text}");
    }

    // The deadline that races a host-key prompt runs on another worker, so the
    // stage clock must already be paused when the prompt is emitted.
    #[test]
    fn prompt_pauses_the_stage_clock_before_it_is_shown() {
        let wait = HumanWait::default();
        let pending: DashMap<String, (PromptOwner, oneshot::Sender<bool>)> = DashMap::new();
        let owner = || -> PromptOwner { ("s1".to_string(), 1) };
        let mut paused_at_emit = false;
        let raised = raise_prompt(&wait, &pending, "hk-1", owner(), || false, || {
            paused_at_emit = wait.waited().1;
            true
        });
        assert!(paused_at_emit, "prompt emitted while the deadline was still running");
        let (human, _rx) = raised.expect("shown");
        assert!(wait.waited().1);
        drop(human);
        assert!(!wait.waited().1);
        // A prompt that is never shown leaves the clock running.
        assert!(raise_prompt(&wait, &pending, "hk-2", owner(), || true, || true).is_none());
        assert!(!wait.waited().1);
    }

    #[test]
    fn copy_id_cancel_that_overtakes_the_install_is_honoured() {
        let r = Registry::default();
        // The editor's cancel IPC is handled before the install registers.
        r.copy_id_cancel("op-1");
        let (tx, _rx) = watch::channel(());
        assert!(!r.copy_id_register("op-1", 1, tx), "install ran after its cancel");
        assert!(r.copy_ids.is_empty());
        // The early cancel is consumed; a fresh install under the id runs.
        let (tx, _rx) = watch::channel(());
        assert!(r.copy_id_register("op-1", 2, tx));
        // A cancel for a registered install removes it and leaves no tombstone.
        r.copy_id_cancel("op-1");
        assert!(r.copy_ids.is_empty() && r.copy_id_cancels.is_empty());
    }

    /* ------------------------------------------- transport lifetime (W2b) */

    /// A client handler that trusts any key (the tests below are about the
    /// transport's lifetime, not host-key policy).
    struct AnyKey;

    impl client::Handler for AnyKey {
        type Error = SshError;

        async fn check_server_key(
            &mut self,
            _: &russh::keys::PublicKeyOrCertificate,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    /// A listener that accepts one connection, sends an SSH banner, then never
    /// answers the key exchange. Resolves the receiver when its side of the
    /// socket sees the connection close (EOF or reset).
    async fn kex_tarpit() -> (std::net::SocketAddr, oneshot::Receiver<Instant>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (closed_tx, closed_rx) = oneshot::channel();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            sock.write_all(b"SSH-2.0-tarpit\r\n").await.unwrap();
            let mut buf = [0u8; 4096];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
            let _ = closed_tx.send(Instant::now());
        });
        (addr, closed_rx)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn handshake_deadline_closes_a_stalled_transport() {
        let (addr, closed) = kex_tarpit().await;
        let sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        let guard = KillGuard::new();
        let start = Instant::now();
        let r = handshake(
            Arc::new(client::Config::default()),
            sock,
            AnyKey,
            &HumanWait::default(),
            "tarpit",
            Duration::from_millis(300),
            &guard.kill(),
        )
        .await;
        assert!(matches!(r, Err(SshError::Timeout { .. })), "{:?}", r.err());
        assert!(start.elapsed() < Duration::from_secs(2));
        // russh's session task owned the socket; the peer seeing it close
        // means that task is gone too.
        let at = tokio::time::timeout(Duration::from_secs(2), closed)
            .await
            .expect("the stalled transport survived the deadline")
            .unwrap();
        assert!(at.duration_since(start) < Duration::from_secs(3));
    }

    // Control for the test above: the same deadline WITHOUT the kill switch
    // leaves russh's task holding the socket open (the bug being fixed).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stalled_transport_outlives_a_plain_deadline() {
        let (addr, closed) = kex_tarpit().await;
        let sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        let r = within(
            &HumanWait::default(),
            Duration::from_millis(300),
            "tarpit",
            "handshake",
            client::connect_stream(Arc::new(client::Config::default()), sock, AnyKey),
        )
        .await;
        assert!(matches!(r, Err(SshError::Timeout { .. })));
        assert!(
            tokio::time::timeout(Duration::from_millis(800), closed).await.is_err(),
            "expected the unkilled transport to stay open"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_handshake_closes_its_transport() {
        let (addr, closed) = kex_tarpit().await;
        let sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        let guard = KillGuard::new();
        let kill = guard.kill();
        let wait = HumanWait::default();
        // A cancel drops the connect future mid-handshake...
        tokio::select! {
            _ = handshake(
                Arc::new(client::Config::default()), sock, AnyKey, &wait,
                "tarpit", Duration::from_secs(30), &kill,
            ) => panic!("the tarpit completed a handshake"),
            _ = tokio::time::sleep(Duration::from_millis(200)) => {}
        }
        // ...and with it the attempt's guard.
        drop(guard);
        tokio::time::timeout(Duration::from_secs(2), closed)
            .await
            .expect("the cancelled transport survived")
            .unwrap();
    }

    const TEST_SERVER_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAfv5/eq75dWNkgZ+e28E5l7vex5x2Nk7HR13o0FD26OwAAAJhJGmXPSRpl
zwAAAAtzc2gtZWQyNTUxOQAAACAfv5/eq75dWNkgZ+e28E5l7vex5x2Nk7HR13o0FD26Ow
AAAEB3HRbaDvsyEtbyMLwOV9P5RVX3zX5N2iVkDacnyzPnAx+/n96rvl1Y2SBn57bwTmXu
97HnHY2TsdHXejQUPbo7AAAAEmhhd3Nlci10ZXN0LXNlcnZlcgECAw==
-----END OPENSSH PRIVATE KEY-----
";

    #[derive(Clone, Copy)]
    enum ShellMode {
        /// Accept the PTY, then print a reason and end the session without
        /// answering the shell request (an expired account, a forced command).
        ExitDuringSetup,
        /// Start the shell, then print far more than the client buffers.
        Flood,
    }

    struct TestServer {
        mode: ShellMode,
    }

    impl russh::server::Handler for TestServer {
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
            // Drained, so the server side never blocks delivering our input.
            tokio::spawn(async move {
                let mut channel = channel;
                while channel.wait().await.is_some() {}
            });
            reply.accept().await;
            Ok(())
        }

        async fn pty_request(
            &mut self,
            channel: russh::ChannelId,
            _: &str,
            _: u32,
            _: u32,
            _: u32,
            _: u32,
            _: &[(russh::Pty, u32)],
            session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            session.channel_success(channel)
        }

        async fn shell_request(
            &mut self,
            channel: russh::ChannelId,
            session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            match self.mode {
                ShellMode::ExitDuringSetup => {
                    session.data(channel, &b"This account has expired.\r\n"[..])?;
                    session.eof(channel)?;
                    session.close(channel)?;
                }
                ShellMode::Flood => {
                    session.channel_success(channel)?;
                    let h = session.handle();
                    tokio::spawn(async move {
                        let chunk = vec![b'x'; 16 * 1024];
                        for _ in 0..1024 {
                            if h.data(channel, chunk.clone()).await.is_err() {
                                break;
                            }
                        }
                    });
                }
            }
            Ok(())
        }
    }

    /// An authenticated client session to an in-process russh server whose
    /// receive window is `server_window` bytes.
    async fn test_session(mode: ShellMode, server_window: u32) -> Handle<AnyKey> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let config = Arc::new(russh::server::Config {
                keys: vec![russh::keys::PrivateKey::from_openssh(TEST_SERVER_KEY).unwrap()],
                window_size: server_window,
                auth_rejection_time: Duration::from_millis(1),
                auth_rejection_time_initial: Some(Duration::ZERO),
                ..Default::default()
            });
            let server = TestServer { mode };
            if let Ok(running) = russh::server::run_stream(config, sock, server).await {
                let _ = running.await;
            }
        });
        let sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut h = handshake(
            Arc::new(client::Config::default()),
            sock,
            AnyKey,
            &HumanWait::default(),
            "test",
            Duration::from_secs(10),
            &Kill::default(),
        )
        .await
        .unwrap();
        let auth = h.authenticate_password("u", "p").await.unwrap();
        assert!(matches!(auth, russh::client::AuthResult::Success));
        h
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shell_that_ends_during_setup_reports_its_output() {
        let h = test_session(ShellMode::ExitDuringSetup, 2 * 1024 * 1024).await;
        let e = open_shell(&h, "acct.example", 80, 24).await.unwrap_err();
        assert!(matches!(e, SshError::ShellEndedEarly { .. }), "{e:?}");
        let text = e.to_string();
        assert!(text.starts_with("This account has expired.\r\n"), "{text:?}");
        assert!(text.ends_with("acct.example closed the session before the shell started"));
    }

    #[test]
    fn early_output_is_capped() {
        let big = ChannelMsg::Data { data: vec![b'a'; EARLY_OUTPUT_CAP].into() };
        let err = ChannelMsg::ExtendedData { data: b"more"[..].into(), ext: 1 };
        assert_eq!(early_output(&[big, err]).len(), EARLY_OUTPUT_CAP);
        assert_eq!(
            shell_ended_early_text("h", "bye"),
            "bye\r\nh closed the session before the shell started"
        );
        assert_eq!(shell_ended_early_text("h", ""), "h closed the session before the shell started");
    }

    /// Startup input larger than the server's window, against a shell that
    /// floods output. With the output read concurrently (as the pump does) it
    /// all goes out; with nobody reading, russh blocks delivering output and
    /// never takes the window adjustment the write waits for.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn startup_input_goes_out_while_the_output_is_read() {
        let commands: Vec<String> = (0..32).map(|i| format!("echo {i} {}", "y".repeat(8 * 1024))).collect();

        let h = test_session(ShellMode::Flood, 4096).await;
        let (mut read, write, _, _) = open_shell(&h, "flood", 80, 24).await.unwrap();
        let shell = Arc::new(Mutex::new(Some(write)));
        let reader = tokio::spawn(async move {
            let mut n = 0usize;
            while let Some(m) = read.wait().await {
                if let ChannelMsg::Data { data } = m {
                    n += data.len();
                }
            }
            n
        });
        let guard = Arc::clone(&shell).lock_owned().await;
        send_startup(guard, &commands, Duration::from_secs(10), |_| {})
            .await
            .expect("startup input stalled although output was being read");
        reader.abort();

        // Control: the same, with the output left unread, deadlocks.
        let h = test_session(ShellMode::Flood, 4096).await;
        let (_read, write, _, _) = open_shell(&h, "flood", 80, 24).await.unwrap();
        let shell = Arc::new(Mutex::new(Some(write)));
        let guard = Arc::clone(&shell).lock_owned().await;
        // A Ctrl-U that cannot go out either: bound the whole call.
        let r = tokio::time::timeout(
            Duration::from_secs(4),
            send_startup(guard, &commands, Duration::from_secs(2), |_| {}),
        )
        .await;
        assert!(
            !matches!(r, Ok(Ok(()))),
            "expected the unread session to block the startup input"
        );
    }

    /// The writer is taken before the session is exposed (here: before the
    /// "user" task starts), so a keystroke cannot overtake the startup lines;
    /// and a line cut off by the deadline keeps the writer until a Ctrl-U has
    /// gone out after it, so the user's typing never extends it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn startup_holds_the_writer_and_never_leaves_a_partial_line() {
        let h = test_session(ShellMode::Flood, 4096).await;
        let (mut read, write, _, _) = open_shell(&h, "flood", 80, 24).await.unwrap();
        let shell = Arc::new(Mutex::new(Some(write)));
        let guard = Arc::clone(&shell).lock_owned().await;
        // Nobody reads the flood yet: one long line stalls part-way.
        let commands = vec![format!("echo {}", "z".repeat(256 * 1024))];
        let reported = Arc::new(AtomicBool::new(false));
        let rep = Arc::clone(&reported);
        let startup = tokio::spawn(async move {
            send_startup(guard, &commands, Duration::from_millis(500), move |_| {
                rep.store(true, Ordering::SeqCst)
            })
            .await
        });
        // "User input" queued right after registration must wait.
        let user_shell = Arc::clone(&shell);
        let user = tokio::spawn(async move {
            let g = user_shell.lock().await;
            drop(g);
            Instant::now()
        });
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert!(reported.load(Ordering::SeqCst), "the timeout was not reported");
        assert!(!user.is_finished(), "user input got the writer mid-line");
        // Output drains: the window opens, the Ctrl-U goes out, the writer frees.
        let reader = tokio::spawn(async move { while read.wait().await.is_some() {} });
        let r = tokio::time::timeout(Duration::from_secs(10), startup).await.unwrap().unwrap();
        assert!(r.is_err());
        tokio::time::timeout(Duration::from_secs(5), user).await.unwrap().unwrap();
        reader.abort();
    }

    /// Two streams on one switch (a ProxyJump attempt: bastion socket and the
    /// target's channel), each with a write parked on a full pipe in its own
    /// task: firing must wake BOTH.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn kill_switch_wakes_every_parked_stream() {
        let kill = Kill::default();
        let mut tasks = Vec::new();
        let mut peers = Vec::new();
        for _ in 0..2 {
            let (a, b) = tokio::io::duplex(16);
            peers.push(b); // never read: writes park once 16 bytes are queued
            let mut s = Killable::new(a, kill.clone());
            tasks.push(tokio::spawn(async move {
                let r = s.write_all(&[0u8; 4096]).await;
                let f = s.flush().await;
                (r, f)
            }));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(tasks.iter().all(|t| !t.is_finished()), "writes should be parked");
        kill.fire();
        for t in tasks {
            let (r, _) = tokio::time::timeout(Duration::from_secs(2), t)
                .await
                .expect("a parked stream was not woken by the kill switch")
                .unwrap();
            assert!(r.is_err());
        }
        drop(peers);
    }

    #[test]
    fn exec_refusal_and_stderr_are_reported_apart() {
        let refused = ExecRun { refused: true, ..Default::default() };
        let e = exec_verdict(refused, 60).unwrap_err().to_string();
        assert!(e.contains("refused"), "{e}");

        let ok = ExecRun {
            out: b"hostname r1\n".to_vec(),
            err: b"setlocale: LC_ALL: cannot change locale\n".to_vec(),
            eof: true,
            confirmed: true,
            exit_status: Some(0),
            ..Default::default()
        };
        let out = exec_verdict(ok, 60).unwrap();
        assert_eq!(out.stdout, "hostname r1\n");
        assert!(!out.stdout.contains("setlocale"));
        assert!(out.labelled().contains("--- stderr ---\nsetlocale"));

        let failed = ExecRun {
            err: b"% Invalid input\n".to_vec(),
            eof: true,
            confirmed: true,
            exit_status: Some(1),
            ..Default::default()
        };
        let e = exec_verdict(failed, 60).unwrap_err().to_string();
        assert!(e.contains("status 1") && e.contains("Invalid input"), "{e}");
    }

    const TEST_PUB: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB+/n96rvl1Y2SBn57bwTmXu97HnHY2TsdHXejQUPbo7 hawser test";

    #[test]
    fn public_key_is_validated_before_install() {
        assert_eq!(validate_public_key(&format!("  {TEST_PUB}\n")).unwrap(), TEST_PUB);
        assert!(validate_public_key("").is_err());
        assert!(validate_public_key("   ").is_err());
        assert!(validate_public_key(&format!("{TEST_PUB}\n{TEST_PUB}")).is_err());
        assert!(validate_public_key(&format!("-{TEST_PUB}")).is_err());
        assert!(validate_public_key(&format!("{TEST_PUB} it's")).is_err());
        assert!(validate_public_key("-----BEGIN OPENSSH PRIVATE KEY-----").is_err());
        assert!(validate_public_key("hello world").is_err());
    }

    /// The install, run for real the way sshd runs it: the login shell gets
    /// `-c 'exec sh -s'` and the script arrives on stdin. Under sh, csh and
    /// tcsh, with a key comment holding `!`, `$` and backticks (csh/tcsh
    /// history-expand `!` even inside single quotes): it installs the exact
    /// line once, is idempotent, and fixes a missing final newline.
    #[cfg(unix)]
    #[test]
    fn copy_id_installs_through_posix_and_csh_login_shells() {
        use std::io::Write;
        let key = format!("{} !! $HOME `echo pwned` !$ $(id)", TEST_PUB);
        assert_eq!(validate_public_key(&key).unwrap(), key);
        let script = copy_id_script(&key);
        assert!(COPY_ID_COMMAND.chars().all(|c| c.is_ascii_alphanumeric() || c == ' ' || c == '-'));
        let mut ran = 0;
        for shell in ["/bin/sh", "/bin/csh", "/bin/tcsh"] {
            if !std::path::Path::new(shell).exists() {
                continue;
            }
            ran += 1;
            let home = std::env::temp_dir().join(format!(
                "hawser-copyid-{}-{}",
                std::process::id(),
                crate::utils::artifacts::random_hex(4)
            ));
            std::fs::create_dir_all(home.join(".ssh")).unwrap();
            std::fs::write(home.join(".ssh/authorized_keys"), "ssh-rsa AAAA old").unwrap();
            for _ in 0..2 {
                let mut child = std::process::Command::new(shell)
                    .arg("-c")
                    .arg(COPY_ID_COMMAND)
                    .env("HOME", &home)
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .unwrap();
                child.stdin.take().unwrap().write_all(script.as_bytes()).unwrap();
                let out = child.wait_with_output().unwrap();
                let text = String::from_utf8_lossy(&out.stdout);
                assert!(
                    text.contains("HAWSER_KEY_OK") && out.status.success(),
                    "{shell}: {text} {}",
                    String::from_utf8_lossy(&out.stderr)
                );
                assert!(!text.contains("pwned"), "{shell}: {text}");
            }
            let ak = std::fs::read_to_string(home.join(".ssh/authorized_keys")).unwrap();
            assert_eq!(ak, format!("ssh-rsa AAAA old\n{key}\n"), "{shell}");
            let _ = std::fs::remove_dir_all(&home);
        }
        assert!(ran > 0, "no shell to test with");
    }

    #[test]
    fn staging_names_fit_name_max_and_are_hidden() {
        let long = "a".repeat(255);
        let n = staging_name(&long, "0123456789ab", PART_SUFFIX);
        assert!(n.len() <= NAME_MAX, "{}", n.len());
        assert!(n.starts_with('.') && n.ends_with(PART_SUFFIX));
        // A multi-byte name is cut at a character boundary.
        let wide = "é".repeat(200);
        let n = staging_name(&wide, "0123456789ab", BAK_SUFFIX);
        assert!(n.len() <= NAME_MAX);
        assert!(std::str::from_utf8(n.as_bytes()).is_ok());
        assert_eq!(staging_name("f.txt", "t", PART_SUFFIX), ".f.txt.t.hawserpart");
        assert_eq!(remote_staging("/etc/f", PART_SUFFIX).len(), "/etc/.f.".len() + 12 + PART_SUFFIX.len());
    }

    #[test]
    fn windows_only_name_rules_stay_on_windows() {
        // Legal on macOS/Linux, refused on Windows.
        for name in ["aux.c", "con.h", "NUL", "com1.log", "report.", "notes "] {
            assert_eq!(safe_local_component(name), !cfg!(windows), "{name}");
        }
    }

    #[test]
    fn overwrite_policy_parses_and_defaults_to_never() {
        assert_eq!(Overwrite::parse(None).unwrap(), Overwrite::Never);
        assert_eq!(Overwrite::parse(Some("confirmed")).unwrap(), Overwrite::Confirmed);
        assert!(Overwrite::parse(Some("replace")).unwrap().allows_replace());
        assert!(!Overwrite::Never.allows_replace());
        assert!(Overwrite::parse(Some("yes")).is_err());
    }

    /// Real file operations, with chosen calls made to fail.
    struct FailFs {
        /// Fail the Nth call (0-based) of each kind, by kind name.
        fail: Vec<(&'static str, usize)>,
        calls: std::sync::Mutex<std::collections::HashMap<&'static str, usize>>,
    }

    impl FailFs {
        fn new(fail: &[(&'static str, usize)]) -> Self {
            Self { fail: fail.to_vec(), calls: Default::default() }
        }
        fn hit(&self, kind: &'static str) -> std::io::Result<()> {
            let mut c = self.calls.lock().unwrap();
            let n = c.entry(kind).or_insert(0);
            let this = *n;
            *n += 1;
            if self.fail.contains(&(kind, this)) {
                Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, format!("injected {kind}#{this}")))
            } else {
                Ok(())
            }
        }
    }

    impl CommitFs for FailFs {
        fn rename(&self, a: &std::path::Path, b: &std::path::Path) -> std::io::Result<()> {
            self.hit("rename")?;
            std::fs::rename(a, b)
        }
        fn rename_noreplace(&self, a: &std::path::Path, b: &std::path::Path) -> std::io::Result<()> {
            self.hit("noreplace")?;
            RealFs.rename_noreplace(a, b)
        }
        fn hard_link(&self, a: &std::path::Path, b: &std::path::Path) -> std::io::Result<()> {
            self.hit("link")?;
            std::fs::hard_link(a, b)
        }
        fn remove(&self, p: &std::path::Path) -> std::io::Result<()> {
            self.hit("remove")?;
            std::fs::remove_file(p)
        }
        fn kind(&self, p: &std::path::Path) -> Option<LocalKind> {
            RealFs.kind(p)
        }
    }

    /// A filesystem with no atomic no-replace at all (exFAT, some network
    /// shares), where another program creates the destination at the worst
    /// moment: inside any replacing rename to it.
    struct RacyFs {
        dest: std::path::PathBuf,
    }

    impl CommitFs for RacyFs {
        fn rename(&self, a: &std::path::Path, b: &std::path::Path) -> std::io::Result<()> {
            if b == self.dest {
                std::fs::write(&self.dest, "theirs").unwrap();
            }
            std::fs::rename(a, b)
        }
        fn rename_noreplace(&self, _: &std::path::Path, _: &std::path::Path) -> std::io::Result<()> {
            Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "no RENAME_NOREPLACE here"))
        }
        fn hard_link(&self, _: &std::path::Path, _: &std::path::Path) -> std::io::Result<()> {
            Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "no hard links here"))
        }
        fn remove(&self, p: &std::path::Path) -> std::io::Result<()> {
            std::fs::remove_file(p)
        }
        fn kind(&self, p: &std::path::Path) -> Option<LocalKind> {
            RealFs.kind(p)
        }
    }

    fn commit_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "hawser-commit-{tag}-{}-{}",
            std::process::id(),
            crate::utils::artifacts::random_hex(4)
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn read(p: &std::path::Path) -> Option<String> {
        std::fs::read_to_string(p).ok()
    }

    #[test]
    fn download_commit_never_destroys_both_copies() {
        // Each case: injected failures -> (ok?, dest content, tmp kept?, bak content).
        let cases: &[(&[(&str, usize)], bool, Option<&str>, bool, Option<&str>)] = &[
            (&[], true, Some("new"), false, None),
            // Atomic replace refused: aside, then in (no-replace), works.
            (&[("rename", 0)], true, Some("new"), false, None),
            // Cannot move the original aside: original untouched, new kept.
            (&[("rename", 0), ("noreplace", 0), ("rename", 1)], false, Some("old"), true, None),
            // New copy cannot go in (no-replace, link, plain rename all fail):
            // original restored without replacing, new kept.
            (&[("rename", 0), ("noreplace", 1), ("link", 0), ("rename", 1)], false, Some("old"), true, None),
            // ...and the restore fails too: original at bak, new kept.
            (
                &[("rename", 0), ("noreplace", 1), ("link", 0), ("rename", 1), ("noreplace", 2), ("link", 1)],
                false,
                None,
                true,
                Some("old"),
            ),
        ];
        for (i, (fail, ok, dest_c, tmp_kept, bak_c)) in cases.iter().enumerate() {
            let d = commit_dir(&format!("r{i}"));
            let (tmp, dest, bak) = (d.join(".f.x.hawserpart"), d.join("f"), d.join(".f.x.hawserbak"));
            std::fs::write(&tmp, "new").unwrap();
            std::fs::write(&dest, "old").unwrap();
            let fs = FailFs::new(fail);
            let r = commit_download(&fs, &tmp, &dest, &bak, true);
            assert_eq!(r.is_ok(), *ok, "case {i}: {r:?}");
            assert_eq!(read(&dest).as_deref(), *dest_c, "case {i} dest");
            assert_eq!(tmp.exists(), *tmp_kept, "case {i} tmp");
            assert_eq!(read(&bak).as_deref(), *bak_c, "case {i} bak");
            if let Err(e) = &r {
                assert!(e.contains(&tmp.display().to_string()), "case {i}: error must name the kept copy: {e}");
                if bak.exists() {
                    assert!(e.contains(&bak.display().to_string()), "case {i}: error must name the backup: {e}");
                }
            }
            // Never: one of the two contents survives somewhere.
            let survivors = [read(&dest), read(&tmp), read(&bak)];
            assert!(survivors.contains(&Some("new".into())), "case {i}: new copy lost");
            assert!(*ok || survivors.contains(&Some("old".into())), "case {i}: original lost");
            let _ = std::fs::remove_dir_all(&d);
        }
    }

    /// A backup that cannot be removed after a successful replace is reported,
    /// not silently left.
    #[test]
    fn download_commit_reports_a_backup_it_could_not_remove() {
        let d = commit_dir("bak");
        let (tmp, dest, bak) = (d.join(".f.x.hawserpart"), d.join("f"), d.join(".f.x.hawserbak"));
        std::fs::write(&tmp, "new").unwrap();
        std::fs::write(&dest, "old").unwrap();
        let note = commit_download(&FailFs::new(&[("rename", 0), ("remove", 0)]), &tmp, &dest, &bak, true)
            .unwrap()
            .expect("a note about the backup");
        assert!(note.contains(&bak.display().to_string()), "{note}");
        assert_eq!(read(&dest).as_deref(), Some("new"));
        assert_eq!(read(&bak).as_deref(), Some("old"));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A folder that took the destination's place during the copy is never
    /// moved aside or replaced; the downloaded copy is kept and named.
    #[test]
    fn download_commit_never_moves_a_folder_aside() {
        let d = commit_dir("dir");
        let (tmp, dest, bak) = (d.join(".f.x.hawserpart"), d.join("f"), d.join(".f.x.hawserbak"));
        std::fs::write(&tmp, "new").unwrap();
        std::fs::create_dir(&dest).unwrap();
        std::fs::write(dest.join("inside"), "keep").unwrap();
        // Force the move-aside path even where rename(file, dir) would fail anyway.
        let e = commit_download(&FailFs::new(&[("rename", 0)]), &tmp, &dest, &bak, true).unwrap_err();
        assert!(e.contains("no longer a regular file") && e.contains(&tmp.display().to_string()), "{e}");
        assert_eq!(read(&dest.join("inside")).as_deref(), Some("keep"));
        assert!(!bak.exists());
        assert_eq!(read(&tmp).as_deref(), Some("new"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn download_commit_no_clobber_is_enforced_at_commit() {
        let d = commit_dir("nc");
        let (tmp, dest, bak) = (d.join(".g.x.hawserpart"), d.join("g"), d.join(".g.x.hawserbak"));
        // Free destination: lands.
        std::fs::write(&tmp, "new").unwrap();
        commit_download(&RealFs, &tmp, &dest, &bak, false).unwrap();
        assert_eq!(read(&dest).as_deref(), Some("new"));
        // A file appeared there "after the prompt": never replaced.
        std::fs::write(&dest, "theirs").unwrap();
        std::fs::write(&tmp, "new").unwrap();
        let e = commit_download(&RealFs, &tmp, &dest, &bak, false).unwrap_err();
        assert!(e.contains("already exists"), "{e}");
        assert_eq!(read(&dest).as_deref(), Some("theirs"));
        assert!(!tmp.exists());
        // Without a no-replace rename, the hard link still refuses atomically.
        std::fs::write(&tmp, "new").unwrap();
        let fs = FailFs::new(&[("noreplace", 0)]);
        let e = commit_download(&fs, &tmp, &dest, &bak, false).unwrap_err();
        assert!(e.contains("already exists"), "{e}");
        assert_eq!(read(&dest).as_deref(), Some("theirs"));
        // ...and with a free destination, the link puts it in place.
        std::fs::remove_file(&dest).unwrap();
        std::fs::write(&tmp, "new").unwrap();
        commit_download(&FailFs::new(&[("noreplace", 0)]), &tmp, &dest, &bak, false).unwrap();
        assert_eq!(read(&dest).as_deref(), Some("new"));
        assert!(!tmp.exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// W3 P1: on a filesystem with no atomic no-replace, `Never` used to check
    /// and then rename over the destination, so a file created in between was
    /// lost. Now it never renames over anything: it fails, keeping both.
    #[test]
    fn download_never_never_overwrites_a_late_file_without_atomic_noreplace() {
        let d = commit_dir("late");
        let (tmp, dest, bak) = (d.join(".h.x.hawserpart"), d.join("h"), d.join(".h.x.hawserbak"));
        std::fs::write(&tmp, "new").unwrap();
        let e = commit_download(&RacyFs { dest: dest.clone() }, &tmp, &dest, &bak, false).unwrap_err();
        assert!(e.contains("choose Replace") && e.contains(&tmp.display().to_string()), "{e}");
        // Nothing was renamed to the destination at all (RacyFs would have
        // planted "theirs" and then clobbered it).
        assert!(!dest.exists());
        assert_eq!(read(&tmp).as_deref(), Some("new"));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Cancel and Begin share one lock: whichever order they land in, and
    /// however they interleave, a cancel is never lost.
    #[test]
    fn transfer_cancel_is_never_lost_to_registration() {
        let reg = Arc::new(Registry::default());
        for round in 0..2000 {
            let id = format!("t{round}");
            let (r1, r2) = (Arc::clone(&reg), Arc::clone(&reg));
            let id2 = id.clone();
            let canceller = std::thread::spawn(move || r1.transfer_cancel(&id2));
            let begun = r2.transfer_begin(&id);
            canceller.join().unwrap();
            match begun {
                Err(SshError::TransferCancelled) => {}
                Ok((seq, rx)) => {
                    assert!(*rx.borrow(), "round {round}: cancel lost");
                    reg.transfer_end(&id, seq);
                }
                Err(e) => panic!("{e}"),
            }
            // No marker left behind for a transfer that already saw the cancel.
            assert!(reg.transfers.lock().unwrap().early_cancels.get(&id).is_none(), "round {round}");
        }
    }

    #[tokio::test]
    async fn local_staging_is_exclusive_private_and_in_the_destination_folder() {
        let d = commit_dir("stage");
        let dest = d.join("x".repeat(250));
        let (a, _fa) = create_local_staging(&dest).await.unwrap();
        let (b, _fb) = create_local_staging(&dest).await.unwrap();
        assert_ne!(a, b);
        assert_eq!(a.parent(), Some(d.as_path()));
        assert!(a.file_name().unwrap().len() <= NAME_MAX);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&a).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    // The pump that awaits forward teardown can be aborted by a reconnect or a
    // tab close. Cut off at its first await, no listener or tunnel survives.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn forward_teardown_survives_its_caller_being_dropped() {
        async fn bind() -> (tokio::net::TcpListener, u16) {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let p = l.local_addr().unwrap().port();
            (l, p)
        }
        async fn port_free(port: u16) -> bool {
            for _ in 0..100 {
                if tokio::net::TcpListener::bind(("127.0.0.1", port)).await.is_ok() {
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            false
        }

        let (accepting, listen_port) = bind().await;
        let (tunnel_sock, tunnel_port) = bind().await;
        let listener = tokio::spawn(async move {
            loop {
                let _ = accepting.accept().await;
            }
        });
        let tunnel = tokio::spawn(async move {
            let _held = tunnel_sock;
            std::future::pending::<()>().await
        });
        let fw = Forward {
            info: ForwardInfo {
                id: "fw-t-1".into(),
                session_id: "t".into(),
                local_port: listen_port,
                remote_host: "r".into(),
                remote_port: 1,
                kind: "local",
            },
            generation: 1,
            listener,
            tunnels: Arc::new(std::sync::Mutex::new(vec![tunnel])),
        };

        // Poll the teardown once (to its first await), then drop it.
        tokio::select! {
            biased;
            _ = teardown_forwards(vec![fw]) => {}
            _ = std::future::ready(()) => {}
        }
        assert!(port_free(listen_port).await, "a listener outlived its teardown");
        assert!(port_free(tunnel_port).await, "a tunnel outlived its teardown");
    }
}

/// An in-process SFTP server (russh + russh-sftp over a real SSH session),
/// for the transfer commit paths.
#[cfg(all(test, unix))]
#[path = "tests/sftp_harness.rs"]
mod sftp_harness;
