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
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::FileType;
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
/// After the shell's EOF, how long to wait for its exit status or channel close
/// before treating the shell as gone. OpenSSH sends both at once.
const SHELL_EOF_GRACE: Duration = Duration::from_secs(2);

/// Minimum gap between progress events for one transfer. At 64 KB chunks an
/// unthrottled emit would fire ~16k times per gigabyte; the IPC bridge and
/// React would both spend more time on bookkeeping than on the transfer.
const PROGRESS_INTERVAL: Duration = Duration::from_millis(100);

const CHUNK: usize = 64 * 1024;

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
    /// A connect stage ran past its deadline (see the `*_TIMEOUT` constants).
    #[error("{host}: {stage} timed out after {secs}s")]
    Timeout { host: String, stage: &'static str, secs: u64 },
    /// The server answered the shell request with a refusal.
    #[error(
        "{host} refused to start a shell (the account may be SFTP-only or have no login \
         shell)"
    )]
    ShellRefused { host: String },
    #[error("{0}")]
    Connect(String),
    /// The tab that started this connect was closed before it finished.
    #[error("connection {0} was cancelled")]
    Cancelled(String),
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
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferProgress {
    pub session_id: String,
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

/// Host-key algorithms to offer, pinned ones first (as OpenSSH orders them):
/// a host pinned as ECDSA that later also offers Ed25519 keeps signing with the
/// pinned key instead of being refused as CHANGED. Only algorithms russh
/// implements are offered; an RSA pin covers all three RSA signature names.
fn preferred_host_key_order(pinned: &[russh::keys::Algorithm]) -> Vec<russh::keys::Algorithm> {
    use russh::keys::{Algorithm, HashAlg};
    let defaults: &[Algorithm] = &russh::Preferred::DEFAULT.key;
    let mut out: Vec<Algorithm> = Vec::with_capacity(defaults.len());
    let mut push = |a: Algorithm| {
        if defaults.contains(&a) && !out.contains(&a) {
            out.push(a);
        }
    };
    for alg in pinned {
        if matches!(alg, Algorithm::Rsa { .. }) {
            push(Algorithm::Rsa { hash: Some(HashAlg::Sha512) });
            push(Algorithm::Rsa { hash: Some(HashAlg::Sha256) });
            push(Algorithm::Rsa { hash: None });
        } else {
            push(alg.clone());
        }
    }
    for alg in defaults {
        push(alg.clone());
    }
    out
}

/// Client config for one hop: keepalives (what makes a dropped link
/// detectable: three missed 15s keepalives end it after ~45s) and the host-key
/// algorithm order for that host.
fn hop_config(host: &str, port: u16) -> Arc<client::Config> {
    let pinned = known_hosts::pinned_algorithms(host, port);
    let mut preferred = russh::Preferred::default();
    preferred.key = std::borrow::Cow::Owned(preferred_host_key_order(&pinned));
    Arc::new(client::Config {
        keepalive_interval: Some(Duration::from_secs(15)),
        keepalive_max: 3,
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

/// SSH identification + key exchange over `stream`, under `HANDSHAKE_TIMEOUT`.
async fn handshake<S>(
    config: Arc<client::Config>,
    stream: S,
    handler: ClientHandler,
    wait: &HumanWait,
) -> Result<Handle<ClientHandler>, SshError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let host = format!("{}:{}", handler.host, handler.port);
    within(
        wait,
        HANDSHAKE_TIMEOUT,
        &host,
        "SSH handshake (no SSH banner, or the key exchange stalled)",
        client::connect_stream(config, stream, handler),
    )
    .await?
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
        let rx = register_and_emit(
            &self.prompts.pending,
            &request_id,
            self.owner.clone(),
            || {
                was_cancelled = self.cancelled();
                was_cancelled
            },
            || self.app.emit("ssh://host-key-prompt", request).is_ok(),
        );
        let Some(rx) = rx else {
            return Err(if was_cancelled {
                SshError::Cancelled(self.owner.0.clone())
            } else {
                SshError::HostKeyRejected { host: self.host.clone() }
            });
        };

        let end = {
            let _human = self.wait.enter();
            await_host_key_answer(rx, HOST_KEY_PROMPT_TIMEOUT).await
        };
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
        settle_host_key(&end, &self.host, self.port, server_public_key, &store)
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
        SshError::Russh(russh::Error::KeepaliveTimeout) => {
            "no reply to keepalives for 45s (the network path or VPN dropped)".into()
        }
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
    shell: Mutex<Option<ChannelWriteHalf<client::Msg>>>,
    sftp: Mutex<Option<Arc<SftpSession>>>,
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
}

/// Generation counter for `Registry::connecting`.
static CONNECT_SEQ: AtomicU64 = AtomicU64::new(1);
static COPY_ID_SEQ: AtomicU64 = AtomicU64::new(0);

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
async fn open_shell(
    handle: &Handle<ClientHandler>,
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
                return Err(SshError::Connect(format!(
                    "{host} closed the session before the shell started"
                )))
            }
            Some(other) => early.push(other),
        }
    }
    if !replies[1] {
        return Err(SshError::ShellRefused { host: host.to_string() });
    }
    Ok((read_half, write_half, early, replies[0]))
}

impl Registry {
    /// The endpoint identity of a live session (see `Session::endpoint`).
    pub fn endpoint_of(&self, id: &str) -> Result<String, SshError> {
        Ok(self.get(id)?.endpoint.clone())
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
        for fw in take_forwards(&self.forwards, |f| f.info.session_id == id) {
            teardown_forward(fw).await;
        }
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
    pub async fn connect(
        &self,
        app: AppHandle,
        prompts: Arc<HostKeyPrompts>,
        auth_prompts: Arc<AuthPrompts>,
        spec: ConnectSpec,
    ) -> Result<(), SshError> {
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
    ) -> Result<(), SshError> {
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
                authorize_stored_password(&auth, &host_id, host, port, username, true)?;
                Some(p)
            }
            None => authorize_stored_password(&auth, &host_id, host, port, username, false)?,
        };
        let jump_secret = match jump.as_ref() {
            Some(j) => authorize_stored_password(&j.auth, &j.host_id, &j.host, j.port, &j.username, false)?,
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
                };
                let mut jh = handshake(hop_config(&j.host, j.port), tcp, jump_handler, &wait).await?;
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
                let jlabel = format!("{}:{}", j.host, j.port);
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
                };
                let h = handshake(hop_config(host, port), tunnel.into_stream(), handler, &wait).await?;
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
                };
                (handshake(hop_config(host, port), tcp, handler, &wait).await?, None)
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

        // Optional first line of input. Written as input rather than via
        // request_exec so it degrades gracefully: if the command does not exist
        // the user sees "command not found" and still has a working shell,
        // whereas a failed exec would close the channel and look like a broken
        // connection.
        // Order matters and is the user's: a `tmux new-session` first means every
        // later line runs *inside* tmux, which is usually what is wanted.
        for cmd in startup_commands.iter().map(|c| c.trim()).filter(|c| !c.is_empty()) {
            let line = format!("{cmd}\n");
            write_half.data(line.as_bytes()).await?;
        }

        let session = Arc::new(Session {
            handle,
            shell: Mutex::new(Some(write_half)),
            sftp: Mutex::new(None),
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
        let (go_tx, go_rx) = oneshot::channel::<Option<SessionLog>>();
        let pump = tokio::spawn(run_pump(
            app.clone(),
            session_id.to_string(),
            Arc::clone(&session),
            read_half,
            early,
            go_rx,
            death,
            Arc::clone(&self.forwards),
        ));

        // Register only while our ticket is still current, holding the
        // `connecting` entry (a shard lock, no await) so a concurrent
        // `remove()` — which deletes that entry first — either runs before us
        // (we see no ticket and do not register) or after us (it finds and
        // tears down what we registered). Never `remove()` by id here: a newer
        // connect may own this id now, and that would cancel or tear down ITS
        // session instead of ours.
        let mut pump = Some(pump);
        let registered = match self.connecting.get(session_id) {
            Some(g) if g.0 == ticket => {
                self.sessions
                    .insert(session_id.to_string(), Arc::clone(&session));
                if let Some(p) = pump.take() {
                    self.pumps.insert(session_id.to_string(), p);
                }
                true
            }
            _ => false,
        };
        if !registered {
            // Superseded or cancelled: tear down only this attempt's own
            // resources. Detached, because the cancel that brought us here also
            // makes `connect`'s select drop this future at its next await — an
            // inline teardown would be cut off half-way. The pump never got its
            // go signal, so it has emitted nothing.
            if let Some(p) = pump.take() {
                p.abort();
            }
            session.alive.store(false, Ordering::SeqCst);
            tokio::spawn(async move { session.close("cancelled").await });
            return Err(SshError::Cancelled(session_id.to_string()));
        }

        // Transcript. Degraded to None rather than propagated: losing a log
        // must never take down a working connection.
        let topic = format!("ssh://{session_id}");
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
        let _ = go_tx.send(log);

        Ok(())
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
    async fn sftp(&self, session_id: &str) -> Result<Arc<SftpSession>, SshError> {
        let session = self.get(session_id)?;
        if !session.alive.load(Ordering::Relaxed) {
            return Err(SshError::Disconnected(session_id.to_string()));
        }
        let mut guard = session.sftp.lock().await;
        if let Some(existing) = guard.as_ref() {
            return Ok(Arc::clone(existing));
        }

        let channel = session.handle.channel_open_session().await?;
        channel.request_subsystem(true, "sftp").await?;
        let sftp = Arc::new(SftpSession::new(channel.into_stream()).await?);
        *guard = Some(Arc::clone(&sftp));
        Ok(sftp)
    }

    /// Forget the cached SFTP session if `r` failed because its channel is gone
    /// (the sftp-server process exited or was killed while the SSH transport
    /// stayed up). Without this every later file operation reuses the dead
    /// session and fails until the whole tab is reconnected; with it the next
    /// call reopens the subsystem.
    async fn check_sftp<T>(&self, session_id: &str, r: Result<T, SshError>) -> Result<T, SshError> {
        use russh_sftp::client::error::Error as SftpErr;
        if let Err(SshError::Sftp(SftpErr::UnexpectedBehavior(_) | SftpErr::IO(_))) = &r {
            if let Ok(session) = self.get(session_id) {
                *session.sftp.lock().await = None;
            }
        }
        r
    }

    pub async fn list_dir(&self, session_id: &str, path: &str) -> Result<DirListing, SshError> {
        let first = self.list_dir_once(session_id, path).await;
        if matches!(first, Err(SshError::Sftp(_))) {
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
        let sftp = self.sftp(session_id).await?;
        let r = self.list_dir_with(&sftp, path).await;
        self.check_sftp(session_id, r).await
    }

    async fn list_dir_with(&self, sftp: &SftpSession, path: &str) -> Result<DirListing, SshError> {
        // Resolve first so the pane shows the real location: the server may
        // return something different for ".", "~", or a symlinked directory.
        let canonical = sftp
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

        for entry in sftp.read_dir(&canonical).await? {
            let meta = entry.metadata();
            let kind = match entry.file_type() {
                FileType::Dir => "directory",
                FileType::Symlink => "symlink",
                _ => "file",
            };
            entries.push(FileEntry {
                name: entry.file_name(),
                kind,
                size: meta.size.unwrap_or(0),
                modified: meta.mtime,
                mode: mode_string(meta.permissions, kind),
            });
        }

        Ok(DirListing {
            path: canonical,
            entries,
        })
    }

    /// Whether a remote path exists — the overwrite guard asks before a
    /// transfer clobbers something already there.
    pub async fn sftp_exists(&self, session_id: &str, path: &str) -> Result<bool, SshError> {
        let sftp = self.sftp(session_id).await?;
        Ok(sftp.metadata(path).await.is_ok())
    }

    /// Rename a remote file or directory. SFTP rename is not a copy — it is
    /// the server's own rename, atomic where the filesystem allows.
    pub async fn sftp_rename(&self, session_id: &str, from: &str, to: &str) -> Result<(), SshError> {
        let sftp = self.sftp(session_id).await?;
        let r = sftp.rename(from, to).await.map_err(SshError::from);
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
            sftp.remove_dir(path).await
        } else {
            sftp.remove_file(path).await
        };
        self.check_sftp(session_id, r.map_err(SshError::from)).await
    }

    /// Create a remote directory.
    pub async fn sftp_mkdir(&self, session_id: &str, path: &str) -> Result<(), SshError> {
        let sftp = self.sftp(session_id).await?;
        let r = sftp.create_dir(path).await.map_err(SshError::from);
        self.check_sftp(session_id, r).await
    }

    /* ------------------------------------------------------------ phase 2 */

    /// Download, streamed and reporting byte-accurate progress.
    ///
    /// Streaming rather than read-to-end is not only about memory: it is what
    /// makes progress reportable at all. Chunks are 64 KB; events are throttled
    /// to one per PROGRESS_INTERVAL with a guaranteed final event so the UI
    /// always lands on 100%.
    pub async fn download(
        &self,
        app: &AppHandle,
        session_id: &str,
        remote: &str,
        local: &str,
    ) -> Result<u64, SshError> {
        let sftp = self.sftp(session_id).await?;

        // A directory recurses; a file copies directly. Walking the tree
        // iteratively (a worklist, not async recursion) keeps this a plain
        // function with no Box::pin ceremony.
        let is_dir = sftp
            .metadata(remote)
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
            return copy_remote_file(&sftp, app, session_id, remote, local, ProgressCtx::single(remote))
                .await;
        }

        // Everything from `local` downward is built from server-chosen names and
        // is therefore untrusted; the folder that CONTAINS `local` is the one the
        // user actually picked and is the trust boundary. Any pre-existing symlink
        // or junction below it must not be followed. (`local` always has a parent
        // here: `safe_local_component` above rejected an empty final component.)
        let root = std::path::Path::new(local)
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .to_path_buf();

        let mut total = 0u64;
        let mut failed: Vec<String> = Vec::new();
        // Bound the walk so a malicious or misconfigured server advertising a
        // pathologically deep/wide tree cannot grow the worklist without limit.
        const MAX_DIRS: usize = 50_000;
        let mut visited = 0usize;
        let mut dirs = vec![(remote.to_string(), local.to_string())];
        while let Some((rdir, ldir)) = dirs.pop() {
            visited += 1;
            // The root failing is a real error; a subdirectory failing is one
            // more item in the tally, like an unreadable file (see below).
            let is_root = visited == 1;
            if visited > MAX_DIRS {
                let reason = format!(
                    "directory limit ({MAX_DIRS}) reached — tree too large; remainder skipped"
                );
                // Empty paths: not retryable — a retry would re-run the whole tree.
                emit_transfer_failure(app, session_id, remote, "(tree)", "", "", reason.clone(), "download");
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
                Ok(()) => sftp.read_dir(&rdir).await.map_err(SshError::from),
            };
            let listing = match listing {
                Ok(l) => l,
                Err(e) if is_root => return Err(e),
                Err(e) => {
                    emit_transfer_failure(app, session_id, remote, &dir_name, &ldir, &rdir, format!("{e}"), "download");
                    failed.push(format!("{rdir}: {e}"));
                    continue;
                }
            };
            for entry in listing {
                let name = entry.file_name();
                let rpath = format!("{}/{}", rdir.trim_end_matches('/'), name);
                // The server chose this name; refuse anything that is not a
                // plain component before it becomes a local path.
                if !safe_local_component(&name) {
                    let reason = format!("{name} (unsafe name, skipped)");
                    emit_transfer_failure(app, session_id, remote, &name, "", &rpath, reason.clone(), "download");
                    failed.push(reason);
                    continue;
                }
                let lpath = std::path::Path::new(&ldir)
                    .join(&name)
                    .to_string_lossy()
                    .to_string();
                let ft = entry.file_type();
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
                    let reason = format!("{rpath} (symlink, skipped)");
                    emit_transfer_failure(app, session_id, remote, &name, "", &rpath, "symlink, skipped".into(), "download");
                    failed.push(reason);
                } else {
                    // One unreadable file must not abort the other 499: keep
                    // walking, collect what failed, report the tally at the end.
                    let ctx = ProgressCtx { root: remote, base: total, tree: true };
                    match copy_remote_file(&sftp, app, session_id, &rpath, &lpath, ctx).await {
                        Ok(n) => total += n,
                        Err(e) => {
                            emit_transfer_failure(app, session_id, remote, &name, &lpath, &rpath, format!("{e}"), "download");
                            failed.push(format!("{rpath}: {e}"));
                        }
                    }
                }
            }
        }
        if failed.is_empty() {
            Ok(total)
        } else {
            Err(SshError::PartialTransfer(format!(
                "copied {} bytes; {} item(s) not transferred — first: {}",
                total,
                failed.len(),
                failed[0]
            )))
        }
    }

    /// Upload, same streaming and reporting contract, directory-aware.
    pub async fn upload(
        &self,
        app: &AppHandle,
        session_id: &str,
        local: &str,
        remote: &str,
    ) -> Result<u64, SshError> {
        let sftp = self.sftp(session_id).await?;

        let is_dir = tokio::fs::metadata(local)
            .await
            .map(|m| m.is_dir())
            .unwrap_or(false);

        if !is_dir {
            return copy_local_file(&sftp, app, session_id, local, remote, ProgressCtx::single(local))
                .await;
        }

        let mut total = 0u64;
        let mut failed: Vec<String> = Vec::new();
        const MAX_DIRS: usize = 50_000;
        let mut visited = 0usize;
        let mut dirs = vec![(local.to_string(), remote.to_string())];
        while let Some((ldir, rdir)) = dirs.pop() {
            visited += 1;
            let is_root = visited == 1;
            if visited > MAX_DIRS {
                let reason = format!(
                    "directory limit ({MAX_DIRS}) reached — tree too large; remainder skipped"
                );
                // Empty paths: not retryable — a retry would re-run the whole tree.
                emit_transfer_failure(app, session_id, local, "(tree)", "", "", reason.clone(), "upload");
                failed.push(reason);
                break;
            }
            // create_dir on an existing directory is an error over SFTP; ignore
            // it so re-uploading into a partially-present tree just works.
            let _ = sftp.create_dir(&rdir).await;
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
                    emit_transfer_failure(app, session_id, local, &dir_name, &ldir, &rdir, format!("{e}"), "upload");
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
                        emit_transfer_failure(app, session_id, local, &name, &lpath, &rpath, format!("{e}"), "upload");
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
                    emit_transfer_failure(app, session_id, local, &name, "", &rpath, "symlink, skipped".into(), "upload");
                    failed.push(format!("{lpath} (symlink, skipped)"));
                } else {
                    let ctx = ProgressCtx { root: local, base: total, tree: true };
                    match copy_local_file(&sftp, app, session_id, &lpath, &rpath, ctx).await {
                        Ok(n) => total += n,
                        Err(e) => {
                            emit_transfer_failure(app, session_id, local, &name, &lpath, &rpath, format!("{e}"), "upload");
                            failed.push(format!("{lpath}: {e}"));
                        }
                    }
                }
            }
        }
        if failed.is_empty() {
            Ok(total)
        } else {
            Err(SshError::PartialTransfer(format!(
                "copied {} bytes; {} item(s) not transferred — first: {}",
                total,
                failed.len(),
                failed[0]
            )))
        }
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
            teardown_forward(old).await;
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
                teardown_forward(ours).await;
            }
            return Err(SshError::Disconnected(sid));
        }
        Ok(())
    }

    /// Stop one forward: its listener first, then every live tunnel, so no
    /// traffic keeps flowing after the user stops it (see `teardown_forward`).
    pub async fn forward_stop(&self, forward_id: &str) {
        if let Some((_, fw)) = self.forwards.remove(forward_id) {
            teardown_forward(fw).await;
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
        self.copy_ids.insert(op.clone(), (seq, tx));
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

    /// Cancel an in-flight `copy_id_run`. Unknown ids are ignored.
    pub fn copy_id_cancel(&self, op_id: &str) {
        self.copy_ids.remove(op_id);
    }
}

impl Registry {
    /// Run one command on a fresh exec channel and capture its output.
    ///
    /// Exec, not the interactive shell: capturing through the user's live
    /// terminal would splatter a full config dump across whatever they were
    /// doing. A separate channel keeps the capture invisible and gives a clean
    /// EOF to stop at. The trade-off is that some appliances only speak
    /// interactive shells and refuse exec — those fail here with the server's
    /// own error, which the UI surfaces as "this device may not support
    /// command capture".
    pub async fn exec_capture(
        &self,
        session_id: &str,
        command: &str,
        timeout_secs: u64,
    ) -> Result<String, SshError> {
        let session = self.get(session_id)?;
        if !session.alive.load(Ordering::Relaxed) {
            return Err(SshError::Disconnected(session_id.to_string()));
        }

        let mut channel = session.handle.channel_open_session().await?;
        channel.exec(true, command).await?;
        let run = run_exec(&mut channel, 16 * 1024 * 1024, Duration::from_secs(timeout_secs)).await;

        // Don't pass off a partial or failed capture as a valid snapshot:
        //  - timed out   -> we have no idea if the config finished printing
        //  - truncated   -> hit the size cap mid-dump
        //  - unconfirmed -> the channel/transport ended before the server
        //    confirmed the run (EOF, then a status or close)
        //  - killed / exit != 0 -> the command itself reported failure (a
        //    missing status after EOF + close is tolerated: much network gear
        //    never sends one over exec)
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
                "capture command was killed by signal {sig}"
            )));
        }
        if let Some(code) = run.exit_status {
            if code != 0 {
                return Err(SshError::PartialTransfer(format!(
                    "capture command exited with status {code}"
                )));
            }
        }
        let out = run.out;

        let (clean, _) = crate::utils::session_log::strip_ansi(&out);
        Ok(String::from_utf8_lossy(&clean).to_string())
    }
}

/// How an exec channel's run ended, as far as the server confirmed it.
struct ExecRun {
    out: Vec<u8>,
    exit_status: Option<u32>,
    /// Name of the signal that killed the command (`exit-signal`).
    signal: Option<String>,
    eof: bool,
    truncated: bool,
    timed_out: bool,
    /// The server confirmed the run finished: EOF, then an exit status/signal
    /// or a channel close (in either order). A transport that drops, or a
    /// close with no EOF first, is NOT confirmation.
    confirmed: bool,
}

/// Collect an exec channel's output under `deadline`, then close the channel.
///
/// Do not stop at EOF: OpenSSH sends the exit status AFTER EOF (when it reaps
/// the child), while other stacks send it before — so the run ends when the
/// second of {EOF, status/signal} arrives, or on close after EOF. No short
/// post-EOF grace: that passed off a command that closed its output and then
/// failed as success. A device that EOFs but never confirms now times out.
async fn run_exec(
    channel: &mut russh::Channel<client::Msg>,
    cap: usize,
    deadline: Duration,
) -> ExecRun {
    let mut run = ExecRun {
        out: Vec::new(),
        exit_status: None,
        signal: None,
        eof: false,
        truncated: false,
        timed_out: false,
        confirmed: false,
    };
    // These commands read no stdin. Send our EOF (like `ssh host cmd
    // </dev/null`) so stacks that wait for the peer's EOF before closing do.
    let _ = channel.eof().await;
    let collect = async {
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { ref data } | ChannelMsg::ExtendedData { ref data, .. } => {
                    run.out.extend_from_slice(data);
                    // A runaway command (`tail -f`) must not eat RAM until the
                    // deadline.
                    if run.out.len() > cap {
                        run.truncated = true;
                        return;
                    }
                }
                ChannelMsg::ExitStatus { exit_status } => run.exit_status = Some(exit_status),
                ChannelMsg::ExitSignal { signal_name, .. } => {
                    run.signal = Some(format!("{signal_name:?}"))
                }
                ChannelMsg::Eof => run.eof = true,
                ChannelMsg::Close => {
                    run.confirmed = run.eof;
                    return;
                }
                _ => {}
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
    // timed-out exec would leak a channel on the user's live session.
    let _ = channel.close().await;
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
fn authorize_stored_password(
    auth: &str,
    host_id: &str,
    host: &str,
    port: u16,
    username: &str,
    one_shot: bool,
) -> Result<Option<zeroize::Zeroizing<String>>, SshError> {
    // Ids in a reserved vault namespace (the AI provider key lives at `ai:…`)
    // are never host credentials: refuse them for every auth method, so no
    // host id can address — and send, or use as a passphrase — that secret.
    if credentials::is_reserved_id(host_id) {
        return Err(SshError::AuthFailed(format!(
            "refusing to use '{host_id}' as a host credential: it is a reserved vault id"
        )));
    }
    if one_shot || auth == "agent" {
        return Ok(None);
    }
    // No saved secret for this id → nothing to leak (a password is then asked
    // for). Only a definite NotFound counts as "no secret": any other vault
    // error (a locked keyring, a dismissed unlock prompt) fails CLOSED and is
    // reported as the vault problem it is.
    let secret = match credentials::read_secret(host_id) {
        Err(credentials::CredError::NotFound(_)) => return Ok(None),
        Err(e) => return Err(vault_error(host_id, e)),
        Ok(s) => s,
    };
    if auth == "key" {
        // A local passphrase: never transmitted, so no destination binding.
        return Ok(Some(secret));
    }
    if crate::utils::hosts::binding_is_authorized(host_id, host, port, username) {
        Ok(Some(secret))
    } else {
        Err(SshError::AuthFailed(format!(
            "refusing to send the saved credential '{host_id}' to {host}:{port} as {username}: \
             it is not an authorized saved destination for that credential"
        )))
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
                    if let Err(e) = credentials::write_secret(host_id, username, secret.as_str()) {
                        eprintln!("hawser: could not save password for {host_id}: {e}");
                    } else if let Err(e) =
                        crate::utils::hosts::snapshot_binding(host_id, host, port, username)
                    {
                        // The binding authorizes this exact destination for the
                        // credential (same pairing the host-editor save records).
                        // If it fails to persist, a saved secret with no binding is
                        // refused by the anti-exfiltration guard on the very next
                        // connect — fail-closed but confusing. Roll the secret back
                        // so the user is simply prompted again next time.
                        eprintln!(
                            "hawser: could not bind saved credential {host_id}: {e}; \
                             rolling back the saved password"
                        );
                        let _ = credentials::delete_secret(host_id);
                        crate::utils::hosts::remove_binding(host_id);
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
    let Some(rx) = register_and_emit(
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

    // The stage deadlines do not run while the human types.
    let _human = ctx.wait.enter();
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
    let key = public_key.trim();
    // The key is wrapped in single quotes in the remote command; a quote in it
    // would break out. Generated keys never contain one, but guard anyway.
    if key.contains('\'') || key.contains('\n') {
        return Err(SshError::AuthFailed(
            "public key contains illegal characters".into(),
        ));
    }

    // Same stage deadlines as a normal connect; the host-key check and any
    // keyboard-interactive challenge pause them while the user reads.
    let wait = HumanWait::default();
    let owner: PromptOwner = (session_id.to_string(), 0);
    let origin = PromptOrigin::new(None, username, host, port, None);
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
    };
    let mut handle = handshake(hop_config(host, port), tcp, handler, &wait).await?;

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
    let hlabel = format!("{host}:{port}");
    within(&wait, AUTH_TIMEOUT, &hlabel, "authentication", authenticate(&mut handle, spec, &ctx))
        .await??;

    // grep -qxF: only append if the exact line is not already present, so
    // running this twice does not duplicate the key. The append is BRACE-GROUPED
    // so the whole chain is conjunctive: HAWSER_KEY_OK is printed only if every
    // step — including the append — actually succeeded. (The earlier version
    // used `;` before chmod/echo, which printed the success marker even when the
    // append failed, e.g. a full or read-only home directory.)
    //
    // A file whose last line has no trailing newline gets one first (as
    // OpenSSH's ssh-copy-id does); otherwise the key is glued onto that line,
    // grep never sees it as its own line, and "success" is reported for a key
    // sshd cannot parse.
    let cmd = format!(
        "mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys \
         && {{ [ ! -s ~/.ssh/authorized_keys ] || [ -z \"$(tail -c 1 ~/.ssh/authorized_keys)\" ] \
               || printf '\\n' >> ~/.ssh/authorized_keys; }} \
         && {{ grep -qxF '{key}' ~/.ssh/authorized_keys || printf '%s\n' '{key}' >> ~/.ssh/authorized_keys; }} \
         && chmod 600 ~/.ssh/authorized_keys && echo HAWSER_KEY_OK"
    );

    let mut channel = within(
        &wait,
        CHANNEL_SETUP_TIMEOUT,
        &hlabel,
        "opening a session channel",
        handle.channel_open_session(),
    )
    .await??;
    channel.exec(true, cmd).await?;
    // A timeout is a failure, not a silent success: don't judge the run by
    // whatever partial output happened to arrive before the clock ran out.
    let run = run_exec(&mut channel, 1024 * 1024, Duration::from_secs(20)).await;
    let completed = !run.timed_out && !run.truncated && run.confirmed && run.signal.is_none();
    let (out, exit_status) = (run.out, run.exit_status);

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
    let _ = handle
        .disconnect(russh::Disconnect::ByApplication, "key installed", "")
        .await;
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
                Err(e) => errors.push(format!("OpenSSH agent: {e}")),
            }
        }
        // russh makes connect_pageant fallible; a missing Pageant is just "no
        // agent".
        if let Ok(mut pageant) = AgentClient::connect_pageant().await {
            match try_agent_identities(&mut pageant, handle, username, &mut rsa, &mut tried).await {
                Ok(Some(r)) => return Ok(Some(r)),
                Ok(None) => {}
                Err(e) => errors.push(format!("Pageant: {e}")),
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
                Err(e) => errors.push(format!("agent: {e}")),
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
/// agent is unreachable or holds no accepted key. `tried` counts attempts
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
    let Ok(identities) = agent.request_identities().await else {
        return Ok(None);
    };
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

/// Reject a remote-supplied name that could escape the local target directory.
///
/// A malicious or compromised server controls the filenames it lists, and on
/// download those names become LOCAL path components. A name like
/// `..\Windows\evil` — or an absolute path, which `Path::join` uses to
/// REPLACE the base entirely — would write outside the folder the user chose.
/// This is the scp/zip-slip class; the defense is to accept only plain file
/// names as path components.
fn safe_local_component(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.contains('\\')
        // Drive letters / alternate data streams are a Windows hazard only; on
        // macOS/Linux ':' is an ordinary filename character (timestamped logs).
        && !(cfg!(windows) && name.contains(':'))
        && !name.contains('\0')
        && !is_windows_reserved(name)
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

/// Push one per-file failure to the UI so a recursive transfer can report the
/// full list and offer a retry. Best-effort — a dropped event only costs detail.
#[allow(clippy::too_many_arguments)]
fn emit_transfer_failure(
    app: &AppHandle,
    session_id: &str,
    root: &str,
    name: &str,
    local: &str,
    remote: &str,
    reason: String,
    direction: &'static str,
) {
    let _ = app.emit(
        "sftp://failure",
        TransferFailure {
            session_id: session_id.to_string(),
            root: root.to_string(),
            name: name.to_string(),
            local: local.to_string(),
            remote: remote.to_string(),
            reason,
            direction,
        },
    );
}

/// Copy one remote file to a local path, streaming with progress.
async fn copy_remote_file(
    sftp: &SftpSession,
    app: &AppHandle,
    session_id: &str,
    remote: &str,
    local: &str,
    ctx: ProgressCtx<'_>,
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
    }

    let total = sftp.metadata(remote).await.ok().and_then(|m| m.size).unwrap_or(0);
    let mut src = sftp.open(remote).await?;

    // Stream to a unique temp file beside the destination, then atomically
    // rename over it. A failed/cancelled/interrupted transfer therefore never
    // destroys the existing file or leaves a truncated partial in its place.
    let tmp = temp_sibling(local);
    let copy_result: Result<u64, SshError> = async {
        let mut dst = tokio::fs::File::create(&tmp).await?;
        let mut reporter = Reporter::new(app, session_id, remote, total, "download", ctx);
        let mut buf = vec![0u8; CHUNK];
        let mut done = 0u64;
        loop {
            let n = src.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            dst.write_all(&buf[..n]).await?;
            done += n as u64;
            reporter.tick(done);
        }
        dst.flush().await?;
        reporter.finish(done);
        Ok(done)
    }
    .await;

    // Close the remote read handle explicitly. Dropping the SFTP `File` does NOT
    // send SSH_FXP_CLOSE, so a recursive download of a large tree would leak one
    // server-side handle per file and eventually exhaust the server's limit —
    // the download-side twin of the upload handle leak. Best-effort: a close
    // failure must not fail an otherwise-complete transfer.
    let _ = src.close().await;

    match copy_result {
        Ok(done) => {
            // The temp was created with default permissions; an overwritten file
            // keeps the mode it had (a 0600 secret must not come back 0644).
            if let Some(meta) = existing.as_ref().filter(|m| m.is_file()) {
                let _ = tokio::fs::set_permissions(&tmp, meta.permissions()).await;
            }
            // Atomic replace. std::fs::rename replaces an existing file on both
            // Unix and Windows; if the platform refuses (e.g. dest locked),
            // fall back to remove-then-rename rather than lose the new content.
            if tokio::fs::rename(&tmp, local).await.is_err() {
                let _ = tokio::fs::remove_file(local).await;
                if let Err(e) = tokio::fs::rename(&tmp, local).await {
                    let _ = tokio::fs::remove_file(&tmp).await;
                    return Err(e.into());
                }
            }
            Ok(done)
        }
        Err(e) => {
            // Leave the original untouched; drop the partial temp.
            let _ = tokio::fs::remove_file(&tmp).await;
            Err(e)
        }
    }
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

/// A unique sibling path for atomic writes: `<name>.<n>.hawserpart`. The counter
/// makes concurrent transfers to the same directory collision-free.
fn temp_sibling(path: &str) -> String {
    static TMP_SEQ: AtomicU64 = AtomicU64::new(0);
    let n = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    format!("{path}.{n}.hawserpart")
}

/// Copy one local file to a remote path, streaming with progress.
async fn copy_local_file(
    sftp: &SftpSession,
    app: &AppHandle,
    session_id: &str,
    local: &str,
    remote: &str,
    ctx: ProgressCtx<'_>,
) -> Result<u64, SshError> {
    let local_meta = tokio::fs::metadata(local).await.ok();
    let total = local_meta.as_ref().map(|m| m.len()).unwrap_or(0);
    let mut src = tokio::fs::File::open(local).await?;

    // The temp-and-rename below replaces the remote inode, so its mode must be
    // carried over explicitly: an overwritten file keeps its own permissions (a
    // 0600 secret must not become 0644, a deploy script must keep +x); a new
    // file takes the local file's mode where the platform has one. Refuse up
    // front to replace a remote DIRECTORY with a file.
    // Only a definite "no such file" means the destination is new. Permission
    // denied (write-only dropboxes: SFTPGo upload-only users, ProFTPD
    // <Limit READ>) leaves it UNKNOWN: still upload, but never replace an
    // existing file whose mode we could not read — see `no_clobber` below. Any
    // other STAT failure aborts.
    use russh_sftp::protocol::StatusCode;
    let mut no_clobber = false;
    let remote_meta = match sftp.metadata(remote).await {
        Ok(m) => Some(m),
        Err(russh_sftp::client::error::Error::Status(st))
            if st.status_code == StatusCode::NoSuchFile =>
        {
            None
        }
        Err(russh_sftp::client::error::Error::Status(st))
            if st.status_code == StatusCode::PermissionDenied =>
        {
            no_clobber = true;
            None
        }
        Err(e) => {
            return Err(SshError::PartialTransfer(format!(
                "could not check whether {remote} already exists ({e}); not overwriting it"
            )))
        }
    };
    if remote_meta.as_ref().is_some_and(|m| m.file_type().is_dir()) {
        return Err(SshError::PartialTransfer(format!(
            "{remote} is a directory on the server; refusing to replace it with a file"
        )));
    }
    let mode = remote_meta
        .as_ref()
        .and_then(|m| m.permissions)
        .map(|p| p & 0o7777)
        .or_else(|| local_mode(local_meta.as_ref()))
        // Destination unknown: take the server's default rather than impose
        // the local mode on what may be an existing file.
        .filter(|_| !no_clobber);
    // Overwriting a file whose mode we know: it MUST survive the replace. A new
    // file's mode is only a best effort (the server's umask may trim it).
    let preserve_required = remote_meta.as_ref().and_then(|m| m.permissions).is_some();

    // Stream to a unique temp file beside the destination, then rename over it,
    // exactly as the download does. `sftp.create` truncates, so writing straight
    // to `remote` would destroy the existing file the moment the transfer began:
    // a connection drop, disk-full, or cancel would then leave a truncated
    // remote file with the original gone.
    let tmp = temp_sibling(remote);
    let copy_result: Result<u64, SshError> = async {
        // Created WITH the mode, so a secret is never briefly world-readable in
        // the temp; set again after the write because the server's umask may
        // have trimmed it at create time.
        let attrs = russh_sftp::protocol::FileAttributes {
            permissions: mode,
            ..Default::default()
        };
        let mut dst = sftp
            .open_with_flags_and_attributes(
                tmp.clone(),
                russh_sftp::protocol::OpenFlags::CREATE
                    | russh_sftp::protocol::OpenFlags::TRUNCATE
                    | russh_sftp::protocol::OpenFlags::WRITE,
                attrs,
            )
            .await?;
        let mut reporter = Reporter::new(app, session_id, local, total, "upload", ctx);
        let mut buf = vec![0u8; CHUNK];
        let mut done = 0u64;
        loop {
            let n = src.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            dst.write_all(&buf[..n]).await?;
            done += n as u64;
            reporter.tick(done);
        }
        if let Some(m) = mode {
            let set = dst
                .set_metadata(russh_sftp::protocol::FileAttributes {
                    permissions: Some(m),
                    ..Default::default()
                })
                .await;
            // FSETSTAT may be denied or unsupported. Retry by path (SETSTAT; the
            // temp is our own unique sibling), then accept it if the permission
            // bits match. Otherwise, for an overwrite, fail BEFORE the rename so
            // the original (and its permissions) stays. Special bits are not
            // compared: servers/kernels routinely strip setuid/setgid.
            if set.is_err() && preserve_required {
                let _ = sftp
                    .set_metadata(
                        tmp.clone(),
                        russh_sftp::protocol::FileAttributes {
                            permissions: Some(m),
                            ..Default::default()
                        },
                    )
                    .await;
                let actual = sftp
                    .metadata(tmp.clone())
                    .await
                    .ok()
                    .and_then(|md| md.permissions)
                    .map(|p| p & 0o777);
                if actual != Some(m & 0o777) {
                    // Close explicitly so it completes before the temp is
                    // removed (some servers cannot delete an open file).
                    let _ = dst.shutdown().await;
                    return Err(SshError::PartialTransfer(format!(
                        "could not preserve the permissions ({m:o}) of {remote}; left it unchanged"
                    )));
                }
            }
        }
        // shutdown (not just flush) closes the remote handle, which must happen
        // before the rename and also avoids leaking the SFTP handle.
        dst.shutdown().await?;
        reporter.finish(done);
        Ok(done)
    }
    .await;

    match copy_result {
        Ok(done) => {
            // Atomic replace. SSH_FXP_RENAME does not universally replace an
            // existing target, so if the direct rename fails, move the existing
            // file ASIDE to a backup (never delete it) before putting the new
            // one in place — so a second failure or a dropped connection cannot
            // destroy the original with nothing to recover.
            if let Err(e) = sftp.rename(tmp.clone(), remote.to_string()).await {
                // Existence/mode unknown: SFTPv3 RENAME does not overwrite, so a
                // failure likely means a file is there. Leave it alone.
                if no_clobber {
                    let _ = sftp.remove_file(tmp).await;
                    return Err(SshError::PartialTransfer(format!(
                        "{remote} may already exist and its permissions could not be read; \
                         not overwriting it ({e})"
                    )));
                }
                let bak = format!("{tmp}.bak");
                let _ = sftp.remove_file(bak.clone()).await; // clear any stale backup
                let moved = sftp.rename(remote.to_string(), bak.clone()).await.is_ok();
                match sftp.rename(tmp.clone(), remote.to_string()).await {
                    Ok(()) => {
                        if moved {
                            let _ = sftp.remove_file(bak).await;
                        }
                    }
                    Err(e) => {
                        // Restore the original rather than leave nothing behind.
                        if moved {
                            let _ = sftp.rename(bak, remote.to_string()).await;
                        }
                        let _ = sftp.remove_file(tmp).await;
                        return Err(e.into());
                    }
                }
            }
            Ok(done)
        }
        Err(e) => {
            // Leave the original untouched; drop the partial temp.
            let _ = sftp.remove_file(tmp).await;
            Err(e)
        }
    }
}

/* ------------------------------------------------------------- progress */

/// Throttled progress emitter. Kept as a small struct so both transfer
/// directions share one policy instead of duplicating the timing logic.
struct Reporter<'a> {
    app: &'a AppHandle,
    payload: TransferProgress,
    last: Instant,
    /// Bytes already moved by earlier files of the same tree.
    base: u64,
    /// Part of a folder transfer: the row's total is unknown, so never report
    /// one file's size (or completion) as the tree's.
    tree: bool,
}

/// Where a single file copy sits in its transfer, for progress reporting.
#[derive(Clone, Copy)]
struct ProgressCtx<'a> {
    root: &'a str,
    base: u64,
    tree: bool,
}

impl<'a> ProgressCtx<'a> {
    fn single(path: &'a str) -> Self {
        Self { root: path, base: 0, tree: false }
    }
}

impl<'a> Reporter<'a> {
    fn new(
        app: &'a AppHandle,
        session_id: &str,
        file_path: &str,
        total_bytes: u64,
        direction: &'static str,
        ctx: ProgressCtx<'_>,
    ) -> Self {
        let payload = TransferProgress {
            session_id: session_id.to_string(),
            root: ctx.root.to_string(),
            file_path: file_path.to_string(),
            bytes_transferred: ctx.base,
            total_bytes: if ctx.tree { 0 } else { total_bytes },
            direction,
            done: false,
        };
        // Emit once immediately so the row appears with a denominator rather
        // than sitting blank until the first interval elapses.
        let _ = app.emit("sftp://progress", payload.clone());
        Self {
            app,
            payload,
            last: Instant::now(),
            base: ctx.base,
            tree: ctx.tree,
        }
    }

    fn tick(&mut self, bytes: u64) {
        if self.last.elapsed() < PROGRESS_INTERVAL {
            return;
        }
        self.last = Instant::now();
        self.payload.bytes_transferred = self.base + bytes;
        let _ = self.app.emit("sftp://progress", self.payload.clone());
    }

    /// Always emitted, regardless of throttling, so the UI never stalls at 97%.
    fn finish(&mut self, bytes: u64) {
        self.payload.bytes_transferred = self.base + bytes;
        if !self.tree {
            if self.payload.total_bytes == 0 {
                self.payload.total_bytes = bytes;
            }
            self.payload.done = true;
        }
        let _ = self.app.emit("sftp://progress", self.payload.clone());
    }
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
) {
    let Ok(mut log) = go.await else { return };
    let topic = format!("ssh://{sid}");
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
    for fw in take_forwards(&forwards, |f| f.info.session_id == sid && f.generation == generation) {
        teardown_forward(fw).await;
    }
    session.close("session ended").await;
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
        assert!(!safe_local_component("CON"));
        assert!(!safe_local_component("nul")); // case-insensitive
        assert!(!safe_local_component("NUL.txt")); // extension ignored
        assert!(!safe_local_component("COM1"));
        assert!(!safe_local_component("LPT9"));
        // Names that merely start with a reserved stem are fine.
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
}
