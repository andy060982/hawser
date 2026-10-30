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
use tokio::sync::{oneshot, Mutex};

use crate::credentials;

/// How long a host-key prompt waits for a human before giving up. Long enough
/// to read a fingerprint off a phone, short enough that a forgotten dialog does
/// not pin a connection task forever.
const HOST_KEY_PROMPT_TIMEOUT: Duration = Duration::from_secs(120);

/// Minimum gap between progress events for one transfer. At 64 KB chunks an
/// unthrottled emit would fire ~16k times per gigabyte; the IPC bridge and
/// React would both spend more time on bookkeeping than on the transfer.
const PROGRESS_INTERVAL: Duration = Duration::from_millis(100);

const CHUNK: usize = 64 * 1024;

/// After an exec channel's EOF, how long to keep reading for the exit status
/// and close that normally follow it.
const EXIT_STATUS_GRACE: Duration = Duration::from_secs(2);

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
         server or an interception attempt. Skiff will not connect until the old entry is \
         removed by hand."
    )]
    ChangedHostKey { host: String, line: usize },
    #[error("{0}")]
    PartialTransfer(String),
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
    pub ip: String,
    pub port: u16,
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
}

/* -------------------------------------------------------------- host keys */

/// Bridges the async Handler to a human decision in the UI.
///
/// `check_server_key` runs inside russh's connection task and cannot block, so
/// it parks on a oneshot while the frontend shows a dialog. The matching sender
/// is handed back by the `host_key_respond` command.
#[derive(Default)]
pub struct HostKeyPrompts {
    /// request id -> (owning session id, answer channel). The session id lets a
    /// closed tab drop its own prompts instead of leaving them on screen.
    pending: DashMap<String, (String, oneshot::Sender<bool>)>,
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

    fn register(&self, request_id: String, session_id: &str) -> oneshot::Receiver<bool> {
        let (tx, rx) = oneshot::channel();
        self.pending.insert(request_id, (session_id.to_string(), tx));
        rx
    }

    fn cancel(&self, request_id: &str) {
        self.pending.remove(request_id);
    }

    /// Drop every prompt raised for `session_id`, returning their request ids so
    /// the UI can be told to close them. Dropping the sender rejects the key,
    /// which aborts that in-flight connect.
    pub fn cancel_session(&self, session_id: &str) -> Vec<String> {
        cancel_for_session(&self.pending, session_id)
    }
}

/// Remove all pending prompts owned by `session_id` from a prompt map.
fn cancel_for_session<T>(
    pending: &DashMap<String, (String, oneshot::Sender<T>)>,
    session_id: &str,
) -> Vec<String> {
    let ids: Vec<String> = pending
        .iter()
        .filter(|e| e.value().0 == session_id)
        .map(|e| e.key().clone())
        .collect();
    for id in &ids {
        pending.remove(id);
    }
    ids
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
    /// When true, the dialog offers a "save to the OS vault" checkbox. Only set
    /// for the up-front "no saved password" prompt — never for a live server
    /// challenge (an OTP or token code is single-use and must not be stored).
    pub offer_save: bool,
}

/// The user's answer to an auth prompt: one typed response per shown prompt,
/// plus whether they asked to save the password to the OS vault.
#[derive(Debug, Default)]
pub struct AuthAnswer {
    pub answers: Vec<String>,
    pub save: bool,
}

/// Same oneshot bridge as `HostKeyPrompts`, but the answer is the typed
/// responses (one per echo prompt shown) plus the save choice. Resolved by
/// `auth_prompt_respond`.
#[derive(Default)]
pub struct AuthPrompts {
    /// request id -> (owning session id, answer channel); see HostKeyPrompts.
    pending: DashMap<String, (String, oneshot::Sender<AuthAnswer>)>,
}

impl AuthPrompts {
    /// Resolve a pending auth prompt with the user's typed answers and save choice.
    pub fn respond(&self, request_id: &str, answers: Vec<String>, save: bool) -> bool {
        match self.pending.remove(request_id) {
            Some((_, (_, tx))) => tx.send(AuthAnswer { answers, save }).is_ok(),
            None => false,
        }
    }

    fn register(&self, request_id: String, session_id: &str) -> oneshot::Receiver<AuthAnswer> {
        let (tx, rx) = oneshot::channel();
        self.pending.insert(request_id, (session_id.to_string(), tx));
        rx
    }

    /// Drop every prompt raised for `session_id` (see HostKeyPrompts). The
    /// waiting auth then fails as cancelled, so nothing is sent.
    pub fn cancel_session(&self, session_id: &str) -> Vec<String> {
        cancel_for_session(&self.pending, session_id)
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
    /// Resolved peer address, shown alongside the hostname so the user can see
    /// *which* machine answered — the distinction that matters when a name
    /// resolves somewhere unexpected.
    ip: String,
    port: u16,
    app: AppHandle,
    prompts: Arc<HostKeyPrompts>,
    /// The tab this connection belongs to, so closing it can drop the prompt.
    session_id: String,
}

impl client::Handler for ClientHandler {
    type Error = SshError;

    async fn check_server_key(
        &mut self,
        presented: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        // russh 0.63 hands us a key-or-certificate. Skiff pins the plain public
        // key; for a certificate we pin the embedded key. Either way the trust
        // decision below runs against a concrete PublicKey.
        let server_public_key = match presented {
            russh::keys::PublicKeyOrCertificate::PublicKey { key, .. } => key.clone(),
            russh::keys::PublicKeyOrCertificate::Certificate(cert) => {
                russh::keys::ssh_key::PublicKey::new(cert.public_key().clone(), "")
            }
        };
        let server_public_key = &server_public_key;
        // Tri-state, and the mapping is the whole security property:
        //   Trusted -> accept silently
        //   Changed -> refuse, never prompt
        //   Unknown -> ask a human
        match known_hosts::check(&self.host, self.port, server_public_key) {
            Ok(HostKeyStatus::Trusted) => return Ok(true),
            Ok(HostKeyStatus::Changed { line }) | Ok(HostKeyStatus::Revoked { line }) => {
                // Both refuse outright and never prompt: a different key for a
                // known host, or one explicitly revoked, is exactly the case a
                // trust dialog must never appear for.
                return Err(SshError::ChangedHostKey {
                    host: self.host.clone(),
                    line,
                })
            }
            Ok(HostKeyStatus::Unknown) => { /* fall through and ask */ }
            // A read/parse failure of the store fails CLOSED (refuse), rather
            // than routing to a first-use trust prompt.
            Err(e) => return Err(SshError::KnownHosts(e)),
        }

        let request_id = format!(
            "hk-{}-{}",
            self.host,
            HOSTKEY_SEQ.fetch_add(1, Ordering::Relaxed)
        );
        let fingerprint = server_public_key
            .fingerprint(russh::keys::HashAlg::Sha256)
            .to_string();

        let rx = self.prompts.register(request_id.clone(), &self.session_id);

        self.app
            .emit(
                "ssh://host-key-prompt",
                HostKeyRequest {
                    request_id: request_id.clone(),
                    host: self.host.clone(),
                    ip: self.ip.clone(),
                    port: self.port,
                    key_type: server_public_key.algorithm().to_string(),
                    fingerprint,
                },
            )
            .map_err(|_| SshError::HostKeyRejected {
                host: self.host.clone(),
            })?;

        match tokio::time::timeout(HOST_KEY_PROMPT_TIMEOUT, rx).await {
            Ok(Ok(true)) => {
                // Trust on first use, recorded so the next connection is silent.
                // Same store the check above reads — writing anywhere else would
                // mean re-prompting forever.
                known_hosts::trust(&self.host, self.port, server_public_key)?;
                Ok(true)
            }
            Ok(Ok(false)) => Err(SshError::HostKeyRejected {
                host: self.host.clone(),
            }),
            // Sender dropped, or nobody answered in time.
            Ok(Err(_)) => Err(SshError::HostKeyRejected {
                host: self.host.clone(),
            }),
            Err(_) => {
                self.prompts.cancel(&request_id);
                emit_prompt_closed(&self.app, &request_id);
                Err(SshError::HostKeyTimeout {
                    host: self.host.clone(),
                })
            }
        }
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
    /// The bastion connection, when this session rides a jump host. Held only
    /// so it is not dropped: dropping the jump Handle closes the tunnel under
    /// the target session's feet.
    _jump: Option<Handle<ClientHandler>>,
    /// Cleared by the output pump when the channel ends. Checked before every
    /// write so input into a dead session fails loudly instead of vanishing
    /// into a closed channel.
    alive: AtomicBool,
}

#[derive(Default)]
pub struct Registry {
    sessions: DashMap<String, Arc<Session>>,
    /// Output-pump task per session, so disconnect can stop it — otherwise the
    /// pump keeps an Arc<Session> (hence the SSH Handle) alive and blocks on
    /// `read_half.wait()` forever after the tab is "closed".
    pumps: DashMap<String, tokio::task::JoinHandle<()>>,
    /// Active local/SOCKS forwards, keyed by forward id. See `Forward`.
    forwards: DashMap<String, Forward>,
    /// Connects still in flight, session id -> generation. `remove` deletes the
    /// entry, which is how closing a tab mid-connect cancels it: the connect
    /// checks its generation at each step and before registering, and tears its
    /// own transport down instead of leaving a logged-in shell no tab owns.
    connecting: DashMap<String, u64>,
}

/// Generation counter for `Registry::connecting`.
static CONNECT_SEQ: AtomicU64 = AtomicU64::new(0);

/// Everything needed to tear a forward down *completely*.
///
/// Aborting only the listener stops new connections but leaves already-
/// established tunnels carrying traffic — a user who "stopped" a forward would
/// still be leaking through the live ones. So each forward also owns the abort
/// handles of the per-connection tunnel tasks it has spawned; tearing the
/// forward down aborts those too.
struct Forward {
    info: ForwardInfo,
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
            eprintln!("skiff: forward accept failed (retrying): {e}");
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
/// abort (and optionally await) them without holding the lock across `.await`.
fn take_tunnels(tunnels: &TunnelHandles) -> Vec<tokio::task::JoinHandle<()>> {
    match tunnels.lock() {
        Ok(mut v) => std::mem::take(&mut *v),
        Err(_) => Vec::new(),
    }
}

impl Registry {
    fn get(&self, id: &str) -> Result<Arc<Session>, SshError> {
        self.sessions
            .get(id)
            .map(|r| Arc::clone(r.value()))
            .ok_or_else(|| SshError::NoSession(id.to_string()))
    }

    /// Tear a session down for real: stop the pump, send an SSH disconnect so
    /// the transport actually closes (Handle's Drop does NOT close it), and
    /// sweep the session's forwards. Without the explicit disconnect the
    /// authenticated connection and remote shell keep running after the user
    /// thinks they have closed the tab.
    ///
    /// Teardown is awaited to completion before returning: `abort()` only
    /// *requests* cancellation, so a caller that returned as soon as abort was
    /// issued could report "disconnected" while the pump was still mid-poll,
    /// still holding its `Arc<Session>` (and thus the SSH `Handle`). Awaiting the
    /// aborted `JoinHandle`s makes "disconnected" mean the tasks have actually
    /// stopped and their session references are gone.
    pub async fn remove(&self, id: &str) {
        // Cancel a connect that has not registered yet (see `connecting`).
        self.connecting.remove(id);
        let session = self.sessions.remove(id).map(|(_, s)| s);

        // Stop the output pump first, and WAIT for it to unwind, so it has
        // dropped its Arc<Session> before we send the disconnect below — then
        // the only remaining Handle reference is ours. An aborted JoinHandle
        // resolves promptly (the pump blocks on a cancel-safe `read_half.wait()`)
        // with a cancellation error, which we discard.
        if let Some((_, pump)) = self.pumps.remove(id) {
            pump.abort();
            let _ = pump.await;
        }

        if let Some(session) = session {
            session.alive.store(false, Ordering::Relaxed);
            // Send SSH_MSG_DISCONNECT. Best-effort: if the link is already gone
            // this errors harmlessly. This closes the transport and, with it,
            // every channel — including any in-flight SFTP transfer, whose next
            // read/write then fails and unwinds rather than continuing against a
            // connection the user believes is closed.
            let _ = session
                .handle
                .disconnect(russh::Disconnect::ByApplication, "closed by user", "")
                .await;
        }

        // A forward's transport is this session; with it gone the listener
        // would sit accepting connections it can never tunnel, forever. Sweep
        // them here so closing a tab tears down its tunnels too, and await each
        // aborted listener so teardown is complete before we return.
        let doomed: Vec<String> = self
            .forwards
            .iter()
            .filter(|e| e.value().info.session_id == id)
            .map(|e| e.key().clone())
            .collect();
        for fid in doomed {
            if let Some((_, fw)) = self.forwards.remove(&fid) {
                // Abort AND await every live tunnel, then the listener, so
                // "disconnected" means the per-connection tunnel tasks have
                // actually unwound and dropped their channels — not merely that
                // cancellation was requested.
                for h in take_tunnels(&fw.tunnels) {
                    h.abort();
                    let _ = h.await;
                }
                fw.listener.abort();
                let _ = fw.listener.await;
            }
        }
    }

    /// Whether connect `ticket` for `id` is still wanted (no
    /// disconnect arrived for it since it started).
    fn still_wanted(&self, id: &str, ticket: u64) -> bool {
        self.connecting.get(id).is_some_and(|g| *g == ticket)
    }

    /// Open a connection, authenticate, and start an interactive shell.
    ///
    /// The password is read from the Windows Credential Manager here, held in a
    /// zeroizing buffer, and dropped as soon as authentication returns. It is
    /// never a parameter, never logged, and never sent to the webview.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect(
        &self,
        app: AppHandle,
        prompts: Arc<HostKeyPrompts>,
        auth_prompts: Arc<AuthPrompts>,
        session_id: &str,
        host_id: &str,
        host: &str,
        port: u16,
        username: &str,
        cols: u32,
        rows: u32,
        startup_commands: &[String],
        auth: &str,
        key_path: Option<&str>,
        jump: Option<JumpParams>,
        one_shot_password: Option<&str>,
    ) -> Result<(), SshError> {
        // A reconnect reuses the session id. Tear the previous connection down
        // first: replacing the map entry alone would leave its transport alive
        // (forward listeners hold their own Arc<Session>) and its forwards still
        // listed under this id.
        if self.sessions.contains_key(session_id) || self.pumps.contains_key(session_id) {
            self.remove(session_id).await;
        }
        let ticket = CONNECT_SEQ.fetch_add(1, Ordering::Relaxed);
        self.connecting.insert(session_id.to_string(), ticket);
        let result = self
            .connect_inner(
                app, prompts, auth_prompts, session_id, host_id, host, port, username, cols,
                rows, startup_commands, auth, key_path, jump, one_shot_password, ticket,
            )
            .await;
        // Clear our in-flight marker, but only if it is still ours.
        self.connecting.remove_if(session_id, |_, g| *g == ticket);
        result
    }

    #[allow(clippy::too_many_arguments)]
    async fn connect_inner(
        &self,
        app: AppHandle,
        prompts: Arc<HostKeyPrompts>,
        auth_prompts: Arc<AuthPrompts>,
        session_id: &str,
        host_id: &str,
        host: &str,
        port: u16,
        username: &str,
        cols: u32,
        rows: u32,
        startup_commands: &[String],
        auth: &str,
        key_path: Option<&str>,
        jump: Option<JumpParams>,
        one_shot_password: Option<&str>,
        ticket: u64,
    ) -> Result<(), SshError> {
        // Before dialing anything, refuse to send a saved password to a
        // destination the catalogue never bound it to (both the target and any
        // jump host). This fails fast, before we even connect to the requested
        // host, so a compromised frontend cannot use the connection itself as an
        // exfiltration channel for another host's stored secret.
        authorize_stored_password(auth, host_id, host, port, username, one_shot_password)?;
        if let Some(j) = jump.as_ref() {
            authorize_stored_password(&j.auth, &j.host_id, &j.host, j.port, &j.username, None)?;
        }

        // Resolve first so the prompt can show which machine actually answered.
        // Best-effort: a failure here is not fatal, the connect below will
        // produce a better error than we could.
        let ip = tokio::net::lookup_host((host, port))
            .await
            .ok()
            .and_then(|mut addrs| addrs.next())
            .map(|a| a.ip().to_string())
            .unwrap_or_else(|| host.to_string());

        // Keepalives are what make a dropped link *detectable*. Without them a
        // VPN drop or an idle firewall timeout leaves the socket open forever:
        // the read half never returns, so nothing ever reports a disconnect and
        // the UI keeps showing a live session. Three missed 15s keepalives tears
        // the connection down after ~45s.
        let config = Arc::new(client::Config {
            keepalive_interval: Some(Duration::from_secs(15)),
            keepalive_max: 3,
            nodelay: true,
            ..client::Config::default()
        });
        let self_prompts = Arc::clone(&prompts);
        let handler = ClientHandler {
            host: host.to_string(),
            ip,
            port,
            app: app.clone(),
            prompts,
            session_id: session_id.to_string(),
        };

        // With a jump host: dial the bastion, authenticate there, then open a
        // direct-tcpip channel to the real target and run the SSH handshake
        // over that stream — exactly what OpenSSH's ProxyJump does. The
        // bastion's own host key is checked and prompted like any other.
        let (mut handle, jump_handle) = match jump {
            Some(j) => {
                let jump_config = Arc::new(client::Config {
                    keepalive_interval: Some(Duration::from_secs(15)),
                    keepalive_max: 3,
                    nodelay: true,
                    ..client::Config::default()
                });
                let jump_ip = tokio::net::lookup_host((j.host.as_str(), j.port))
                    .await
                    .ok()
                    .and_then(|mut a| a.next())
                    .map(|a| a.ip().to_string())
                    .unwrap_or_else(|| j.host.clone());
                let jump_handler = ClientHandler {
                    host: j.host.clone(),
                    ip: jump_ip,
                    port: j.port,
                    app: app.clone(),
                    prompts: Arc::clone(&self_prompts),
                    session_id: session_id.to_string(),
                };
                let mut jh =
                    client::connect(jump_config, (j.host.as_str(), j.port), jump_handler).await?;
                authenticate(
                    &mut jh, &j.host_id, &j.host, j.port, &j.username, &j.auth,
                    j.key_path.as_deref(), None, &app, &auth_prompts, session_id,
                )
                .await?;
                if !self.still_wanted(session_id, ticket) {
                    let _ = jh
                        .disconnect(russh::Disconnect::ByApplication, "cancelled", "")
                        .await;
                    return Err(SshError::Cancelled(session_id.to_string()));
                }

                let tunnel = jh
                    .channel_open_direct_tcpip(host, port as u32, "127.0.0.1", 0)
                    .await?;
                let h =
                    client::connect_stream(config, tunnel.into_stream(), handler).await?;
                (h, Some(jh))
            }
            None => (
                client::connect(config, (host, port), handler).await?,
                None,
            ),
        };

        authenticate(
            &mut handle, host_id, host, port, username, auth, key_path, one_shot_password,
            &app, &auth_prompts, session_id,
        )
        .await?;

        // Interactive shell on its own channel.
        let channel = handle.channel_open_session().await?;
        let (mut read_half, write_half) = channel.split();

        write_half
            .request_pty(true, "xterm-256color", cols, rows, 0, 0, &[])
            .await?;
        write_half.request_shell(true).await?;

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
            let line = format!("{cmd}
");
            write_half.data(line.as_bytes()).await?;
        }

        // Output pump. Emits on the per-session topic TerminalPane subscribes
        // to. stderr (ExtendedData) is interleaved into the same stream, which
        // is what a real terminal does — separating it would reorder output.
        let pump_app = app.clone();
        let topic = format!("ssh://{session_id}");

        // Transcript. Opened here rather than inside the task so a failure is
        // visible immediately, and degraded to None rather than propagated:
        // losing a log must never take down a working connection.
        let mut log = SessionLog::create(host, username).ok();
        if let Some(l) = log.as_ref() {
            let _ = pump_app.emit(
                &topic,
                format!(
                    "\x1b[38;5;244mlogging to {}\x1b[0m\r\n",
                    l.path().display()
                ),
            );
        }

        // The session is registered BEFORE the pump starts so the pump can hold
        // a handle to it and clear the liveness flag when the channel ends.
        let session = Arc::new(Session {
            handle,
            shell: Mutex::new(Some(write_half)),
            sftp: Mutex::new(None),
            _jump: jump_handle,
            alive: AtomicBool::new(true),
        });
        self.sessions
            .insert(session_id.to_string(), Arc::clone(&session));

        let pump_session = Arc::clone(&session);
        let sid = session_id.to_string();

        let pump = tokio::spawn(async move {
            // Distinguishes a clean logout from a link that died under us. The
            // difference matters to the user: one is expected, the other means
            // "your VPN dropped" or "the firewall timed you out".
            let mut reason = "connection closed by remote";
            // Incomplete UTF-8 tails carried to the next chunk, one per stream:
            // a packet boundary can split a multi-byte character, and decoding
            // each chunk alone would print two U+FFFD for one real character.
            let mut pending_out: Vec<u8> = Vec::new();
            let mut pending_err: Vec<u8> = Vec::new();

            while let Some(msg) = read_half.wait().await {
                match msg {
                    ChannelMsg::Data { ref data } | ChannelMsg::ExtendedData { ref data, .. } => {
                        // Logged before display, so anything that reaches the
                        // screen is already durable if the app dies next.
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
                            let _ = pump_app.emit(&topic, text);
                        }
                    }
                    ChannelMsg::Eof | ChannelMsg::Close => {
                        reason = "session closed";
                        break;
                    }
                    ChannelMsg::ExitStatus { exit_status } => {
                        reason = if exit_status == 0 {
                            "shell exited"
                        } else {
                            "shell exited with an error"
                        };
                    }
                    _ => {}
                }
            }

            // Reaching here with no Eof/Close means `wait()` returned None: the
            // transport itself went away — keepalive failure, reset, or a
            // dropped route. That is the case the UI most needs told about.
            pump_session.alive.store(false, Ordering::Relaxed);

            if let Some(l) = log.as_mut() {
                l.footer(reason);
            }

            let _ = pump_app.emit(
                &topic,
                format!("\r\n\x1b[38;2;242;178;92m\u{25cf} disconnected\x1b[0m {reason}\r\n"),
            );
            let _ = pump_app.emit(
                "ssh://status",
                SessionStatusEvent {
                    session_id: sid,
                    status: "disconnected",
                    detail: reason.to_string(),
                },
            );
        });
        self.pumps.insert(session_id.to_string(), pump);

        // A disconnect that raced the registration above found nothing to tear
        // down; it did clear our marker, so finish the teardown ourselves.
        if !self.still_wanted(session_id, ticket) {
            self.remove(session_id).await;
            return Err(SshError::Cancelled(session_id.to_string()));
        }

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

        self.insert_forward(Forward {
            info: info.clone(),
            listener: task,
            tunnels,
        });
        Ok(info)
    }

    /// Register a forward. Ids are `<kind>-<session>-<port>`, so re-creating a
    /// forward on a port whose old listener died yields the same id; tear the
    /// old entry down rather than let `insert` silently detach its tunnels.
    fn insert_forward(&self, fw: Forward) {
        if let Some(old) = self.forwards.insert(fw.info.id.clone(), fw) {
            for h in take_tunnels(&old.tunnels) {
                h.abort();
            }
            old.listener.abort();
        }
    }

    /// Stop one forward: abort its live tunnels AND its listener, so no traffic
    /// keeps flowing after the user stops it — not just the listener.
    pub fn forward_stop(&self, forward_id: &str) {
        if let Some((_, fw)) = self.forwards.remove(forward_id) {
            for h in take_tunnels(&fw.tunnels) {
                h.abort();
            }
            fw.listener.abort();
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

        self.insert_forward(Forward {
            info: info.clone(),
            listener: task,
            tunnels,
        });
        Ok(info)
    }

    pub fn forwards_list(&self, session_id: Option<&str>) -> Vec<ForwardInfo> {
        self.forwards
            .iter()
            .map(|e| e.value().info.clone())
            .filter(|f| session_id.is_none_or(|sid| f.session_id == sid))
            .collect()
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

        let mut out: Vec<u8> = Vec::new();
        let mut truncated = false;
        let mut exit_status: Option<u32> = None;
        let collect = async {
            // Do not stop at EOF: OpenSSH sends the exit status AFTER EOF (when it
            // reaps the child), so breaking on Eof meant a failed command was
            // never seen as failed. After EOF, allow a short grace for the
            // status/close, for appliances that EOF but never close.
            let mut eof = false;
            loop {
                let msg = if eof {
                    match tokio::time::timeout(EXIT_STATUS_GRACE, channel.wait()).await {
                        Ok(m) => m,
                        Err(_) => break,
                    }
                } else {
                    channel.wait().await
                };
                let Some(msg) = msg else { break };
                match msg {
                    ChannelMsg::Data { ref data }
                    | ChannelMsg::ExtendedData { ref data, .. } => {
                        out.extend_from_slice(data);
                        // A config dump has a sane bound; a runaway command
                        // (someone snapshots `tail -f`) must not eat RAM
                        // until the timeout.
                        if out.len() > 16 * 1024 * 1024 {
                            truncated = true;
                            break;
                        }
                    }
                    ChannelMsg::ExitStatus { exit_status: code } => exit_status = Some(code),
                    ChannelMsg::Eof => eof = true,
                    ChannelMsg::Close => break,
                    _ => {}
                }
            }
        };
        // The timeout is the guard against commands that never EOF.
        let completed = tokio::time::timeout(Duration::from_secs(timeout_secs), collect)
            .await
            .is_ok();

        // Don't pass off a partial or failed capture as a valid snapshot:
        //  - timed out  -> we have no idea if the config finished printing
        //  - truncated  -> hit the size cap mid-dump
        //  - exit != 0  -> the command itself reported failure (missing status
        //    is tolerated: much network gear never sends one over exec)
        if !completed {
            return Err(SshError::PartialTransfer(format!(
                "capture timed out after {timeout_secs}s; output discarded"
            )));
        }
        if truncated {
            return Err(SshError::PartialTransfer(
                "capture exceeded 16 MiB; output discarded".into(),
            ));
        }
        if let Some(code) = exit_status {
            if code != 0 {
                return Err(SshError::PartialTransfer(format!(
                    "capture command exited with status {code}"
                )));
            }
        }

        let (clean, _) = crate::utils::session_log::strip_ansi(&out);
        Ok(String::from_utf8_lossy(&clean).to_string())
    }
}

/// Authenticate an open handle by the host's configured method.
///
/// Refuse to send a *stored password* to a destination the saved catalogue
/// never bound it to.
///
/// Only stored password auth transmits the vault secret to the server. Key auth
/// uses the vault entry as a local key passphrase (it decrypts the key here and
/// is never sent), and agent auth / a one-shot password carry no stored secret —
/// so those are exempt. When a stored password exists for `host_id`, the
/// destination must match a connection the user actually saved for that
/// credential (its own record, or one that borrows it via `credentialId`);
/// otherwise a compromised frontend could pair the id with an attacker's host
/// and read the secret off the wire.
fn authorize_stored_password(
    auth: &str,
    host_id: &str,
    host: &str,
    port: u16,
    username: &str,
    one_shot_password: Option<&str>,
) -> Result<(), SshError> {
    // Ids in a reserved vault namespace (the AI provider key lives at `ai:…`)
    // are never host credentials: refuse them for every auth method, so no
    // host id can address — and send, or use as a passphrase — that secret.
    if credentials::is_reserved_id(host_id) {
        return Err(SshError::AuthFailed(format!(
            "refusing to use '{host_id}' as a host credential: it is a reserved vault id"
        )));
    }
    if one_shot_password.is_some() || matches!(auth, "key" | "agent") {
        return Ok(());
    }
    // No saved secret for this id → nothing to leak; a bare password attempt
    // simply fails later if the server demands one. Only a definite NotFound
    // counts as "no secret": any other vault error (a locked keyring, a
    // dismissed unlock prompt) fails CLOSED, since the later read in
    // `authenticate` could succeed and send the secret unchecked.
    match credentials::read_secret(host_id) {
        Err(credentials::CredError::NotFound(_)) => return Ok(()),
        Err(e) => return Err(e.into()),
        Ok(_) => {}
    }
    if crate::utils::hosts::binding_is_authorized(host_id, host, port, username) {
        Ok(())
    } else {
        Err(SshError::AuthFailed(format!(
            "refusing to send the saved credential '{host_id}' to {host}:{port} as {username}: \
             it is not an authorized saved destination for that credential"
        )))
    }
}

/// Shared between the target connection and a jump-host connection so the
/// bastion supports the same three methods as any other host.
#[allow(clippy::too_many_arguments)]
async fn authenticate(
    handle: &mut Handle<ClientHandler>,
    host_id: &str,
    host: &str,
    port: u16,
    username: &str,
    auth: &str,
    key_path: Option<&str>,
    one_shot_password: Option<&str>,
    app: &AppHandle,
    auth_prompts: &Arc<AuthPrompts>,
    session_id: &str,
) -> Result<(), SshError> {
    let authed = match auth {
        // Private key file. The Credential Manager entry for this host, if
        // present, is used as the key's passphrase — one vault slot per host,
        // meaning either "password" or "key passphrase" depending on the auth
        // method, never both.
        "key" => {
            let path = key_path.ok_or_else(|| {
                SshError::AuthFailed(format!("{username}: no key file configured"))
            })?;
            let passphrase = credentials::read_secret(host_id).ok();
            let key = russh::keys::load_secret_key(path, passphrase.as_ref().map(|p| p.as_str()))
                .map_err(|e| SshError::AuthFailed(format!("could not load key {path}: {e}")))?;
            // RSA needs the strongest hash the server advertises; rsa-sha1 is
            // refused by modern OpenSSH. Non-RSA ignores it.
            let hash_alg = handle.best_supported_rsa_hash().await?.flatten();
            let key = russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), hash_alg);
            handle.authenticate_publickey(username, key).await?
        }

        // Running SSH agent: the OpenSSH agent service pipe, then Pageant.
        // Keys never leave the agent; it only signs.
        "agent" => {
            let hash_alg = handle.best_supported_rsa_hash().await?.flatten();
            match agent_auth(handle, username, hash_alg).await? {
                Some(result) => result,
                None => {
                    return Err(SshError::AuthFailed(format!(
                        "{username}: no SSH agent reachable (tried the OpenSSH agent                          pipe and Pageant), or the agent holds no accepted keys"
                    )))
                }
            }
        }

        // Password (default). A one-shot password (quick connect, never saved)
        // takes precedence over the vault; it lives only for this call.
        //
        // On failure, keyboard-interactive is tried with the same secret.
        // That fallback is what makes TACACS+-fronted network gear work:
        // many appliances advertise ONLY keyboard-interactive and then ask a
        // single hidden "Password:" question. Users should not need to know
        // which of the two dances their firewall does.
        _ => {
            // Hold the working copy in Zeroizing so it is wiped on EVERY exit
            // path: the old code copied the secret into a plain String and only
            // wiped it after both awaits succeeded, so a failed `?` between them
            // (or a cancellation) left the plaintext in the heap. read_secret
            // already returns Zeroizing; a one-shot password is wrapped to match.
            // The previous `unsafe { as_mut_vec().fill(0) }` is gone — fill(0) is
            // not a guaranteed zeroization primitive, and Zeroizing::drop is.
            // A password the user typed AND asked to save, held until we know it
            // actually authenticated — never persist a wrong guess.
            let mut save_typed: Option<zeroize::Zeroizing<String>> = None;
            let pw: zeroize::Zeroizing<String> = match one_shot_password {
                Some(p) => zeroize::Zeroizing::new(p.to_string()),
                None => match credentials::read_secret(host_id) {
                    Ok(secret) => secret,
                    // No saved password and none supplied for this connect: ask
                    // the user for it interactively rather than failing outright
                    // with "no saved credential". The prompt is hidden (masked),
                    // and the typed password comes INWARD via auth_prompt_respond
                    // — no stored secret is ever emitted outward, so the
                    // "secrets never cross IPC outward" invariant holds.
                    Err(credentials::CredError::NotFound(_)) => {
                        let answer = request_auth_answers(
                            app,
                            auth_prompts,
                            session_id,
                            "Password required",
                            &format!("Enter the password for {username}"),
                            vec![AuthPromptField { prompt: "Password:".into(), echo: false }],
                            true,
                        )
                        .await?;
                        let typed = zeroize::Zeroizing::new(
                            answer.answers.into_iter().next().unwrap_or_default(),
                        );
                        if answer.save {
                            save_typed = Some(typed.clone());
                        }
                        typed
                    }
                    Err(e) => return Err(e.into()),
                },
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
                    app,
                    auth_prompts,
                    session_id,
                )
                .await?
            };
            // Persist a freshly-typed password only now that it has authenticated,
            // and only if the user opted in. A vault-write failure must not fail an
            // otherwise-good session, so it is logged, not propagated.
            if matches!(result, russh::client::AuthResult::Success) {
                if let Some(secret) = &save_typed {
                    if let Err(e) = credentials::write_secret(host_id, username, secret.as_str()) {
                        eprintln!("skiff: could not save password for {host_id}: {e}");
                    } else if let Err(e) =
                        crate::utils::hosts::snapshot_binding(host_id, host, port, username)
                    {
                        // The binding authorizes this exact destination for the
                        // credential (same pairing the host-editor save records).
                        // If it fails to persist, a saved secret with no binding is
                        // refused by the anti-exfiltration guard on the very next
                        // connect — fail-closed but confusing. Roll the secret back
                        // so the user is simply prompted again next time instead of
                        // hitting an inexplicable "not an authorized destination".
                        eprintln!(
                            "skiff: could not bind saved credential {host_id}: {e}; \
                             rolling back the saved password"
                        );
                        let _ = credentials::delete_secret(host_id);
                        crate::utils::hosts::remove_binding(host_id);
                    }
                }
            }
            result
            // `pw` (Zeroizing) drops here — or at any `?` above — wiping its
            // buffer on every exit path; no manual fill, no plain-String copy.
        }
    };

    if !matches!(authed, russh::client::AuthResult::Success) {
        return Err(SshError::AuthFailed(username.to_string()));
    }
    Ok(())
}

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

/// Which prompts of one keyboard-interactive round get the password, in the
/// backend. At most one per auth attempt (`password_used`), and only a hidden
/// prompt that reads like a password — or, in the first round, a lone hidden
/// prompt when the password has not already been accepted (the TACACS+ single
/// unlabelled question). Every other prompt, hidden or not, goes to the user.
fn password_slots(
    prompts: &[(String, bool)],
    first_round: bool,
    password_used: bool,
    password_accepted: bool,
) -> Vec<bool> {
    let mut used = password_used;
    let lone_hidden = first_round && !password_accepted && prompts.len() == 1 && !prompts[0].1;
    prompts
        .iter()
        .map(|(text, echo)| {
            if used || *echo {
                return false;
            }
            if lone_hidden || looks_like_password_prompt(text) {
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
    app: &AppHandle,
    auth_prompts: &Arc<AuthPrompts>,
    session_id: &str,
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
                // here — no additional copy is retained on Skiff's side.
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
                    request_auth_answers(
                        app, auth_prompts, session_id, &name, &instructions, ask, false,
                    )
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
                            typed.next().unwrap_or_default()
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
    app: &AppHandle,
    auth_prompts: &Arc<AuthPrompts>,
    session_id: &str,
    name: &str,
    instruction: &str,
    fields: Vec<AuthPromptField>,
    offer_save: bool,
) -> Result<AuthAnswer, SshError> {
    let request_id = format!(
        "auth-{}-{}",
        session_id,
        AUTH_PROMPT_SEQ.fetch_add(1, Ordering::Relaxed)
    );
    let rx = auth_prompts.register(request_id.clone(), session_id);

    if app
        .emit(
            "ssh://auth-prompt",
            AuthPromptRequest {
                request_id: request_id.clone(),
                session_id: session_id.to_string(),
                name: name.to_string(),
                instruction: instruction.to_string(),
                prompts: fields,
                offer_save,
            },
        )
        .is_err()
    {
        // The dialog will never be shown, so nothing will ever resolve this
        // request — drop the pending entry instead of leaking it until timeout.
        auth_prompts.cancel(&request_id);
        return Err(SshError::AuthFailed(
            "could not raise the interactive auth prompt".into(),
        ));
    }

    match tokio::time::timeout(AUTH_PROMPT_TIMEOUT, rx).await {
        Ok(Ok(answer)) => Ok(answer),
        // Sender dropped (dialog cancelled) — abort auth cleanly.
        Ok(Err(_)) => Err(SshError::AuthFailed("interactive auth cancelled".into())),
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
pub async fn copy_id(
    app: AppHandle,
    prompts: Arc<HostKeyPrompts>,
    auth_prompts: Arc<AuthPrompts>,
    host: &str,
    port: u16,
    username: &str,
    password: &str,
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

    let ip = tokio::net::lookup_host((host, port))
        .await
        .ok()
        .and_then(|mut a| a.next())
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|| host.to_string());

    let config = Arc::new(client::Config {
        keepalive_interval: Some(Duration::from_secs(15)),
        nodelay: true,
        ..client::Config::default()
    });
    let handler = ClientHandler {
        host: host.to_string(),
        ip,
        port,
        app: app.clone(),
        prompts,
        session_id: "install-key".to_string(),
    };
    let mut handle = client::connect(config, (host, port), handler).await?;

    // Password (with keyboard-interactive fallback), one-shot. host_id "" is
    // never consulted because the one-shot password is supplied.
    authenticate(
        &mut handle, "", host, port, username, "password", None, Some(password),
        &app, &auth_prompts, "install-key",
    )
    .await?;

    // grep -qxF: only append if the exact line is not already present, so
    // running this twice does not duplicate the key. The append is BRACE-GROUPED
    // so the whole chain is conjunctive: SKIFF_KEY_OK is printed only if every
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
         && chmod 600 ~/.ssh/authorized_keys && echo SKIFF_KEY_OK"
    );

    let mut channel = handle.channel_open_session().await?;
    channel.exec(true, cmd).await?;
    let mut out = Vec::new();
    let mut exit_status: Option<u32> = None;
    let collect = async {
        // Read past EOF for the exit status (sent after EOF), as exec_capture does.
        let mut eof = false;
        loop {
            let msg = if eof {
                match tokio::time::timeout(EXIT_STATUS_GRACE, channel.wait()).await {
                    Ok(m) => m,
                    Err(_) => break,
                }
            } else {
                channel.wait().await
            };
            let Some(msg) = msg else { break };
            match msg {
                ChannelMsg::Data { ref data } | ChannelMsg::ExtendedData { ref data, .. } => {
                    out.extend_from_slice(data)
                }
                ChannelMsg::ExitStatus { exit_status: code } => exit_status = Some(code),
                ChannelMsg::Eof => eof = true,
                ChannelMsg::Close => break,
                _ => {}
            }
        }
    };
    // A timeout is a failure, not a silent success: don't judge the run by
    // whatever partial output happened to arrive before the clock ran out.
    let completed = tokio::time::timeout(Duration::from_secs(20), collect)
        .await
        .is_ok();

    // Three signals must agree before we claim the key is installed:
    //   - the command actually finished within the timeout,
    //   - any exit status it reported was 0 (missing status is tolerated, as
    //     some servers close the channel without sending one — the marker below
    //     is the primary positive proof), and
    //   - the conjunctive `&&` chain printed its end marker, which it only does
    //     if every step (including the append) succeeded.
    // Deciding on the marker alone let a non-zero exit or a truncated/timed-out
    // run be reported as success.
    let marker = String::from_utf8_lossy(&out).contains("SKIFF_KEY_OK");
    let exit_ok = exit_status.map_or(true, |code| code == 0);
    if completed && exit_ok && marker {
        Ok(())
    } else {
        Err(SshError::AuthFailed(format!(
            "install did not confirm success (completed={completed}, exit={exit_status:?}): {}",
            String::from_utf8_lossy(&out).chars().take(200).collect::<String>()
        )))
    }
}

/// Try every identity a running SSH agent offers.
///
/// Returns `Ok(None)` when no agent is reachable or no key was accepted —
/// distinct from an SSH-level error, so the caller can produce a message that
/// says what to actually do (start the agent, add a key) rather than a generic
/// failure. Tries the Windows OpenSSH agent service first because it is the
/// one Windows ships; Pageant second for the PuTTY crowd.
async fn agent_auth(
    handle: &mut Handle<ClientHandler>,
    username: &str,
    hash_alg: Option<russh::keys::HashAlg>,
) -> Result<Option<russh::client::AuthResult>, SshError> {
    use russh::keys::agent::client::AgentClient;

    // Windows ships the OpenSSH agent on a fixed pipe; Pageant serves the PuTTY
    // crowd. On Unix the one agent socket is named by $SSH_AUTH_SOCK.
    #[cfg(windows)]
    {
        if let Ok(mut agent) =
            AgentClient::connect_named_pipe(r"\\.\pipe\openssh-ssh-agent").await
        {
            if let Some(r) = try_agent_identities(&mut agent, handle, username, hash_alg, "agent").await? {
                return Ok(Some(r));
            }
        }

        // Pageant (PuTTY). russh 0.63 makes connect_pageant fallible; a missing
        // Pageant is just "no agent", so skip on Err and fall through.
        if let Ok(mut pageant) = AgentClient::connect_pageant().await {
            if let Some(r) = try_agent_identities(&mut pageant, handle, username, hash_alg, "pageant").await? {
                return Ok(Some(r));
            }
        }
    }

    #[cfg(not(windows))]
    {
        // $SSH_AUTH_SOCK — set by ssh-agent, gnome-keyring, 1Password, etc.
        if let Ok(mut agent) = AgentClient::connect_env().await {
            if let Some(r) = try_agent_identities(&mut agent, handle, username, hash_alg, "agent").await? {
                return Ok(Some(r));
            }
        }
    }

    Ok(None)
}

/// Offer each identity a connected agent holds to the server, signing with the
/// agent. Returns `Ok(Some(..))` on the first accepted key, `Ok(None)` if the
/// agent is unreachable or holds no accepted key. `label` names the agent in
/// the error message so "agent signing failed" vs "pageant signing failed"
/// still tells the user which one balked.
async fn try_agent_identities(
    agent: &mut russh::keys::agent::client::AgentClient<
        impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    >,
    handle: &mut Handle<ClientHandler>,
    username: &str,
    hash_alg: Option<russh::keys::HashAlg>,
    label: &str,
) -> Result<Option<russh::client::AuthResult>, SshError> {
    let Ok(identities) = agent.request_identities().await else {
        return Ok(None);
    };
    for identity in identities {
        // russh 0.63 yields AgentIdentity (key or certificate); publickey auth
        // wants the underlying PublicKey.
        let key = identity.public_key().into_owned();
        let result = handle
            .authenticate_publickey_with(username, key, hash_alg, agent)
            .await
            .map_err(|e| SshError::AuthFailed(format!("{label} signing failed: {e}")))?;
        if matches!(result, russh::client::AuthResult::Success) {
            return Ok(Some(result));
        }
    }
    Ok(None)
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

/// A unique sibling path for atomic writes: `<name>.<n>.skiffpart`. The counter
/// makes concurrent transfers to the same directory collision-free.
fn temp_sibling(path: &str) -> String {
    static TMP_SEQ: AtomicU64 = AtomicU64::new(0);
    let n = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    format!("{path}.{n}.skiffpart")
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
    let remote_meta = sftp.metadata(remote).await.ok();
    if remote_meta.as_ref().is_some_and(|m| m.file_type().is_dir()) {
        return Err(SshError::PartialTransfer(format!(
            "{remote} is a directory on the server; refusing to replace it with a file"
        )));
    }
    let mode = remote_meta
        .as_ref()
        .and_then(|m| m.permissions)
        .map(|p| p & 0o7777)
        .or_else(|| local_mode(local_meta.as_ref()));

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
            let _ = dst
                .set_metadata(russh_sftp::protocol::FileAttributes {
                    permissions: Some(m),
                    ..Default::default()
                })
                .await;
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
            if sftp.rename(tmp.clone(), remote.to_string()).await.is_err() {
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

/// Streaming UTF-8 decode: append `data` to `pending`, return every complete
/// character, and keep an incomplete trailing sequence (at most 3 bytes) in
/// `pending` for the next chunk. Only genuinely invalid bytes become U+FFFD.
fn decode_utf8_stream(pending: &mut Vec<u8>, data: &[u8]) -> String {
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
    use super::{reject_link_in_subtree, safe_local_component};

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
        let base = std::env::temp_dir().join(format!("skiff-symtest-{}", std::process::id()));
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
}
