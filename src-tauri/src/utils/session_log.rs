//! Per-session transcript logging.
//!
//! Every byte the remote sends is appended to a file as it arrives, so a
//! transcript survives a dropped connection, a killed process, or a crash —
//! whatever was already written is already on disk. There is no "save on exit"
//! step that a crash could skip.
//!
//! # What gets logged, and the honest limitation
//!
//! The stream is written as readable text with ANSI control sequences removed.
//! For an interactive shell that yields exactly what you want: your typed
//! commands (echoed back by the remote) interleaved with their output.
//!
//! It is lossy for full-screen programs. `vim`, `top`, or a pager redraw the
//! screen by repositioning the cursor, and a linear transcript cannot represent
//! that — expect those sections to read as a stream of partial redraws. That is
//! an inherent property of flattening a 2D terminal into a 1D log, not a bug to
//! fix here.
//!
//! Passwords typed at a remote prompt are not echoed by the remote, so they do
//! not appear. Anything you *see* on screen, however, is written to disk in
//! plaintext — this file is as sensitive as the session was.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use super::artifacts;
use super::known_hosts::KnownHostsError;

/// Header fragment that records the endpoint key: `(endpoint <key>)`.
const ENDPOINT_MARK: &str = "(endpoint ";

/// `%APPDATA%\hawser\logs`
pub fn logs_dir() -> Result<PathBuf, KnownHostsError> {
    let store = super::known_hosts::store_path()?;
    Ok(store
        .parent()
        .ok_or(KnownHostsError::NoAppDataDir)?
        .join("logs"))
}

/// The logs folder when it exists as a real folder (every component under the
/// app-data root checked, see `artifacts::real_dir`); None when nothing was
/// recorded yet. A linked or non-folder `logs` is an error, never followed.
fn existing_logs_dir() -> Result<Option<PathBuf>, KnownHostsError> {
    let d = logs_dir()?;
    Ok(artifacts::verified_dir(&d, false)?.then_some(d))
}

/// Civil date from a Unix timestamp, so filenames sort chronologically and are
/// readable without a converter. Hinnant's algorithm; avoids pulling in chrono
/// for what is ultimately one format string.
/// Public alias so sibling modules (config snapshots) share the same
/// filename convention instead of inventing a second timestamp format.
pub fn timestamp_for(secs: u64) -> String {
    timestamp_name(secs)
}

fn timestamp_name(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let tod = secs % 86_400;

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!(
        "{:04}{:02}{:02}-{:02}{:02}{:02}",
        y,
        m,
        d,
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

/// First line of every transcript. With an endpoint key it ends in
/// `(endpoint <key>) ===`, which `latest_transcript` checks.
fn header_line(username: &str, host: &str, stamp: &str, endpoint: Option<&str>) -> String {
    let ident = endpoint.map(|e| format!(" {ENDPOINT_MARK}{e})")).unwrap_or_default();
    format!("=== hawser session: {username}@{host} started {stamp} UTC{ident} ===")
}

/// Filesystem-safe form of a host label.
fn slug(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '.' { c } else { '_' })
        .collect()
}

pub struct SessionLog {
    file: File,
    path: PathBuf,
    /// Carries a trailing ESC across chunk boundaries: a control sequence can
    /// be split between two reads, and a stripper with no memory would emit the
    /// tail of it as text.
    partial: Vec<u8>,
    /// Bytes written so far, to enforce a per-session size cap.
    written: u64,
    /// Set once the cap is hit so the truncation notice is written only once.
    capped: bool,
    /// Inside an over-long string sequence (OSC/DCS/APC/SOS/PM: an OSC 52
    /// clipboard blob, an inline image, sixel), whose body is being dropped
    /// until its terminator; see `skip_string`.
    in_string: bool,
    /// The previous chunk ended with ESC while dropping such a body (the first
    /// half of an `ESC \` terminator).
    string_esc: bool,
    /// Bytes of the current string body dropped so far.
    string_skipped: usize,
}

/// Longest string-sequence body (OSC/DCS/APC/SOS/PM) carried between chunks
/// while waiting for its terminator. Titles and hyperlinks are far shorter; a
/// longer one is an image or clipboard payload and is dropped in a streaming
/// way instead of being buffered (or, as before, leaked into the transcript as
/// text once the carry-over was cleared mid-payload).
const MAX_STRING_CARRY: usize = 4096;

/// After this much of a single unterminated string body, give up dropping it
/// (a stray `ESC P` in binary output must not silence the transcript forever).
const MAX_STRING_SKIP: usize = 64 * 1024 * 1024;

/// Whether `seq` starts a string sequence: ESC followed by `]` (OSC), `P`
/// (DCS), `X` (SOS), `^` (PM) or `_` (APC).
fn is_string_start(seq: &[u8]) -> bool {
    seq.len() >= 2 && seq[0] == 0x1b && matches!(seq[1], b']' | b'P' | b'X' | b'^' | b'_')
}

/// Scan a dropped string body for its terminator: BEL, `ESC \` (ST), or the
/// CAN / SUB that abort a sequence. Returns the offset just past it, or None
/// if `data` ends inside the body. `esc` carries a trailing ESC across calls.
fn skip_string(data: &[u8], esc: &mut bool) -> Option<usize> {
    for (i, &b) in data.iter().enumerate() {
        if std::mem::take(esc) && b == b'\\' {
            return Some(i + 1);
        }
        match b {
            0x07 | 0x18 | 0x1a => return Some(i + 1),
            0x1b => *esc = true,
            _ => {}
        }
    }
    None
}

impl SessionLog {
    /// Open a transcript for one session. Failure is non-fatal to the caller —
    /// losing a log must never take down a working connection.
    ///
    /// Without an endpoint key the file gets the legacy hostname-only name
    /// (local shells use that, keyed `local-<profile>`). Such a transcript is
    /// never returned by `latest_transcript`, so it is never fed to the AI or
    /// replayed into another tab.
    pub fn create(host: &str, username: &str) -> Result<Self, KnownHostsError> {
        Self::create_for(None, host, username)
    }

    /// Open a transcript keyed by endpoint identity (see `artifacts`): named
    /// `<host>@<tag>_<stamp>.log`, with the full key in the header line so a
    /// reader can confirm which connection actually wrote it.
    pub fn create_for(
        endpoint: Option<&str>,
        host: &str,
        username: &str,
    ) -> Result<Self, KnownHostsError> {
        let endpoint = endpoint.filter(|e| artifacts::validate_endpoint(e).is_ok());
        let dir = logs_dir()?;
        // Created and checked component by component: a `logs` that is a link
        // would send every transcript somewhere else.
        artifacts::verified_dir(&dir, true)?;
        // A transcript holds everything the session displayed, in plaintext, so
        // it is as sensitive as the session was. Keep the directory owner-only.
        super::platform::restrict_perms(&dir, 0o700);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Two sessions to the same host can start in the same second (split
        // pane, restored tabs). create_new + a numeric suffix gives each its own
        // file instead of interleaving both into one transcript with a doubled
        // size cap — same scheme as save_capture.
        let base = match endpoint {
            Some(e) => format!(
                "{}@{}_{}",
                artifacts::safe_component(host),
                artifacts::endpoint_tag(e),
                timestamp_name(now)
            ),
            None => format!("{}_{}", slug(host), timestamp_name(now)),
        };
        let mut path = dir.join(format!("{base}.log"));
        let mut n = 0u32;
        let mut file = loop {
            let mut open = OpenOptions::new();
            open.create_new(true).append(true);
            // Create the file 0600 up front on Unix so it is never briefly
            // world-readable between create and chmod.
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                open.mode(0o600);
            }
            match open.open(&path) {
                Ok(f) => break f,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && n < 1000 => {
                    n += 1;
                    path = dir.join(format!("{base}.{n}.log"));
                }
                Err(source) => {
                    return Err(KnownHostsError::Io {
                        path: path.clone(),
                        source,
                    })
                }
            }
        };
        // Belt-and-braces for platforms where the mode above does not apply.
        super::platform::restrict_perms(&path, 0o600);

        let _ = writeln!(file, "{}", header_line(username, host, &timestamp_name(now), endpoint));

        Ok(Self {
            file,
            path,
            partial: Vec::new(),
            written: 0,
            capped: false,
            in_string: false,
            string_esc: false,
            string_skipped: 0,
        })
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    /// Append a chunk, stripping terminal control sequences.
    ///
    /// Flushed on every call rather than buffered: transcript durability is the
    /// entire point, and terminal output is far too low-volume for the syscall
    /// to matter.
    pub fn append(&mut self, chunk: &[u8]) {
        // Per-session on-disk cap: a runaway remote (`yes`, `cat` of a huge
        // file) must not be able to fill the disk through the transcript. Once
        // the cap is reached, note it once and stop appending.
        const MAX_LOG_BYTES: u64 = 50 * 1024 * 1024;
        if self.capped {
            return;
        }

        let mut chunk = chunk;
        if self.in_string {
            match skip_string(chunk, &mut self.string_esc) {
                Some(end) => {
                    self.in_string = false;
                    self.string_skipped = 0;
                    chunk = &chunk[end..];
                }
                None => {
                    self.string_skipped = self.string_skipped.saturating_add(chunk.len());
                    if self.string_skipped > MAX_STRING_SKIP {
                        // Never terminated: resume recording from here.
                        self.in_string = false;
                        self.string_skipped = 0;
                    }
                    return;
                }
            }
        }

        let mut buf = std::mem::take(&mut self.partial);
        buf.extend_from_slice(chunk);

        let (text, mut leftover) = strip_ansi(&buf);
        // Bound the pending-escape carry-over. A real control sequence is a
        // handful of bytes; a multi-KB "unterminated sequence" is a broken or
        // hostile server growing this buffer without bound, so drop it rather
        // than re-prepend it on every future chunk. A string sequence (an
        // image, a clipboard blob) is instead dropped up to its terminator:
        // clearing it mid-body made the rest of its payload print as text.
        const MAX_PENDING: usize = 64 * 1024;
        if is_string_start(&leftover) && leftover.len() > MAX_STRING_CARRY {
            self.in_string = true;
            self.string_esc = leftover.last() == Some(&0x1b);
            self.string_skipped = leftover.len();
            leftover.clear();
        } else if leftover.len() > MAX_PENDING {
            leftover.clear();
        }
        self.partial = leftover;

        if !text.is_empty() {
            // Write only up to the remaining budget, so a single oversized chunk
            // cannot blow past the cap before the check below flips it on.
            let remaining = MAX_LOG_BYTES.saturating_sub(self.written);
            let take = std::cmp::min(remaining, text.len() as u64) as usize;
            if take > 0 {
                let _ = self.file.write_all(&text[..take]);
                self.written = self.written.saturating_add(take as u64);
            }
            if self.written >= MAX_LOG_BYTES {
                let _ = writeln!(
                    self.file,
                    "\n=== transcript truncated: {MAX_LOG_BYTES}-byte session cap reached ==="
                );
                self.capped = true;
            }
            let _ = self.file.flush();
        }
    }

    pub fn footer(&mut self, reason: &str) {
        let _ = writeln!(self.file, "\n=== session ended: {reason} ===");
        let _ = self.file.flush();
    }
}

/// Remove ANSI/VT control sequences, returning (clean bytes, unconsumed tail).
///
/// The tail matters: if the chunk ends mid-sequence, those bytes are handed
/// back so the next call can finish parsing them rather than leaking escape
/// codes into the transcript.
pub(crate) fn strip_ansi(input: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;

    while i < input.len() {
        let b = input[i];

        if b == 0x1b {
            // CSI: ESC [ ... final byte in 0x40..=0x7e
            if i + 1 >= input.len() {
                return (out, input[i..].to_vec());
            }
            match input[i + 1] {
                b'[' => {
                    let mut j = i + 2;
                    while j < input.len() && !(0x40..=0x7e).contains(&input[j]) {
                        j += 1;
                    }
                    if j >= input.len() {
                        return (out, input[i..].to_vec());
                    }
                    i = j + 1;
                }
                // String sequences, whose body is dropped whole: OSC (ESC ]),
                // DCS (ESC P: sixel, tmux passthrough), SOS (ESC X), PM (ESC ^)
                // and APC (ESC _: kitty graphics). Ended by BEL, ST (ESC \),
                // or CAN / SUB, which abort a sequence. Unterminated: carried
                // to the next chunk.
                b']' | b'P' | b'X' | b'^' | b'_' => {
                    let mut j = i + 2;
                    let mut end = None;
                    while j < input.len() {
                        match input[j] {
                            0x07 | 0x18 | 0x1a => {
                                end = Some(j + 1);
                                break;
                            }
                            0x1b if j + 1 < input.len() && input[j + 1] == b'\\' => {
                                end = Some(j + 2);
                                break;
                            }
                            _ => j += 1,
                        }
                    }
                    match end {
                        Some(e) => i = e,
                        None => return (out, input[i..].to_vec()),
                    }
                }
                // nF escapes: ESC, one or more intermediates (0x20..=0x2f), then
                // a final byte — charset designators like ESC ( B (emitted by
                // ncurses' sgr0 on every reset), ESC ) 0, ESC # 8. Skipping only
                // two bytes would leak the final byte as a stray letter.
                0x20..=0x2f => {
                    let mut j = i + 1;
                    while j < input.len() && (0x20..=0x2f).contains(&input[j]) {
                        j += 1;
                    }
                    if j >= input.len() {
                        return (out, input[i..].to_vec());
                    }
                    i = j + 1;
                }
                // Two-byte escapes (ESC =, ESC >, ESC M, ...)
                _ => i += 2,
            }
            continue;
        }

        // Drop the carriage return of CRLF; keep lone CR out too, since a
        // transcript has no cursor to move.
        if b == b'\r' {
            i += 1;
            continue;
        }

        // Keep printable text, newlines, and tabs; drop other C0 controls
        // (BEL, backspace and friends would render as noise).
        if b == b'\n' || b == b'\t' || b >= 0x20 {
            out.push(b);
        }
        i += 1;
    }

    (out, Vec::new())
}

/* -------------------------------------------------------------------------- */

/// Largest tail `latest_transcript` returns, whatever the caller asks for.
const MAX_TAIL_BYTES: usize = 256 * 1024;

/// Tail of the most recent transcript written for one endpoint.
///
/// This is the only form of "session history" available on appliances. A Palo
/// Alto or a switch cannot run tmux, so nothing on the remote survives the
/// connection dropping — but the transcript does, and replaying its tail into a
/// reconnected tab restores the one thing that actually matters there: what you
/// ran and what it said.
///
/// Keyed by endpoint identity, not hostname. Only a transcript whose filename
/// carries this endpoint's tag AND whose header names this exact key counts, so
/// a legacy hostname-keyed file, or one from another catalogue entry that
/// merely shares the address, is never returned. That is what makes the AI
/// panel's per-host policy check meaningful: the text it sends came from the
/// connection whose policy was checked.
///
/// Returns None when the endpoint has no prior transcript.
pub fn latest_transcript(endpoint: &str, max_bytes: usize) -> Result<Option<String>, KnownHostsError> {
    artifacts::validate_endpoint(endpoint)?;
    match existing_logs_dir()? {
        Some(d) => latest_in(&d, endpoint, max_bytes),
        None => Ok(None),
    }
}

fn latest_in(dir: &Path, endpoint: &str, max_bytes: usize) -> Result<Option<String>, KnownHostsError> {
    let tag = artifacts::endpoint_tag(endpoint);
    let entries = std::fs::read_dir(dir).map_err(|source| KnownHostsError::Io {
        path: dir.to_path_buf(),
        source,
    })?;

    // Newest by modified time rather than by filename: a clock change or a
    // manually copied file would break lexical ordering.
    let mut candidates: Vec<(SystemTime, PathBuf)> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let Some((host, _)) = split_log_name(&name) else { continue };
        if artifacts::split_tagged(host).map(|(_, t)| t) != Some(tag.as_str()) {
            continue;
        }
        // DirEntry::file_type does not follow links: only a plain file counts.
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        if meta.len() == 0 {
            continue; // an aborted session has nothing to replay
        }
        let Ok(modified) = meta.modified() else { continue };
        candidates.push((modified, entry.path()));
    }
    candidates.sort_by(|a, b| b.0.cmp(&a.0));

    let wanted = format!(" {ENDPOINT_MARK}{endpoint}) ===");
    for (_, path) in candidates {
        let Ok(mut file) = artifacts::open_regular(&path) else { continue };
        if !first_line(&mut file).is_some_and(|l| l.ends_with(&wanted)) {
            continue;
        }
        let tail = read_tail(&mut file, max_bytes.min(MAX_TAIL_BYTES))
            .map_err(|source| KnownHostsError::Io { path: path.clone(), source })?;
        return Ok(Some(tail));
    }
    Ok(None)
}

/// The header line, read from the start of the file (bounded).
fn first_line(file: &mut File) -> Option<String> {
    use std::io::{Read, Seek, SeekFrom};
    file.seek(SeekFrom::Start(0)).ok()?;
    let mut head = Vec::new();
    file.take(4096).read_to_end(&mut head).ok()?;
    let end = head.iter().position(|&b| b == b'\n')?;
    Some(String::from_utf8_lossy(&head[..end]).into_owned())
}

/// The last `max_bytes` of the file, starting at a line boundary so a replay
/// never starts mid-word.
fn read_tail(file: &mut File, max_bytes: usize) -> std::io::Result<String> {
    use std::io::{Read, Seek, SeekFrom};
    let len = file.metadata()?.len();
    let start = len.saturating_sub(max_bytes as u64);
    file.seek(SeekFrom::Start(start))?;
    let mut bytes = Vec::new();
    file.take(max_bytes as u64).read_to_end(&mut bytes)?;
    let slice = if start > 0 {
        match bytes.iter().position(|&b| b == b'\n') {
            Some(i) => &bytes[i + 1..],
            None => &bytes[..],
        }
    } else {
        &bytes[..]
    };
    Ok(String::from_utf8_lossy(slice).into_owned())
}

/* -------------------------------------------------------------------------- */

/// Delete old transcripts.
///
/// These files hold plaintext records of production firewall sessions, so
/// letting them accumulate forever is a quiet liability. Two independent caps,
/// whichever removes more:
///   * anything older than `max_age_days`
///   * beyond `max_files`, the oldest first
///
/// Best-effort: a file that will not delete (locked, permissions) is skipped,
/// never fatal. Returns how many were removed, for the startup log line.
pub fn prune(max_age_days: u64, max_files: usize) -> usize {
    let dir = match existing_logs_dir() {
        Ok(Some(d)) => d,
        _ => return 0,
    };

    let now = SystemTime::now();
    let max_age = std::time::Duration::from_secs(max_age_days * 86_400);

    // (modified, path) for every transcript, newest first.
    let mut logs: Vec<(SystemTime, PathBuf)> = match std::fs::read_dir(&dir) {
        Ok(rd) => rd
            .flatten()
            .filter(|e| {
                let n = e.file_name();
                let n = n.to_string_lossy();
                n.ends_with(".log")
            })
            .filter_map(|e| e.metadata().ok().and_then(|m| m.modified().ok()).map(|t| (t, e.path())))
            .collect(),
        Err(_) => return 0,
    };
    logs.sort_by(|a, b| b.0.cmp(&a.0));

    let mut removed = 0;
    for (i, (modified, path)) in logs.iter().enumerate() {
        let too_old = now.duration_since(*modified).map(|age| age > max_age).unwrap_or(false);
        let over_count = i >= max_files;
        if (too_old || over_count) && std::fs::remove_file(path).is_ok() {
            removed += 1;
        }
    }
    removed
}

/* -------------------------------------------------------------------------- */

use serde::Serialize;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEntry {
    /// Bare filename, e.g. "fw1@0123456789abcdef_20260918-141530.log". Also the
    /// id used by `read_log`; never a path, so it cannot point outside the dir.
    pub name: String,
    /// Readable host label parsed back out of the filename for grouping.
    pub host: String,
    /// Endpoint tag for transcripts keyed by endpoint identity.
    pub endpoint: Option<String>,
    /// Written before endpoint keying (hostname only): still viewable here, but
    /// it may belong to any entry that shared the hostname, so it is never
    /// replayed or sent to the AI.
    pub legacy: bool,
    /// Unix epoch seconds parsed from the filename's timestamp, for sorting and
    /// display without opening the file.
    pub started: Option<u64>,
    pub bytes: u64,
}

/// List transcripts, newest first. Empty when there are none.
pub fn list() -> Result<Vec<LogEntry>, KnownHostsError> {
    match existing_logs_dir()? {
        Some(d) => list_in(&d),
        None => Ok(Vec::new()),
    }
}

fn list_in(dir: &Path) -> Result<Vec<LogEntry>, KnownHostsError> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|source| KnownHostsError::Io {
        path: dir.to_path_buf(),
        source,
    })? {
        let Ok(entry) = entry else { continue };
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".log") {
            continue;
        }
        // Links and special files are never transcripts this app wrote.
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }
        let bytes = entry.metadata().map(|m| m.len()).unwrap_or(0);

        // Filename shape is "<host>[@<tag>]_<YYYYMMDD-HHMMSS>[.<n>].log". Split
        // on the LAST underscore so hosts containing underscores (slugged
        // dots, etc.) keep their name intact.
        let (raw_host, started) = match split_log_name(&name) {
            Some((h, stamp)) => (h.to_string(), parse_stamp(stamp)),
            None => {
                let stem = name.trim_end_matches(".log");
                match stem.rfind('_') {
                    Some(i) => (stem[..i].to_string(), parse_stamp(&stem[i + 1..])),
                    None => (stem.to_string(), None),
                }
            }
        };
        let (host, endpoint) = match artifacts::split_tagged(&raw_host) {
            Some((label, tag)) => (label.to_string(), Some(tag.to_string())),
            None => (raw_host.clone(), None),
        };
        let legacy = endpoint.is_none() && !host.starts_with("local-");
        out.push(LogEntry { name, host, endpoint, legacy, started, bytes });
    }

    out.sort_by(|a, b| b.started.cmp(&a.started));
    Ok(out)
}

/// Accept only a single *normal* path component ending in .log. Parsing the
/// name (rather than ad-hoc substring checks) rejects separators, absolute
/// paths, Windows prefixes, "." and ".." in one shot. The explicit ':' check
/// additionally blocks Windows drive-relative ("C:foo") and NTFS
/// alternate-data-stream ("foo.log:evil") syntax — a colon is not a path
/// separator, so the component parser alone would let those through.
fn validate_log_name(name: &str) -> Result<(), KnownHostsError> {
    let single_normal = {
        let mut comps = Path::new(name).components();
        matches!(
            (comps.next(), comps.next()),
            (Some(std::path::Component::Normal(c)), None) if c == std::ffi::OsStr::new(name)
        )
    };
    if !single_normal || name.contains(':') || name.contains('\0') || !name.ends_with(".log") {
        return Err(KnownHostsError::Parse(format!("invalid log name: {name}")));
    }
    Ok(())
}

/// Bytes per transcript page sent to the viewer. A transcript can reach 50 MB;
/// one IPC string of that size, rendered as one text node, froze the webview.
pub const PAGE_BYTES: u64 = 512 * 1024;

/// Which window of a transcript to read.
#[derive(Debug, Clone, Copy)]
pub enum PageAt {
    /// The newest page (the default view).
    Tail,
    /// A page around this 1-based line (a search hit).
    Line(u64),
    /// The page ending at this byte offset ("load earlier").
    Before(u64),
    /// The page starting at this byte offset ("load later").
    After(u64),
}

/// One window of a transcript, aligned to whole lines.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogPage {
    pub text: String,
    /// Byte range of `text` within the file.
    pub start: u64,
    pub end: u64,
    /// File size, so the viewer knows whether there is more either side.
    pub total: u64,
    /// 1-based line number of the first line of `text`.
    pub first_line: u64,
}

/// Read one page of a transcript by its bare filename. Never through a
/// symlink, and never a FIFO or device that could block the read.
pub fn read_log(name: &str, at: PageAt) -> Result<LogPage, KnownHostsError> {
    let dir = existing_logs_dir()?.ok_or_else(|| KnownHostsError::Parse(format!("no transcript {name}")))?;
    read_page_in(&dir, name, at, PAGE_BYTES)
}

fn read_page_in(dir: &Path, name: &str, at: PageAt, page: u64) -> Result<LogPage, KnownHostsError> {
    use std::io::{Read, Seek, SeekFrom};
    validate_log_name(name)?;
    let path = dir.join(name);
    let io_err = |source| KnownHostsError::Io { path: path.clone(), source };
    let mut file = artifacts::open_regular(&path).map_err(io_err)?;
    let total = file.metadata().map_err(io_err)?.len();

    let (s, e) = match at {
        PageAt::Tail => (total.saturating_sub(page), total),
        PageAt::Before(b) => {
            let b = b.min(total);
            (b.saturating_sub(page), b)
        }
        PageAt::After(a) => {
            let a = a.min(total);
            (a, a.saturating_add(page).min(total))
        }
        PageAt::Line(n) => {
            let off = line_offset(&mut file, n).map_err(io_err)?.min(total);
            let s = off.saturating_sub(page / 4);
            (s, s.saturating_add(page).min(total))
        }
    };

    // Read one byte before `s` to learn whether `s` already sits on a line
    // start; otherwise the partial first line is dropped.
    let rs = s.saturating_sub(1);
    file.seek(SeekFrom::Start(rs)).map_err(io_err)?;
    let mut buf = Vec::new();
    (&mut file).take(e - rs).read_to_end(&mut buf).map_err(io_err)?;

    let mut lo = 0usize;
    if s > 0 && !buf.is_empty() {
        lo = 1;
        if buf[0] != b'\n' {
            if let Some(i) = buf[1..].iter().position(|&b| b == b'\n') {
                lo = i + 2;
            }
        }
    }
    let mut hi = buf.len();
    if e < total && lo < hi {
        if let Some(i) = buf[lo..].iter().rposition(|&b| b == b'\n') {
            hi = lo + i + 1;
        }
    }
    // A single line longer than a page has nothing to align on; show the raw
    // slice rather than an empty page.
    if lo >= hi && e > s {
        lo = usize::from(s > 0);
        hi = buf.len();
    }
    // The file can shrink between the size check and the read; never let the
    // range invert (buf[1..0] would panic, and panic aborts).
    let hi = hi.min(buf.len());
    let lo = lo.min(hi);
    let start = rs + lo as u64;
    let end = rs + hi as u64;
    let first_line = 1 + count_newlines(&mut file, start).map_err(io_err)?;
    Ok(LogPage {
        text: String::from_utf8_lossy(&buf[lo..hi]).into_owned(),
        start,
        end,
        total,
        first_line,
    })
}

/// Byte offset where 1-based line `n` starts (the file length if it has fewer).
fn line_offset(file: &mut File, n: u64) -> std::io::Result<u64> {
    use std::io::{Read, Seek, SeekFrom};
    if n <= 1 {
        return Ok(0);
    }
    file.seek(SeekFrom::Start(0))?;
    let mut seen = 0u64;
    let mut off = 0u64;
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        let got = file.read(&mut chunk)?;
        if got == 0 {
            return Ok(off);
        }
        for (i, &b) in chunk[..got].iter().enumerate() {
            if b == b'\n' {
                seen += 1;
                if seen == n - 1 {
                    return Ok(off + i as u64 + 1);
                }
            }
        }
        off += got as u64;
    }
}

/// Newlines in the first `upto` bytes of the file.
fn count_newlines(file: &mut File, upto: u64) -> std::io::Result<u64> {
    use std::io::{Read, Seek, SeekFrom};
    file.seek(SeekFrom::Start(0))?;
    let mut reader = file.take(upto);
    let mut chunk = vec![0u8; 64 * 1024];
    let mut count = 0u64;
    loop {
        let got = reader.read(&mut chunk)?;
        if got == 0 {
            return Ok(count);
        }
        count += chunk[..got].iter().filter(|&&b| b == b'\n').count() as u64;
    }
}

/* ------------------------------------------------------------------ search */

/// One matching line in one transcript.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchHit {
    /// Transcript filename (the `read_log` id).
    pub name: String,
    pub host: String,
    pub started: Option<u64>,
    /// 1-based line number within the transcript, for jumping to it.
    pub line: u64,
    /// The matching line, trimmed to a window around the match if very long.
    pub text: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchResult {
    pub hits: Vec<SearchHit>,
    /// Transcripts that were read.
    pub scanned: usize,
    /// True when a cap cut the results short (total hits, hits per session, or
    /// an oversized transcript read only in part).
    pub truncated: bool,
    /// A newer search (or an explicit cancel) stopped this one early.
    pub cancelled: bool,
}

/// Most matches reported from any one transcript, so one chatty session (a
/// `show log` dump) cannot crowd every other session out of the results. The
/// NEWEST matches in the file are the ones kept.
const HITS_PER_LOG: usize = 25;
/// Bytes read from any one transcript. Above the 50 MB transcript cap plus
/// its header and footer, so in practice the whole file is searched.
const SEARCH_READ_CAP: u64 = 64 * 1024 * 1024;
/// Bytes of one line examined; a `cat` of a binary can make one huge "line".
const SEARCH_LINE_CAP: usize = 1024 * 1024;
/// Characters of context kept around a match on a very long line.
const SNIPPET_CHARS: usize = 240;

/// Generation of the newest search. Typing starts a new scan every pause, and
/// each scan can read hundreds of MB; a scan whose generation is no longer
/// current stops at the next check instead of running to completion.
static SEARCH_GEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Register a new search, superseding every earlier one.
pub fn begin_search() -> u64 {
    SEARCH_GEN.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1
}

/// Stop every running search (the history window closed, or the query was cleared).
pub fn cancel_searches() {
    SEARCH_GEN.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

/// Case-insensitive substring search across every transcript, newest session
/// first. This is the "memory" view: "when did I last run X, and on which box?"
///
/// Reads only regular `.log` files in the logs directory (never through a
/// symlink, same rule as `read_log`). A query shorter than 2 characters returns
/// nothing rather than every line ever recorded.
pub fn search(query: &str, limit: usize, generation: u64) -> Result<SearchResult, KnownHostsError> {
    let stale = || SEARCH_GEN.load(std::sync::atomic::Ordering::SeqCst) != generation;
    match existing_logs_dir()? {
        Some(d) => search_in(&d, query, limit, &stale),
        None => Ok(SearchResult { hits: Vec::new(), scanned: 0, truncated: false, cancelled: false }),
    }
}

fn search_in(
    dir: &Path,
    query: &str,
    limit: usize,
    cancelled: &dyn Fn() -> bool,
) -> Result<SearchResult, KnownHostsError> {
    use std::io::Read;

    let needle = fold(query.trim());
    let mut res = SearchResult { hits: Vec::new(), scanned: 0, truncated: false, cancelled: false };
    if needle.chars().count() < 2 {
        return Ok(res);
    }
    let limit = limit.clamp(1, 1000);

    'logs: for log in list_in(dir)? {
        if cancelled() {
            res.cancelled = true;
            break;
        }
        if res.hits.len() >= limit {
            res.truncated = true;
            break;
        }
        let Ok(file) = artifacts::open_regular(&dir.join(&log.name)) else { continue };
        res.scanned += 1;
        if log.bytes > SEARCH_READ_CAP {
            res.truncated = true;
        }

        // Streamed line by line, so memory stays bounded however big the file.
        let mut reader = std::io::BufReader::with_capacity(64 * 1024, file.take(SEARCH_READ_CAP));
        let mut found: std::collections::VecDeque<SearchHit> = std::collections::VecDeque::new();
        let mut raw = Vec::new();
        let mut line_no = 0u64;
        loop {
            raw.clear();
            match read_line_capped(&mut reader, &mut raw, SEARCH_LINE_CAP) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
            line_no += 1;
            if line_no % 4096 == 0 && cancelled() {
                res.cancelled = true;
                break 'logs;
            }
            while matches!(raw.last(), Some(b'\n' | b'\r')) {
                raw.pop();
            }
            let line = String::from_utf8_lossy(&raw);
            let Some(at) = fold(&line).find(&needle) else { continue };
            if found.len() == HITS_PER_LOG {
                found.pop_front();
                res.truncated = true;
            }
            found.push_back(SearchHit {
                name: log.name.clone(),
                host: log.host.clone(),
                started: log.started,
                line: line_no,
                text: snippet(&line, orig_char_index(&line, at)),
            });
        }
        let room = limit - res.hits.len();
        if found.len() > room {
            res.truncated = true;
        }
        let skip = found.len().saturating_sub(room);
        res.hits.extend(found.into_iter().skip(skip));
    }
    Ok(res)
}

/// `read_until(b'\n')` that keeps at most `cap` bytes of the line but still
/// consumes all of it. Returns the bytes consumed (0 at end of file).
fn read_line_capped<R: std::io::BufRead>(r: &mut R, out: &mut Vec<u8>, cap: usize) -> std::io::Result<usize> {
    let mut consumed = 0;
    loop {
        let buf = r.fill_buf()?;
        if buf.is_empty() {
            return Ok(consumed);
        }
        let (used, done) = match buf.iter().position(|&b| b == b'\n') {
            Some(i) => (i + 1, true),
            None => (buf.len(), false),
        };
        let keep = cap.saturating_sub(out.len()).min(used);
        out.extend_from_slice(&buf[..keep]);
        r.consume(used);
        consumed += used;
        if done {
            return Ok(consumed);
        }
    }
}

/// Append the case fold of `c` to `out`. Must stay identical to
/// `src/lib/foldMatch.ts`, which highlights what this matched:
/// - per-character lowercase (no context, so offsets map back simply);
/// - final sigma ς folded to σ, so `ΠΑΝΕΠΙΣ` still finds `ΠΑΝΕΠΙΣΤΗΜΙΟ` and
///   `οδοσ` finds `οδος`;
/// - the combining dot (U+0307) after an `i` dropped, so `İstanbul`
///   (lowercase "i̇stanbul") is found by `istanbul` and the reverse;
/// - the common full folds in `FULL_FOLDS` expanded, so `Straße` is found by
///   `STRASSE` and the `ﬁ` ligature by `fi`.
///
/// Limits (shared with the frontend): no Unicode normalisation (std has none),
/// no full folds beyond that table, and per-character lowercase follows each
/// runtime's Unicode tables, which can differ for very recent characters.
/// Full case folds beyond lowercase, applied to each lowercased character.
/// Must match `FULL_FOLDS` in src/lib/foldMatch.ts exactly.
const FULL_FOLDS: [(char, &str); 9] = [
    ('ß', "ss"),
    ('ﬀ', "ff"),
    ('ﬁ', "fi"),
    ('ﬂ', "fl"),
    ('ﬃ', "ffi"),
    ('ﬄ', "ffl"),
    ('ﬅ', "st"),
    ('ﬆ', "st"),
    ('ŉ', "ʼn"),
];

fn fold_char(c: char, prev_i: &mut bool, out: &mut String) {
    for l in c.to_lowercase() {
        if l == '\u{307}' && *prev_i {
            *prev_i = false;
            continue;
        }
        if l == 'ς' {
            out.push('σ');
            *prev_i = false;
        } else if let Some((_, full)) = FULL_FOLDS.iter().find(|(k, _)| *k == l) {
            out.push_str(full);
            *prev_i = full.ends_with('i');
        } else {
            out.push(l);
            *prev_i = l == 'i';
        }
    }
}

fn fold(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_i = false;
    for c in s.chars() {
        fold_char(c, &mut prev_i, &mut out);
    }
    out
}

/// Char index in `line` of the character whose fold starts at byte `folded_at`
/// of `fold(line)`. Folding can change length (`İ` is two bytes, `i` one), so
/// an offset in the folded text cannot be reused against the original.
fn orig_char_index(line: &str, folded_at: usize) -> usize {
    let mut out = String::new();
    let mut prev_i = false;
    for (i, c) in line.chars().enumerate() {
        if out.len() >= folded_at {
            return i;
        }
        fold_char(c, &mut prev_i, &mut out);
    }
    line.chars().count()
}

/// `line`, or a window of it around char index `at` when it is long, with an
/// ellipsis marking each cut side. Char-based so it never splits a code point.
fn snippet(line: &str, at: usize) -> String {
    let n = line.chars().count();
    if n <= SNIPPET_CHARS {
        return line.to_string();
    }
    let start = at.saturating_sub(SNIPPET_CHARS / 3).min(n - SNIPPET_CHARS);
    let mut out: String = line.chars().skip(start).take(SNIPPET_CHARS).collect();
    if start > 0 {
        out.insert(0, '…');
    }
    if start + SNIPPET_CHARS < n {
        out.push('…');
    }
    out
}

/// Split "<host>_<YYYYMMDD-HHMMSS>[.<n>].log" into (host part, stamp), where
/// ".<n>" is the collision suffix `SessionLog::create` adds and the host part
/// may end in "@<tag>". None unless the part after the last underscore is a
/// well-formed timestamp.
fn split_log_name(name: &str) -> Option<(&str, &str)> {
    let stem = name.strip_suffix(".log")?;
    let stem = match stem.rsplit_once('.') {
        Some((head, n)) if !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) => head,
        _ => stem,
    };
    let (host, stamp) = stem.rsplit_once('_')?;
    parse_stamp(stamp)?;
    Some((host, stamp))
}

/// Inverse of `timestamp_name`: "YYYYMMDD-HHMMSS" back to epoch seconds.
///
/// Every field is range-checked and the arithmetic is checked: a filename
/// dated before 1970 (or the 31st of February) used to cast a negative day
/// count to u64. Only filenames are parsed here, and anything this app did not
/// write must degrade to "no date", never to a panic (panic = abort).
fn parse_stamp(s: &str) -> Option<u64> {
    let (date, time) = s.split_once('-')?;
    // Require exactly 8 + 6 ASCII digits. Without the digit check, a multibyte
    // char that satisfies the byte-length test (e.g. "123é456") would panic at
    // the byte-offset slices below.
    if date.len() != 8
        || time.len() != 6
        || !date.bytes().all(|b| b.is_ascii_digit())
        || !time.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let y: i64 = date[0..4].parse().ok()?;
    let mo: i64 = date[4..6].parse().ok()?;
    let d: i64 = date[6..8].parse().ok()?;
    let h: u64 = time[0..2].parse().ok()?;
    let mi: u64 = time[2..4].parse().ok()?;
    let se: u64 = time[4..6].parse().ok()?;

    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let month_days = match mo {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if y < 1970 || !(1..=month_days).contains(&d) || h > 23 || mi > 59 || se > 59 {
        return None;
    }

    // Days since epoch (Howard Hinnant's days_from_civil); y >= 1970 keeps
    // every intermediate non-negative.
    let yy = if mo <= 2 { y - 1 } else { y };
    let era = yy / 400;
    let yoe = yy - era * 400;
    let doy = (153 * (if mo > 2 { mo - 3 } else { mo + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = u64::try_from(era * 146_097 + doe - 719_468).ok()?;
    days.checked_mul(86_400)?.checked_add(h * 3600 + mi * 60 + se)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn search_dir(files: &[(&str, &str)]) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("hawser-search-test-{}", artifacts::random_hex(8)));
        std::fs::create_dir_all(&d).unwrap();
        for (name, body) in files {
            std::fs::write(d.join(name), body).unwrap();
        }
        d
    }

    const NEVER: &dyn Fn() -> bool = &|| false;

    #[test]
    fn search_finds_lines_case_insensitively_newest_first() {
        let d = search_dir(&[
            ("fw1_20260901-100000.log", "fw1# show run\nfw1# Show Interfaces\n"),
            ("core_20261001-100000.log", "core# show interfaces status\n"),
            ("notes.txt", "show interfaces"),
        ]);
        let r = search_in(&d, "SHOW INTERFACES", 50, NEVER).unwrap();
        assert_eq!(r.scanned, 2);
        assert!(!r.truncated);
        let got: Vec<_> = r.hits.iter().map(|h| (h.host.as_str(), h.line)).collect();
        assert_eq!(got, [("core", 1), ("fw1", 2)]);
        assert_eq!(r.hits[1].text, "fw1# Show Interfaces");
    }

    #[test]
    fn search_ignores_tiny_queries_and_caps_results() {
        let body = "match\n".repeat(100);
        let d = search_dir(&[
            ("a_20261001-100000.log", body.as_str()),
            ("b_20261002-100000.log", body.as_str()),
        ]);
        assert!(search_in(&d, " m ", 50, NEVER).unwrap().hits.is_empty());
        let r = search_in(&d, "match", 1000, NEVER).unwrap();
        assert_eq!(r.hits.len(), 2 * HITS_PER_LOG);
        assert!(r.truncated);
        let r = search_in(&d, "match", 10, NEVER).unwrap();
        assert_eq!(r.hits.len(), 10);
        assert!(r.truncated);
    }

    #[test]
    fn search_keeps_the_newest_hits_of_a_chatty_session() {
        let body: String = (1..=100).map(|i| format!("match {i}\n")).collect();
        let d = search_dir(&[("a_20261001-100000.log", body.as_str())]);
        let r = search_in(&d, "match", 1000, NEVER).unwrap();
        let lines: Vec<u64> = r.hits.iter().map(|h| h.line).collect();
        assert_eq!(lines, (76..=100).collect::<Vec<u64>>());
    }

    #[test]
    fn a_superseded_search_stops_early() {
        let d = search_dir(&[("a_20261001-100000.log", "match\n")]);
        let r = search_in(&d, "match", 50, &|| true).unwrap();
        assert!(r.cancelled);
        assert!(r.hits.is_empty());
        // The generation counter is what lib.rs wires in.
        let g = begin_search();
        let stale = || SEARCH_GEN.load(std::sync::atomic::Ordering::SeqCst) != g;
        assert!(!stale());
        cancel_searches();
        assert!(stale());
    }

    #[cfg(unix)]
    #[test]
    fn search_does_not_follow_symlinks() {
        let secret = search_dir(&[("x.txt", "needle in a private file\n")]);
        let d = search_dir(&[]);
        std::os::unix::fs::symlink(secret.join("x.txt"), d.join("evil_20261001-100000.log")).unwrap();
        assert!(search_in(&d, "needle", 50, NEVER).unwrap().hits.is_empty());
    }

    #[test]
    fn folding_matches_turkish_dotted_i_and_greek_sigma() {
        let d = search_dir(&[(
            "a_20261001-100000.log",
            "İSTANBUL office\nflight to izmir\nΠΑΝΕΠΙΣΤΗΜΙΟ\nοδος\n",
        )]);
        let lines = |q: &str| -> Vec<u64> {
            search_in(&d, q, 50, NEVER).unwrap().hits.iter().map(|h| h.line).collect()
        };
        assert_eq!(lines("istanbul"), [1]);
        assert_eq!(lines("İzmir"), [2]);
        assert_eq!(lines("ΠΑΝΕΠΙΣ"), [3]);
        assert_eq!(lines("οδοσ"), [4]);
        assert_eq!(fold("ΟΣ"), "οσ");
        assert_eq!(fold("İ"), "i");
    }

    #[test]
    fn folding_expands_common_full_folds() {
        let d = search_dir(&[("a_20261001-100000.log", "Hauptstraße 1
STRASSE 2
the ﬁle
GROẞ
")]);
        let lines = |q: &str| -> Vec<u64> {
            search_in(&d, q, 50, NEVER).unwrap().hits.iter().map(|h| h.line).collect()
        };
        assert_eq!(lines("STRASSE"), [1, 2]);
        assert_eq!(lines("straße"), [1, 2]);
        assert_eq!(lines("file"), [3]);
        assert_eq!(lines("gross"), [4]);
        // Same vectors as the frontend test.
        assert_eq!(fold("Straße"), "strasse");
        assert_eq!(fold("ẞﬃ"), "ssffi");
        // The hit's snippet still maps back to the original characters.
        assert_eq!(orig_char_index("Hauptstraße", fold("Hauptstraße").find("sse").unwrap()), 9);
    }

    #[test]
    fn match_offset_survives_case_expansion() {
        // Each 'İ' is two bytes but folds to one; 300 of them would push a
        // naive folded-offset window right past the match.
        let line = format!("{}needle{}", "İ".repeat(300), "x".repeat(300));
        let at = fold(&line).find("needle").unwrap();
        assert_eq!(orig_char_index(&line, at), 300);
        assert!(snippet(&line, orig_char_index(&line, at)).contains("needle"));
    }

    #[test]
    fn long_lines_are_windowed_around_the_match() {
        let line = format!("{}NEEDLE{}", "é".repeat(1000), "x".repeat(1000));
        let s = snippet(&line, 1000);
        assert!(s.starts_with('…') && s.ends_with('…'));
        assert!(s.contains("NEEDLE"));
        assert!(s.chars().count() <= SNIPPET_CHARS + 2);
    }

    #[test]
    fn strips_colour_and_keeps_text() {
        let (out, rest) = strip_ansi(b"\x1b[1;32mhello\x1b[0m world\r\n");
        assert_eq!(String::from_utf8_lossy(&out), "hello world\n");
        assert!(rest.is_empty());
    }

    #[test]
    fn carries_split_sequence_across_chunks() {
        // Sequence cut in half by a chunk boundary.
        let (out1, rest1) = strip_ansi(b"abc\x1b[3");
        assert_eq!(String::from_utf8_lossy(&out1), "abc");
        assert!(!rest1.is_empty(), "incomplete sequence is carried forward");

        let mut joined = rest1;
        joined.extend_from_slice(b"1mdef");
        let (out2, rest2) = strip_ansi(&joined);
        assert_eq!(String::from_utf8_lossy(&out2), "def");
        assert!(rest2.is_empty());
    }

    #[test]
    fn strips_osc_title_sequences() {
        let (out, _) = strip_ansi(b"\x1b]0;my title\x07prompt$ ");
        assert_eq!(String::from_utf8_lossy(&out), "prompt$ ");
    }

    #[test]
    fn strips_dcs_apc_sos_pm_bodies_and_st_terminated_osc() {
        let (out, rest) = strip_ansi(b"a\x1bPq#0;2;0;0;0~~\x1b\\b\x1b_Gf=24;AAAA\x1b\\c\x1bXsos\x07d\x1b^pm\x1b\\e\x1b]2;t\x1b\\f");
        assert_eq!(String::from_utf8_lossy(&out), "abcdef");
        assert!(rest.is_empty(), "an ST at the very end is complete, not carried: {rest:?}");
        // CAN aborts a sequence.
        let (out, _) = strip_ansi(b"x\x1bPjunk\x18y");
        assert_eq!(String::from_utf8_lossy(&out), "xy");
    }

    /// An OSC 52 clipboard blob or an inline image (megabytes of base64) split
    /// across many chunks never lands in the transcript as text.
    #[test]
    fn large_escape_payloads_never_reach_the_transcript() {
        let dir = std::env::temp_dir().join(format!("hawser-osc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.log");
        let file = OpenOptions::new().create(true).append(true).open(&path).unwrap();
        let mut log = SessionLog {
            file,
            path: path.clone(),
            partial: Vec::new(),
            written: 0,
            capped: false,
            in_string: false,
            string_esc: false,
            string_skipped: 0,
        };
        let body = "QUJD".repeat(512 * 1024); // 2 MiB of base64
        for (intro, end) in [("\x1b]52;c;", "\x07"), ("\x1b]1337;File=inline=1:", "\x1b\\"), ("\x1b_Ga=T;", "\x1b\\"), ("\x1bPq", "\x1b\\")] {
            let stream = format!("before {intro}{body}{end} after\n");
            // 16 KiB chunks, as the PTY reader delivers them; the ST split
            // across two chunks as well.
            for c in stream.as_bytes().chunks(16 * 1024 - 1) {
                log.append(c);
            }
        }
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("QUJD"), "payload leaked ({} bytes written)", text.len());
        assert_eq!(text.matches("before  after").count(), 4, "{text:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn strips_charset_designators() {
        let (out, rest) = strip_ansi(b"a\x1b(B\x1b[mb\x1b)0c\x1b#8d");
        assert_eq!(String::from_utf8_lossy(&out), "abcd");
        assert!(rest.is_empty());

        // Designator split before its final byte is carried, not leaked.
        let (out1, rest1) = strip_ansi(b"x\x1b(");
        assert_eq!(String::from_utf8_lossy(&out1), "x");
        let mut joined = rest1;
        joined.extend_from_slice(b"By");
        let (out2, _) = strip_ansi(&joined);
        assert_eq!(String::from_utf8_lossy(&out2), "y");
    }

    #[test]
    fn log_names_parse_with_and_without_an_endpoint_tag() {
        assert_eq!(
            split_log_name("192.0.2.10_20260918-141530.log"),
            Some(("192.0.2.10", "20260918-141530"))
        );
        assert_eq!(
            split_log_name("192.0.2.10_20260918-141530.2.log"),
            Some(("192.0.2.10", "20260918-141530"))
        );
        assert_eq!(split_log_name("notes.log"), None);
        let tag = artifacts::endpoint_tag("host:h-1");
        let name = format!("fw_lab@{tag}_20261030-101500.3.log");
        let (host, _) = split_log_name(&name).unwrap();
        assert_eq!(artifacts::split_tagged(host), Some(("fw_lab", tag.as_str())));

        let d = search_dir(&[
            (name.as_str(), "x\n"),
            ("fw_lab_20261030-101500.log", "x\n"),
            ("local-zsh_20261030-101500.log", "x\n"),
        ]);
        let mut got: Vec<_> = list_in(&d)
            .unwrap()
            .into_iter()
            .map(|e| (e.host, e.endpoint.is_some(), e.legacy))
            .collect();
        got.sort();
        assert_eq!(
            got,
            [
                ("fw_lab".to_string(), false, true),
                ("fw_lab".to_string(), true, false),
                ("local-zsh".to_string(), false, false),
            ]
        );
    }

    /// A transcript as `SessionLog::create_for` would write it.
    fn transcript(endpoint: Option<&str>, host: &str, stamp: &str, body: &str) -> (String, String) {
        let name = match endpoint {
            Some(e) => format!("{}@{}_{stamp}.log", artifacts::safe_component(host), artifacts::endpoint_tag(e)),
            None => format!("{}_{stamp}.log", slug(host)),
        };
        (name, format!("{}\n{body}", header_line("admin", host, stamp, endpoint)))
    }

    #[test]
    fn latest_transcript_is_per_endpoint_and_never_legacy() {
        let a = "host:prod-fw";
        let b = "host:lab-fw|via:host:bastion-b";
        let files = [
            transcript(Some(a), "10.0.0.1", "20261101-090000", "prod show run\n"),
            transcript(Some(b), "10.0.0.1", "20261101-080000", "lab output\n"),
            // Newest of all, but hostname-keyed: must never be picked.
            transcript(None, "10.0.0.1", "20261101-100000", "legacy output\n"),
        ];
        let refs: Vec<(&str, &str)> = files.iter().map(|(n, b)| (n.as_str(), b.as_str())).collect();
        let d = search_dir(&refs);
        let got_a = latest_in(&d, a, 4000).unwrap().unwrap();
        assert!(got_a.contains("prod show run") && !got_a.contains("lab") && !got_a.contains("legacy"));
        let got_b = latest_in(&d, b, 4000).unwrap().unwrap();
        assert!(got_b.contains("lab output") && !got_b.contains("prod"));
        assert_eq!(latest_in(&d, "host:other", 4000).unwrap(), None);
        assert_eq!(latest_in(&d, "qc:admin@10.0.0.1:22", 4000).unwrap(), None);
    }

    #[test]
    fn latest_transcript_checks_the_header_not_just_the_name() {
        // Right tag in the name, but the header names another endpoint (a
        // renamed or copied file): not this endpoint's output.
        let a = "host:a";
        let (name, _) = transcript(Some(a), "fw", "20261101-090000", "");
        let (_, other_body) = transcript(Some("host:b"), "fw", "20261101-090000", "b's output\n");
        let d = search_dir(&[(name.as_str(), other_body.as_str())]);
        assert_eq!(latest_in(&d, a, 4000).unwrap(), None);
    }

    #[cfg(unix)]
    #[test]
    fn latest_transcript_skips_links() {
        let a = "host:a";
        let (name, body) = transcript(Some(a), "fw", "20261101-090000", "real\n");
        let elsewhere = search_dir(&[("x.log", body.as_str())]);
        let d = search_dir(&[]);
        std::os::unix::fs::symlink(elsewhere.join("x.log"), d.join(&name)).unwrap();
        assert_eq!(latest_in(&d, a, 4000).unwrap(), None);
    }

    #[test]
    fn pages_tile_the_transcript_on_line_boundaries() {
        let body: String = (1..=200).map(|i| format!("line{i}\n")).collect();
        let d = search_dir(&[("a_20261001-100000.log", body.as_str())]);
        let name = "a_20261001-100000.log";
        let check = |p: &LogPage| {
            let first = p.text.lines().next().unwrap();
            assert_eq!(first, format!("line{}", p.first_line), "page {p:?}");
            assert!(p.text.ends_with('\n'));
        };

        let tail = read_page_in(&d, name, PageAt::Tail, 100).unwrap();
        assert_eq!((tail.end, tail.total), (body.len() as u64, body.len() as u64));
        check(&tail);

        // Walking back with Before() reassembles the whole file exactly.
        let mut text = tail.text.clone();
        let mut start = tail.start;
        while start > 0 {
            let p = read_page_in(&d, name, PageAt::Before(start), 100).unwrap();
            check(&p);
            assert_eq!(p.end, start);
            text = p.text + &text;
            start = p.start;
        }
        assert_eq!(text, body);

        let around = read_page_in(&d, name, PageAt::Line(57), 100).unwrap();
        check(&around);
        assert!(around.text.contains("line57\n"));
        let next = read_page_in(&d, name, PageAt::After(around.end), 100).unwrap();
        check(&next);
        assert_eq!(next.start, around.end);

        assert!(read_page_in(&d, "../x.log", PageAt::Tail, 100).is_err());
    }

    #[test]
    fn timestamp_is_readable_and_sorts() {
        // 2026-09-17T12:00:00Z
        let name = timestamp_name(1_789_646_400);
        assert_eq!(&name[..8], "20260917");
        assert!(timestamp_name(1_789_646_400) < timestamp_name(1_789_732_800));
        assert_eq!(parse_stamp(&name), Some(1_789_646_400));
    }

    #[test]
    fn parse_stamp_rejects_impossible_dates_instead_of_wrapping() {
        assert_eq!(parse_stamp("19691231-120000"), None); // before the epoch
        assert_eq!(parse_stamp("00000101-000000"), None);
        assert_eq!(parse_stamp("20260231-000000"), None);
        assert_eq!(parse_stamp("20261301-000000"), None);
        assert_eq!(parse_stamp("20260101-250000"), None);
        assert_eq!(parse_stamp("20260101-006000"), None);
        assert_eq!(parse_stamp("19700101-000000"), Some(0));
        assert_eq!(parse_stamp("20240229-000000"), Some(1_709_164_800));
        assert_eq!(parse_stamp("99991231-235959"), Some(253_402_300_799));
        assert_eq!(split_log_name("lab_19691231-120000.log"), None);
    }
}
