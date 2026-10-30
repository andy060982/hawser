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
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use super::known_hosts::KnownHostsError;

/// `%APPDATA%\hawser\logs`
pub fn logs_dir() -> Result<PathBuf, KnownHostsError> {
    let store = super::known_hosts::store_path()?;
    Ok(store
        .parent()
        .ok_or(KnownHostsError::NoAppDataDir)?
        .join("logs"))
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
}

impl SessionLog {
    /// Open a transcript for one session. Failure is non-fatal to the caller —
    /// losing a log must never take down a working connection.
    pub fn create(host: &str, username: &str) -> Result<Self, KnownHostsError> {
        let dir = logs_dir()?;
        std::fs::create_dir_all(&dir).map_err(|source| KnownHostsError::Io {
            path: dir.clone(),
            source,
        })?;
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
        let base = format!("{}_{}", slug(host), timestamp_name(now));
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

        let _ = writeln!(
            file,
            "=== hawser session: {username}@{host} started {} UTC ===",
            timestamp_name(now)
        );

        Ok(Self {
            file,
            path,
            partial: Vec::new(),
            written: 0,
            capped: false,
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

        let mut buf = std::mem::take(&mut self.partial);
        buf.extend_from_slice(chunk);

        let (text, mut leftover) = strip_ansi(&buf);
        // Bound the pending-escape carry-over. A real control sequence is a
        // handful of bytes; a multi-KB "unterminated sequence" is a broken or
        // hostile server growing this buffer without bound, so drop it rather
        // than re-prepend it on every future chunk.
        const MAX_PENDING: usize = 64 * 1024;
        if leftover.len() > MAX_PENDING {
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
                // OSC: ESC ] ... terminated by BEL or ESC \
                b']' => {
                    let mut j = i + 2;
                    while j < input.len() {
                        if input[j] == 0x07 {
                            j += 1;
                            break;
                        }
                        if input[j] == 0x1b && j + 1 < input.len() && input[j + 1] == b'\\' {
                            j += 2;
                            break;
                        }
                        j += 1;
                    }
                    if j >= input.len() && !input.ends_with(&[0x07]) {
                        return (out, input[i..].to_vec());
                    }
                    i = j;
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn log_stem_parsing_handles_suffix_and_rejects_other_hosts() {
        assert_eq!(
            split_log_name("192.0.2.10_20260918-141530.log"),
            Some(("192.0.2.10", "20260918-141530"))
        );
        assert_eq!(
            split_log_name("192.0.2.10_20260918-141530.2.log"),
            Some(("192.0.2.10", "20260918-141530"))
        );
        assert_eq!(split_log_name("notes.log"), None);

        // "fw" must not pick up "fw_lab" transcripts, nor "2001:db8::1" those
        // of "2001:db8::1:5".
        assert!(is_log_for("fw_", "fw_20261030-101500.log"));
        assert!(is_log_for("fw_", "fw_20261030-101500.3.log"));
        assert!(!is_log_for("fw_", "fw_lab_20261030-101500.log"));
        let p = format!("{}_", slug("2001:db8::1"));
        assert!(!is_log_for(&p, &format!("{}_20261030-101500.log", slug("2001:db8::1:5"))));
    }

    #[test]
    fn timestamp_is_readable_and_sorts() {
        // 2026-09-17T12:00:00Z
        let name = timestamp_name(1_789_646_400);
        assert_eq!(&name[..8], "20260917");
        assert!(timestamp_name(1_789_646_400) < timestamp_name(1_789_732_800));
    }
}

/* -------------------------------------------------------------------------- */

/// Tail of the most recent transcript for a host.
///
/// This is the only form of "session history" available on appliances. A Palo
/// Alto or a switch cannot run tmux, so nothing on the remote survives the
/// connection dropping — but the transcript does, and replaying its tail into a
/// reconnected tab restores the one thing that actually matters there: what you
/// ran and what it said.
///
/// Returns None when the host has no prior transcript.
pub fn latest_transcript(host: &str, max_bytes: usize) -> Result<Option<String>, KnownHostsError> {
    let dir = match logs_dir() {
        Ok(d) if d.exists() => d,
        _ => return Ok(None),
    };

    let prefix = format!("{}_", slug(host));

    // Newest by modified time rather than by filename: a clock change or a
    // manually copied file would break lexical ordering, and picking the wrong
    // transcript silently shows the user someone else's session.
    let mut newest: Option<(std::time::SystemTime, PathBuf)> = None;
    let entries = std::fs::read_dir(&dir).map_err(|source| KnownHostsError::Io {
        path: dir.clone(),
        source,
    })?;

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        // The rest of the name must be exactly a timestamp: slug() maps ':' and
        // '_' to '_', so a bare prefix match lets "fw" pick up "fw_lab"'s logs
        // (or one IPv6 address another's) and replay the wrong host's session.
        if !is_log_for(&prefix, &name) {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        if meta.len() == 0 {
            continue; // an aborted session has nothing to replay
        }
        let Ok(modified) = meta.modified() else { continue };
        if newest.as_ref().is_none_or(|(t, _)| modified > *t) {
            newest = Some((modified, entry.path()));
        }
    }

    let Some((_, path)) = newest else {
        return Ok(None);
    };

    let bytes = std::fs::read(&path).map_err(|source| KnownHostsError::Io {
        path: path.clone(),
        source,
    })?;

    // Take the tail, then discard the first partial line so the replay never
    // starts mid-word.
    let start = bytes.len().saturating_sub(max_bytes);
    let slice = &bytes[start..];
    let slice = if start > 0 {
        match slice.iter().position(|&b| b == b'\n') {
            Some(i) => &slice[i + 1..],
            None => slice,
        }
    } else {
        slice
    };

    Ok(Some(String::from_utf8_lossy(slice).to_string()))
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
    let dir = match logs_dir() {
        Ok(d) if d.exists() => d,
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
    /// Bare filename, e.g. "192.0.2.10_20260918-141530.log". Also the id used
    /// by `read_log`; never a path, so it cannot be pointed outside the dir.
    pub name: String,
    /// Host slug parsed back out of the filename for grouping in the UI.
    pub host: String,
    /// Unix epoch seconds parsed from the filename's timestamp, for sorting and
    /// display without opening the file.
    pub started: Option<u64>,
    pub bytes: u64,
}

/// List transcripts, newest first. Empty when there are none.
pub fn list() -> Result<Vec<LogEntry>, KnownHostsError> {
    let dir = match logs_dir() {
        Ok(d) if d.exists() => d,
        _ => return Ok(Vec::new()),
    };

    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).map_err(|source| KnownHostsError::Io {
        path: dir.clone(),
        source,
    })? {
        let Ok(entry) = entry else { continue };
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".log") {
            continue;
        }
        let bytes = entry.metadata().map(|m| m.len()).unwrap_or(0);

        // Filename shape is "<host>_<YYYYMMDD-HHMMSS>[.<n>].log". Split on the
        // LAST underscore so hosts containing underscores (slugged dots, etc.)
        // keep their name intact.
        let (host, started) = match split_log_name(&name) {
            Some((h, stamp)) => (h.to_string(), parse_stamp(stamp)),
            None => {
                let stem = name.trim_end_matches(".log");
                match stem.rfind('_') {
                    Some(i) => (stem[..i].to_string(), parse_stamp(&stem[i + 1..])),
                    None => (stem.to_string(), None),
                }
            }
        };
        out.push(LogEntry { name, host, started, bytes });
    }

    out.sort_by(|a, b| b.started.cmp(&a.started));
    Ok(out)
}

/// Read one transcript by name. Rejects anything that is not a bare filename,
/// so a crafted name cannot escape the logs directory or read through a link.
pub fn read_log(name: &str) -> Result<String, KnownHostsError> {
    // Accept only a single *normal* path component ending in .log. Parsing the
    // name (rather than ad-hoc substring checks) rejects separators, absolute
    // paths, Windows prefixes, "." and ".." in one shot. The explicit ':' check
    // additionally blocks Windows drive-relative ("C:foo") and NTFS
    // alternate-data-stream ("foo.log:evil") syntax — a colon is not a path
    // separator, so the component parser alone would let those through.
    let single_normal = {
        let mut comps = std::path::Path::new(name).components();
        matches!(
            (comps.next(), comps.next()),
            (Some(std::path::Component::Normal(c)), None) if c == std::ffi::OsStr::new(name)
        )
    };
    if !single_normal || name.contains(':') || name.contains('\0') || !name.ends_with(".log") {
        return Err(KnownHostsError::Parse(format!("invalid log name: {name}")));
    }

    let path = logs_dir()?.join(name);

    // Never read THROUGH a symlink: a link planted at logs_dir/<name> could
    // redirect the read to any file the process can see. A transcript is always
    // a regular file this app wrote, so refuse a symlink outright.
    if let Ok(meta) = std::fs::symlink_metadata(&path) {
        if meta.file_type().is_symlink() {
            return Err(KnownHostsError::Parse(format!(
                "refusing to read a symlinked log: {name}"
            )));
        }
    }

    // Lossy, like latest_transcript: strip_ansi keeps raw high bytes (Latin-1
    // gear output, a cat'd binary) and the size cap can cut a multibyte char,
    // so a strict UTF-8 read would make the whole transcript unviewable.
    let bytes = std::fs::read(&path).map_err(|source| KnownHostsError::Io { path, source })?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Split "<host>_<YYYYMMDD-HHMMSS>[.<n>].log" into (host slug, stamp), where
/// ".<n>" is the collision suffix `SessionLog::create` adds. None unless the
/// part after the last underscore is a well-formed timestamp.
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

/// True when `name` is a transcript whose host slug is exactly `prefix` minus
/// its trailing underscore — i.e. nothing but a timestamp (and optional
/// collision suffix) follows the prefix.
fn is_log_for(prefix: &str, name: &str) -> bool {
    match (name.strip_prefix(prefix), split_log_name(name)) {
        (Some(_), Some((host, _))) => host.len() + 1 == prefix.len(),
        _ => false,
    }
}

/// Inverse of `timestamp_name`: "YYYYMMDD-HHMMSS" back to epoch seconds.
fn parse_stamp(s: &str) -> Option<u64> {
    let (date, time) = s.split_once('-')?;
    // Require exactly 8 + 6 ASCII digits. Without the digit check, a multibyte
    // char that satisfies the byte-length test (e.g. "123é456") would panic at
    // the byte-offset slices below — and with panic=abort that kills the whole
    // app when logs_list scans a crafted filename.
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

    // Days since epoch (Howard Hinnant's days_from_civil).
    let yy = if mo <= 2 { y - 1 } else { y };
    let era = (if yy >= 0 { yy } else { yy - 399 }) / 400;
    let yoe = (yy - era * 400) as i64;
    let doy = (153 * (if mo > 2 { mo - 3 } else { mo + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some((days as u64) * 86_400 + h * 3600 + mi * 60 + se)
}
