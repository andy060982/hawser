//! "Capture command output to file" — run one command over a fresh, hidden exec
//! channel (see `Registry::exec_capture`) and store the output timestamped under
//! `<appdata>/hawser/captures/<host>/`. One plain-text file per capture — the
//! same greppable, Hawser-independent storage as config snapshots, but for an
//! arbitrary command (a `show tech-support`, a `dmesg`, a big log) rather than
//! the host's saved config command.

use serde::Serialize;
use std::path::PathBuf;

use super::known_hosts::KnownHostsError;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureResult {
    pub path: String,
    pub bytes: u64,
    pub lines: usize,
}

/// Reduce an arbitrary string to a safe filesystem component: alphanumerics,
/// '-' and '.' kept, everything else '_'. An all-dots result (which would be a
/// path-traversal component) is neutralised so the path can never escape the
/// captures root.
fn slug(s: &str) -> String {
    let out: String = s
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '.' { c } else { '_' })
        .collect();
    if out.chars().all(|c| c == '.') {
        "_".repeat(out.len().max(1))
    } else {
        out
    }
}

fn captures_dir(host: &str) -> Result<PathBuf, KnownHostsError> {
    let store = super::known_hosts::store_path()?;
    Ok(store
        .parent()
        .ok_or(KnownHostsError::NoAppDataDir)?
        .join("captures")
        .join(slug(host)))
}

/// Save one command capture. The filename is a short slug of the command plus a
/// timestamp, so several captures on one host stay distinguishable at a glance.
pub fn save_capture(host: &str, command: &str, content: &str) -> Result<CaptureResult, KnownHostsError> {
    use std::io::Write as _;

    let dir = captures_dir(host)?;
    std::fs::create_dir_all(&dir).map_err(|source| KnownHostsError::Io {
        path: dir.clone(),
        source,
    })?;
    // A captured config dump can hold secrets (SNMP communities, PSKs); keep the
    // per-host directory owner-only.
    super::platform::restrict_perms(&dir, 0o700);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Cap the command slug so a long command line can't blow the filename limit.
    let mut cmd_slug = slug(command);
    cmd_slug.truncate(40);
    let base = format!(
        "{}-{}",
        cmd_slug.trim_matches('_'),
        super::session_log::timestamp_for(now)
    );

    // Create the file EXCLUSIVELY and owner-only:
    //   - create_new(true) refuses to open an existing path, so it can never
    //     follow or overwrite a symlink/junction a hostile tree planted at the
    //     target (the plain fs::write here previously would have);
    //   - mode 0600 makes it owner-only from birth on Unix (no world-readable
    //     window), a no-op on Windows where the per-user profile already gates.
    // On the rare same-second, same-command collision, bump a numeric suffix so
    // two captures never clobber each other either.
    let mut path = dir.join(format!("{base}.txt"));
    let mut file = {
        let mut n: u32 = 0;
        loop {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            match opts.open(&path) {
                Ok(f) => break f,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && n < 1000 => {
                    n += 1;
                    path = dir.join(format!("{base}.{n}.txt"));
                }
                Err(source) => {
                    return Err(KnownHostsError::Io {
                        path: path.clone(),
                        source,
                    })
                }
            }
        }
    };
    file.write_all(content.as_bytes()).map_err(|source| KnownHostsError::Io {
        path: path.clone(),
        source,
    })?;

    Ok(CaptureResult {
        path: path.to_string_lossy().to_string(),
        bytes: content.len() as u64,
        lines: content.lines().count(),
    })
}
