//! "Capture command output to file" — run one command over a fresh, hidden exec
//! channel (see `Registry::exec_capture`) and store the output timestamped under
//! `<appdata>/hawser/captures/<host>@<endpoint tag>/`. One plain-text file per
//! capture — the same greppable, Hawser-independent storage as config
//! snapshots, but for an arbitrary command (a `show tech-support`, a `dmesg`, a big log) rather than
//! the host's saved config command.

use serde::Serialize;
use std::path::PathBuf;

use super::artifacts;
use super::known_hosts::KnownHostsError;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureResult {
    pub path: String,
    pub bytes: u64,
    pub lines: usize,
}

fn captures_dir(endpoint: &str, label: &str) -> Result<PathBuf, KnownHostsError> {
    artifacts::validate_endpoint(endpoint)?;
    let store = super::known_hosts::store_path()?;
    let root = store
        .parent()
        .ok_or(KnownHostsError::NoAppDataDir)?
        .join("captures");
    Ok(artifacts::endpoint_dir(&root, label, endpoint))
}

/// Save one command capture under the endpoint's folder.
///
/// The filename is the timestamp plus a random id, never derived from the
/// command: a command line can carry a token (`curl -H 'Authorization: …'`),
/// and a filename turns up in directory listings, backups and indexers that
/// never open the file.
pub fn save_capture(endpoint: &str, label: &str, content: &str) -> Result<CaptureResult, KnownHostsError> {
    let dir = captures_dir(endpoint, label)?;
    // Every component a real folder, never through a planted link.
    artifacts::verified_dir(&dir, true)?;
    // A captured config dump can hold secrets (SNMP communities, PSKs); keep the
    // per-host directory owner-only.
    super::platform::restrict_perms(&dir, 0o700);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let base = capture_base(&super::session_log::timestamp_for(now), &artifacts::random_hex(4));

    // Staged, synced, then published under a name nothing else holds (owner-
    // only from birth, never through a planted link): a failed write leaves no
    // partial file behind.
    let name = artifacts::publish_new(&dir, &base, "txt", content.as_bytes()).map_err(|source| {
        KnownHostsError::Io { path: dir.join(format!("{base}.txt")), source }
    })?;
    let path = dir.join(name);

    Ok(CaptureResult {
        path: path.to_string_lossy().to_string(),
        bytes: content.len() as u64,
        lines: content.lines().count(),
    })
}

fn capture_base(stamp: &str, id: &str) -> String {
    format!("capture-{stamp}-{id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_names_carry_no_command_text() {
        let base = capture_base("20261030-120000", "a1b2c3d4");
        assert_eq!(base, "capture-20261030-120000-a1b2c3d4");
        assert!(artifacts::random_hex(4).bytes().all(|b| b.is_ascii_hexdigit()));
    }
}
