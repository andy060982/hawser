//! The format of a Hawser vault item: a secret together with a digest of where
//! it may go.
//!
//! A saved host password (or key passphrase) and the AI provider key are each
//! stored as ONE OS-vault item:
//!
//! ```text
//! hawser-vault:2:{"user":"admin","secret":"…","dest_digest":"<sha-256 hex>"}
//! hawser-vault:2:{"user":"api-key","secret":"…","origin_digest":"<sha-256 hex>"}
//! ```
//!
//! The destination list itself lives in a backend-owned file
//! (`credential_bindings.json`, `ai_origins.json`), keyed by id; the vault
//! item holds only its SHA-256 digest ([`dest_digest`], [`origin_digest`]).
//! A secret is authorized for a destination only when the file entry's digest
//! equals the one in the secret's own vault item, so the file and the vault
//! can never disagree silently: any mismatch (a crash between the two writes,
//! a failed rollback, a tampered file) fails closed and the user re-enters the
//! secret. The item's size no longer depends on how many hosts share it,
//! which matters for Windows Credential Manager's 2,560-byte blob limit.
//!
//! The `hawser-vault:2:` prefix makes the encoding unambiguous: nothing a user
//! could type as a password is ever read as an item, and anything without the
//! prefix is refused (`DecodeError::NotAnItem`), never guessed at.
//!
//! No other format is read. Hawser has never been released: the last public
//! build was Skiff v0.5.0-beta.1, which used a different vault namespace
//! (`skiff:host:…`), and the rename to Hawser was a clean break with no
//! migration. The intermediate formats of unreleased development builds (plain
//! secrets, the W4b intent journals, the W4c JSON envelope) therefore exist on
//! no user's machine and are not upgraded; on a developer machine such an item
//! fails closed and the secret is entered again.
//!
//! Secrets are held in `Zeroizing` buffers, the item types have no
//! `Debug`/`Display`, and nothing here logs.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

/// The format version this build writes and accepts.
pub const VERSION: u64 = 2;

/// Every item starts with this marker (then `VERSION`, a colon and JSON).
const MAGIC: &str = "hawser-vault:";

/// Windows Credential Manager's limit on a credential blob
/// (`CRED_MAX_CREDENTIAL_BLOB_SIZE`, 5 * 512 bytes). Items are stored there as
/// UTF-16, so an item may be at most half as many UTF-16 units.
const WINDOWS_MAX_BLOB: usize = 5 * 512;

/// A destination a host secret may be sent to: (host, port, username).
pub type Destination = (String, u16, String);

/// An origin an API key may be sent to: (provider kind, base URL).
pub type Origin = (String, String);

/// A decoded vault item. Deliberately not `Debug`.
pub struct Envelope {
    /// The vault item's account name (Windows shows it; it is not secret).
    pub user: String,
    pub secret: Zeroizing<String>,
    /// For a host credential: [`dest_digest`] of its destination set.
    pub dest_digest: Option<String>,
    /// For an AI key: [`origin_digest`] of its one origin.
    pub origin_digest: Option<String>,
}

/// The item could not be decoded. Carries no secret material.
#[derive(Debug, PartialEq)]
pub enum DecodeError {
    /// Not a Hawser vault item (no `hawser-vault:` marker): written by an
    /// unreleased development build, or by something else.
    NotAnItem,
    /// Marked as an item, but not one this build can read.
    Malformed,
    /// An item from a newer build.
    UnsupportedVersion(u64),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::NotAnItem => write!(f, "the saved item is not in Hawser's format; enter it again"),
            DecodeError::Malformed => write!(f, "the saved item is damaged; enter it again"),
            DecodeError::UnsupportedVersion(v) => {
                write!(f, "the saved item was written by a newer Hawser (format {v})")
            }
        }
    }
}

/// The wire shape. Its `secret` is wiped when it is dropped, including when
/// decoding fails part-way.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    user: String,
    secret: String,
    #[serde(default)]
    dest_digest: Option<String>,
    #[serde(default)]
    origin_digest: Option<String>,
}

impl Drop for Wire {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

#[derive(Serialize)]
struct WireRef<'a> {
    user: &'a str,
    secret: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    dest_digest: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    origin_digest: Option<&'a str>,
}

fn is_digest(d: &str) -> bool {
    d.len() == 64 && d.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Decode a vault item. Takes ownership so the raw text is wiped on return.
pub fn decode(raw: Zeroizing<String>) -> Result<Envelope, DecodeError> {
    let rest = raw.strip_prefix(MAGIC).ok_or(DecodeError::NotAnItem)?;
    let (version, json) = rest.split_once(':').ok_or(DecodeError::Malformed)?;
    let version: u64 = version.parse().map_err(|_| DecodeError::Malformed)?;
    if version != VERSION {
        return Err(DecodeError::UnsupportedVersion(version));
    }
    let mut wire: Wire = serde_json::from_str(json).map_err(|_| DecodeError::Malformed)?;
    // Exactly one kind of authorization: a host item or an AI item.
    let ok = match (&wire.dest_digest, &wire.origin_digest) {
        (Some(d), None) | (None, Some(d)) => is_digest(d),
        _ => false,
    };
    if !ok {
        return Err(DecodeError::Malformed);
    }
    Ok(Envelope {
        user: std::mem::take(&mut wire.user),
        secret: Zeroizing::new(std::mem::take(&mut wire.secret)),
        dest_digest: wire.dest_digest.take(),
        origin_digest: wire.origin_digest.take(),
    })
}

/// Encode an item for one vault write. The output buffer is sized up front,
/// so it is never reallocated (which would leave copies of the secret
/// behind), and it is wiped when dropped.
pub fn encode(env: &Envelope) -> Result<Zeroizing<String>, String> {
    let wire = WireRef {
        user: &env.user,
        secret: env.secret.as_str(),
        dest_digest: env.dest_digest.as_deref(),
        origin_digest: env.origin_digest.as_deref(),
    };
    let meta = WireRef { secret: "", ..wire };
    let meta_len = serde_json::to_string(&meta).map_err(|e| e.to_string())?.len();
    let prefix = format!("{MAGIC}{VERSION}:");
    // Worst case a character escapes to six bytes (\uXXXX).
    let mut buf: Zeroizing<Vec<u8>> =
        Zeroizing::new(Vec::with_capacity(prefix.len() + meta_len + env.secret.len() * 6 + 16));
    buf.extend_from_slice(prefix.as_bytes());
    serde_json::to_writer(&mut *buf, &wire).map_err(|e| e.to_string())?;
    let text = String::from_utf8(std::mem::take(&mut *buf)).map_err(|e| e.to_string())?;
    let text = Zeroizing::new(text);
    check_size(&text, cfg!(windows))?;
    Ok(text)
}

/// Refuse an item the vault cannot store (Windows only; macOS Keychain and
/// the Secret Service have no practical limit). Checked before writing, so the
/// error is clear and nothing is written. With destinations held as a digest
/// only an extremely long secret can reach it.
fn check_size(text: &str, windows: bool) -> Result<(), String> {
    if windows && text.encode_utf16().count() * 2 > WINDOWS_MAX_BLOB {
        return Err("this secret is too long for Windows Credential Manager to store".into());
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// SHA-256 over the canonical destination SET of vault id `id_key` (the id as
/// the vault keys it, `credentials::vault_id_key`): sorted, duplicates
/// removed, so the order the destinations were listed in does not matter.
/// The id and a domain label are hashed too, so a digest never authorizes
/// another credential's list or an AI origin.
pub fn dest_digest(id_key: &str, dests: &[Destination]) -> String {
    let mut set: Vec<&Destination> = dests.iter().collect();
    set.sort();
    set.dedup();
    let body = serde_json::to_string(&(id_key, set)).unwrap_or_default();
    let mut h = Sha256::new();
    h.update(b"hawser-dests:v1\n");
    h.update(body.as_bytes());
    hex(&h.finalize())
}

/// SHA-256 over AI profile `profile`'s origin, exactly as stored.
pub fn origin_digest(profile: &str, origin: &Origin) -> String {
    let body = serde_json::to_string(&(profile, origin)).unwrap_or_default();
    let mut h = Sha256::new();
    h.update(b"hawser-ai-origin:v1\n");
    h.update(body.as_bytes());
    hex(&h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host_item(secret: &str) -> Envelope {
        Envelope {
            user: "admin".into(),
            secret: Zeroizing::new(secret.into()),
            dest_digest: Some(dest_digest("h-1", &[("fw-01".into(), 22, "admin".into())])),
            origin_digest: None,
        }
    }

    #[test]
    fn host_items_round_trip_including_awkward_secrets() {
        for secret in ["pw", "p\"w\\x\u{1}\u{4e2d}", "", "{\"v\":2}", "hawser-vault:2:{}"] {
            let text = encode(&host_item(secret)).unwrap();
            assert!(text.starts_with("hawser-vault:2:{"), "marked");
            let env = decode(text).unwrap();
            assert_eq!(env.secret.as_str(), secret);
            assert_eq!(env.user, "admin");
            assert_eq!(env.dest_digest, host_item("").dest_digest);
            assert!(env.origin_digest.is_none());
        }
    }

    #[test]
    fn ai_items_carry_an_origin_digest() {
        let o = ("openai".to_string(), "https://api.openai.com/v1".to_string());
        let env = Envelope {
            user: "api-key".into(),
            secret: Zeroizing::new("sk-1".into()),
            dest_digest: None,
            origin_digest: Some(origin_digest("default", &o)),
        };
        let back = decode(encode(&env).unwrap()).unwrap();
        assert_eq!(back.origin_digest, Some(origin_digest("default", &o)));
        assert!(back.dest_digest.is_none());
    }

    /// W4d: an unmarked value is never an item, however it looks, so no
    /// password a user typed can be read as one (or as another secret).
    #[test]
    fn anything_without_the_marker_is_refused() {
        let d = "0".repeat(64);
        for raw in [
            "hunter2".to_string(),
            "{\"v\":\"example\"}".to_string(),
            format!("{{\"v\":2,\"user\":\"u\",\"secret\":\"x\",\"destinations\":[]}}"),
            format!("{{\"user\":\"u\",\"secret\":\"x\",\"dest_digest\":\"{d}\"}}"),
            " hawser-vault:2:{}".to_string(),
            "HAWSER-VAULT:2:{}".to_string(),
            String::new(),
        ] {
            assert_eq!(decode(Zeroizing::new(raw.clone())).err(), Some(DecodeError::NotAnItem), "{raw:?}");
        }
    }

    #[test]
    fn damaged_or_future_items_are_refused_not_guessed() {
        let d = "a".repeat(64);
        let bad = |s: String| decode(Zeroizing::new(s)).err();
        assert_eq!(bad("hawser-vault:2:{\"user\":\"u\",\"secret\":".into()), Some(DecodeError::Malformed));
        assert_eq!(bad("hawser-vault:2:{\"user\":\"u\",\"secret\":\"x\"}".into()), Some(DecodeError::Malformed), "no digest");
        assert_eq!(
            bad(format!("hawser-vault:2:{{\"user\":\"u\",\"secret\":\"x\",\"dest_digest\":\"{d}\",\"origin_digest\":\"{d}\"}}")),
            Some(DecodeError::Malformed),
            "both kinds"
        );
        assert_eq!(
            bad("hawser-vault:2:{\"user\":\"u\",\"secret\":\"x\",\"dest_digest\":\"XYZ\"}".into()),
            Some(DecodeError::Malformed),
            "not a digest"
        );
        assert_eq!(
            bad(format!("hawser-vault:2:{{\"user\":\"u\",\"secret\":\"x\",\"dest_digest\":\"{d}\",\"destinations\":[]}}")),
            Some(DecodeError::Malformed),
            "unknown field"
        );
        assert_eq!(bad(format!("hawser-vault:3:{{\"secret\":\"x\",\"dest_digest\":\"{d}\"}}")), Some(DecodeError::UnsupportedVersion(3)));
        assert_eq!(bad("hawser-vault:x:{}".into()), Some(DecodeError::Malformed));
        assert_eq!(bad("hawser-vault:".into()), Some(DecodeError::Malformed));
    }

    #[test]
    fn decode_errors_never_carry_the_secret() {
        let e = decode(Zeroizing::new("hawser-vault:2:{\"user\":\"u\",\"secret\":\"topsecret\",\"dest_digest\":7}".into()))
            .err()
            .unwrap();
        assert!(!format!("{e} {e:?}").contains("topsecret"));
    }

    #[test]
    fn the_destination_digest_is_over_the_set_and_the_id() {
        let a: Destination = ("a".into(), 22, "u".into());
        let b: Destination = ("b".into(), 2222, "root".into());
        let ab = dest_digest("h-1", &[a.clone(), b.clone()]);
        assert_eq!(ab, dest_digest("h-1", &[b.clone(), a.clone(), b.clone()]), "order and repeats do not matter");
        assert_ne!(ab, dest_digest("h-1", &[a.clone()]));
        assert_ne!(ab, dest_digest("h-2", &[a.clone(), b.clone()]), "bound to its id");
        assert_ne!(dest_digest("h-1", &[]), dest_digest("h-2", &[]));
        assert!(is_digest(&ab));
        let o = ("a".to_string(), "u".to_string());
        assert_ne!(origin_digest("default", &o), dest_digest("default", &[]));
    }

    /// W4d: the item no longer grows with the destinations, so 500 hosts
    /// sharing a password fit in Windows Credential Manager.
    #[test]
    fn item_size_is_independent_of_the_destination_count() {
        let many: Vec<Destination> =
            (0..500).map(|i| (format!("host-{i}.example.internal"), 22, "administrator".to_string())).collect();
        let env = Envelope { dest_digest: Some(dest_digest("h-1", &many)), ..host_item("a-reasonable-password") };
        let text = encode(&env).unwrap();
        assert!(check_size(&text, true).is_ok());
        assert_eq!(text.len(), encode(&host_item("a-reasonable-password")).unwrap().len());
        // Only an absurdly long secret is refused, and only on Windows.
        let huge = "x".repeat(2000);
        let wire = WireRef { user: "u", secret: &huge, dest_digest: env.dest_digest.as_deref(), origin_digest: None };
        let text = format!("{MAGIC}{VERSION}:{}", serde_json::to_string(&wire).unwrap());
        assert!(check_size(&text, true).is_err());
        assert!(check_size(&text, false).is_ok());
    }
}
