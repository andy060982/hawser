//! The format of a Hawser vault item: a secret together with where it may go.
//!
//! A saved host password (or key passphrase) and the AI provider key are each
//! stored as ONE OS-vault item holding a versioned JSON envelope:
//!
//! ```text
//! {"v":2,"user":"admin","secret":"…","destinations":[["fw-01",22,"admin"],…]}
//! {"v":2,"user":"api-key","secret":"…","origin":["openai","https://api.openai.com/v1"]}
//! ```
//!
//! The secret and its authorization are written by a single vault write, so
//! they can never disagree: no crash, failed second write or rollback can pair
//! a new secret with an old destination. (Earlier builds kept the
//! authorization in a separate file, and needed intent journals to repair the
//! window between the two writes; those are gone.)
//!
//! Items written by those builds hold the plain secret. They are read as
//! [`Item::Legacy`] and keep working, read-only, against the separate binding
//! file until the next save writes an envelope.
//!
//! Secrets are held in `Zeroizing` buffers on both paths, the envelope types
//! have no `Debug`/`Display`, and nothing here logs.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

/// The envelope version this build writes and accepts.
pub const VERSION: u64 = 2;

/// Windows Credential Manager's limit on a credential blob
/// (`CRED_MAX_CREDENTIAL_BLOB_SIZE`, 5 * 512 bytes). Items are stored there as
/// UTF-16, so an envelope may be at most half as many UTF-16 units.
const WINDOWS_MAX_BLOB: usize = 5 * 512;

/// A destination a host secret may be sent to: (host, port, username).
pub type Destination = (String, u16, String);

/// An origin an API key may be sent to: (provider kind, base URL).
pub type Origin = (String, String);

/// A decoded envelope. Deliberately not `Debug`.
pub struct Envelope {
    /// The vault item's account name (Windows shows it; it is not secret).
    pub user: String,
    pub secret: Zeroizing<String>,
    /// For a host credential: every destination it may be sent to.
    pub destinations: Option<Vec<Destination>>,
    /// For an AI key: the one origin it may be sent to.
    pub origin: Option<Origin>,
}

/// What a vault item holds.
pub enum Item {
    /// A v2 envelope.
    V2(Envelope),
    /// A plain secret written by an earlier build; its authorization (if any)
    /// is in the legacy binding file.
    Legacy(Zeroizing<String>),
}

/// The item could not be decoded. Carries no secret material.
#[derive(Debug, PartialEq)]
pub enum DecodeError {
    /// Shaped like an envelope, but not one this build can read.
    Malformed,
    /// An envelope from a newer build.
    UnsupportedVersion(u64),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::Malformed => write!(f, "the saved item is damaged"),
            DecodeError::UnsupportedVersion(v) => {
                write!(f, "the saved item was written by a newer Hawser (format {v})")
            }
        }
    }
}

/// The wire shape. Its `secret` is wiped when it is dropped, including when
/// decoding fails part-way.
#[derive(Deserialize)]
struct Wire {
    v: u64,
    #[serde(default)]
    user: String,
    secret: String,
    #[serde(default)]
    destinations: Option<Vec<Destination>>,
    #[serde(default)]
    origin: Option<Origin>,
}

impl Drop for Wire {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

#[derive(Serialize, Clone, Copy)]
struct WireRef<'a> {
    v: u64,
    user: &'a str,
    secret: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    destinations: Option<&'a [Destination]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    origin: Option<&'a Origin>,
}

/// Whether `raw` claims to be an envelope: a JSON object whose first member is
/// `"v"`. Only this build's writer produces that; a plain password that
/// happens to start the same way is refused (`Malformed`), never guessed at.
fn looks_like_envelope(raw: &str) -> bool {
    let t = raw.trim_start();
    t.strip_prefix('{').is_some_and(|rest| rest.trim_start().starts_with("\"v\""))
}

/// Decode a vault item. Takes ownership so the raw text is wiped on return.
pub fn decode(raw: Zeroizing<String>) -> Result<Item, DecodeError> {
    if !looks_like_envelope(&raw) {
        return Ok(Item::Legacy(raw));
    }
    let mut wire: Wire = serde_json::from_str(&raw).map_err(|_| DecodeError::Malformed)?;
    if wire.v != VERSION {
        return Err(DecodeError::UnsupportedVersion(wire.v));
    }
    if wire.destinations.is_none() == wire.origin.is_none() {
        // Exactly one kind of authorization: a host item or an AI item.
        return Err(DecodeError::Malformed);
    }
    Ok(Item::V2(Envelope {
        user: std::mem::take(&mut wire.user),
        secret: Zeroizing::new(std::mem::take(&mut wire.secret)),
        destinations: wire.destinations.take(),
        origin: wire.origin.take(),
    }))
}

/// Encode an envelope for one vault write. The output buffer is sized up
/// front, so it is never reallocated (which would leave copies of the secret
/// behind), and it is wiped when dropped.
pub fn encode(env: &Envelope) -> Result<Zeroizing<String>, String> {
    let wire = WireRef {
        v: VERSION,
        user: &env.user,
        secret: env.secret.as_str(),
        destinations: env.destinations.as_deref(),
        origin: env.origin.as_ref(),
    };
    let meta = WireRef { secret: "", ..wire };
    let meta_len = serde_json::to_string(&meta).map_err(|e| e.to_string())?.len();
    // Worst case a character escapes to six bytes (\uXXXX).
    let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(meta_len + env.secret.len() * 6 + 16));
    serde_json::to_writer(&mut *buf, &wire).map_err(|e| e.to_string())?;
    let text = String::from_utf8(std::mem::take(&mut *buf)).map_err(|e| e.to_string())?;
    let text = Zeroizing::new(text);
    check_size(&text, cfg!(windows))?;
    Ok(text)
}

/// Refuse an envelope the vault cannot store (Windows only; macOS Keychain and
/// the Secret Service have no practical limit). Checked before writing, so the
/// error is clear and nothing is written.
fn check_size(text: &str, windows: bool) -> Result<(), String> {
    if windows && text.encode_utf16().count() * 2 > WINDOWS_MAX_BLOB {
        return Err(
            "too many hosts share this saved password for Windows Credential Manager to store it \
             with their addresses; give some of them their own password"
                .into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host_env(secret: &str, dests: &[(&str, u16, &str)]) -> Envelope {
        Envelope {
            user: "admin".into(),
            secret: Zeroizing::new(secret.into()),
            destinations: Some(dests.iter().map(|(h, p, u)| (h.to_string(), *p, u.to_string())).collect()),
            origin: None,
        }
    }

    #[test]
    fn host_envelopes_round_trip_including_awkward_secrets() {
        for secret in ["pw", "p\"w\\x\u{1}\u{4e2d}", "", "{\"v\":2}"] {
            let text = encode(&host_env(secret, &[("fw-01", 22, "admin"), ("b", 2222, "root")])).unwrap();
            let Item::V2(env) = decode(text).unwrap() else { panic!("not v2") };
            assert_eq!(env.secret.as_str(), secret);
            assert_eq!(env.user, "admin");
            assert_eq!(
                env.destinations.unwrap(),
                vec![("fw-01".to_string(), 22, "admin".to_string()), ("b".to_string(), 2222, "root".to_string())]
            );
            assert!(env.origin.is_none());
        }
    }

    #[test]
    fn ai_envelopes_carry_their_origin() {
        let env = Envelope {
            user: "api-key".into(),
            secret: Zeroizing::new("sk-1".into()),
            destinations: None,
            origin: Some(("openai".into(), "https://api.openai.com/v1".into())),
        };
        let Item::V2(back) = decode(encode(&env).unwrap()).unwrap() else { panic!() };
        assert_eq!(back.origin, Some(("openai".to_string(), "https://api.openai.com/v1".to_string())));
        assert!(back.destinations.is_none());
    }

    #[test]
    fn plain_secrets_from_earlier_builds_are_legacy() {
        for raw in ["hunter2", "{not json", "{\"a\":1}", "[1]", ""] {
            match decode(Zeroizing::new(raw.into())) {
                Ok(Item::Legacy(s)) => assert_eq!(s.as_str(), raw),
                _ => panic!("{raw:?} should be legacy"),
            }
        }
    }

    #[test]
    fn damaged_or_future_envelopes_are_refused_not_guessed() {
        let bad = |s: &str| decode(Zeroizing::new(s.into())).err();
        assert_eq!(bad("{\"v\":2,\"secret\":"), Some(DecodeError::Malformed));
        assert_eq!(bad("{\"v\":2,\"secret\":\"x\"}"), Some(DecodeError::Malformed), "no authorization");
        assert_eq!(
            bad("{\"v\":2,\"secret\":\"x\",\"destinations\":[],\"origin\":[\"a\",\"b\"]}"),
            Some(DecodeError::Malformed),
            "both kinds"
        );
        assert_eq!(bad("{\"v\":3,\"secret\":\"x\",\"destinations\":[]}"), Some(DecodeError::UnsupportedVersion(3)));
        assert_eq!(bad(" { \"v\" : 2 }"), Some(DecodeError::Malformed));
    }

    #[test]
    fn decode_errors_never_carry_the_secret() {
        let e = decode(Zeroizing::new("{\"v\":2,\"secret\":\"topsecret\",\"destinations\":7}".into())).err().unwrap();
        assert!(!format!("{e} {e:?}").contains("topsecret"));
    }

    #[test]
    fn oversized_envelopes_are_refused_on_windows_only() {
        let many: Vec<(String, u16, String)> =
            (0..60).map(|i| (format!("host-{i}.example.internal"), 22, "administrator".to_string())).collect();
        let env = Envelope { destinations: Some(many), ..host_env("pw", &[]) };
        let wire = WireRef {
            v: VERSION,
            user: &env.user,
            secret: &env.secret,
            destinations: env.destinations.as_deref(),
            origin: None,
        };
        let text = serde_json::to_string(&wire).unwrap();
        assert!(check_size(&text, true).is_err());
        assert!(check_size(&text, false).is_ok());
        assert!(check_size(&encode(&host_env("pw", &[("a", 22, "u")])).unwrap(), true).is_ok());
    }
}
