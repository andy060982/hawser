//! OS credential-vault access, behind one cross-platform API.
//!
//! The backend differs per platform — Windows Credential Manager (DPAPI),
//! macOS Keychain, or the freedesktop Secret Service on Linux — but three rules
//! hold everywhere:
//!
//! 1. **A secret never crosses the IPC boundary.** No `#[tauri::command]` here
//!    returns a password. The frontend refers to a host by id; resolution to a
//!    secret happens entirely in Rust. Anything returned to the webview is
//!    reachable from devtools and from any XSS in the UI.
//! 2. **Secrets are zeroized.** Reads return a `Zeroizing<String>` that wipes on
//!    drop; the Windows path additionally wipes its UTF-16 staging buffers and
//!    the credential blob returned by `CredReadW` before it is freed.
//! 3. **Every raw resource is released.** The Windows `CredReadW` allocation is
//!    freed on every path, including errors.

#[derive(Debug, thiserror::Error)]
pub enum CredError {
    #[error("no saved credential for {0}")]
    NotFound(String),
    #[error("stored secret for {0} is not valid text")]
    Malformed(String),
    #[cfg(windows)]
    #[error("credential manager error 0x{0:08X}")]
    Win32(u32),
    #[cfg(not(windows))]
    #[error("credential store error: {0}")]
    Backend(String),
}

/// Vault key for a host. Namespaced so Hawser's entries are obvious in each
/// platform's vault UI and cannot collide with another application's entries.
pub fn target_name(host_id: &str) -> String {
    format!("hawser:host:{host_id}")
}

/// True for vault ids that belong to another namespace and must never be used
/// as a host credential id. The AI provider key is stored at `ai:<profile>`
/// (see utils::ai::vault_profile), which shares `target_name`'s prefix — so a
/// host whose id were `ai:default` would otherwise address that key. Matched
/// case-insensitively because Windows Credential Manager target names are.
pub fn is_reserved_id(id: &str) -> bool {
    id.get(..3).is_some_and(|p| p.eq_ignore_ascii_case("ai:"))
}

/// Whether a secret exists, without exposing it. Lets the UI show "password
/// saved" while the plaintext stays in the vault.
pub fn has_secret(host_id: &str) -> bool {
    matches!(read_secret(host_id), Ok(_))
}

pub use imp::{delete_secret, read_secret, write_secret};

// ---------------------------------------------------------------------------
// Windows: Credential Manager via CredReadW/CredWriteW/CredDeleteW.
// ---------------------------------------------------------------------------
#[cfg(windows)]
mod imp {
    use std::ffi::c_void;

    use windows_sys::Win32::Foundation::{GetLastError, ERROR_NOT_FOUND};
    use windows_sys::Win32::Security::Credentials::{
        CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_PERSIST_LOCAL_MACHINE,
        CRED_TYPE_GENERIC,
    };
    use zeroize::{Zeroize, Zeroizing};

    use super::{target_name, CredError};

    /// NUL-terminated UTF-16, as every `*W` Win32 entry point expects.
    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Read a password out of the vault.
    ///
    /// The returned `String` zeroizes on drop. Callers should keep it alive for
    /// as short a span as possible and never log, serialise, or return it.
    pub fn read_secret(host_id: &str) -> Result<Zeroizing<String>, CredError> {
        let target = target_name(host_id);
        let target_w = wide(&target);
        let mut ptr: *mut CREDENTIALW = std::ptr::null_mut();

        // SAFETY: target_w is NUL-terminated and outlives the call; ptr is a
        // valid out-param. On success the API allocates a buffer we must free.
        let ok = unsafe { CredReadW(target_w.as_ptr(), CRED_TYPE_GENERIC, 0, &mut ptr) };
        if ok == 0 {
            let code = unsafe { GetLastError() };
            return Err(if code == ERROR_NOT_FOUND {
                CredError::NotFound(target)
            } else {
                CredError::Win32(code)
            });
        }

        // Copy the blob out before freeing, then wipe the staging buffer. The
        // blob is raw bytes; Windows tooling stores UTF-16LE here.
        let result = unsafe {
            let cred = &*ptr;
            let len = cred.CredentialBlobSize as usize;
            // An empty credential comes back with a NULL blob, and
            // from_raw_parts(NULL, 0) is undefined behaviour — use an empty slice.
            let bytes: &[u8] = if cred.CredentialBlob.is_null() || len == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(cred.CredentialBlob, len)
            };

            if len % 2 != 0 {
                // Odd length cannot be UTF-16. Fall back to UTF-8, which is what
                // a credential written by a non-Windows-native tool may hold.
                String::from_utf8(bytes.to_vec())
                    .map(Zeroizing::new)
                    .map_err(|_| CredError::Malformed(target.clone()))
            } else {
                let mut units: Vec<u16> = bytes
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                let decoded = String::from_utf16(&units)
                    .map(Zeroizing::new)
                    .map_err(|_| CredError::Malformed(target.clone()));
                units.zeroize();
                decoded
            }
        };

        // Wipe the vault's plaintext copy in our own address space before
        // releasing it: CredFree returns the buffer to the heap without
        // scrubbing it, leaving the decrypted secret readable in freed memory.
        // SAFETY: ptr is a live CredReadW allocation; CredentialBlob/Size
        // describe a buffer we own until CredFree, so zeroing it is in-bounds.
        unsafe {
            let cred = &*ptr;
            let len = cred.CredentialBlobSize as usize;
            if !cred.CredentialBlob.is_null() && len > 0 {
                std::slice::from_raw_parts_mut(cred.CredentialBlob, len).zeroize();
            }
        }

        // SAFETY: ptr came from a successful CredReadW and is freed exactly once.
        unsafe { CredFree(ptr as *mut c_void) };
        result
    }

    /// Store or replace a password. Called from the host-editor flow, never
    /// with a value that originated in the webview on a machine the user does
    /// not control.
    pub fn write_secret(host_id: &str, username: &str, secret: &str) -> Result<(), CredError> {
        let target = target_name(host_id);
        let mut target_w = wide(&target);
        let mut user_w = wide(username);

        // UTF-16LE bytes, matching what read_secret expects and what the
        // Credential Manager UI displays correctly.
        let mut blob: Vec<u8> = secret
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();

        let mut cred: CREDENTIALW = unsafe { std::mem::zeroed() };
        cred.Type = CRED_TYPE_GENERIC;
        cred.TargetName = target_w.as_mut_ptr();
        cred.CredentialBlobSize = blob.len() as u32;
        cred.CredentialBlob = blob.as_mut_ptr();
        // LOCAL_MACHINE keeps the entry off roaming profiles: a credential for
        // an internal host should not follow the user to another machine.
        cred.Persist = CRED_PERSIST_LOCAL_MACHINE;
        cred.UserName = user_w.as_mut_ptr();

        // SAFETY: every pointer in `cred` refers to a buffer alive for this call.
        let ok = unsafe { CredWriteW(&cred, 0) };
        blob.zeroize();

        if ok == 0 {
            return Err(CredError::Win32(unsafe { GetLastError() }));
        }
        Ok(())
    }

    /// Remove a stored password. Used when a host is deleted, so the vault does
    /// not accumulate orphaned secrets.
    pub fn delete_secret(host_id: &str) -> Result<(), CredError> {
        let target = target_name(host_id);
        let target_w = wide(&target);

        // SAFETY: target_w is NUL-terminated and outlives the call.
        let ok = unsafe { CredDeleteW(target_w.as_ptr(), CRED_TYPE_GENERIC, 0) };
        if ok == 0 {
            let code = unsafe { GetLastError() };
            return Err(if code == ERROR_NOT_FOUND {
                CredError::NotFound(target)
            } else {
                CredError::Win32(code)
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Unix (Linux Secret Service / macOS Keychain) via the `keyring` crate.
//
// A host is keyed by (service = "hawser", account = target_name(host_id)) so a
// read needs only the host id — the username the Windows path stores is not
// part of the lookup key here. `get_password` returns a plain `String`; we wrap
// it in `Zeroizing` immediately so it wipes on drop like the Windows path.
// ---------------------------------------------------------------------------
#[cfg(not(windows))]
mod imp {
    use keyring::{Entry, Error as KeyringError};
    use zeroize::Zeroizing;

    use super::{target_name, CredError};

    const SERVICE: &str = "hawser";

    fn entry(host_id: &str) -> Result<Entry, CredError> {
        Entry::new(SERVICE, &target_name(host_id)).map_err(|e| CredError::Backend(e.to_string()))
    }

    pub fn read_secret(host_id: &str) -> Result<Zeroizing<String>, CredError> {
        match entry(host_id)?.get_password() {
            Ok(pw) => Ok(Zeroizing::new(pw)),
            Err(KeyringError::NoEntry) => Err(CredError::NotFound(target_name(host_id))),
            Err(e) => Err(CredError::Backend(e.to_string())),
        }
    }

    pub fn write_secret(host_id: &str, _username: &str, secret: &str) -> Result<(), CredError> {
        entry(host_id)?
            .set_password(secret)
            .map_err(|e| CredError::Backend(e.to_string()))
    }

    pub fn delete_secret(host_id: &str) -> Result<(), CredError> {
        match entry(host_id)?.delete_credential() {
            Ok(()) => Ok(()),
            Err(KeyringError::NoEntry) => Err(CredError::NotFound(target_name(host_id))),
            Err(e) => Err(CredError::Backend(e.to_string())),
        }
    }
}

#[cfg(test)]
mod reserved_tests {
    use super::is_reserved_id;

    #[test]
    fn ai_namespace_is_reserved_case_insensitively() {
        assert!(is_reserved_id("ai:default"));
        assert!(is_reserved_id("AI:default"));
        assert!(is_reserved_id("Ai:"));
        assert!(!is_reserved_id("h-lq3x"));
        assert!(!is_reserved_id("ai")); // too short to carry the prefix
        assert!(!is_reserved_id("air-1"));
        assert!(!is_reserved_id("h1:ai:"));
    }
}

// The live round-trip tests hit the real OS vault, so they run only on Windows
// where CI has a working Credential Manager. The Linux Secret Service needs a
// running D-Bus session + unlocked keyring that headless CI does not provide;
// the Unix path is exercised by the real app and compile-checked in CI.
#[cfg(all(test, windows))]
mod tests {
    use super::*;

    /// Round-trips a secret through the real Credential Manager.
    ///
    /// Uses a namespaced throwaway id and removes it afterwards. It exercises
    /// CredWriteW/CredReadW/CredDeleteW for real rather than against a mock —
    /// the UTF-16 marshalling is exactly the part worth testing, and a mock
    /// would test nothing at all.
    #[test]
    fn write_read_delete_roundtrip() {
        let id = "__hawser_selftest__";
        // Deliberately not ASCII: the blob is UTF-16LE, and a truncation bug in
        // the encode/decode pair only shows up above the BMP-free happy path.
        let secret = "p@ss w\u{f6}rd \u{4e2d}\u{6587} 123";

        write_secret(id, "testuser", secret).expect("write");
        let got = read_secret(id).expect("read");
        assert_eq!(got.as_str(), secret, "secret survived the round trip");

        assert!(has_secret(id));
        delete_secret(id).expect("delete");
        assert!(!has_secret(id), "gone after delete");
    }

    #[test]
    fn missing_secret_is_not_found() {
        match read_secret("__hawser_definitely_absent__") {
            Err(CredError::NotFound(_)) => {}
            other => panic!("expected NotFound, got {other:?}"),
        }
    }
}
