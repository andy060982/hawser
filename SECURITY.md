# Security

## Reporting

Open a private security advisory on GitHub, or email the maintainer. Please do
not open public issues for vulnerabilities.

## Design notes for reviewers

The properties below are load-bearing; a change that weakens one is a bug even
if everything still works:

- **Secrets never cross IPC.** No Tauri command returns a password or
  passphrase to the webview. `credential_save` accepts one (user just typed
  it) and writes it to Windows Credential Manager; there is deliberately no
  `credential_read` command.
- **Changed host keys are refused, not prompted.** Only *unknown* keys get a
  trust-on-first-use dialog. `%APPDATA%\hawser\known_hosts` is standard OpenSSH
  format; a changed key requires manually editing that file.
- **Port forwards bind 127.0.0.1 only.**
- **`open_logs_folder` takes no path argument** — a parameterised open() would
  be a shell-execute primitive if the webview were ever compromised.
- **Transcripts are plaintext.** Anything visible on screen lands on disk.
  Retention (30 days / 500 files) prunes on launch; treat the logs directory
  as sensitive as the sessions were. Transcript files and config snapshots are
  created owner-only (`0700`/`0600`) on Unix.
- **Key auth prefers Ed25519.** The key generator defaults to Ed25519, and
  agent-backed auth is supported; both avoid in-process RSA. `rsa` is present
  only transitively in the SSH stack and used only for SSH *signatures*, never
  RSA *decryption* — see the RSA note below.

## Dependency advisories

`cargo audit` runs in CI (`.github/workflows/ci.yml`) against `Cargo.lock`, so a
newly published advisory against a dependency fails the build. Known advisories
that cannot yet be resolved by an upgrade are tracked in
`src-tauri/.cargo/audit.toml` with a rationale, not silently ignored:

- **RUSTSEC-2023-0071** (`rsa`, "Marvin Attack" timing sidechannel): no fixed
  `rsa` release exists. It is a decryption/PKCS#1v1.5-unpadding oracle; Hawser
  performs only SSH signing with RSA (no decryption), a 2026-09-24 review found
  no reachable oracle, and users are steered to Ed25519/agent keys. Tracked for
  removal as soon as a patched `rsa` ships.
