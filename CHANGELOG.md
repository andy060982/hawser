# Changelog

All notable changes to Hawser are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions use
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- **Renamed Skiff → Hawser.** New app name, bundle id, data folder, and
  keychain namespace. Hosts and saved passwords from Skiff builds are not
  migrated; export hosts from Skiff and import them into Hawser.

### Added

- **Tamper-evident audit log** (menu → Audit log…). Connects, logins, file
  transfers, deletes, key generation/installs, credential changes, and host
  exports are recorded as a hash chain whose head is sealed in the OS keychain.
  "Verify integrity" reports verified / not fully verified / failed, and where
  the chain broke. Records hold metadata only: no passwords, keys, command
  text, or command output. "Archive and start new" sets a failed log aside
  (kept, and pinned by fingerprint in the new log).
- **Search inside sessions** in Session history: full-text search across every
  recorded transcript, grouped by session, newest first; click a match to open
  the transcript at that line.

## [0.5.0-beta.1] - 2026-10-30

First public beta. Includes the full bug-sprint hardening pass and a security
dependency update on top of the features below.

### Added

- **Copy-on-select and middle-click paste** in the terminal: finishing a mouse
  selection copies it to the clipboard (iTerm2/PuTTY style), and the mouse-wheel
  button pastes. Both toggle in Settings → Terminal (default on).
- **Mixed split-pane layouts.** A tab is now a binary split tree, so panes can be
  nested in any mix of rows and columns ("Split right" / "Split down" on the
  focused pane). Dividers drag to resize and double-click to reset; each pane has
  its own close button; proportions hold on window resize.
- **Interactive password prompt** when connecting to a host with no saved
  secret, instead of failing with "no saved credential". An opt-in "Save this
  password to your OS keychain" records the credential→destination binding on a
  successful login (and rolls the secret back if the binding fails to persist).
- **In-app confirm / alert dialogs** (Enter confirms, Esc cancels).

### Changed

- Replaced native `window.confirm` / `window.alert` — which do not reliably show
  in the WebView — with the in-app dialogs across the destructive-command guard,
  tab close, SFTP delete/overwrite, connect confirmation, snippet guard, and host
  delete.

### Fixed

- The per-pane close button did nothing: a `pointerdown` `preventDefault`
  cancelled the click in WebKit.
- Separating the first ("anchor") pane of a split was a no-op; it now moves to its
  own tab like any other pane.
- Native paste (Cmd/Ctrl+V, platform/WebView paste) bypassed the
  destructive-command guard; it is now intercepted and routed through the guard.
- **72 verified defects** across the SSH backend, SFTP, auth, and the frontend,
  found and fixed in a dedicated audit sprint (connect cancellation on tab
  close, hidden keyboard-interactive OTP prompts, `exec_capture` reading past
  EOF, `copy_id` newline handling, and others). Full detail in PR #47.

### Security

- Reserved the `ai:` vault namespace and added a one-shot credential-binding
  migration marker so a compromised WebView cannot forge a credential→host
  binding source.
- Patched 8 advisories in transitive dependencies (lockfile only, no source
  change): `rustls` 0.23.46 (RUSTSEC-2026-0346/0347/0348/0349, incl. a `Debug`
  impl that could log TLS secrets), `rustls-webpki` 0.103.16 (RUSTSEC-2026-0382),
  `webpki-root-certs` 1.0.10 (RUSTSEC-2026-0383), `crypto-bigint` 0.7.6
  (RUSTSEC-2026-0387), and `ctutils` 0.4.7 (RUSTSEC-2026-0385).

## [0.4.0] - 2026-09-26

### Security

Full remediation of the 2026-09-24 Codex security audit (18 findings), each
fixed via a focused PR with a cross-read and CI green on macOS/Linux/Windows:

- Host-key verification fails closed on a corrupt store and enforces `@revoked`
  keys (matched by key material, robust to any host-pattern form).
- Vault secrets and AI API keys are bound to backend-owned destinations/origins
  (recorded at save time), so a compromised frontend cannot redirect a saved
  password or key to an attacker-chosen host.
- Downloads reject symlink/junction ancestors; disconnect awaits full teardown
  and terminates live forward tunnels.
- Catalogue, settings, upload, and snapshot/capture writes are atomic and never
  delete the original before replacing it; transcripts and captures are created
  owner-only (`0700`/`0600`) and refuse to follow planted symlinks.
- Resource caps on the logger and AI stream; key-install success requires a
  clean exit; `read_log` rejects drive-relative/ADS names and symlinks.
- Password kept in `Zeroizing` across all auth paths; Windows credential blob
  wiped before free. `cargo audit` runs in CI.

### Added

- Transfer panel with a full per-file failure list and one-click retry.
- Right-click the host sidebar to create a New Connection or New Folder.
- Capture a command's output to a file (per-host, hidden exec channel).
- Interactive keyboard-interactive auth: OTP / 2FA / challenge prompts are
  surfaced in the UI; the stored password stays in the backend and Cancel truly
  aborts authentication.

### Fixed

- SFTP handle exhaustion on large recursive transfers (handles now closed after
  each file, both directions).

## [0.3.1] - 2026-09-24

- Security hardening pass (server-side).

## [0.3.0] - 2026-09-24

- Initial cross-platform release (Windows, Linux, macOS/arm64).
