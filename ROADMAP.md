# Roadmap

What exists, what is planned, and what was deliberately rejected — so future
work (and future contributors) inherit the reasoning, not just the code.

## Shipped

**Platforms:** Windows and Linux (v0.2.0). Secrets live in the OS vault on each —
Windows Credential Manager, or the freedesktop Secret Service on Linux — and the
SSH agent is the Windows OpenSSH pipe / Pageant, or `$SSH_AUTH_SOCK` on Linux.

**v0.3.0 — settings + safety:** app settings store + Settings dialog;
**customizable host-colour policies** (per-colour AI on/off, confirm-on-connect,
exclude-from-broadcast — the old hardcoded "red disables AI" is now a default,
not a rule); **dangerous-command guard** (warns before a paste/snippet/broadcast
with `rm -rf`, `reload`, `write erase`, etc.); **device-type profiles** (PAN-OS /
IOS / Junos / Linux one-pick command fill); **subnet-aware host filter**
(`10.20.0.0/16`); rename-tab, confirm-close-live-tab, terminal font zoom.

### Core
- Terminal: xterm.js + WebGL, persistent scrollback across tab switches,
  split panes (columns/rows, resizable, per-pane tmux `hawser-{pane}`),
  broadcast-to-panes, right-click paste, find (Ctrl+Shift+F)
- Auth: password / private key / SSH agent (Windows OpenSSH pipe + Pageant) /
  keyboard-interactive fallback (TACACS+-style hidden prompts answered with the
  stored password automatically); secrets in Windows Credential Manager, never
  in files, never returned over IPC
- Ed25519 key generation from the host editor (never clobbers existing keys)
- Credential sharing: a host can borrow another host's vault entry, so one
  TACACS/AD password rotation is one edit
- ProxyJump through any saved host (single level)
- Port forwarding: local (`-L`) and SOCKS5 dynamic (`-D`), 127.0.0.1-only,
  per-session tunnel manager
- Quick connect (Ctrl+Shift+P): `user@host:port`, one-shot password, nothing saved
- SFTP: dual-pane, recursive, drag-drop from Explorer, resilient tree walks,
  global transfer queue with byte progress
- Host catalogue: nested folders, per-host accent colours, snippets with
  Ctrl+Shift+1-9 slots, on-connect presets (tmux/PAN-OS/IOS), export/import
- Host keys: TOFU prompt with SHA256 fingerprint; CHANGED keys refused outright
- Sessions: transcripts (ANSI-stripped, crash-safe, 30-day/500-file retention),
  history browser, transcript-tail replay on reconnect, dormant restore
  (never auto-dials on launch), keepalive-based disconnect detection

### Network-engineer tooling
- Network tools dialog: ping, traceroute (streamed live), TCP port check with
  OPEN/CLOSED/FILTERED distinction, DNS lookup — run from the workstation,
  for exactly the moments SSH cannot connect
- Reachability sweep: on-demand concurrent TCP probe of every host's SSH port,
  results shown in the sidebar. On demand only — never a background scanner
- Config snapshots: per-host capture command runs over a hidden exec channel,
  stored as plain text under `%APPDATA%\hawser\configs\<host>\`, with
  added/removed counts on capture and unified diff between any two snapshots

## Planned (backlog, rough priority)

0. **Nested split layouts** — a pane full-height beside two stacked, arbitrary
   trees. Recursive layout tree (per-node direction + sizes) replacing the
   current single-orientation flat model. v0.3.x.

1. **Scheduled capture** — "connect nightly, snapshot config, disconnect":
   poor-man's RANCID. Composes from existing parts (connect, exec capture,
   snapshots); needs a scheduler and unattended-auth policy decisions.
2. **Keyword alerts** — highlight/flash on `%ERR`, `down`, `mismatch` in live
   terminal output. Per-host patterns.
3. **Output capture to file** — "log just this command's output", for
   `show tech-support`-sized dumps.
4. **Inventory grabber** — per-device-type `show version`/`show system info`
   parsed to CSV, for audit season.
7. **Remote forwarding (-R)** — -L and -D exist; -R completes the set
   (needs the Handler's forwarded-tcpip callback and a listener registry).
7b. **Interactive auth prompts in the UI** — keyboard-interactive currently
   auto-answers hidden prompts with the stored password; an OTP/echo prompt
   needs a real dialog (same oneshot bridge as host keys).
7c. **YubiKey / PIV** — works today IF the key lives in the OpenSSH agent;
   first-class support would mean PKCS#11.
8. **Config push** — staged upload + diff-before-push + confirm. High value,
   high blast radius; wants the red-frame treatment and an explicit typed
   confirmation.
9. **Serial console (COM port) sessions** — for when the network is the
   problem. After the SSH paths are battle-hardened.
10. **Multi-hop ProxyJump** — chain of bastions; single level covers the
    current need.
11. **Trace-path visualisation** — run traceroute from inside a session and
    render hops; nice, not core.

_All three desktop platforms now ship: Windows + Linux (v0.2.0), macOS (v0.3.0,
signed + notarised Developer ID `.dmg`; `macos-latest` in CI)._

## Deliberately rejected

- **SNMP polling / NetFlow / continuous monitoring** — that is LibreNMS/
  Zabbix territory. Hawser complements monitoring systems; competing with
  them would sink the small-fast-sharp identity (and the 4-5 MB binary).
- **Automatic background reachability probes** — an SSH client that
  continuously port-scans the management network trips IDS and violates
  least surprise. Probes stay a button.
- **Auto-installing tmux on servers** — an SSH client that installs packages
  is a change-control incident. The on-connect field lets users opt in.
- **"Don't ask again" on host-key prompts** — accepting already records the
  key; a broader suppression toggle only silences the one warning that matters.

## Invariants (see SECURITY.md — breaking these is a bug even if tests pass)

Secrets never cross IPC outward · changed host keys never prompt · forwards
bind loopback only · no parameterised shell-open commands · seed data uses
documentation address ranges only.
