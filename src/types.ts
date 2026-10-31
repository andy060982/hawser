/* ---------------------------------------------------------------------------
   Domain types.

   Two trees matter in this app and they are deliberately kept apart:

   1. HostNode  - the *saved* connection catalogue. Persisted, user-organised,
                  arbitrarily nested. Survives app restarts.
   2. Session   - a *live* connection. Ephemeral, flat (tabs don't nest), and
                  always points back at a Host by id rather than embedding it,
                  so renaming a saved host updates every open tab for free.
--------------------------------------------------------------------------- */

import type { HostColor } from './lib/hostColors'

export type AuthMethod = 'agent' | 'password' | 'key'

export interface Host {
  kind: 'host'
  id: string
  name: string
  hostname: string
  port: number
  username: string
  auth: AuthMethod
  /** Path to the private key file, for auth = 'key'. The passphrase, if the
   *  key has one, lives in Credential Manager under this host's id — the same
   *  vault slot that holds the password for password auth. */
  keyPath?: string
  /** Another saved host to tunnel through (ProxyJump). Single level only — a
   *  bastion's own jumpHostId is deliberately ignored to keep the chain from
   *  looping or fanning out invisibly. */
  jumpHostId?: string
  /** Optional free-text grouping shown as a chip; not the same as folders. */
  tag?: string
  /** Accent colour key (see lib/hostColors). A visual guard against acting on
   *  the wrong host — e.g. red for production. Undefined means no accent. */
  color?: HostColor
  /** Commands sent as the first lines of input once the shell is up.
   *
   *  Presets (tmux, PAN-OS terminal width, IOS paging) are stored as their
   *  literal command text, so what runs against the equipment is always visible
   *  in hosts.json rather than hidden behind an id. */
  startupCommands?: string[]
  /** @deprecated Single-command shape from an earlier build. Still read by
   *  resolveStartupCommands() so existing hosts keep working. */
  startupCommand?: string
  /** Whether the AI assistant may see this host's terminal output. Unset
   *  means "yes unless the accent colour is red" — production defaults to
   *  private. See aiAllowedFor() in AiPanel. */
  aiAllowed?: boolean
  /** Command whose output is stored by "Snapshot config" — e.g.
   *  `show running-config` (IOS), `show config running` (PAN-OS),
   *  `cat /etc/network/interfaces` (Linux). Runs over a fresh exec channel,
   *  never through the visible terminal. */
  configCommand?: string
  /** Run `configCommand` on every connect and report whether the config
   *  changed since the last snapshot ("what changed since my last visit").
   *  Opt-in: it executes a command on the device, so never on by default. */
  checkConfigOnConnect?: boolean
  /** Borrow another host's Credential Manager entry ("same password as
   *  fw-01"). One vault edit then covers every host that points here —
   *  the TACACS/AD-account case. */
  credentialId?: string
  /** Saved commands for this host, sendable to the focused pane.
   *
   *  `slot` 1-9 binds Ctrl+Shift+<digit>. Per-host rather than global because
   *  the commands worth one keystroke differ per device: `show session all` on
   *  a Palo Alto, `df -h` on a Linux box. Slot digits are chosen by the user so
   *  the same finger memory can mean the same *kind* of thing across hosts. */
  snippets?: Snippet[]
  /** Set on the synthetic hosts behind local terminal tabs (never saved to the
   *  catalogue): the shell profile id to start instead of dialling SSH. */
  local?: { profile: string }
}

export interface Snippet {
  label: string
  command: string
  /** 1-9 for Ctrl+Shift+<digit>, or null for menu/palette only. */
  slot: number | null
  /** Append Enter, so the command runs immediately rather than sitting on the
   *  prompt. Off by default for safety: run-on-paste against a firewall should
   *  be a deliberate choice per snippet. */
  autoRun?: boolean
}

export interface HostFolder {
  kind: 'folder'
  id: string
  name: string
  children: HostNode[]
  /** Optional accent, shown as a coloured bar on the folder row — the same
   *  wrong-window cue as a host's colour, applied to a whole group. */
  color?: HostColor
}

export type HostNode = Host | HostFolder

export const isFolder = (n: HostNode): n is HostFolder => n.kind === 'folder'

/* -------------------------------------------------------------------------- */

export type SessionStatus = 'connecting' | 'connected' | 'disconnected' | 'error'

/** Which surface a tab is showing. Stored per-session, not globally: switching
 *  tabs should restore whatever that tab was last doing. */
export type WorkspaceView = 'terminal' | 'sftp'

export interface Session {
  id: string
  hostId: string
  /** Sessions sharing a groupId are shown side by side in one tab.
   *
   *  A group rather than a nested layout tree: two panes covers the actual need
   *  (watch a log while you work), and an arbitrary split tree brings focus
   *  traversal, serialisation, and drag-to-rearrange with it — a lot of
   *  machinery for a case nobody asked for. A flat group can grow to three or
   *  four panes without any of that. */
  groupId: string
  /** 1-based position among this host's open sessions, substituted for {pane}
   *  in on-connect commands so each pane gets its own tmux/screen session. */
  paneIndex: number
  /** Denormalised for the tab strip so rendering tabs never walks the host tree. */
  title: string
  status: SessionStatus
  view: WorkspaceView
}

/* -------------------------------------------------------------------------- */

export interface FileEntry {
  name: string
  kind: 'file' | 'directory' | 'symlink'
  size: number
  /** Unix epoch seconds, or null when the server does not report mtime.
   *  Deliberately not a preformatted string: the grid sorts on this, and
   *  sorting formatted dates lexicographically is a classic silent bug. */
  modified: number | null
  /** POSIX mode string, e.g. "drwxr-xr-x". Empty for local Windows entries. */
  mode: string
}

/** One directory read. `path` is echoed back by the backend already normalised
 *  (symlinks resolved, "." and ".." collapsed) so the pane displays the real
 *  location rather than whatever the user typed. */
export interface DirListing {
  path: string
  entries: FileEntry[]
}

export type PaneSide = 'local' | 'remote'

export type TransferDirection = 'upload' | 'download'

export interface Transfer {
  id: string
  /** Which session this transfer belongs to, so the global queue can attribute
   *  progress events correctly when several sessions transfer at once. */
  sessionId: string
  direction: TransferDirection
  name: string
  /** Full path, used to correlate `sftp://progress` events with this row. The
   *  backend keys progress by path because it has no notion of our row ids. */
  path: string
  bytesDone: number
  bytesTotal: number
  status: 'active' | 'done' | 'error'
  error?: string
  /** Per-file failures accumulated from `sftp://failure` events during a
   *  recursive (folder) transfer. Lets the UI show the FULL list — not just the
   *  first — and retry exactly the files that didn't make it. */
  failures?: TransferFailureItem[]
}

/** One failed file inside a recursive transfer, with both sides retained so a
 *  "Retry failed" can rebuild the exact job. `local` may be empty for items that
 *  were skipped rather than attempted (e.g. an unsafe server-supplied name). */
export interface TransferFailureItem {
  name: string
  local: string
  remote: string
  reason: string
}

/** Payload of the `sftp://progress` event. Mirrors TransferProgress in
 *  src-tauri/src/ssh.rs — change the two together. */
export interface TransferProgressEvent {
  sessionId: string
  /** The transfer's ROOT source path — the queue row's `path`. Equals
   *  `filePath` for a single file; for a folder it is the folder, and
   *  `bytesTransferred` is cumulative across the tree (with `totalBytes` 0). */
  root: string
  filePath: string
  bytesTransferred: number
  /** 0 means the server did not report a size: render indeterminate, never
   *  divide by it. */
  totalBytes: number
  direction: TransferDirection
  done: boolean
}

/** Payload of the `sftp://failure` event. Mirrors TransferFailure in
 *  src-tauri/src/ssh.rs — change the two together. `root` is the transfer's
 *  source path, matching the queue row's `path`. */
export interface TransferFailureEvent {
  sessionId: string
  root: string
  name: string
  local: string
  remote: string
  reason: string
  direction: TransferDirection
}
