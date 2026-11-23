/** Common on-connect commands, offered as toggles.
 *
 *  Presets are stored as their literal command text, not as opaque ids. That is
 *  deliberate: a host file full of `{"preset": "tmux"}` would need a migration
 *  every time a command changed, and would hide from the user what actually
 *  runs against their equipment. Matching a toggle is then just membership —
 *  and anything the user types by hand survives untouched because it simply
 *  fails to match any preset.
 */
export interface StartupPreset {
  id: string
  label: string
  command: string
  hint: string
}

export const STARTUP_PRESETS: StartupPreset[] = [
  {
    // -A attach-if-exists, -D detach any other client first.
    //
    // -D is what makes tmux track the window. tmux sizes a window to the
    // SMALLEST attached client, so a stale client left over from a previous
    // connection (or a crashed one the server has not reaped) pins the session
    // to that old geometry and the pane never fills the window. Detaching
    // others on attach means the current client alone decides the size.
    id: 'tmux',
    label: 'Keep session alive (tmux)',
    command: 'tmux new-session -A -D -s hawser-{pane}',
    hint: 'Survives closing Hawser. Each pane gets its own tmux session.',
  },
  {
    // -d detaches elsewhere, -R reattaches if possible, -R twice creates if not.
    id: 'screen',
    label: 'Keep session alive (screen)',
    command: 'screen -dRR hawser-{pane}',
    hint: 'Same idea where tmux is unavailable.',
  },
  {
    // `start-server \; set -g mouse on` (not a bare `set -g mouse on`) so it works
    // regardless of send order: if it runs before the tmux session exists it
    // starts the server and sets the global option, which the new session then
    // inherits; if it runs after (inside tmux) it applies immediately. `set -g`
    // is a SERVER-WIDE tmux option — hence the warning in the hint.
    id: 'tmux-mouse',
    label: 'Mouse-wheel scroll in tmux',
    command: 'tmux start-server \\; set -g mouse on',
    hint: 'Wheel scrolls the tmux buffer, not shell history. Turns on tmux mouse mode SERVER-WIDE (affects all your tmux sessions). Hold Shift to select text normally.',
  },
  {
    id: 'panos-width',
    label: 'Wide terminal (PAN-OS)',
    command: 'set cli terminal width 200',
    hint: 'Palo Alto ignores SSH window resize; this is the fix.',
  },
  {
    id: 'panos-nopager',
    label: 'Disable pager (PAN-OS)',
    command: 'set cli pager off',
    hint: 'Stops output pausing partway through.',
  },
  {
    id: 'ios-nopage',
    label: 'Disable paging (Cisco IOS)',
    command: 'terminal length 0',
    hint: 'Stops --More-- prompts.',
  },
]

const PRESET_COMMANDS = new Set(STARTUP_PRESETS.map((p) => p.command))

/** Commands that are not one of the presets — the user's own additions. */
export function customCommands(list: string[]): string[] {
  return list.filter((c) => !PRESET_COMMANDS.has(c))
}

/** Expands per-session tokens in a command.
 *
 *  `{pane}` is what stops a split from eating itself. `tmux new-session -A -D`
 *  attaches to a named session and detaches any other client on it — so two
 *  panes pointed at the same name means the second one steals the session from
 *  the first, which looks exactly like "split did not open anything". Numbering
 *  the name per pane gives each its own tmux session, and because the number is
 *  derived from position rather than randomness, reconnecting later reattaches
 *  to the same one instead of stranding it. */
export function expandTokens(command: string, paneIndex: number): string {
  return command.split('{pane}').join(String(paneIndex))
}

/** The stored commands as-is, WITHOUT token expansion.
 *
 *  Reads either the current array field or the earlier single-string field.
 *  Hosts saved before that change carry `startupCommand`; rather than migrating
 *  hosts.json on load (which risks rewriting a file over a half-read parse),
 *  both shapes are accepted here and the array wins.
 *
 *  Use this anywhere the literal command matters — editing (so `{pane}` is not
 *  frozen to a number on save) and preset matching (whose commands contain the
 *  literal `{pane}`). Use `resolveStartupCommands` only at connect time. */
export function rawStartupCommands(host: {
  startupCommands?: string[]
  startupCommand?: string
}): string[] {
  return host.startupCommands?.length
    ? host.startupCommands
    : host.startupCommand?.trim()
      ? [host.startupCommand.trim()]
      : []
}

/** The stored commands with per-session tokens expanded — for connect time. */
export function resolveStartupCommands(
  host: { startupCommands?: string[]; startupCommand?: string },
  paneIndex = 1,
): string[] {
  return rawStartupCommands(host).map((c) => expandTokens(c, paneIndex))
}
