/** Heuristic detection of destructive commands, for the pre-send guard.
 *
 *  Best-effort, like the AI secret scanner: it catches the well-known
 *  foot-guns across Linux and network gear so a paste, snippet, or broadcast of
 *  one pauses for a confirm. It is not a sandbox and cannot catch everything —
 *  a creative rewrite slips it — so it errs toward the obvious shapes and lets
 *  the human decide.
 */
const RULES: { re: RegExp; reason: string }[] = [
  { re: /\brm\s+-[a-z]*[rf]/i, reason: 'rm -rf (recursive/forced delete)' },
  { re: /\bmkfs(\.\w+)?\b/i, reason: 'mkfs (format a filesystem)' },
  { re: /\bdd\b[^\n]*\bof=\/dev\//i, reason: 'dd writing to a device' },
  { re: />\s*\/dev\/(sd|nvme|vd|hd)/i, reason: 'redirect over a raw disk' },
  { re: /\b(shutdown|poweroff|halt|reboot)\b/i, reason: 'power/reboot command' },
  { re: /:\s*\(\s*\)\s*\{/, reason: 'shell fork bomb' },
  // Network gear
  { re: /\breload\b/i, reason: 'reload (device restart)' },
  { re: /\bwrite\s+erase\b/i, reason: 'write erase (wipe config)' },
  { re: /\berase\s+(startup-config|flash|nvram)/i, reason: 'erase config/flash' },
  { re: /\bdelete\s+\/force\b/i, reason: 'delete /force' },
  { re: /\bformat\s+(flash|disk\d)/i, reason: 'format flash/disk' },
  { re: /\brequest\s+system\s+(shutdown|reboot|zeroize)/i, reason: 'PAN-OS/Junos system shutdown' },
  { re: /\bfactory-default\b/i, reason: 'factory-default reset' },
]

/** Returns a short reason if the text looks destructive, else null. */
export function isDangerousCommand(text: string): string | null {
  for (const { re, reason } of RULES) {
    if (re.test(text)) return reason
  }
  return null
}

/** Whether model-written text may be typed into a terminal, and how.
 *
 *  - `refuse`: it holds control characters (CR, ESC, ^C, DEL, C1 controls…).
 *    A CR is Enter, ESC starts a key sequence, ^U wipes the line; none belongs
 *    in a suggestion, and AI output is attacker-steerable through the context.
 *  - `multiline`: every LF is Enter to a shell or a device CLI without
 *    bracketed paste, so every line but the last would run on insert. The
 *    caller must confirm.
 *  - `ok`: one line, nothing that acts before the user presses Enter. */
export type InsertCheck =
  | { kind: 'ok' }
  | { kind: 'multiline'; lines: number }
  | { kind: 'refuse'; reason: string }

// Tab and LF are the only C0 characters allowed; U+2028/2029 render as line
// breaks without looking like one.
const CONTROL = /[\x00-\x08\x0b-\x1f\x7f-\x9f\u2028\u2029]/

export function checkInsert(text: string): InsertCheck {
  if (CONTROL.test(text)) return { kind: 'refuse', reason: 'it contains control characters' }
  const lines = text.split('\n').length
  return lines > 1 ? { kind: 'multiline', lines } : { kind: 'ok' }
}
