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

/** What "Insert into terminal" may do with model-written text, given whether
 *  the terminal will bracket the paste RIGHT NOW. Call it again immediately
 *  before writing, in the same tick (after any dialog has closed): the remote
 *  can turn bracketed paste off while a confirm is open.
 *
 *  - Single line: inserted without its trailing newline, and only if it holds
 *    no control character at all (CR is Enter, ESC starts a key sequence, ^U
 *    wipes the line, Tab completes).
 *  - Anything with a line break: only as one bracketed paste, which the shell
 *    treats as inert text until the user presses Enter. Without bracketed
 *    paste every line break IS Enter and would run the line before it, so it
 *    is refused and the user is told to copy it instead. Inside a bracketed
 *    paste LF and Tab are allowed; any other control character (ESC above
 *    all, which could close the bracket early with `ESC [201~`) is refused.
 *
 *  AI output is attacker-steerable through the terminal context, so this is
 *  a hard rule, not a confirm. */
export type InsertPlan =
  | { kind: 'insert'; text: string; lines: number }
  | { kind: 'refuse'; reason: string }

// Line breaks of any kind, including the ones that do not look like one.
const LINE_BREAK = /[\n\r\x0b\x0c\u0085\u2028\u2029]/
// Every C0/C1 control character and DEL.
// eslint-disable-next-line no-control-regex
const ANY_CONTROL = /[\x00-\x1f\x7f-\x9f\u2028\u2029]/
// Inside a bracketed paste: LF and Tab are text.
// eslint-disable-next-line no-control-regex
const PASTE_CONTROL = /[\x00-\x08\x0b-\x1f\x7f-\x9f\u2028\u2029]/

export const COPY_INSTEAD = 'Use Copy and paste it yourself if you really want it.'

export function planInsert(text: string, bracketed: boolean): InsertPlan {
  // Trailing line breaks only ever mean "and press Enter": drop them.
  const t = text.replace(/[\r\n]+$/, '').replace(/\r\n/g, '\n')
  if (!t) return { kind: 'refuse', reason: 'the suggestion is empty' }
  if (!LINE_BREAK.test(t)) {
    if (ANY_CONTROL.test(t)) return { kind: 'refuse', reason: 'it contains control characters' }
    return { kind: 'insert', text: t, lines: 1 }
  }
  if (!bracketed) {
    return {
      kind: 'refuse',
      reason:
        'it has more than one line and this terminal has not enabled bracketed paste, so every line would run as soon as it was inserted',
    }
  }
  if (PASTE_CONTROL.test(t)) return { kind: 'refuse', reason: 'it contains control characters' }
  return { kind: 'insert', text: t, lines: t.split('\n').length }
}
