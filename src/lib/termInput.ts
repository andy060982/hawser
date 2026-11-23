/** Rules for bytes leaving a terminal pane: which of them broadcast mirrors to
 *  sibling panes, and when a paste needs a confirm first. Pure, so they are
 *  tested without a terminal. */

/* xterm writes its protocol replies through the same onData stream as typed
   input: DA/DA2 (`ESC[?1;2c`, `ESC[>0;276;0c`), DSR/CPR (`ESC[0n`,
   `ESC[12;5R`), DECRQM (`ESC[?2004;1$y`), focus reports (`ESC[I`, `ESC[O`),
   window reports (`ESC[8;24;80t`), OSC colour replies (`ESC]11;rgb:…`),
   DECRQSS (`ESC P1$r…ESC \`) and mouse reports. None of them is input a
   sibling shell should receive: a cursor-position report typed into another
   device's prompt is garbage, and in config mode it can be worse. */

// eslint-disable-next-line no-control-regex
const CSI_REPLY = /^\x1b\[[?>]?[\d;]*(?:c|n|R|t|\$y)$/
// eslint-disable-next-line no-control-regex
const FOCUS_REPORT = /^\x1b\[[IO]$/
// eslint-disable-next-line no-control-regex
const OSC_REPLY = /^\x1b\][\d;]*[^\x07\x1b]*(?:\x07|\x1b\\)$/
// eslint-disable-next-line no-control-regex
const DCS_REPLY = /^\x1bP[\s\S]*\x1b\\$/

/** Mouse reports in every encoding xterm emits as text: SGR / SGR-pixels
 *  (`ESC[<0;12;5M`), URXVT (`ESC[32;12;5M`) and UTF-8/X10 (`ESC[M` + 3 chars).
 *  (DEFAULT encoding goes out on onBinary, which is never broadcast.) */
// eslint-disable-next-line no-control-regex
const MOUSE_REPORT = /^(?:\x1b\[<\d+;\d+;\d+[Mm]|\x1b\[\d+;\d+;\d+M|\x1b\[M[\s\S]{3})$/

/** A chunk only the terminal itself would produce (a protocol reply or a
 *  focus report). Used where the input's origin is not known; a user key can
 *  collide with it (Shift+F3 is `ESC[1;2R`, the shape of a cursor report), so
 *  the origin flag wins whenever it is available. */
export function looksLikeTerminalReply(data: string): boolean {
  return (
    CSI_REPLY.test(data) || FOCUS_REPORT.test(data) || OSC_REPLY.test(data) || DCS_REPLY.test(data)
  )
}

export function isMouseReport(data: string): boolean {
  return MOUSE_REPORT.test(data)
}

/** Whether a chunk from the focused pane is mirrored to its siblings.
 *
 *  `userInput` is xterm's own "this came from the user" flag (keyboard, IME,
 *  paste, mouse) when the pane could read it, or null when it could not, in
 *  which case the chunk's shape decides. Mouse reports are user-made but
 *  describe a position in THIS pane, so they never travel either. */
export function shouldBroadcast(data: string, userInput: boolean | null): boolean {
  if (isMouseReport(data)) return false
  if (userInput === null) return !looksLikeTerminalReply(data)
  return userInput
}

/** What a paste needs before it reaches the remote.
 *
 *  Without bracketed paste (Cisco IOS, PAN-OS, Junos, cmd.exe, plain sh never
 *  enable it) every line break in the clipboard IS Enter: each line runs the
 *  moment it lands. That needs an explicit yes, like Windows Terminal's
 *  multi-line warning. Trailing line breaks count too: they run the last
 *  line. */
export type PastePlan = { kind: 'paste' } | { kind: 'confirm'; lines: number }

export function planPaste(text: string, bracketed: boolean): PastePlan {
  if (bracketed) return { kind: 'paste' }
  const breaks = text.replace(/\r\n/g, '\n').match(/[\r\n]/g)?.length ?? 0
  if (breaks === 0) return { kind: 'paste' }
  // Lines that would execute: every line ended by a break.
  return { kind: 'confirm', lines: breaks }
}

/** Bytes a snippet sends: as typed, and with autoRun the Enter key — CR, which
 *  is what xterm sends for Enter (LF is ^J, which not every CLI accepts). */
export function snippetText(command: string, autoRun: boolean): string {
  return autoRun ? `${command}\r` : command
}

/** Whether xterm will bracket a paste right now: the remote enabled the mode
 *  and the terminal is not configured to ignore it (xterm's Clipboard.ts
 *  applies both). Read synchronously right before every write. */
export function bracketedNow(term: {
  modes: { bracketedPasteMode: boolean }
  options: { ignoreBracketedPasteMode?: boolean }
}): boolean {
  return term.modes.bracketedPasteMode && term.options.ignoreBracketedPasteMode !== true
}

/** Any line break: such text is never broadcast (see pasteMirrorText). */
export const isMultiLine = (text: string): boolean => /[\r\n]/.test(text)

/** What a paste mirrors to broadcast siblings: the text itself for a single
 *  line of plain characters, else nothing (it goes to the source pane only).
 *
 *  Broadcast cannot know each sibling's bracketed-paste state, and the bytes
 *  a bracketed source would send (`ESC[200~…ESC[201~` around embedded CRs)
 *  run line by line on a sibling that never enabled the mode. So the rule is
 *  deliberately blunt: multi-line text (paste, AI insert, snippet) is never
 *  broadcast, and neither is a paste carrying any other control character.
 *  A single plain line is mirrored unframed, as if typed. */
export function pasteMirrorText(text: string): string | null {
  // eslint-disable-next-line no-control-regex
  return text.length > 0 && !/[\x00-\x1f\x7f]/.test(text) ? text : null
}

/** The synchronous re-check right before a paste is written, after every
 *  dialog: the remote can turn bracketed paste off while one is open, and a
 *  paste that was safe when it was planned would then run line by line.
 *  True when the multi-line confirm is needed now and was not given yet. */
export function pasteNeedsConfirmNow(text: string, bracketed: boolean, multiConfirmed: boolean): boolean {
  return !multiConfirmed && planPaste(text, bracketed).kind === 'confirm'
}

/** Where a snippet goes when the source pane would broadcast to `siblings`.
 *  A multi-line snippet goes to the source only (the multi-line rule above);
 *  `localOnly` says that broadcast was on and was not applied. */
export function snippetTargets(
  command: string,
  siblings: readonly string[],
): { targets: string[]; localOnly: boolean } {
  if (isMultiLine(command)) return { targets: [], localOnly: siblings.length > 0 }
  return { targets: [...siblings], localOnly: false }
}

/** Siblings a confirmed broadcast may still reach: those the user approved
 *  that are still broadcast targets now. A pane added while the dialog was
 *  open was never named in it, so it gets nothing. */
export function stillApproved(approved: readonly string[], now: readonly string[]): string[] {
  return approved.filter((id) => now.includes(id))
}
