/** Keyboard chord classification, shared by the terminal's key handler and the
 *  app-wide shortcut listener so the two can never disagree about who owns a
 *  key.
 *
 *  Why this exists: xterm handles a key on its textarea BEFORE the event
 *  bubbles to `window`, and for a chord it can encode (Ctrl+Tab is TAB, Ctrl+3
 *  is ESC, Ctrl+8 is DEL, Ctrl+Shift+2 is NUL on a US layout) it sends the byte
 *  to the remote and stops propagation. The app shortcut then never fires and
 *  the remote gets a stray control character. The terminal asks
 *  `appShortcut()` first and hands every app chord back unprocessed.
 *
 *  AltGr: on Windows (WebView2/Chromium) AltGr arrives as Ctrl+Alt, so a
 *  German `}` (AltGr+0) or `\` (AltGr+ß) looks like Ctrl+0 / Ctrl+Minus. No
 *  Ctrl shortcut here ever fires with Alt (or Meta) held. */

export interface KeyLike {
  key: string
  code: string
  ctrlKey: boolean
  shiftKey: boolean
  altKey: boolean
  metaKey: boolean
}

/** What an app-level shortcut asks for. */
export type AppShortcut =
  | { kind: 'cycleTab'; dir: 1 | -1 }
  | { kind: 'gotoTab'; index: number }
  | { kind: 'snippet'; slot: number }
  | { kind: 'command'; code: AppCommandCode }

/** Ctrl+Shift+<letter> commands. Terminals cannot encode Ctrl+Shift+letter
 *  distinctly from Ctrl+letter, so this space is free for the UI. */
export const APP_COMMAND_CODES = ['KeyA', 'KeyP', 'KeyT', 'KeyF', 'KeyE', 'KeyW', 'KeyK'] as const
export type AppCommandCode = (typeof APP_COMMAND_CODES)[number]

/** A plain Ctrl chord: Ctrl held, and neither Alt (AltGr) nor Meta. */
export const isPlainCtrl = (e: KeyLike): boolean => e.ctrlKey && !e.altKey && !e.metaKey

/** The app shortcut this chord means, or null. Pure: whether the shortcut can
 *  act right now (a tab at that index, a snippet in that slot, no modal open)
 *  is the caller's business, but the chord is the app's either way, so the
 *  remote must never receive it. */
export function appShortcut(e: KeyLike): AppShortcut | null {
  if (!isPlainCtrl(e)) return null
  if (e.key === 'Tab' || e.code === 'Tab') return { kind: 'cycleTab', dir: e.shiftKey ? -1 : 1 }
  // e.code, never e.key: Shift+1 is "!" and Ctrl+Shift+2 is "@" in e.key.
  const digit = /^Digit([1-9])$/.exec(e.code)
  if (digit) {
    const n = Number(digit[1])
    return e.shiftKey ? { kind: 'snippet', slot: n } : { kind: 'gotoTab', index: n - 1 }
  }
  if (e.shiftKey && (APP_COMMAND_CODES as readonly string[]).includes(e.code)) {
    return { kind: 'command', code: e.code as AppCommandCode }
  }
  return null
}

/** What the focused terminal should do with a key event. */
export type TerminalKeyAction =
  /** An app shortcut: xterm must not process it, and the event must bubble. */
  | 'app'
  | 'copy'
  | 'paste'
  /** Ctrl+C: copy when there is a selection, else SIGINT to the remote. */
  | 'copyOrInterrupt'
  | 'zoomIn'
  | 'zoomOut'
  | 'zoomReset'
  /** Not ours: let xterm encode it. */
  | 'pass'

export function terminalKeyAction(e: KeyLike): TerminalKeyAction {
  if (appShortcut(e)) return 'app'
  if (!isPlainCtrl(e)) return 'pass'
  if (e.shiftKey && e.code === 'KeyC') return 'copy'
  if (e.shiftKey && e.code === 'KeyV') return 'paste'
  if (!e.shiftKey && e.code === 'KeyC') return 'copyOrInterrupt'
  // Ctrl+= and Ctrl++ (Shift+Equal on US layouts) both zoom in.
  if (e.code === 'Equal' || e.code === 'NumpadAdd') return 'zoomIn'
  // Ctrl+Shift+Minus is Ctrl+_ (readline/emacs undo): it belongs to the shell.
  if ((e.code === 'Minus' && !e.shiftKey) || e.code === 'NumpadSubtract') return 'zoomOut'
  if ((e.code === 'Digit0' && !e.shiftKey) || e.code === 'Numpad0') return 'zoomReset'
  return 'pass'
}
