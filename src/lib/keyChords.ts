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

/** A key value that is one printable character (not "Unidentified",
 *  "Dead", "Process", "Tab", a control character…). */
const printable = (key: string): boolean =>
  // eslint-disable-next-line no-control-regex
  [...key].length === 1 && !/[\x00-\x1f\x7f]/.test(key)

/** The tab digit (1-9) a Ctrl chord without Shift names, or null.
 *
 *  By the character the key produces (`e.key`) whenever that is printable,
 *  and by the physical key (`e.code`) only when it is not. On French AZERTY
 *  the Digit8 key produces `_` without Shift, and Ctrl+_ is readline's undo:
 *  mapping it by `e.code` swallowed it as "tab 8". The number row there
 *  produces digits only with Shift, so on AZERTY Ctrl+<digit> tab switching
 *  is simply not available; the chord belongs to the terminal. Numpad keys
 *  are never tab chords. */
function tabDigit(e: KeyLike): number | null {
  if (e.code.startsWith('Numpad')) return null
  if (printable(e.key)) {
    return /^[1-9]$/.test(e.key) ? Number(e.key) : null
  }
  const m = /^Digit([1-9])$/.exec(e.code)
  return m ? Number(m[1]) : null
}

/** The app shortcut this chord means, or null. Pure. Whether the shortcut can
 *  act right now (a snippet in that slot, no modal open) is mostly the
 *  caller's business, and the chord is the app's either way, so the remote
 *  must never receive it, with one exception: a tab chord for a tab that
 *  does not exist (`tabCount` given and too small) is not an app chord at
 *  all, so the terminal encodes it as usual. */
export function appShortcut(e: KeyLike, tabCount?: number): AppShortcut | null {
  if (!isPlainCtrl(e)) return null
  if (e.key === 'Tab' || e.code === 'Tab') return { kind: 'cycleTab', dir: e.shiftKey ? -1 : 1 }
  if (e.shiftKey) {
    // Snippet slots by physical key: Shift+1 is "!" on US (and "1" on
    // AZERTY) in e.key, and Ctrl+Shift+2 must never reach xterm as NUL.
    const digit = /^Digit([1-9])$/.exec(e.code)
    if (digit) return { kind: 'snippet', slot: Number(digit[1]) }
  } else {
    const n = tabDigit(e)
    if (n !== null) {
      if (tabCount !== undefined && n > tabCount) return null
      return { kind: 'gotoTab', index: n - 1 }
    }
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

/** `tabCount`: tabs open now, so a chord for a tab that does not exist is
 *  left to xterm (see appShortcut). */
export function terminalKeyAction(e: KeyLike, tabCount?: number): TerminalKeyAction {
  if (appShortcut(e, tabCount)) return 'app'
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

/** Tabs open right now, kept by the app shell for the terminal's key handler
 *  (which lives outside React). Infinity until the shell reports. */
let openTabs = Number.POSITIVE_INFINITY
export const setOpenTabCount = (n: number): void => {
  openTabs = n
}
export const openTabCount = (): number => openTabs
