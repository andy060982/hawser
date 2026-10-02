import { useEffect, useRef } from 'react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { WebglAddon } from '@xterm/addon-webgl'
import { SearchAddon } from '@xterm/addon-search'
import type { Session } from '../types'
import { safeInvoke, safeListen, inTauri } from '../lib/tauri'
import { onLocal } from '../lib/localTerm'
import { isDangerousCommand } from '../lib/dangerous'
import { useSettings } from '../lib/settings'
import { useDialogs } from '../lib/dialogs'
import { registerTerm, unregisterTerm } from '../lib/termRegistry'
import {
  TERMINAL_FONT,
  TERMINAL_FONT_SIZE,
  TERMINAL_LINE_HEIGHT,
  buildTerminalTheme,
} from '../lib/terminalTheme'

/* ---------------------------------------------------------------------------
   One xterm instance, bound to one session, for the lifetime of that session.

   This component is mounted for EVERY open session (see TerminalDeck) and
   merely hidden when its tab is inactive. That is deliberate: destroying and
   recreating a Terminal on tab switch throws away scrollback, viewport
   position, and any in-progress line edit. Mount cost is a few hundred KB of
   buffer; the alternative is the most-reported bug in tabbed SSH clients.

   Consequence: the main effect must have a stable dependency list. If it
   re-runs on anything but session.id, the terminal is silently rebuilt and the
   bug returns through the side door.
--------------------------------------------------------------------------- */

interface Props {
  session: Session
  visible: boolean
  /** Reports the measured grid after every fit, so the status bar can show the
   *  real geometry instead of a guess. */
  onSize?: (sessionId: string, cols: number, rows: number) => void
  /** Other session ids to mirror this pane's input to (broadcast mode). Only
   *  the focused pane should carry these, or panes would echo each other. */
  broadcastTo?: string[]
}

export function TerminalPane({ session, visible, onSize, broadcastTo }: Props) {
  const hostRef = useRef<HTMLDivElement>(null)
  const termRef = useRef<Terminal | null>(null)
  const fitRef = useRef<FitAddon | null>(null)
  /** Last dimensions pushed to the backend, to suppress duplicate PTY resizes. */
  const sizeRef = useRef({ cols: 0, rows: 0 })
  // Held in refs: putting these in the effect deps would tear down and rebuild
  // the terminal whenever the parent re-rendered, losing all scrollback.
  const onSizeRef = useRef(onSize)
  onSizeRef.current = onSize
  const broadcastRef = useRef<string[]>(broadcastTo ?? [])
  broadcastRef.current = broadcastTo ?? []
  const { settings } = useSettings()
  const settingsRef = useRef(settings)
  settingsRef.current = settings
  // Held in a ref so the terminal effect (keyed on session.id) always calls the
  // current confirm without being torn down when the dialog api identity changes.
  const { confirm } = useDialogs()
  const confirmRef = useRef(confirm)
  confirmRef.current = confirm

  useEffect(() => {
    const host = hostRef.current
    if (!host) return

    const term = new Terminal({
      fontFamily: TERMINAL_FONT,
      fontSize: TERMINAL_FONT_SIZE,
      lineHeight: TERMINAL_LINE_HEIGHT,
      letterSpacing: 0,
      theme: buildTerminalTheme(),
      cursorBlink: true,
      cursorStyle: 'block',
      scrollback: 10_000,
      // SSH servers send well-formed CRLF; converting again doubles line breaks.
      convertEol: false,
      allowProposedApi: true,
    })

    const fit = new FitAddon()
    term.loadAddon(fit)
    const search = new SearchAddon()
    term.loadAddon(search)
    term.open(host)
    registerTerm(session.id, term, search)

    // WebGL renderer: the difference between smooth and unusable when tailing a
    // busy log. Context loss (GPU reset, driver update, RDP reconnect) silently
    // blanks the canvas unless we dispose and let xterm fall back to the DOM
    // renderer.
    let webgl: WebglAddon | null = null
    try {
      const addon = new WebglAddon()
      addon.onContextLoss(() => {
        addon.dispose()
        webgl = null
      })
      term.loadAddon(addon)
      webgl = addon
    } catch {
      // No WebGL available (software rendering, GPU policy) — DOM renderer.
    }

    termRef.current = term
    fitRef.current = fit

    // All paste paths funnel here so the dangerous-command guard can inspect the
    // full clipboard text before it reaches the shell; term.paste keeps
    // bracketed-paste framing.
    const doPaste = async (text: string) => {
      if (settingsRef.current.dangerousGuard) {
        const reason = isDangerousCommand(text)
        if (
          reason &&
          !(await confirmRef.current(`Pasted text looks destructive (${reason}). Paste it?`, {
            title: 'Destructive paste',
            confirmLabel: 'Paste',
            danger: true,
          }))
        ) {
          return
        }
      }
      term.paste(text)
    }

    // Read the clipboard and paste it through the guard. Shared by every paste
    // gesture — right-click, Ctrl+Shift+V, and middle-click — so the
    // dangerous-command check and the "clipboard blocked" notice behave
    // identically no matter how the paste was triggered.
    const pasteFromClipboard = () => {
      void navigator.clipboard
        .readText()
        .then((text) => {
          if (text) void doPaste(text)
        })
        .catch(() => {
          term.write('\r\n\x1b[38;2;242;178;92m● clipboard read blocked\x1b[0m\r\n')
        })
    }

    // Copy the current selection to the clipboard, if any. Returns whether there
    // was a selection to copy, so callers can branch (right-click copies-then-
    // pastes off this).
    const copySelection = (): boolean => {
      const sel = term.getSelection()
      if (!sel) return false
      void navigator.clipboard.writeText(sel)
      return true
    }

    /* ---------------------------------------------------- keystrokes out */

    // onData is the correct hook, not a keydown listener: it delivers decoded
    // input AFTER xterm has handled IME composition, bracketed paste, and
    // modifier encoding. Pasted text, dead keys, and arrow-key escape sequences
    // all arrive as the exact bytes the remote PTY expects.
    // ssh_write takes Vec<u8>. TextEncoder produces the UTF-8 bytes the PTY
    // expects; handing over the JS string would re-encode anything outside
    // ASCII and corrupt both pasted text and escape sequences.
    const encoder = new TextEncoder()

    // A write into a session that never connected rejects with "no open
    // session". Swallowing that is what made a dead tab look like a hung app:
    // keys vanish, Enter does nothing, no clue why. Report it once — per
    // keystroke would paint the screen with duplicates.
    let warnedDead = false
    const send = (bytes: number[]) => {
      void safeInvoke('ssh_write', { sessionId: session.id, data: bytes }).catch(
        (e: unknown) => {
          if (warnedDead) return
          warnedDead = true
          const msg = e instanceof Error ? e.message : String(e)
          term.write(
            `\r\n\x1b[38;2;242;178;92m● input not sent\x1b[0m ${msg}\r\n` +
              `\x1b[38;5;244mThis tab is not connected. Close it and reconnect from the sidebar.\x1b[0m\r\n`,
          )
        },
      )
      // Broadcast: mirror the same bytes to sibling panes. Fire-and-forget and
      // errors ignored — a dead sibling is not this pane's problem to report,
      // and the input-not-sent notice above already covers the focused one.
      for (const other of broadcastRef.current) {
        void safeInvoke('ssh_write', { sessionId: other, data: bytes }).catch(() => {})
      }
    }

    // Right-click pastes, PuTTY-style — the muscle memory every network admin
    // brings to a terminal. The browser context menu is suppressed only inside
    // the terminal surface; with a selection active, right-click copies it
    // first and then clears it (PuTTY's copy-on-select + paste-on-right-click
    // combined into the one gesture people actually use).
    const onCtx = (e: MouseEvent) => {
      e.preventDefault()
      // With a selection, right-click copies it and clears — but copy-on-select
      // has usually already put it on the clipboard, so this is mostly a no-op
      // confirmation. Without a selection, right-click pastes (PuTTY muscle
      // memory). doPaste applies the dangerous-command guard, then term.paste
      // (not a raw send) so xterm keeps bracketed-paste framing — a multi-line
      // payload arrives inert for review instead of auto-running.
      if (copySelection()) {
        term.clearSelection()
        return
      }
      pasteFromClipboard()
    }
    host.addEventListener('contextmenu', onCtx)

    // Copy-on-select: the instant a mouse-drag selection ends, put it on the
    // clipboard — no Ctrl-chord, no right-click. This is the "copy/paste should
    // be easy" behaviour of iTerm2 and PuTTY. Guarded on hasSelection so a plain
    // click (no drag) never clobbers the clipboard, and the selection is left
    // highlighted rather than cleared, so it stays visible after copying.
    const onMouseUp = () => {
      if (settingsRef.current.copyOnSelect) copySelection()
    }
    host.addEventListener('mouseup', onMouseUp)

    // Middle-click (mouse wheel button) pastes, X11 / PuTTY style. preventDefault
    // on the button-1 mousedown suppresses the browser's auto-scroll cursor that
    // would otherwise hijack the gesture.
    const onMouseDown = (e: MouseEvent) => {
      if (e.button === 1 && settingsRef.current.middleClickPaste) {
        e.preventDefault()
        pasteFromClipboard()
      }
    }
    host.addEventListener('mousedown', onMouseDown)

    // Native paste (Cmd/Ctrl+V, the platform Edit menu, a WebView paste) fires a
    // `paste` event that xterm's hidden textarea would otherwise ingest directly,
    // bypassing the dangerous-command guard entirely. Intercept it in the capture
    // phase — which runs on this host ancestor before xterm's own textarea
    // handler — take over, and route the text through the guarded doPaste. This
    // adds no new paste trigger; it only gates the native path xterm already had.
    const onPaste = (e: ClipboardEvent) => {
      e.preventDefault()
      e.stopPropagation()
      const text = e.clipboardData?.getData('text/plain')
      // clipboardData is normally populated on a paste event; if it isn't (some
      // WebView paths), fall back to an async clipboard read — still guarded.
      if (text) void doPaste(text)
      else pasteFromClipboard()
    }
    host.addEventListener('paste', onPaste, true)

    const dataSub = term.onData((data) => {
      send(Array.from(encoder.encode(data)))

      // Local echo so the layout stays usable in a plain browser (npm run dev)
      // with no backend attached.
      if (!inTauri()) term.write(data === '\r' ? '\r\n' : data)
    })

    // onBinary carries latin1-encoded bytes — one char per byte — so charCodeAt
    // is correct here and TextEncoder would be actively wrong.
    const binarySub = term.onBinary((data) => {
      send(Array.from(data, (ch) => ch.charCodeAt(0) & 0xff))
    })

    /* -------------------------------------------------- copy / paste keys */

    // Ctrl+C is overloaded: with a selection it means copy, without one it must
    // reach the remote as SIGINT. Returning false tells xterm "handled, do not
    // forward to the PTY". Ctrl+Shift+C/V are the unambiguous forms.
    term.attachCustomKeyEventHandler((e) => {
      if (e.type !== 'keydown') return true

      if (e.ctrlKey && e.shiftKey && e.code === 'KeyC') {
        copySelection()
        return false
      }
      if (e.ctrlKey && e.shiftKey && e.code === 'KeyV') {
        // Guarded paste — see pasteFromClipboard and the context-menu paste above.
        pasteFromClipboard()
        return false
      }
      if (e.ctrlKey && !e.shiftKey && e.code === 'KeyC' && term.hasSelection()) {
        copySelection()
        term.clearSelection()
        return false
      }

      // Font zoom: Ctrl +/- to resize this pane's text, Ctrl+0 to reset —
      // like a browser. Clamped, then re-fit so the grid stays correct.
      if (e.ctrlKey && (e.code === 'Equal' || e.code === 'NumpadAdd')) {
        term.options.fontSize = Math.min((term.options.fontSize ?? TERMINAL_FONT_SIZE) + 1, 32)
        fit.fit()
        return false
      }
      if (e.ctrlKey && (e.code === 'Minus' || e.code === 'NumpadSubtract')) {
        term.options.fontSize = Math.max((term.options.fontSize ?? TERMINAL_FONT_SIZE) - 1, 8)
        fit.fit()
        return false
      }
      if (e.ctrlKey && (e.code === 'Digit0' || e.code === 'Numpad0')) {
        term.options.fontSize = TERMINAL_FONT_SIZE
        fit.fit()
        return false
      }

      // Any other keystroke drops the selection.
      //
      // This is the fix for "Ctrl+C does not interrupt". A selection made ten
      // minutes ago stays active in xterm forever, so the branch above kept
      // winning: you type `dir`, hit Ctrl+C expecting SIGINT, and instead
      // re-copy stale text while the command keeps running. Real terminals
      // clear the selection as soon as you type, which makes Ctrl+C mean
      // "interrupt" in every case except the one where you *just* selected
      // something on purpose.
      if (term.hasSelection() && !e.ctrlKey && !e.altKey && !e.metaKey) {
        term.clearSelection()
      }
      return true
    })

    /* ---------------------------------------------------------- output in */

    let disposed = false
    let unlisten: (() => void) | null = null

    // Frontend-originated text (connect failures, local notices). Subscribed
    // before the backend listener so buffered messages flush immediately.
    const unLocal = onLocal(session.id, (text) => term.write(text))

    void safeListen<string>(`ssh://${session.id}`, (chunk) => {
      term.write(chunk)
    }).then((un) => {
      // The session may have closed while the listener was registering.
      if (disposed) un()
      else unlisten = un
    })

    /* ------------------------------------------------------------ sizing */

    const pushResize = () => {
      // fit() measures the container. A hidden pane measures 0 and would send a
      // nonsense 0x0 PTY resize, which some servers answer by hanging up.
      if (host.clientWidth === 0 || host.clientHeight === 0) return
      fit.fit()
      const { cols, rows } = term
      if (cols === sizeRef.current.cols && rows === sizeRef.current.rows) return
      sizeRef.current = { cols, rows }
      onSizeRef.current?.(session.id, cols, rows)

      // Do not swallow the rejection. If the PTY resize fails the remote keeps
      // drawing to the old geometry, which looks exactly like "the terminal
      // does not expand" while the local grid has in fact resized fine.
      void safeInvoke('ssh_resize', { sessionId: session.id, cols, rows }).catch(
        (e: unknown) => {
          const msg = e instanceof Error ? e.message : String(e)
          term.write(`\r\n\x1b[38;2;242;178;92m● PTY resize failed\x1b[0m ${msg}\r\n`)
        },
      )
    }

    // ResizeObserver rather than a window listener: this pane also changes size
    // when the sidebar is dragged, which fires no window resize event at all.
    let frame = 0
    const ro = new ResizeObserver(() => {
      cancelAnimationFrame(frame)
      frame = requestAnimationFrame(pushResize)
    })
    ro.observe(host)
    pushResize()

    if (!inTauri()) {
      term.writeln('\x1b[38;5;244mNo Tauri backend attached - local echo only.\x1b[0m')
      term.write('\x1b[38;2;79;156;249m$\x1b[0m ')
    }

    /* ---------------------------------------------------------- teardown */

    return () => {
      disposed = true
      cancelAnimationFrame(frame)
      ro.disconnect()
      unlisten?.()
      unLocal()
      host.removeEventListener('contextmenu', onCtx)
      host.removeEventListener('mouseup', onMouseUp)
      host.removeEventListener('mousedown', onMouseDown)
      host.removeEventListener('paste', onPaste, true)
      unregisterTerm(session.id)
      dataSub.dispose()
      binarySub.dispose()
      // Dispose the renderer before the Terminal: the reverse order leaks the
      // WebGL context until GC, and browsers cap live contexts at roughly 16.
      webgl?.dispose()
      term.dispose()
      termRef.current = null
      fitRef.current = null
      void safeInvoke('ssh_disconnect', { sessionId: session.id })
    }
  }, [session.id])

  /* Becoming visible: the pane measured 0 while hidden, so re-fit before the
     user sees a stale grid, then take focus so typing goes straight through. */
  useEffect(() => {
    if (!visible) return
    const id = requestAnimationFrame(() => {
      const host = hostRef.current
      if (!host || host.clientWidth === 0) return
      fitRef.current?.fit()
      // A pane hidden with display:none has a zero-sized canvas, and the WebGL
      // renderer does not always repaint it on the way back. Without this the
      // returning tab can come up blank, which reads as "my session is gone"
      // even though the buffer is intact.
      const t = termRef.current
      if (t) t.refresh(0, t.rows - 1)
      t?.focus()
    })
    return () => cancelAnimationFrame(id)
  }, [visible])

  return (
    <div
      // `hidden` (display:none) rather than unmounting. The instance and its
      // scrollback survive; only layout stops.
      hidden={!visible}
      className="absolute inset-0 bg-surface-0 px-2.5 py-2"
    >
      {/* Padding lives on the wrapper, never on the xterm host: FitAddon sizes
          the grid from the host's client box, and padding there makes it
          overestimate by a column or two. */}
      <div ref={hostRef} className="selectable h-full w-full" />
    </div>
  )
}
