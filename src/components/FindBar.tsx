import { useEffect, useRef, useState } from 'react'
import { ChevronDown, ChevronUp, Search, X } from 'lucide-react'
import { getTerm } from '../lib/termRegistry'

/* ---------------------------------------------------------------------------
   Find in terminal (Ctrl+Shift+F).

   Floats over the top-right of the workspace and searches the FOCUSED pane's
   scrollback via xterm's SearchAddon. Enter steps forward, Shift+Enter back,
   Escape closes and returns focus to the terminal — the bar must never strand
   keyboard focus, or "find then keep typing" breaks.
--------------------------------------------------------------------------- */
export function FindBar({
  sessionId,
  focusNonce = 0,
  onClose,
}: {
  /** The pane to search: the focused one, followed as the user switches. */
  sessionId: string
  /** Changes on every Ctrl+Shift+F, so pressing it again re-focuses. */
  focusNonce?: number
  onClose: () => void
}) {
  const [query, setQuery] = useState('')
  const inputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    inputRef.current?.focus()
    inputRef.current?.select()
  }, [focusNonce])

  // Retarget: when the focused pane changes, the old pane's highlights go
  // (they were left behind), and the search runs again in the new one.
  useEffect(
    () => () => {
      getTerm(sessionId)?.search.clearDecorations()
      getTerm(sessionId)?.term.clearSelection()
    },
    [sessionId],
  )

  // Live-search as the query changes; decorations highlight every match.
  useEffect(() => {
    const entry = getTerm(sessionId)
    if (!entry) return
    if (query) {
      entry.search.findNext(query, { incremental: true })
    } else {
      entry.search.clearDecorations()
    }
  }, [query, sessionId])

  const step = (dir: 1 | -1) => {
    const entry = getTerm(sessionId)
    if (!entry || !query) return
    if (dir === 1) entry.search.findNext(query)
    else entry.search.findPrevious(query)
  }

  const close = () => {
    getTerm(sessionId)?.search.clearDecorations()
    getTerm(sessionId)?.term.focus()
    onClose()
  }

  return (
    <div className="absolute top-10 right-3 z-40 flex items-center gap-1 rounded-md border border-line-strong bg-surface-2 p-1 shadow-[0_8px_24px_-6px_rgba(0,0,0,0.6)]">
      <Search size={12} className="ml-1 shrink-0 text-ink-faint" aria-hidden />
      <input
        ref={inputRef}
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Enter') step(e.shiftKey ? -1 : 1)
          if (e.key === 'Escape') close()
        }}
        placeholder="Find in terminal"
        className="h-6 w-44 bg-transparent px-1 text-[12px] text-ink placeholder:text-ink-faint focus:outline-none"
      />
      <button
        type="button"
        aria-label="Previous match"
        onClick={() => step(-1)}
        className="grid h-6 w-6 place-items-center rounded text-ink-dim hover:bg-surface-3 hover:text-ink"
      >
        <ChevronUp size={13} />
      </button>
      <button
        type="button"
        aria-label="Next match"
        onClick={() => step(1)}
        className="grid h-6 w-6 place-items-center rounded text-ink-dim hover:bg-surface-3 hover:text-ink"
      >
        <ChevronDown size={13} />
      </button>
      <button
        type="button"
        aria-label="Close find"
        onClick={close}
        className="grid h-6 w-6 place-items-center rounded text-ink-faint hover:bg-surface-3 hover:text-ink"
      >
        <X size={13} />
      </button>
    </div>
  )
}
