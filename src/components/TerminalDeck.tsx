import { useRef } from 'react'
import { X } from 'lucide-react'
import type { Session } from '../types'
import { TerminalPane } from './TerminalPane'
import {
  collectDividers,
  collectLeafIds,
  computeRects,
  type Divider as DividerModel,
  type LayoutNode,
} from '../lib/paneLayout'

/** Holds one live TerminalPane per open session and positions the active group's
 *  panes from its layout tree.
 *
 *  Every session's pane is mounted for its whole lifetime and only hidden when
 *  its tab is inactive — hiding rather than unmounting keeps the xterm instance
 *  and its scrollback alive across tab switches and, crucially, across splits.
 *
 *  The layout tree is expressed purely as CSS rectangles: each visible leaf is
 *  an absolutely-positioned box sized from `computeRects`. Because the pane DOM
 *  nodes are a flat, stable list keyed by session id, restructuring the tree
 *  (split, close, resize) only changes inline styles — it never moves a pane in
 *  the React child list, so React never remounts a terminal. That is what makes
 *  arbitrary mixed layouts safe here.
 */
export function TerminalDeck({
  sessions,
  layout,
  focusedId,
  broadcast,
  broadcastExcluded,
  onResizeSplit,
  onResetSplit,
  onClosePane,
  onFocus,
  onSize,
}: {
  sessions: Session[]
  /** The active group's layout tree, or null when the terminal view is hidden
   *  (e.g. the SFTP lens is up) so no group should be shown. */
  layout: LayoutNode | null
  focusedId: string | null
  /** When true, input to the focused pane is mirrored to its siblings. */
  broadcast: boolean
  broadcastExcluded?: Set<string>
  /** Nudge a split's ratio by a fraction of its own extent (from a divider drag). */
  onResizeSplit: (splitId: string, ratioDelta: number) => void
  /** Reset a split back to an even 50/50 (double-click its divider). */
  onResetSplit: (splitId: string) => void
  /** Close a single pane (session). */
  onClosePane: (sessionId: string) => void
  onFocus: (sessionId: string) => void
  onSize?: (sessionId: string, cols: number, rows: number) => void
}) {
  const boxRef = useRef<HTMLDivElement>(null)

  const rects = layout ? computeRects(layout) : new Map()
  const dividers = layout ? collectDividers(layout) : []
  const visibleIds = new Set(layout ? collectLeafIds(layout) : [])
  const split = visibleIds.size > 1

  return (
    <div ref={boxRef} className="relative h-full w-full">
      {sessions.map((s) => {
        const rect = rects.get(s.id)
        const visible = rect != null
        return (
          <div
            key={s.id}
            hidden={!visible}
            onMouseDown={() => onFocus(s.id)}
            style={
              rect
                ? {
                    position: 'absolute',
                    left: `${rect.left * 100}%`,
                    top: `${rect.top * 100}%`,
                    width: `${rect.width * 100}%`,
                    height: `${rect.height * 100}%`,
                  }
                : undefined
            }
            className={`group/pane min-h-0 min-w-0 ${
              split && focusedId === s.id ? 'ring-1 ring-accent/40 ring-inset' : ''
            }`}
          >
            {/* Per-pane close, shown only in a split (a lone pane is closed via
                the tab). Hover-revealed so it never covers terminal output. */}
            {split && visible && (
              <button
                type="button"
                aria-label="Close pane"
                title="Close this pane"
                // Only stopPropagation on mousedown — NOT preventDefault. In
                // WebKit (WKWebView), preventDefault on pointerdown/mousedown
                // suppresses the click event, so the close would never fire.
                onMouseDown={(e) => e.stopPropagation()}
                onClick={(e) => {
                  e.stopPropagation()
                  onClosePane(s.id)
                }}
                className="absolute right-1 top-1 z-30 grid h-5 w-5 place-items-center rounded bg-surface-2/90 text-ink-faint opacity-0 shadow transition hover:bg-surface-4 hover:text-ink group-hover/pane:opacity-100 focus-visible:opacity-100"
              >
                <X size={12} />
              </button>
            )}
            <TerminalPane
              session={s}
              visible={visible}
              onSize={onSize}
              broadcastTo={
                // Only the focused pane fans out, to the other visible panes;
                // otherwise every pane would echo every other and loop.
                broadcast && split && s.id === focusedId
                  ? [...visibleIds].filter((id) => id !== s.id && !broadcastExcluded?.has(id))
                  : undefined
              }
            />
          </div>
        )
      })}

      {/* Divider overlay. Absolutely positioned bands centred on each split
          boundary; drags convert pixels to a ratio delta against the split's own
          measured extent, so proportions hold when the window resizes. */}
      {dividers.map((d) => (
        <Divider
          key={d.splitId}
          divider={d}
          boxRef={boxRef}
          onResize={onResizeSplit}
          onReset={onResetSplit}
        />
      ))}
    </div>
  )
}

function Divider({
  divider: d,
  boxRef,
  onResize,
  onReset,
}: {
  divider: DividerModel
  boxRef: React.RefObject<HTMLDivElement | null>
  onResize: (splitId: string, ratioDelta: number) => void
  onReset: (splitId: string) => void
}) {
  const last = useRef(0)
  const horizontal = d.axis === 'x'

  // A pixel delta becomes a ratio delta against the split's extent in pixels.
  const toRatioDelta = (deltaPx: number): number => {
    const box = boxRef.current
    if (!box) return 0
    const boxPx = horizontal ? box.clientWidth : box.clientHeight
    const extentPx = d.extent * boxPx
    return extentPx > 0 ? deltaPx / extentPx : 0
  }

  const style: React.CSSProperties = horizontal
    ? {
        left: `${d.pos * 100}%`,
        top: `${d.start * 100}%`,
        height: `${d.length * 100}%`,
      }
    : {
        top: `${d.pos * 100}%`,
        left: `${d.start * 100}%`,
        width: `${d.length * 100}%`,
      }

  return (
    <div
      role="separator"
      aria-orientation={horizontal ? 'vertical' : 'horizontal'}
      aria-label="Resize panes"
      tabIndex={0}
      style={style}
      onDoubleClick={() => onReset(d.splitId)}
      onKeyDown={(e) => {
        const back = horizontal ? 'ArrowLeft' : 'ArrowUp'
        const fwd = horizontal ? 'ArrowRight' : 'ArrowDown'
        if (e.key === back) onResize(d.splitId, toRatioDelta(-16))
        if (e.key === fwd) onResize(d.splitId, toRatioDelta(16))
      }}
      onPointerDown={(e) => {
        last.current = horizontal ? e.clientX : e.clientY
        e.currentTarget.setPointerCapture(e.pointerId)
      }}
      onPointerMove={(e) => {
        if (!e.currentTarget.hasPointerCapture(e.pointerId)) return
        const pos = horizontal ? e.clientX : e.clientY
        onResize(d.splitId, toRatioDelta(pos - last.current))
        last.current = pos
      }}
      onPointerUp={(e) => {
        if (e.currentTarget.hasPointerCapture(e.pointerId)) {
          e.currentTarget.releasePointerCapture(e.pointerId)
        }
      }}
      onPointerCancel={(e) => {
        // Capture can be lost externally (a window blur, a touch cancel); release
        // defensively so a dropped pointer never leaves the divider "stuck".
        if (e.currentTarget.hasPointerCapture(e.pointerId)) {
          e.currentTarget.releasePointerCapture(e.pointerId)
        }
      }}
      className={`group absolute z-10 ${
        horizontal
          ? 'w-[7px] -translate-x-1/2 cursor-col-resize'
          : 'h-[7px] -translate-y-1/2 cursor-row-resize'
      }`}
    >
      <span
        className={`absolute bg-line transition-colors group-hover:bg-accent group-focus-visible:bg-accent ${
          horizontal
            ? 'inset-y-0 left-1/2 w-px -translate-x-1/2'
            : 'inset-x-0 top-1/2 h-px -translate-y-1/2'
        }`}
      />
    </div>
  )
}
