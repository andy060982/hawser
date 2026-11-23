import { useLayoutEffect, useRef, useState } from 'react'
import { useModalLayer } from '../lib/useModalLayer'

export interface MenuItem {
  label: string
  onSelect: () => void
  /** Red text, for destructive actions like Delete. */
  danger?: boolean
  disabled?: boolean
  /** Draw a divider above this item. */
  dividerBefore?: boolean
}

export interface MenuState {
  x: number
  y: number
  items: MenuItem[]
}

/* ---------------------------------------------------------------------------
   One floating menu, driven by {x, y, items}. Positioned at the cursor and
   clamped so it never spills off-screen — a menu opened near the right or
   bottom edge flips back into view rather than being half-cut. A transparent
   full-window layer sits behind it to catch the click (or right-click) that
   dismisses it, and Escape closes too.

   Presentational only: it owns no actions, just renders whatever items it is
   handed, so hosts, tabs, and the terminal all share the same component with
   their own item lists.
--------------------------------------------------------------------------- */
export function ContextMenu({ menu, onClose }: { menu: MenuState | null; onClose: () => void }) {
  const ref = useRef<HTMLDivElement>(null)
  const [pos, setPos] = useState({ x: 0, y: 0 })

  // Measure after render, then clamp into the viewport.
  useLayoutEffect(() => {
    if (!menu) return
    const el = ref.current
    const w = el?.offsetWidth ?? 200
    const h = el?.offsetHeight ?? 0
    const pad = 6
    const x = Math.min(menu.x, window.innerWidth - w - pad)
    const y = Math.min(menu.y, window.innerHeight - h - pad)
    setPos({ x: Math.max(pad, x), y: Math.max(pad, y) })
  }, [menu])

  // A layer while open: Escape closes the menu only, never a dialog under it.
  useModalLayer(!!menu, onClose)

  if (!menu) return null

  return (
    <div
      className="fixed inset-0 z-[60]"
      onMouseDown={onClose}
      onContextMenu={(e) => {
        // A right-click on the backdrop dismisses rather than opening the OS
        // menu; without this you get the browser menu layered over ours.
        e.preventDefault()
        onClose()
      }}
    >
      <div
        ref={ref}
        role="menu"
        style={{ left: pos.x, top: pos.y }}
        onMouseDown={(e) => e.stopPropagation()}
        className="absolute min-w-[11rem] overflow-hidden rounded-md border border-line-strong bg-surface-2 py-1 shadow-[0_12px_32px_-8px_rgba(0,0,0,0.7)]"
      >
        {menu.items.map((item, i) => (
          <div key={i}>
            {item.dividerBefore && <div className="my-1 h-px bg-line" />}
            <button
              type="button"
              role="menuitem"
              disabled={item.disabled}
              onClick={() => {
                onClose()
                item.onSelect()
              }}
              className={`flex w-full items-center px-3 py-1 text-left text-[12.5px] transition-colors disabled:opacity-40 ${
                item.danger
                  ? 'text-alert hover:bg-alert/15'
                  : 'text-ink-dim hover:bg-surface-3 hover:text-ink'
              }`}
            >
              {item.label}
            </button>
          </div>
        ))}
      </div>
    </div>
  )
}
