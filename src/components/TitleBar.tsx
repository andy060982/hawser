import { Menu, Minus, Square, X, Waves } from 'lucide-react'
import { windowAction } from '../lib/tauri'

/** Custom chrome. `decorations: false` in tauri.conf.json hands us the whole
 *  window, so this bar owns dragging (data-tauri-drag-region) and the three
 *  window buttons. Height is kept at 32px to match native Windows metrics. */
export function TitleBar({
  subtitle,
  onMenu,
}: {
  subtitle?: string
  /** Opens the app menu, anchored under the button. */
  onMenu?: (x: number, y: number) => void
}) {
  return (
    <header
      data-tauri-drag-region
      className="flex h-8 shrink-0 items-center justify-between border-b border-line bg-surface-1 pl-3 select-none"
    >
      <div data-tauri-drag-region className="flex items-center gap-2 text-ink-dim">
        {onMenu && (
          <button
            type="button"
            aria-label="Menu"
            title="Menu"
            onClick={(e) => {
              const r = e.currentTarget.getBoundingClientRect()
              onMenu(r.left, r.bottom + 4)
            }}
            className="grid h-6 w-6 place-items-center rounded text-ink-dim hover:bg-surface-3 hover:text-ink"
          >
            <Menu size={14} />
          </button>
        )}
        <Waves size={14} className="text-accent" aria-hidden />
        <span className="text-[12px] font-medium tracking-wide text-ink">Hawser</span>
        {subtitle && (
          <>
            <span className="text-ink-faint">/</span>
            <span className="text-[12px] text-ink-dim">{subtitle}</span>
          </>
        )}
      </div>

      <div className="flex h-full">
        <WinButton label="Minimize" onClick={() => windowAction('minimize')}>
          <Minus size={14} />
        </WinButton>
        <WinButton label="Maximize" onClick={() => windowAction('toggleMaximize')}>
          <Square size={11} />
        </WinButton>
        <WinButton label="Close" danger onClick={() => windowAction('close')}>
          <X size={15} />
        </WinButton>
      </div>
    </header>
  )
}

function WinButton({
  children, onClick, label, danger,
}: {
  children: React.ReactNode
  onClick: () => void
  label: string
  danger?: boolean
}) {
  return (
    <button
      type="button"
      aria-label={label}
      onClick={onClick}
      className={`grid w-12 place-items-center text-ink-dim transition-colors hover:text-ink ${
        danger ? 'hover:bg-alert/80' : 'hover:bg-surface-3'
      }`}
    >
      {children}
    </button>
  )
}
