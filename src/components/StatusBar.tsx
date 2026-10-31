import { FileDiff, Lock, RotateCw, Wifi, WifiOff } from 'lucide-react'
import type { Session } from '../types'

export function StatusBar({
  session, hostCount, size, onReconnect, configChange, onViewConfigChange, local = false,
}: {
  /** The active tab is a local terminal: "Restart shell" instead of
   *  "Reconnect", and no SSH cipher line. */
  local?: boolean
  session?: Session
  hostCount: number
  /** Measured terminal grid for the active session, if it has one. */
  size?: { cols: number; rows: number }
  onReconnect?: () => void
  /** Set when the on-connect config check found changes since the last visit. */
  configChange?: { added: number; removed: number }
  onViewConfigChange?: () => void
}) {
  const dead = session && session.status !== 'connected' && session.status !== 'connecting'
  return (
    <footer className="flex h-6 shrink-0 items-center gap-4 border-t border-line bg-surface-1 px-3 text-[11px] text-ink-faint">
      {session ? (
        <>
          {/* The icon must follow the real state. Showing a live-link glyph for
              a dead session is worse than showing nothing. */}
          <span className="flex items-center gap-1.5 text-ink-dim">
            {session.status === 'connected' ? (
              <Wifi size={11} className="text-ok" aria-hidden />
            ) : (
              <WifiOff size={11} className="text-warn" aria-hidden />
            )}
            {session.title}
            {session.status !== 'connected' && (
              <span className="text-warn">({session.status})</span>
            )}
          </span>
          {dead && onReconnect && (
            <button
              type="button"
              onClick={onReconnect}
              className="flex items-center gap-1 rounded border border-accent/50 bg-accent/10 px-1.5 text-[10.5px] text-accent transition-colors hover:bg-accent/20"
            >
              <RotateCw size={10} aria-hidden />
              {local ? 'Restart shell' : 'Reconnect'}
            </button>
          )}
          {configChange && onViewConfigChange && (
            <button
              type="button"
              onClick={onViewConfigChange}
              title="The device config differs from your last snapshot — view the diff"
              className="flex items-center gap-1 rounded border border-warn/50 bg-warn/10 px-1.5 text-[10.5px] text-warn transition-colors hover:bg-warn/20"
            >
              <FileDiff size={10} aria-hidden />
              Config changed +{configChange.added} −{configChange.removed}
            </button>
          )}
          {session.status === 'connected' && !local && (
            <span className="flex items-center gap-1.5">
              <Lock size={10} aria-hidden />
              aes256-gcm · ed25519
            </span>
          )}
          {/* Real measured geometry. This was a hardcoded 80x24 placeholder,
              which made a broken resize impossible to notice. */}
          <span className="font-mono tabular-nums" title="terminal columns x rows">
            {size ? `${size.cols}×${size.rows}` : '--×--'}
          </span>
        </>
      ) : (
        <span>No active session</span>
      )}
      <span className="ml-auto tabular-nums">{hostCount} saved hosts</span>
    </footer>
  )
}
