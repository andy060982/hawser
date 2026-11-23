import { useCallback, useEffect, useRef, useState, type KeyboardEvent as ReactKeyboardEvent } from 'react'
import { ArrowRight, Cable, Plus, X } from 'lucide-react'
import { safeInvoke } from '../lib/tauri'
import { validateForward } from '../lib/transfers'

interface ForwardInfo {
  id: string
  sessionId: string
  localPort: number
  remoteHost: string
  remotePort: number
  kind: 'local' | 'socks'
}

/* ---------------------------------------------------------------------------
   Local port forwarding (`ssh -L`) for one session.

   The classic use on a segmented network: the web UI of a device on an
   isolated management VLAN, reached as localhost:<port> through a box that
   can see it. Forwards bind 127.0.0.1 only (enforced in Rust) and die with
   the session — both facts stated in the UI because they are the two things
   an operator needs to trust before pointing a browser at the tunnel.
--------------------------------------------------------------------------- */
export function TunnelDialog({
  sessionId,
  sessionTitle,
  onClose,
}: {
  sessionId: string
  sessionTitle: string
  onClose: () => void
}) {
  const [forwards, setForwards] = useState<ForwardInfo[]>([])
  const [localPort, setLocalPort] = useState('')
  const [remoteHost, setRemoteHost] = useState('127.0.0.1')
  const [remotePort, setRemotePort] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [mode, setMode] = useState<'local' | 'socks'>('local')
  const [busy, setBusy] = useState(false)

  const refresh = useCallback(() => {
    void safeInvoke<ForwardInfo[]>('forwards_list', { sessionId })
      .then((l) => setForwards(l ?? []))
      .catch((e) => setError(e instanceof Error ? e.message : String(e)))
  }, [sessionId])

  /** Synchronous guard: `busy` is render-time state, so a double Enter (or a
   *  click plus Enter) could start two forwards before it re-rendered. */
  const busyRef = useRef(false)

  useEffect(refresh, [refresh])

  /* Escape closes this dialog only when the key is pressed INSIDE it (no
     window listener): a confirm or alert opened above it holds the focus,
     so its Escape dismisses just that alert and never this dialog too. */
  const panelRef = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!panelRef.current?.contains(document.activeElement)) panelRef.current?.focus()
  }, [])
  const onPanelKey = (e: ReactKeyboardEvent) => {
    if (e.key !== 'Escape') return
    e.stopPropagation()
    onClose()
  }

  const add = async () => {
    if (busyRef.current) return
    const req = validateForward(mode, localPort, remoteHost, remotePort)
    if (typeof req === 'string') {
      setError(req)
      return
    }
    busyRef.current = true
    setBusy(true)
    setError(null)
    try {
      // Local port 0 = "pick a free one"; the result shows what bound.
      if (mode === 'socks') {
        await safeInvoke('forward_start_socks', { sessionId, localPort: req.localPort })
      } else {
        await safeInvoke('forward_start', {
          sessionId,
          localPort: req.localPort,
          remoteHost: req.remoteHost,
          remotePort: req.remotePort,
        })
      }
      setLocalPort('')
      setRemotePort('')
      refresh()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      busyRef.current = false
      setBusy(false)
    }
  }

  const stop = (id: string) => {
    void safeInvoke('forward_stop', { forwardId: id })
      .catch((e) => setError(`Could not stop the forward: ${e instanceof Error ? e.message : String(e)}`))
      .finally(refresh)
  }

  return (
    <div className="absolute inset-0 z-50 flex justify-center">
      <div className="animate-scrim-in absolute inset-0 bg-surface-0/75 backdrop-blur-[2px]" aria-hidden />

      <div
        ref={panelRef}
        tabIndex={-1}
        onKeyDown={onPanelKey}
        role="dialog"
        aria-modal="true"
        aria-labelledby="tun-title"
        className="animate-drop-in relative outline-none mt-12 h-fit w-[34rem] max-w-[92vw] overflow-hidden rounded-panel border border-line-strong bg-surface-2 shadow-[0_24px_60px_-12px_rgba(0,0,0,0.75)]"
      >
        <header className="flex items-center gap-2 border-b border-line px-5 py-3">
          <Cable size={15} className="shrink-0 text-accent" aria-hidden />
          <h2 id="tun-title" className="flex-1 text-[13.5px] font-medium text-ink">
            Port forwarding — {sessionTitle}
          </h2>
          <button
            type="button"
            aria-label="Close"
            onClick={onClose}
            className="grid h-6 w-6 place-items-center rounded text-ink-faint hover:bg-surface-3 hover:text-ink"
          >
            <X size={14} />
          </button>
        </header>

        <div className="space-y-3 px-5 py-4">
          {forwards.length > 0 && (
            <ul className="space-y-1">
              {forwards.map((f) => (
                <li
                  key={f.id}
                  className="flex items-center gap-2 rounded border border-line bg-surface-1 px-3 py-1.5 font-mono text-[12px]"
                >
                  <span className="selectable text-ink">localhost:{f.localPort}</span>
                  <ArrowRight size={11} className="shrink-0 text-ink-faint" aria-hidden />
                  <span className="selectable min-w-0 flex-1 truncate text-ink-dim">
                    {f.kind === 'socks'
                      ? 'SOCKS5 proxy — point a browser at it'
                      : `${f.remoteHost}:${f.remotePort}`}
                  </span>
                  <button
                    type="button"
                    onClick={() => stop(f.id)}
                    className="shrink-0 rounded border border-line px-1.5 py-0.5 text-[10.5px] text-ink-dim hover:border-alert/50 hover:text-alert"
                  >
                    Stop
                  </button>
                </li>
              ))}
            </ul>
          )}

          <div className="flex items-center gap-1">
            {(['local', 'socks'] as const).map((m) => (
              <button
                key={m}
                type="button"
                onClick={() => setMode(m)}
                aria-pressed={mode === m}
                className={`h-6 rounded border px-2 text-[11.5px] transition-colors ${
                  mode === m
                    ? 'border-accent/60 bg-accent/15 text-accent'
                    : 'border-line text-ink-dim hover:bg-surface-3 hover:text-ink'
                }`}
              >
                {m === 'local' ? 'Local forward (-L)' : 'SOCKS proxy (-D)'}
              </button>
            ))}
          </div>

          <div className="flex items-end gap-2">
            <label className="block w-24">
              <span className="mb-1 block text-[10.5px] uppercase tracking-wider text-ink-faint">
                Local port
              </span>
              <input
                value={localPort}
                onChange={(e) => setLocalPort(e.target.value.replace(/\D/g, ''))}
                placeholder="auto"
                className="h-7 w-full rounded border border-line bg-surface-0 px-2 font-mono text-[12px] text-ink placeholder:text-ink-faint focus:border-accent focus:outline-none"
              />
            </label>
            {mode === 'local' && (
            <label className="block min-w-0 flex-1">
              <span className="mb-1 block text-[10.5px] uppercase tracking-wider text-ink-faint">
                Remote host (as the server sees it)
              </span>
              <input
                value={remoteHost}
                onChange={(e) => setRemoteHost(e.target.value)}
                placeholder="10.20.5.30"
                className="h-7 w-full rounded border border-line bg-surface-0 px-2 font-mono text-[12px] text-ink placeholder:text-ink-faint focus:border-accent focus:outline-none"
              />
            </label>
            )}
            {mode === 'local' && (
            <label className="block w-24">
              <span className="mb-1 block text-[10.5px] uppercase tracking-wider text-ink-faint">
                Remote port
              </span>
              <input
                value={remotePort}
                onChange={(e) => setRemotePort(e.target.value.replace(/\D/g, ''))}
                onKeyDown={(e) => e.key === 'Enter' && !busy && void add()}
                placeholder="443"
                className="h-7 w-full rounded border border-line bg-surface-0 px-2 font-mono text-[12px] text-ink placeholder:text-ink-faint focus:border-accent focus:outline-none"
              />
            </label>
            )}
            <button
              type="button"
              disabled={busy}
              onClick={() => void add()}
              className="flex h-7 shrink-0 items-center gap-1 rounded border border-accent/60 bg-accent/15 px-2.5 text-[12px] font-medium text-accent hover:bg-accent/25 disabled:opacity-50"
            >
              <Plus size={12} aria-hidden />
              Forward
            </button>
          </div>

          {error && (
            <p className="selectable rounded border border-alert/40 bg-alert/10 px-3 py-2 text-[12px] text-alert">
              {error}
            </p>
          )}

          <p className="text-[11px] leading-relaxed text-ink-faint">
            Tunnels listen on 127.0.0.1 only and end when this session
            disconnects. “Remote host” is resolved by the server, so
            127.0.0.1 there means the server itself.
          </p>
        </div>
      </div>
    </div>
  )
}
