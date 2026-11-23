import { useEffect, useRef, useState } from 'react'
import { KeyRound, X, Zap } from 'lucide-react'
import { useModalLayer } from '../lib/useModalLayer'

/* ---------------------------------------------------------------------------
   Quick connect (Ctrl+Shift+P): `user@host[:port]`, optional password, go.

   For the box you will touch once and never save — a vendor appliance during
   an install, a customer's router, a temporary VM. Nothing is persisted: the
   host is not added to the catalogue and the password, if given, is passed
   one-shot to the connect call and never written to the vault. Closing the
   tab leaves no trace beyond the transcript.
--------------------------------------------------------------------------- */
export function QuickConnect({
  onConnect,
  onClose,
}: {
  onConnect: (username: string, hostname: string, port: number, password: string | null) => void
  onClose: () => void
}) {
  const [dest, setDest] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    inputRef.current?.focus()
  }, [])

  // Escape closes this dialog only while it is the top modal (an alert over
  // it takes its own Escape).
  useModalLayer(true, onClose)

  const go = () => {
    // user@host[:port] — the same shape everyone already types into ssh.
    const m = /^([^@\s]+)@([^\s:@]+|\[[0-9a-fA-F:]+\])(?::(\d{1,5}))?$/.exec(dest.trim())
    if (!m) {
      setError('Format: user@host or user@host:port')
      return
    }
    const port = m[3] ? Number(m[3]) : 22
    if (port < 1 || port > 65535) {
      setError('Port must be 1–65535.')
      return
    }
    onConnect(m[1], m[2].replace(/^\[|\]$/g, ''), port, password || null)
    onClose()
  }

  return (
    <div className="absolute inset-0 z-50 flex justify-center">
      <div className="animate-scrim-in absolute inset-0 bg-surface-0/75 backdrop-blur-[2px]" aria-hidden />

      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="qc-title"
        className="animate-drop-in relative mt-16 h-fit w-[26rem] max-w-[92vw] overflow-hidden rounded-panel border border-line-strong bg-surface-2 shadow-[0_24px_60px_-12px_rgba(0,0,0,0.75)]"
      >
        <header className="flex items-center gap-2 border-b border-line px-4 py-2.5">
          <Zap size={14} className="shrink-0 text-accent" aria-hidden />
          <h2 id="qc-title" className="flex-1 text-[13px] font-medium text-ink">
            Quick connect
          </h2>
          <button
            type="button"
            aria-label="Close"
            onClick={onClose}
            className="grid h-6 w-6 place-items-center rounded text-ink-faint hover:bg-surface-3 hover:text-ink"
          >
            <X size={13} />
          </button>
        </header>

        <div className="space-y-2.5 px-4 py-3">
          <input
            ref={inputRef}
            value={dest}
            onChange={(e) => { setDest(e.target.value); setError(null) }}
            onKeyDown={(e) => e.key === 'Enter' && go()}
            placeholder="admin@192.0.2.10:22"
            className="h-8 w-full rounded border border-line bg-surface-0 px-2.5 font-mono text-[13px] text-ink placeholder:text-ink-faint focus:border-accent focus:outline-none"
          />
          <div className="relative">
            <KeyRound size={12} className="pointer-events-none absolute top-1/2 left-2 -translate-y-1/2 text-ink-faint" aria-hidden />
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && go()}
              placeholder="password (optional — agent is tried without one)"
              autoComplete="off"
              className="h-8 w-full rounded border border-line bg-surface-0 pl-7 pr-2 font-mono text-[12.5px] text-ink placeholder:text-ink-faint focus:border-accent focus:outline-none"
            />
          </div>
          {error && <p className="text-[12px] text-alert">{error}</p>}
          <p className="text-[11px] text-ink-faint">
            Not saved to the catalogue; the password is used once and discarded.
          </p>
        </div>

        <footer className="flex justify-end gap-2 border-t border-line bg-surface-1 px-4 py-2.5">
          <button
            type="button"
            onClick={onClose}
            className="rounded border border-line px-3 py-1 text-[12.5px] text-ink-dim hover:bg-surface-3 hover:text-ink"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={go}
            className="rounded border border-accent/60 bg-accent/15 px-3 py-1 text-[12.5px] font-medium text-accent hover:bg-accent/25"
          >
            Connect
          </button>
        </footer>
      </div>
    </div>
  )
}
