import { useCallback, useEffect, useMemo, useState } from 'react'
import { AlertTriangle, CheckCircle2, ShieldCheck, X } from 'lucide-react'
import { safeInvoke } from '../lib/tauri'

interface AuditView {
  seq: number
  ts: number
  event: string
  summary: string
  detail: Record<string, unknown>
}

interface VerifyReport {
  ok: boolean
  count: number
  message: string
  brokenAt: number | null
  sealStatus: string
}

const fmtWhen = (epoch: number) => {
  const d = new Date(epoch * 1000)
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

/* A failure event (its tag ends in ".fail") reads amber so a denied login or a
   failed transfer stands out when scanning the log. */
const isFailure = (event: string) => event.endsWith('.fail')

/* Compact one-line detail: the fields worth seeing at a glance, secrets never
   among them (the backend only ever records metadata). */
const detailLine = (d: Record<string, unknown>): string => {
  const parts: string[] = []
  for (const k of ['user', 'host', 'port', 'remote', 'local', 'path', 'bytes', 'error']) {
    const v = d[k]
    if (v !== undefined && v !== null && v !== '') parts.push(`${k}=${v}`)
  }
  return parts.join('  ')
}

/* ---------------------------------------------------------------------------
   Audit log: a tamper-evident record of security-relevant actions.

   Every connect, file transfer, key install, and credential change is appended
   to a hash-chained log on disk, with the chain head sealed into the OS
   keychain. "Verify integrity" walks the chain and reports whether it is intact
   or exactly where it was altered — so the log can be trusted as evidence, not
   just read. Read-only here; the record is written as actions happen.
--------------------------------------------------------------------------- */
export function AuditDialog({ onClose }: { onClose: () => void }) {
  const [entries, setEntries] = useState<AuditView[] | null>(null)
  const [report, setReport] = useState<VerifyReport | null>(null)
  const [verifying, setVerifying] = useState(false)

  const refresh = useCallback(() => {
    void safeInvoke<AuditView[]>('audit_list', { limit: 500 }).then((l) => setEntries(l ?? []))
  }, [])

  useEffect(refresh, [refresh])

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKey, true)
    return () => window.removeEventListener('keydown', onKey, true)
  }, [onClose])

  const verify = () => {
    setVerifying(true)
    setReport(null)
    void safeInvoke<VerifyReport>('audit_verify')
      .then((r) => {
        if (r) setReport(r)
      })
      .finally(() => setVerifying(false))
  }

  const empty = useMemo(() => (entries?.length ?? 0) === 0, [entries])

  return (
    <div className="absolute inset-0 z-50 flex justify-center">
      <div className="animate-scrim-in absolute inset-0 bg-surface-0/75 backdrop-blur-[2px]" aria-hidden />

      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="audit-title"
        className="animate-drop-in relative mt-10 flex h-[80vh] w-[56rem] max-w-[94vw] flex-col overflow-hidden rounded-panel border border-line-strong bg-surface-2 shadow-[0_24px_60px_-12px_rgba(0,0,0,0.75)]"
      >
        <header className="flex items-center gap-2 border-b border-line px-4 py-2.5">
          <ShieldCheck size={15} className="shrink-0 text-accent" aria-hidden />
          <h2 id="audit-title" className="flex-1 text-[13.5px] font-medium text-ink">
            Audit log
          </h2>
          <button
            type="button"
            onClick={verify}
            disabled={verifying}
            className="flex h-7 items-center gap-1.5 rounded border border-line bg-surface-1 px-2.5 text-[12px] text-ink hover:border-accent hover:text-accent disabled:opacity-50"
          >
            <ShieldCheck size={13} aria-hidden />
            {verifying ? 'Verifying…' : 'Verify integrity'}
          </button>
          <button
            type="button"
            aria-label="Close"
            onClick={onClose}
            className="grid h-6 w-6 place-items-center rounded text-ink-faint hover:bg-surface-3 hover:text-ink"
          >
            <X size={14} />
          </button>
        </header>

        {/* Verify result banner */}
        {report && (
          <div
            role="status"
            className={`flex items-start gap-2 border-b px-4 py-2 text-[12px] ${
              report.ok
                ? 'border-line bg-accent-soft/40 text-ink'
                : 'border-warn/60 bg-warn/10 text-ink'
            }`}
          >
            {report.ok ? (
              <CheckCircle2 size={14} className="mt-0.5 shrink-0 text-accent" aria-hidden />
            ) : (
              <AlertTriangle size={14} className="mt-0.5 shrink-0 text-warn" aria-hidden />
            )}
            <span className="min-w-0">
              {report.message}
              {report.brokenAt !== null && (
                <span className="font-mono"> (entry {report.brokenAt})</span>
              )}
            </span>
          </div>
        )}

        {/* Entry list */}
        <div className="min-h-0 flex-1 overflow-y-auto bg-surface-0">
          {entries === null ? (
            <p className="px-3 py-6 text-center text-[12px] text-ink-faint">Loading…</p>
          ) : empty ? (
            <p className="px-3 py-6 text-center text-[12px] text-ink-faint">
              No audited actions yet. Connecting, transferring files, installing keys, and changing
              saved credentials are all recorded here.
            </p>
          ) : (
            entries.map((e) => {
              const line = detailLine(e.detail)
              return (
                <div
                  key={e.seq}
                  className="flex items-start gap-2.5 border-b border-line/50 px-3 py-1.5"
                >
                  <span className="w-[136px] shrink-0 pt-0.5 text-[10.5px] tabular-nums text-ink-faint">
                    {fmtWhen(e.ts)}
                  </span>
                  <span
                    className={`shrink-0 rounded px-1.5 py-0.5 font-mono text-[10.5px] ${
                      isFailure(e.event)
                        ? 'bg-warn/15 text-warn'
                        : 'bg-surface-3 text-ink-dim'
                    }`}
                  >
                    {e.event}
                  </span>
                  <span className="flex min-w-0 flex-1 flex-col">
                    <span className="truncate text-[12px] text-ink">{e.summary}</span>
                    {line && (
                      <span className="truncate font-mono text-[10.5px] text-ink-faint">{line}</span>
                    )}
                  </span>
                  <span className="shrink-0 pt-0.5 font-mono text-[10.5px] tabular-nums text-ink-faint">
                    #{e.seq}
                  </span>
                </div>
              )
            })
          )}
        </div>
      </div>
    </div>
  )
}
