import { useEffect, useMemo, useRef, useState } from 'react'
import { Clock, FileText, Search, X } from 'lucide-react'
import { safeInvoke } from '../lib/tauri'

interface LogEntry {
  name: string
  host: string
  started: number | null
  bytes: number
}

const fmtBytes = (n: number) => {
  if (n < 1024) return `${n} B`
  const units = ['KB', 'MB', 'GB']
  let v = n / 1024
  let u = 0
  while (v >= 1024 && u < units.length - 1) { v /= 1024; u++ }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${units[u]}`
}

const fmtWhen = (epoch: number | null) => {
  if (!epoch) return '—'
  const d = new Date(epoch * 1000)
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}

/* ---------------------------------------------------------------------------
   Session history: browse and read past transcripts.

   The transcripts already existed on disk — this just surfaces them, which is
   the whole value on appliances that keep no session of their own. Read-only:
   these are a record, and the viewer must never look like a live shell you can
   type into.
--------------------------------------------------------------------------- */
export function HistoryBrowser({ onClose }: { onClose: () => void }) {
  const [logs, setLogs] = useState<LogEntry[] | null>(null)
  const [query, setQuery] = useState('')
  const [selected, setSelected] = useState<string | null>(null)
  const [content, setContent] = useState<string>('')
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    void safeInvoke<LogEntry[]>('logs_list').then((l) => setLogs(l ?? []))
  }, [])

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKey, true)
    return () => window.removeEventListener('keydown', onKey, true)
  }, [onClose])

  /* Reads run concurrently on the backend, so a large transcript clicked first
     can resolve after a small one clicked second. Only the latest request may
     touch the viewer. */
  const latest = useRef<string | null>(null)

  const open = (name: string) => {
    latest.current = name
    setSelected(name)
    setLoading(true)
    setContent('')
    void safeInvoke<string>('log_read', { name })
      .then((c) => {
        if (latest.current === name) setContent(c ?? '')
      })
      .catch((e) => {
        if (latest.current === name) {
          setContent(`Could not read ${name}: ${e instanceof Error ? e.message : e}`)
        }
      })
      .finally(() => {
        if (latest.current === name) setLoading(false)
      })
  }

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    const all = logs ?? []
    return q ? all.filter((l) => l.host.toLowerCase().includes(q)) : all
  }, [logs, query])

  return (
    <div className="absolute inset-0 z-50 flex justify-center">
      <div className="animate-scrim-in absolute inset-0 bg-surface-0/75 backdrop-blur-[2px]" aria-hidden />

      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="hist-title"
        className="animate-drop-in relative mt-10 flex h-[80vh] w-[56rem] max-w-[94vw] flex-col overflow-hidden rounded-panel border border-line-strong bg-surface-2 shadow-[0_24px_60px_-12px_rgba(0,0,0,0.75)]"
      >
        <header className="flex items-center gap-2 border-b border-line px-4 py-2.5">
          <Clock size={15} className="shrink-0 text-accent" aria-hidden />
          <h2 id="hist-title" className="flex-1 text-[13.5px] font-medium text-ink">
            Session history
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

        <div className="flex min-h-0 flex-1">
          {/* List */}
          <div className="flex w-[22rem] shrink-0 flex-col border-r border-line">
            <div className="relative p-2">
              <Search size={12} className="pointer-events-none absolute top-1/2 left-4 -translate-y-1/2 text-ink-faint" aria-hidden />
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Filter by host"
                className="h-7 w-full rounded border border-line bg-surface-1 pl-7 pr-2 text-[12px] text-ink placeholder:text-ink-faint focus:border-accent focus:outline-none"
              />
            </div>
            <div className="min-h-0 flex-1 overflow-y-auto">
              {logs === null ? (
                <p className="px-3 py-6 text-center text-[12px] text-ink-faint">Loading…</p>
              ) : filtered.length === 0 ? (
                <p className="px-3 py-6 text-center text-[12px] text-ink-faint">
                  {logs.length === 0 ? 'No sessions recorded yet.' : 'No hosts match.'}
                </p>
              ) : (
                filtered.map((l) => (
                  <button
                    key={l.name}
                    type="button"
                    onClick={() => open(l.name)}
                    className={`flex w-full flex-col items-start gap-0.5 border-b border-line/50 px-3 py-1.5 text-left transition-colors ${
                      selected === l.name ? 'bg-accent-soft' : 'hover:bg-surface-1'
                    }`}
                  >
                    <span className="flex w-full items-center gap-1.5">
                      <FileText size={12} className="shrink-0 text-ink-faint" aria-hidden />
                      <span className="min-w-0 flex-1 truncate font-mono text-[12px] text-ink">
                        {l.host}
                      </span>
                      <span className="shrink-0 text-[10.5px] tabular-nums text-ink-faint">
                        {fmtBytes(l.bytes)}
                      </span>
                    </span>
                    <span className="pl-[18px] text-[10.5px] tabular-nums text-ink-faint">
                      {fmtWhen(l.started)}
                    </span>
                  </button>
                ))
              )}
            </div>
          </div>

          {/* Viewer */}
          <div className="flex min-w-0 flex-1 flex-col bg-surface-0">
            {selected ? (
              loading ? (
                <p className="p-4 text-[12px] text-ink-faint">Loading…</p>
              ) : (
                <pre className="selectable min-h-0 flex-1 overflow-auto whitespace-pre-wrap break-words p-3 font-mono text-[12px] leading-relaxed text-ink-dim">
                  {content}
                </pre>
              )
            ) : (
              <div className="flex flex-1 items-center justify-center text-[12px] text-ink-faint">
                Select a session to view its transcript.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
