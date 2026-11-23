import { Fragment, useEffect, useMemo, useRef, useState } from 'react'
import { Clock, FileText, Search, TextSearch, X } from 'lucide-react'
import { safeInvoke } from '../lib/tauri'
import { foldMatches } from '../lib/foldMatch'

interface LogEntry {
  name: string
  host: string
  /** Recorded before transcripts were keyed per host entry: viewable here,
   *  never replayed or given to the assistant. */
  legacy: boolean
  started: number | null
  bytes: number
}

/** One window of a transcript (utils::session_log::LogPage). */
interface LogPage {
  text: string
  start: number
  end: number
  total: number
  firstLine: number
}

/** Lines in a page's text (it always ends on a line boundary, or at EOF). */
const lineCount = (text: string) => {
  let n = 0
  for (let i = text.indexOf('\n'); i !== -1; i = text.indexOf('\n', i + 1)) n++
  return text.endsWith('\n') || text === '' ? n : n + 1
}

const fmtBytes = (n: number) => {
  if (n < 1024) return `${n} B`
  const units = ['KB', 'MB', 'GB']
  let v = n / 1024
  let u = 0
  while (v >= 1024 && u < units.length - 1) { v /= 1024; u++ }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${units[u]}`
}

interface SearchHit {
  name: string
  host: string
  started: number | null
  line: number
  text: string
}

interface SearchResult {
  hits: SearchHit[]
  scanned: number
  truncated: boolean
}

/* `text` with every case-insensitive occurrence of `q` wrapped in <mark>.
   Ranges come from foldMatches, which maps case-folded matches back to the
   original characters (see lib/foldMatch.ts). */
function Highlight({ text, q }: { text: string; q: string }) {
  const parts: React.ReactNode[] = []
  let shown = 0
  for (const [start, end] of foldMatches(text, q)) {
    parts.push(text.slice(shown, start))
    parts.push(
      <mark key={start} className="rounded-sm bg-accent-soft text-ink">
        {text.slice(start, end)}
      </mark>,
    )
    shown = end
  }
  parts.push(text.slice(shown))
  return <>{parts}</>
}

const fmtWhen = (epoch: number | null) => {
  if (!epoch) return '—'
  const d = new Date(epoch * 1000)
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}

/* ---------------------------------------------------------------------------
   Session history: browse, search, and read past transcripts.

   The transcripts already existed on disk — this just surfaces them, which is
   the whole value on appliances that keep no session of their own. "Search
   inside sessions" is the memory half: find the line where you last ran a
   command (or saw an error) on any host, and jump straight to it. Read-only:
   these are a record, and the viewer must never look like a live shell you can
   type into.
--------------------------------------------------------------------------- */
export function HistoryBrowser({ onClose }: { onClose: () => void }) {
  const [logs, setLogs] = useState<LogEntry[] | null>(null)
  const [query, setQuery] = useState('')
  const [selected, setSelected] = useState<string | null>(null)
  /* The loaded part of the open transcript. Transcripts can reach 50 MB, so
     the backend serves pages and the viewer grows them on request instead of
     taking the whole file as one string. */
  const [page, setPage] = useState<LogPage | null>(null)
  const [readError, setReadError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [loadingMore, setLoadingMore] = useState(false)
  const [listError, setListError] = useState<string | null>(null)
  const [mode, setMode] = useState<'hosts' | 'contents'>('hosts')
  const [result, setResult] = useState<SearchResult | null>(null)
  const [searching, setSearching] = useState(false)
  const [searchError, setSearchError] = useState<string | null>(null)
  /* Line to scroll to and highlight in the open transcript (from a search hit). */
  const [target, setTarget] = useState<{ line: number; q: string } | null>(null)
  const markRef = useRef<HTMLElement>(null)

  useEffect(() => {
    void safeInvoke<LogEntry[]>('logs_list')
      .then((l) => setLogs(l ?? []))
      .catch((e: unknown) => {
        setLogs([])
        setListError(e instanceof Error ? e.message : String(e))
      })
  }, [])

  /* A search still scanning when the window closes would otherwise run to
     completion on the backend for nothing. */
  useEffect(() => () => void safeInvoke('logs_search_cancel').catch(() => {}), [])

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKey, true)
    return () => window.removeEventListener('keydown', onKey, true)
  }, [onClose])

  /* Reads run concurrently on the backend, so a large transcript clicked first
     can resolve after a small one clicked second. Only the latest request may
     touch the viewer. */
  const latest = useRef<string | null>(null)

  const open = (name: string, at: { line: number; q: string } | null = null) => {
    setTarget(at)
    // Already showing that line (or, with no target, that transcript).
    if (name === selected && !loading && page) {
      const last = page.firstLine + lineCount(page.text) - 1
      if (!at || (at.line >= page.firstLine && at.line <= last)) return
    }
    const token = `${name}:${at?.line ?? 'tail'}`
    latest.current = token
    setSelected(name)
    setLoading(true)
    setPage(null)
    setReadError(null)
    void safeInvoke<LogPage>('log_read', at ? { name, line: at.line } : { name })
      .then((p) => {
        if (latest.current === token) setPage(p ?? null)
      })
      .catch((e) => {
        if (latest.current === token) {
          setReadError(`Could not read ${name}: ${e instanceof Error ? e.message : e}`)
        }
      })
      .finally(() => {
        if (latest.current === token) setLoading(false)
      })
  }

  /** Grow the loaded window by one page before or after it. */
  const loadMore = (dir: 'before' | 'after') => {
    if (!selected || !page || loadingMore) return
    const token = latest.current
    const name = selected
    setLoadingMore(true)
    void safeInvoke<LogPage>('log_read', dir === 'before' ? { name, before: page.start } : { name, after: page.end })
      .then((p) => {
        if (!p || latest.current !== token) return
        setPage((cur) => {
          if (!cur) return cur
          return dir === 'before'
            ? { ...cur, text: p.text + cur.text, start: p.start, firstLine: p.firstLine, total: p.total }
            : { ...cur, text: cur.text + p.text, end: p.end, total: p.total }
        })
      })
      .catch((e) => {
        if (latest.current === token) setReadError(`Could not read more: ${e instanceof Error ? e.message : e}`)
      })
      .finally(() => setLoadingMore(false))
  }

  /* Contents search: debounced, and only the newest query's answer is kept. */
  const searchSeq = useRef(0)
  const wasContents = useRef(false)
  useEffect(() => {
    if (mode !== 'contents') {
      // Leaving contents search: stop a scan already running on the backend
      // (clearing the debounce timer only stops one not yet started), and
      // drop its answer.
      if (wasContents.current) {
        wasContents.current = false
        ++searchSeq.current
        setSearching(false)
        void safeInvoke('logs_search_cancel').catch(() => {})
      }
      return
    }
    wasContents.current = true
    const q = query.trim()
    const seq = ++searchSeq.current
    if (q.length < 2) {
      setResult(null)
      setSearching(false)
      void safeInvoke('logs_search_cancel').catch(() => {})
      return
    }
    setSearching(true)
    setSearchError(null)
    // Each new search supersedes the previous one on the backend too, so a
    // burst of typing does not leave full scans running in parallel.
    const t = window.setTimeout(() => {
      void safeInvoke<SearchResult>('logs_search', { query: q, limit: 300 })
        .then((r) => {
          if (searchSeq.current === seq) setResult(r ?? null)
        })
        .catch((e: unknown) => {
          if (searchSeq.current === seq) {
            setResult(null)
            setSearchError(e instanceof Error ? e.message : String(e))
          }
        })
        .finally(() => {
          if (searchSeq.current === seq) setSearching(false)
        })
    }, 250)
    return () => window.clearTimeout(t)
  }, [mode, query])

  /* Closing the browser mid-search stops the scan too. */
  useEffect(
    () => () => {
      if (wasContents.current) void safeInvoke('logs_search_cancel').catch(() => {})
    },
    [],
  )

  /* Hits grouped by session, keeping the backend's newest-first order. */
  const groups = useMemo(() => {
    const out: { name: string; host: string; started: number | null; hits: SearchHit[] }[] = []
    for (const h of result?.hits ?? []) {
      const last = out[out.length - 1]
      if (last && last.name === h.name) last.hits.push(h)
      else out.push({ name: h.name, host: h.host, started: h.started, hits: [h] })
    }
    return out
  }, [result])

  /* The open transcript split around the target line, so only that one line
     needs a wrapper to scroll to and highlight. */
  const content = page?.text ?? ''
  const split = useMemo(() => {
    if (!target || !page) return null
    // Search hits carry absolute line numbers; the page starts at firstLine.
    const rel = target.line - page.firstLine + 1
    if (rel < 1) return null
    let start = 0
    for (let n = 1; n < rel; n++) {
      const nl = content.indexOf('\n', start)
      if (nl === -1) return null
      start = nl + 1
    }
    const end = content.indexOf('\n', start)
    const stop = end === -1 ? content.length : end
    return { before: content.slice(0, start), line: content.slice(start, stop), after: content.slice(stop) }
  }, [content, page, target])

  useEffect(() => {
    if (split) markRef.current?.scrollIntoView({ block: 'center' })
  }, [split])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    const all = logs ?? []
    return q && mode === 'hosts' ? all.filter((l) => l.host.toLowerCase().includes(q)) : all
  }, [logs, query, mode])

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
            <div className="flex flex-col gap-1.5 p-2">
              <div role="tablist" aria-label="Search mode" className="flex rounded border border-line bg-surface-1 p-0.5 text-[11.5px]">
                {([
                  ['hosts', 'Filter by host', Search],
                  ['contents', 'Search inside sessions', TextSearch],
                ] as const).map(([m, label, Icon]) => (
                  <button
                    key={m}
                    type="button"
                    role="tab"
                    aria-selected={mode === m}
                    onClick={() => setMode(m)}
                    className={`flex flex-1 items-center justify-center gap-1 rounded-sm py-0.5 ${
                      mode === m ? 'bg-surface-3 text-ink' : 'text-ink-faint hover:text-ink'
                    }`}
                  >
                    <Icon size={11} aria-hidden />
                    {label}
                  </button>
                ))}
              </div>
              <div className="relative">
                <Search size={12} className="pointer-events-none absolute top-1/2 left-2 -translate-y-1/2 text-ink-faint" aria-hidden />
                <input
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder={mode === 'hosts' ? 'Filter by host' : 'Command, output, error…'}
                  aria-label={mode === 'hosts' ? 'Filter by host' : 'Search inside sessions'}
                  className="h-7 w-full rounded border border-line bg-surface-1 pl-7 pr-2 text-[12px] text-ink placeholder:text-ink-faint focus:border-accent focus:outline-none"
                />
              </div>
            </div>
            <div className="min-h-0 flex-1 overflow-y-auto">
              {mode === 'contents' ? (
                query.trim().length < 2 ? (
                  <p className="px-3 py-6 text-center text-[12px] text-ink-faint">
                    Search every recorded session for a command, an output line, or an error message.
                  </p>
                ) : searchError ? (
                  <p className="px-3 py-6 text-center text-[12px] text-alert">Search failed: {searchError}</p>
                ) : searching && !result ? (
                  <p className="px-3 py-6 text-center text-[12px] text-ink-faint">Searching…</p>
                ) : !result || result.hits.length === 0 ? (
                  <p className="px-3 py-6 text-center text-[12px] text-ink-faint">
                    No matches in {result?.scanned ?? 0} session{result?.scanned === 1 ? '' : 's'}.
                  </p>
                ) : (
                  <>
                    <p className="px-3 pt-1 pb-1.5 text-[10.5px] text-ink-faint">
                      {result.hits.length} match{result.hits.length === 1 ? '' : 'es'} in {groups.length} session
                      {groups.length === 1 ? '' : 's'}
                      {result.truncated ? ' (showing the first; refine the search for more)' : ''}
                    </p>
                    {groups.map((g) => (
                      <Fragment key={g.name}>
                        <div className="flex items-center gap-1.5 border-y border-line/50 bg-surface-1 px-3 py-1 text-[10.5px]">
                          <FileText size={11} className="shrink-0 text-ink-faint" aria-hidden />
                          <span className="min-w-0 flex-1 truncate font-mono text-ink">{g.host}</span>
                          <span className="shrink-0 tabular-nums text-ink-faint">{fmtWhen(g.started)}</span>
                        </div>
                        {g.hits.map((h) => (
                          <button
                            key={`${h.name}:${h.line}`}
                            type="button"
                            onClick={() => open(h.name, { line: h.line, q: query })}
                            className={`flex w-full items-baseline gap-2 border-b border-line/30 px-3 py-1 text-left ${
                              selected === h.name && target?.line === h.line ? 'bg-accent-soft' : 'hover:bg-surface-1'
                            }`}
                          >
                            <span className="w-9 shrink-0 text-right font-mono text-[10px] tabular-nums text-ink-faint">
                              {h.line}
                            </span>
                            <span className="min-w-0 flex-1 truncate font-mono text-[11.5px] text-ink-dim">
                              <Highlight text={h.text} q={query} />
                            </span>
                          </button>
                        ))}
                      </Fragment>
                    ))}
                  </>
                )
              ) : logs === null ? (
                <p className="px-3 py-6 text-center text-[12px] text-ink-faint">Loading…</p>
              ) : listError ? (
                <p className="px-3 py-6 text-center text-[12px] text-alert">
                  Could not list sessions: {listError}
                </p>
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
                      {l.legacy && (
                        <span
                          title="Recorded before transcripts were kept per host entry, so it may come from any entry with this hostname. It is never replayed or sent to the assistant."
                          className="shrink-0 rounded-sm border border-line px-1 text-[9.5px] uppercase tracking-wider text-ink-faint"
                        >
                          legacy
                        </span>
                      )}
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
              ) : readError && !page ? (
                <p className="selectable p-4 text-[12px] text-alert">{readError}</p>
              ) : (
                <div className="flex min-h-0 flex-1 flex-col">
                  {page && page.start > 0 && (
                    <button
                      type="button"
                      disabled={loadingMore}
                      onClick={() => loadMore('before')}
                      className="shrink-0 border-b border-line py-1 text-[11px] text-accent hover:bg-surface-1 disabled:opacity-50"
                    >
                      Load earlier ({fmtBytes(page.start)} not shown)
                    </button>
                  )}
                  <pre className="selectable min-h-0 flex-1 overflow-auto whitespace-pre-wrap break-words p-3 font-mono text-[12px] leading-relaxed text-ink-dim">
                    {split && target ? (
                      <>
                        {split.before}
                        <mark ref={markRef} className="-mx-1 rounded-sm bg-surface-3 px-1 text-ink">
                          <Highlight text={split.line} q={target.q} />
                        </mark>
                        {split.after}
                      </>
                    ) : (
                      content
                    )}
                  </pre>
                  {page && page.end < page.total && (
                    <button
                      type="button"
                      disabled={loadingMore}
                      onClick={() => loadMore('after')}
                      className="shrink-0 border-t border-line py-1 text-[11px] text-accent hover:bg-surface-1 disabled:opacity-50"
                    >
                      Load later ({fmtBytes(page.total - page.end)} not shown)
                    </button>
                  )}
                  {readError && page && (
                    <p className="shrink-0 border-t border-line px-3 py-1 text-[11px] text-alert">{readError}</p>
                  )}
                </div>
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
