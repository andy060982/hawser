import { useCallback, useEffect, useMemo, useState } from 'react'
import { Camera, FileDiff, GitCompareArrows, X } from 'lucide-react'
import type { Host } from '../types'
import { safeInvoke } from '../lib/tauri'

interface SnapshotInfo {
  name: string
  bytes: number
  modified: number | null
}

interface SnapshotResult {
  name: string
  lines: number
  added: number | null
  removed: number | null
}

const fmtWhen = (epoch: number | null) => {
  if (!epoch) return '—'
  const d = new Date(epoch * 1000)
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}

/* ---------------------------------------------------------------------------
   Config snapshots: capture, browse, diff.

   Answers the question that starts most network incident calls — "what
   changed on this box". Snapshot runs the host's configured capture command
   over a fresh exec channel (invisible to the interactive terminal), stores
   plain text under %APPDATA%\hawser\configs\<host>\, and any two snapshots
   diff as unified text with added/removed colouring.

   Select one snapshot to view it; select two to diff them.
--------------------------------------------------------------------------- */
export function ConfigHistoryDialog({
  host,
  liveSessionId,
  onClose,
}: {
  host: Host
  /** A connected session to this host, if any — required for Snapshot now. */
  liveSessionId: string | null
  onClose: () => void
}) {
  const [snaps, setSnaps] = useState<SnapshotInfo[] | null>(null)
  const [selected, setSelected] = useState<string[]>([])
  const [content, setContent] = useState('')
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState<string | null>(null)

  const captureCommand = host.configCommand?.trim() ?? ''

  const refresh = useCallback(() => {
    void safeInvoke<SnapshotInfo[]>('config_list', { host: host.hostname }).then((l) =>
      setSnaps(l ?? []),
    )
  }, [host.hostname])

  useEffect(refresh, [refresh])

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKey, true)
    return () => window.removeEventListener('keydown', onKey, true)
  }, [onClose])

  /* Selection drives the viewer: one snapshot shows its content, two show
     their diff (chronologically ordered regardless of click order). A
     superseded request's late reply is dropped so it can't overwrite the
     current view (e.g. a slow diff landing after dropping back to one). */
  useEffect(() => {
    let stale = false
    const show = (c: string) => {
      if (!stale) setContent(c)
    }
    setContent('')
    if (selected.length === 1) {
      void safeInvoke<string>('config_read', { host: host.hostname, name: selected[0] })
        .then((c) => show(c ?? ''))
        .catch((e) => show(String(e)))
    } else if (selected.length === 2) {
      const [a, b] = [...selected].sort() // timestamp names sort chronologically
      void safeInvoke<string>('config_diff', { host: host.hostname, older: a, newer: b })
        .then((c) => show(c || '(no differences)'))
        .catch((e) => show(String(e)))
    }
    return () => {
      stale = true
    }
  }, [selected, host.hostname])

  const toggle = (name: string) =>
    setSelected((cur) =>
      cur.includes(name)
        ? cur.filter((n) => n !== name)
        : [...cur.slice(-1), name], // keep at most the previous one + this
    )

  const snapshotNow = async () => {
    if (!liveSessionId || !captureCommand) return
    setBusy(true)
    setNotice(null)
    try {
      const r = await safeInvoke<SnapshotResult>('config_snapshot', {
        sessionId: liveSessionId,
        host: host.hostname,
        command: captureCommand,
      })
      if (r) {
        setNotice(
          r.added === null
            ? `First snapshot saved: ${r.lines} lines.`
            : `Saved. ${r.added} line(s) added, ${r.removed} removed since the last snapshot.`,
        )
      }
      refresh()
    } catch (e) {
      setNotice(`Snapshot failed: ${e instanceof Error ? e.message : e}`)
    } finally {
      setBusy(false)
    }
  }

  const diffMode = selected.length === 2

  const rendered = useMemo(() => {
    if (!diffMode) return null
    return content.split('\n').map((line, i) => {
      const cls = line.startsWith('+') && !line.startsWith('+++')
        ? 'text-ok'
        : line.startsWith('-') && !line.startsWith('---')
          ? 'text-alert'
          : line.startsWith('@@')
            ? 'text-accent'
            : 'text-ink-faint'
      return (
        <span key={i} className={cls}>
          {line}
          {'\n'}
        </span>
      )
    })
  }, [content, diffMode])

  return (
    <div className="absolute inset-0 z-50 flex justify-center">
      <div className="animate-scrim-in absolute inset-0 bg-surface-0/75 backdrop-blur-[2px]" aria-hidden />

      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="cfg-title"
        className="animate-drop-in relative mt-8 flex h-[84vh] w-[60rem] max-w-[96vw] flex-col overflow-hidden rounded-panel border border-line-strong bg-surface-2 shadow-[0_24px_60px_-12px_rgba(0,0,0,0.75)]"
      >
        <header className="flex items-center gap-2 border-b border-line px-4 py-2.5">
          <FileDiff size={15} className="shrink-0 text-accent" aria-hidden />
          <h2 id="cfg-title" className="flex-1 truncate text-[13.5px] font-medium text-ink">
            Config snapshots — {host.name}
          </h2>
          <button
            type="button"
            disabled={busy || !liveSessionId || !captureCommand}
            onClick={() => void snapshotNow()}
            title={
              !captureCommand
                ? 'Set a capture command in the host editor first'
                : !liveSessionId
                  ? 'Connect to this host first'
                  : `Runs: ${captureCommand}`
            }
            className="flex h-7 items-center gap-1.5 rounded border border-accent/60 bg-accent/15 px-2.5 text-[12px] font-medium text-accent hover:bg-accent/25 disabled:opacity-40"
          >
            <Camera size={12} aria-hidden />
            {busy ? 'Capturing…' : 'Snapshot now'}
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

        {notice && (
          <p className="selectable border-b border-line bg-surface-1 px-4 py-1.5 text-[12px] text-ink-dim">
            {notice}
          </p>
        )}

        <div className="flex min-h-0 flex-1">
          <div className="flex w-[19rem] shrink-0 flex-col border-r border-line">
            <p className="flex items-center gap-1.5 border-b border-line px-3 py-1.5 text-[10.5px] uppercase tracking-wider text-ink-faint">
              <GitCompareArrows size={11} aria-hidden />
              Pick one to view, two to diff
            </p>
            <div className="min-h-0 flex-1 overflow-y-auto">
              {snaps === null ? (
                <p className="px-3 py-6 text-center text-[12px] text-ink-faint">Loading…</p>
              ) : snaps.length === 0 ? (
                <p className="px-3 py-6 text-center text-[12px] leading-relaxed text-ink-faint">
                  No snapshots yet.
                  {captureCommand
                    ? ' Connect and press Snapshot now.'
                    : ' Set a capture command in the host editor first.'}
                </p>
              ) : (
                snaps.map((sn) => (
                  <label
                    key={sn.name}
                    className={`flex cursor-pointer items-center gap-2 border-b border-line/50 px-3 py-1.5 transition-colors ${
                      selected.includes(sn.name) ? 'bg-accent-soft' : 'hover:bg-surface-1'
                    }`}
                  >
                    <input
                      type="checkbox"
                      checked={selected.includes(sn.name)}
                      onChange={() => toggle(sn.name)}
                      className="h-3 w-3 shrink-0 accent-[var(--color-accent)]"
                    />
                    <span className="min-w-0 flex-1">
                      <span className="block font-mono text-[11.5px] text-ink">
                        {fmtWhen(sn.modified)}
                      </span>
                      <span className="block text-[10.5px] text-ink-faint">
                        {(sn.bytes / 1024).toFixed(1)} KB
                      </span>
                    </span>
                  </label>
                ))
              )}
            </div>
          </div>

          <pre className="selectable min-h-0 min-w-0 flex-1 overflow-auto whitespace-pre-wrap break-words bg-surface-0 p-3 font-mono text-[12px] leading-relaxed text-ink-dim">
            {selected.length === 0
              ? 'Select a snapshot on the left.'
              : diffMode
                ? rendered
                : content || 'Loading…'}
          </pre>
        </div>
      </div>
    </div>
  )
}
