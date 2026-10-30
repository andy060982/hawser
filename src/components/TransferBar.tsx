import { useState } from 'react'
import {
  ArrowDownToLine,
  ArrowUpFromLine,
  Check,
  ChevronDown,
  ChevronRight,
  RotateCw,
  TriangleAlert,
  X,
} from 'lucide-react'
import type { Transfer } from '../types'

/** Global transfer status panel.
 *
 *  Lives in AppLayout, not in SftpView, and that placement is the whole point:
 *  SftpView unmounts when you switch to the terminal, and a queue rendered
 *  inside it took the progress of every in-flight transfer down with it — the
 *  bytes kept moving in Rust, invisibly. Mounted at the shell root, the panel
 *  persists across view and tab switches, so a big download started in Files
 *  keeps showing progress while you work in the terminal.
 *
 *  A recursive (folder) transfer is one row; the per-file failures it collects
 *  expand under it, with the full list and a retry — instead of the old single
 *  truncated "first: …" string. */
export function TransferBar({
  transfers,
  onClear,
  onRetry,
}: {
  transfers: Transfer[]
  onClear: () => void
  onRetry: (t: Transfer) => void
}) {
  if (transfers.length === 0) return null
  const active = transfers.filter((t) => t.status === 'active').length
  const failed = transfers.filter((t) => t.status === 'error' || (t.failures?.length ?? 0) > 0).length

  return (
    <div className="shrink-0 border-t border-line bg-surface-1">
      <div className="flex items-center justify-between px-3 py-1 text-[11px] text-ink-faint">
        <span>
          Transfers
          {active > 0 && <span className="ml-1 text-accent">· {active} active</span>}
          {failed > 0 && <span className="ml-1 text-alert">· {failed} with errors</span>}
        </span>
        <button
          type="button"
          onClick={onClear}
          className="flex items-center gap-1 rounded px-1 hover:bg-surface-3 hover:text-ink"
        >
          <X size={11} aria-hidden />
          Clear finished
        </button>
      </div>

      <ul className="max-h-52 overflow-y-auto">
        {transfers.map((t) => (
          <TransferRow key={t.id} transfer={t} onRetry={onRetry} />
        ))}
      </ul>
    </div>
  )
}

const fmtBytes = (n: number) => {
  if (n < 1024) return `${n} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let v = n / 1024
  let u = 0
  while (v >= 1024 && u < units.length - 1) { v /= 1024; u++ }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${units[u]}`
}

function TransferRow({ transfer: t, onRetry }: { transfer: Transfer; onRetry: (t: Transfer) => void }) {
  const failures = t.failures ?? []
  const hasFailures = failures.length > 0
  // A row with failures opens by default so the problem is visible without a
  // click; the user can collapse it. Derived rather than seeded into state:
  // rows mount with no failures (they arrive later over sftp://failure), so a
  // useState(hasFailures) initial value was always false. Once the user
  // toggles, their choice wins.
  const [userOpen, setOpen] = useState<boolean | null>(null)
  const open = userOpen ?? hasFailures

  // A zero total means the server declined to report a size. Show an
  // indeterminate bar rather than inventing a denominator.
  const determinate = t.bytesTotal > 0
  const pct = determinate ? Math.min(100, (t.bytesDone / t.bytesTotal) * 100) : 0
  const retryable = failures.filter((f) => f.local && f.remote).length

  return (
    <li className="text-[11.5px] text-ink-dim">
      <div className="flex items-center gap-2 px-3 py-1">
        {t.direction === 'upload' ? (
          <ArrowUpFromLine size={11} className="shrink-0 text-accent" aria-label="upload" />
        ) : (
          <ArrowDownToLine size={11} className="shrink-0 text-accent" aria-label="download" />
        )}

        {hasFailures ? (
          <button
            type="button"
            onClick={() => setOpen(!open)}
            className="flex min-w-0 flex-1 items-center gap-1 text-left"
            aria-expanded={open}
          >
            {open ? (
              <ChevronDown size={11} className="shrink-0 text-ink-faint" aria-hidden />
            ) : (
              <ChevronRight size={11} className="shrink-0 text-ink-faint" aria-hidden />
            )}
            <span className="min-w-0 flex-1 truncate font-mono" title={t.path}>
              {t.name}
            </span>
          </button>
        ) : (
          <span className="min-w-0 flex-1 truncate font-mono" title={t.path}>
            {t.name}
          </span>
        )}

        {t.status === 'active' && (
          <>
            <span
              role="progressbar"
              aria-valuenow={determinate ? Math.round(pct) : undefined}
              aria-valuemin={0}
              aria-valuemax={100}
              className="h-1.5 w-24 shrink-0 overflow-hidden rounded-full bg-surface-3"
            >
              <span
                className={`block h-full rounded-full bg-accent ${
                  determinate ? 'transition-[width] duration-150' : 'w-1/3 animate-pulse'
                }`}
                style={determinate ? { width: `${pct}%` } : undefined}
              />
            </span>
            <span className="w-32 shrink-0 text-right font-mono text-[10.5px] tabular-nums text-ink-faint">
              {determinate ? `${fmtBytes(t.bytesDone)} / ${fmtBytes(t.bytesTotal)}` : fmtBytes(t.bytesDone)}
            </span>
          </>
        )}

        {t.status === 'done' && !hasFailures && (
          <>
            <span className="font-mono text-[10.5px] tabular-nums text-ink-faint">
              {fmtBytes(t.bytesDone)}
            </span>
            <Check size={12} className="shrink-0 text-ok" aria-label="complete" />
          </>
        )}

        {(t.status === 'error' || hasFailures) && (
          <span className="flex shrink-0 items-center gap-1 text-alert" title={t.error}>
            <TriangleAlert size={12} className="shrink-0" aria-label="failed" />
            <span className="tabular-nums">{hasFailures ? `${failures.length} failed` : 'failed'}</span>
          </span>
        )}
      </div>

      {open && hasFailures && (
        <div className="border-t border-line/40 bg-surface-2/40 px-3 py-1.5">
          <div className="mb-1 flex items-center justify-between">
            <span className="text-[10.5px] text-ink-faint">
              {failures.length} item{failures.length === 1 ? '' : 's'} not transferred
            </span>
            {retryable > 0 && (
              <button
                type="button"
                onClick={() => onRetry(t)}
                className="flex items-center gap-1 rounded px-1.5 py-0.5 text-[10.5px] text-accent hover:bg-surface-3 hover:text-ink"
              >
                <RotateCw size={11} aria-hidden />
                Retry {retryable} failed
              </button>
            )}
          </div>
          <ul className="max-h-32 space-y-0.5 overflow-y-auto font-mono text-[10.5px] text-ink-faint">
            {failures.map((f, i) => (
              <li key={i} className="truncate" title={`${f.remote || f.local}\n${f.reason}`}>
                <span className="text-ink-dim">{f.name}</span>
                <span className="text-alert"> — {f.reason}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </li>
  )
}
