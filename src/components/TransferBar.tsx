import { useState } from 'react'
import {
  ArrowDownToLine,
  ArrowUpFromLine,
  Check,
  ChevronDown,
  ChevronRight,
  FilePen,
  FolderOpen,
  Info,
  RotateCw,
  Square,
  TriangleAlert,
  Upload,
  X,
} from 'lucide-react'
import type { EditInfo, EditLeftover, EditStopOutcome, Transfer } from '../types'
import { canRetry, isLive, retryableFailures } from '../lib/transfers'
import { conflictCopyName, conflictPromptDue, discardPrompt, editStatusLabel } from '../lib/remoteEdit'
import { useRemoteEdits } from '../lib/useRemoteEdits'
import { useDialogs } from '../lib/dialogs'
import { safeInvoke } from '../lib/tauri'

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
 *  truncated "first: …" string.
 *
 *  Remote files open in a local editor ("Edit in local editor" in the SFTP
 *  pane) are listed above the transfers, in an Editing section, for the same
 *  reason: they keep syncing while you work in the terminal. */
export function TransferBar({
  transfers,
  onClear,
  onRetry,
  onCancel,
}: {
  transfers: Transfer[]
  onClear: () => void
  onRetry: (t: Transfer) => void
  onCancel: (t: Transfer) => void
}) {
  const remote = useRemoteEdits()
  const editing = remote.edits.length > 0 || remote.leftovers.length > 0
  if (transfers.length === 0 && !editing) return null
  const active = transfers.filter(isLive).length
  const failed = transfers.filter((t) => t.status === 'error' || (t.failures?.length ?? 0) > 0).length

  return (
    <div className="shrink-0 border-t border-line bg-surface-1">
      {editing && <EditingSection {...remote} />}
      {transfers.length > 0 && (
      <>
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
          <TransferRow key={t.id} transfer={t} onRetry={onRetry} onCancel={onCancel} />
        ))}
      </ul>
      </>
      )}
    </div>
  )
}

const errorText = (e: unknown) => (e instanceof Error ? e.message : String(e))

/** Remote files open in a local editor, and local copies kept because they
 *  held changes that were never uploaded. */
function EditingSection({
  edits,
  leftovers,
  update,
  closed,
  dropLeftover,
}: ReturnType<typeof useRemoteEdits>) {
  const { confirm, alert } = useDialogs()
  /** editId -> the conflict "Keep editing" dismissed (see conflictPromptDue). */
  const [dismissed, setDismissed] = useState<Record<string, number>>({})
  const report = (e: unknown) => void alert(errorText(e), { title: 'Remote editing' })

  const upload = (edit: EditInfo, mode: 'now' | 'overwrite' | 'copy') =>
    void safeInvoke<EditInfo>('edit_upload', { editId: edit.editId, mode }).then(update).catch(report)

  const stop = async (edit: EditInfo) => {
    try {
      // "ask": the backend stops only if nothing would be lost.
      const first = await safeInvoke<EditStopOutcome>('edit_stop', { editId: edit.editId, mode: 'ask' })
      if (!first) return
      if (!first.stopped) {
        const discard = await confirm(discardPrompt(edit), {
          title: 'Unsynced changes',
          confirmLabel: 'Discard changes',
          cancelLabel: 'Keep editing',
          danger: true,
        })
        if (!discard) return
        await safeInvoke<EditStopOutcome>('edit_stop', { editId: edit.editId, mode: 'discard' })
      }
      closed(edit.editId)
    } catch (e) {
      report(e)
    }
  }

  const discardLeftover = async (l: EditLeftover) => {
    const ok = await confirm(
      `Delete the local copy of ${l.name}? Its changes were never uploaded to ${l.remotePath}.`,
      { title: 'Discard changes', confirmLabel: 'Discard changes', danger: true },
    )
    if (!ok) return
    try {
      await safeInvoke('edit_leftover_discard', { id: l.id })
      dropLeftover(l.id)
    } catch (e) {
      report(e)
    }
  }

  const btn =
    'grid h-5 w-5 shrink-0 place-items-center rounded text-ink-faint hover:bg-surface-3 hover:text-ink'
  const statusTone: Record<EditInfo['status'], string> = {
    synced: 'text-ok',
    uploading: 'text-accent',
    conflict: 'text-warn',
    error: 'text-alert',
  }

  return (
    <div className="border-b border-line">
      <div className="px-3 py-1 text-[11px] text-ink-faint">
        Editing
        {edits.length > 0 && <span className="ml-1">· {edits.length} open</span>}
      </div>
      <ul className="max-h-40 overflow-y-auto">
        {edits.map((e) => (
          <li key={e.editId} className="text-[11.5px] text-ink-dim">
            <div className="flex items-center gap-2 px-3 py-1">
              <FilePen size={11} className="shrink-0 text-accent" aria-hidden />
              <span className="min-w-0 flex-1 truncate font-mono" title={`${e.remotePath}\n${e.localPath}`}>
                {e.name}
                <span className="ml-1.5 text-ink-faint">{e.remotePath}</span>
              </span>
              <span className={`shrink-0 font-mono text-[10.5px] ${e.dirty && e.status === 'synced' ? 'text-warn' : statusTone[e.status]}`}>
                {editStatusLabel(e)}
              </span>
              <button
                type="button"
                onClick={() => upload(e, 'now')}
                disabled={e.status === 'uploading'}
                title="Upload now"
                aria-label={`Upload ${e.name} now`}
                className={`${btn} disabled:opacity-40`}
              >
                <Upload size={11} aria-hidden />
              </button>
              <button
                type="button"
                onClick={() => void safeInvoke('edit_reveal', { editId: e.editId }).catch(report)}
                title="Show the local copy"
                aria-label={`Show the local copy of ${e.name}`}
                className={btn}
              >
                <FolderOpen size={11} aria-hidden />
              </button>
              <button
                type="button"
                onClick={() => void stop(e)}
                title="Stop editing"
                aria-label={`Stop editing ${e.name}`}
                className={`${btn} hover:text-alert`}
              >
                <X size={11} aria-hidden />
              </button>
            </div>
            {e.message && !conflictPromptDue(e, dismissed) && (
              <p className={`break-words border-t border-line/40 bg-surface-2/40 px-3 py-1 font-mono text-[10.5px] ${e.status === 'error' ? 'text-alert' : 'text-warn'}`}>
                {e.message}
              </p>
            )}
            {conflictPromptDue(e, dismissed) && (
              <div role="alert" className="border-t border-warn/40 bg-warn/10 px-3 py-1.5">
                <p className="text-[11px] text-warn">
                  {e.message ?? `${e.name} changed on the server.`} Your save was not uploaded.
                </p>
                <div className="mt-1 flex flex-wrap gap-1.5">
                  <button
                    type="button"
                    onClick={() => upload(e, 'overwrite')}
                    className="rounded border border-alert/60 px-1.5 py-0.5 text-[10.5px] text-alert hover:bg-alert/15"
                  >
                    Overwrite remote
                  </button>
                  <button
                    type="button"
                    onClick={() => upload(e, 'copy')}
                    className="rounded border border-line-strong px-1.5 py-0.5 text-[10.5px] text-ink hover:bg-surface-3"
                  >
                    Save a copy as {conflictCopyName(e.name)}
                  </button>
                  <button
                    type="button"
                    onClick={() => setDismissed((d) => ({ ...d, [e.editId]: e.conflictSeq }))}
                    className="rounded border border-line-strong px-1.5 py-0.5 text-[10.5px] text-ink-dim hover:bg-surface-3 hover:text-ink"
                  >
                    Keep editing
                  </button>
                </div>
              </div>
            )}
          </li>
        ))}
        {leftovers.map((l) => (
          <li key={l.id} className="text-[11.5px] text-ink-dim">
            <div className="flex items-center gap-2 px-3 py-1">
              <TriangleAlert size={11} className="shrink-0 text-warn" aria-hidden />
              <span className="min-w-0 flex-1 truncate" title={`${l.remotePath}\n${l.localPath}`}>
                <span className="font-mono">{l.name}</span>
                <span className="ml-1.5 text-warn">not uploaded — kept at</span>
                <span className="selectable ml-1 font-mono text-ink-faint">{l.localPath}</span>
              </span>
              <button
                type="button"
                onClick={() => void safeInvoke('edit_leftover_reveal', { id: l.id }).catch(report)}
                title="Show the kept copy"
                aria-label={`Show the kept copy of ${l.name}`}
                className={btn}
              >
                <FolderOpen size={11} aria-hidden />
              </button>
              <button
                type="button"
                onClick={() => void discardLeftover(l)}
                title="Discard the kept copy"
                aria-label={`Discard the kept copy of ${l.name}`}
                className={`${btn} hover:text-alert`}
              >
                <X size={11} aria-hidden />
              </button>
            </div>
          </li>
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

function TransferRow({
  transfer: t,
  onRetry,
  onCancel,
}: {
  transfer: Transfer
  onRetry: (t: Transfer) => void
  onCancel: (t: Transfer) => void
}) {
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
  const retryable = retryableFailures(t).length
  const notes = t.notes ?? []

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

        {t.status === 'queued' && (
          <span className="font-mono text-[10.5px] text-ink-faint">queued</span>
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

        {isLive(t) && (
          <button
            type="button"
            onClick={() => onCancel(t)}
            title="Cancel this transfer"
            aria-label={`Cancel ${t.name}`}
            className="grid h-5 w-5 shrink-0 place-items-center rounded text-ink-faint hover:bg-surface-3 hover:text-alert"
          >
            <Square size={9} aria-hidden />
          </button>
        )}

        {t.status === 'done' && !hasFailures && (
          <>
            <span className="font-mono text-[10.5px] tabular-nums text-ink-faint">
              {fmtBytes(t.bytesDone)}
            </span>
            {notes.length > 0 && (
              <Info size={12} className="shrink-0 text-warn" aria-label="notes" />
            )}
            <Check size={12} className="shrink-0 text-ok" aria-label="complete" />
          </>
        )}

        {t.status === 'cancelled' && (
          <span className="font-mono text-[10.5px] text-ink-faint">cancelled</span>
        )}

        {(t.status === 'error' || hasFailures) && (
          <span className="flex shrink-0 items-center gap-1 text-alert" title={t.error}>
            <TriangleAlert size={12} className="shrink-0" aria-label="failed" />
            <span className="tabular-nums">{hasFailures ? `${failures.length} failed` : 'failed'}</span>
          </span>
        )}
      </div>

      {t.status === 'active' && t.note && (
        <p className="break-words border-t border-line/40 bg-surface-2/40 px-3 py-1 font-mono text-[10.5px] text-warn">
          {t.note}
        </p>
      )}

      {notes.length > 0 && (
        <ul className="border-t border-line/40 bg-surface-2/40 px-3 py-1 font-mono text-[10.5px] text-warn">
          {notes.map((n, i) => (
            <li key={i} className="break-words">
              {n}
            </li>
          ))}
        </ul>
      )}

      {open && hasFailures && (
        <div className="border-t border-line/40 bg-surface-2/40 px-3 py-1.5">
          <div className="mb-1 flex items-center justify-between">
            <span className="text-[10.5px] text-ink-faint">
              {failures.length} item{failures.length === 1 ? '' : 's'} not transferred
            </span>
            {canRetry(t) && (
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
