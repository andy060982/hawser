import { useCallback, useEffect, useMemo, useState } from 'react'
import { AlertTriangle, ChevronDown, ChevronRight, Download, RefreshCw, X } from 'lucide-react'
import type { HostNode } from '../types'
import { safeInvoke } from '../lib/tauri'
import { useModalLayer } from '../lib/useModalLayer'
import { useDialogs } from '../lib/dialogs'
import {
  buildImport, folderLabels, importFolderName, importSelection, planImport, routeConfirmText, routeRowsToConfirm,
  type ImportRow, type ImportSource, type ImportTarget, type ScanReport,
} from '../lib/tree'

interface Sources {
  sshConfig: string | null
  putty: boolean
}

/* ---------------------------------------------------------------------------
   Import from SSH config / PuTTY.

   The backend scans (utils/ssh_import.rs) and reports candidate hosts; this
   dialog previews them, lets the user pick, and hands the resulting catalogue
   to the parent, which saves it through the normal catalogue path. Only
   addresses are imported: host, port, user, key file path, jump host. No
   password or key material is read or stored, and nothing that acts on its
   own (on-connect commands, config checks, AI access) is ever set.
--------------------------------------------------------------------------- */
export function ImportHostsDialog({
  catalogue,
  onImport,
  onClose,
}: {
  catalogue: HostNode[]
  /** Called with a builder rather than a finished tree, so the parent
   *  applies it to its catalogue as it stands at that moment. */
  onImport: (
    build: (existing: HostNode[]) => { catalogue: HostNode[]; added: number; notes: string[] },
    source: ImportSource,
  ) => void
  onClose: () => void
}) {
  const [sources, setSources] = useState<Sources | null>(null)
  const [source, setSource] = useState<ImportSource>('ssh-config')
  const [path, setPath] = useState('')
  const [report, setReport] = useState<ScanReport | null>(null)
  const [scanning, setScanning] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [checked, setChecked] = useState<Set<number>>(new Set())
  const [targetSel, setTargetSel] = useState<string>('new')
  const [folderName, setFolderName] = useState(importFolderName('ssh-config'))
  const [showSummary, setShowSummary] = useState(false)

  useModalLayer(true, onClose)
  const { confirm } = useDialogs()

  const rows = useMemo(() => (report ? planImport(report, catalogue) : []), [report, catalogue])
  const folders = useMemo(() => [...folderLabels(catalogue)], [catalogue])

  const scan = useCallback((src: ImportSource, p: string) => {
    setScanning(true)
    setError(null)
    setReport(null)
    void safeInvoke<ScanReport>('hosts_import_scan', { source: src, path: src === 'ssh-config' ? p : null })
      .then((r) => {
        if (!r) {
          setError('Importing needs the desktop app.')
          return
        }
        setReport(r)
      })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)))
      .finally(() => setScanning(false))
  }, [])

  useEffect(() => {
    void safeInvoke<Sources>('hosts_import_sources')
      .then((s) => {
        const got = s ?? { sshConfig: null, putty: false }
        setSources(got)
        const p = got.sshConfig ?? ''
        setPath(p)
        if (s) scan('ssh-config', p)
      })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)))
  }, [scan])

  // Fresh scan: duplicates start unchecked, everything else checked.
  // Keyed on the report only, so a catalogue change while the dialog is
  // open does not reset the user's picks.
  useEffect(() => {
    setChecked(new Set(rows.filter((r) => r.checked).map((r) => r.index)))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [report])

  const pickSource = (s: ImportSource) => {
    if (s === source) return
    setSource(s)
    setFolderName(importFolderName(s))
    scan(s, path)
  }

  // Checking a host whose ProxyJump chain Hawser cannot follow asks first:
  // it would connect via the first hop only.
  const confirmRoutes = async (adding: Set<number>): Promise<boolean> => {
    const risky = routeRowsToConfirm(rows, adding)
    if (risky.length === 0) return true
    return confirm(routeConfirmText(risky), { title: 'Route not supported', confirmLabel: 'Import with first hop only', danger: true })
  }
  const toggle = async (i: number) => {
    const row = rows.find((r) => r.index === i)
    if (!row || row.status === 'blocked') return
    if (!checked.has(i) && !(await confirmRoutes(new Set([i])))) return
    setChecked((prev) => {
      const next = new Set(prev)
      if (next.has(i)) next.delete(i)
      else next.add(i)
      return next
    })
  }
  const selectable = rows.filter((r) => r.status !== 'blocked')
  const allChecked = selectable.length > 0 && selectable.every((r) => checked.has(r.index))
  const toggleAll = async () => {
    if (allChecked) return setChecked(new Set())
    const adding = new Set(selectable.filter((r) => !checked.has(r.index)).map((r) => r.index))
    // Declining the route warning still selects everything else.
    const withRoutes = await confirmRoutes(adding)
    setChecked(new Set(selectable.filter((r) => withRoutes || r.status !== 'route' || checked.has(r.index)).map((r) => r.index)))
  }
  // What an import takes right now: blocked rows never, jump hosts the
  // checked rows need always (shown as "added as jump host").
  const selection = useMemo(() => importSelection(rows, checked), [rows, checked])

  const target: ImportTarget =
    targetSel === 'new'
      ? { kind: 'new-folder', name: folderName }
      : targetSel === 'top'
        ? { kind: 'top' }
        : { kind: 'folder', id: targetSel }

  const doImport = () => {
    if (!report || selection.picked.size === 0) return
    const picked = new Set(checked)
    const { localUser } = report
    // Rows are re-planned against the catalogue the parent passes, so a
    // duplicate check or jump link never uses a stale tree.
    onImport((existing) => buildImport(planImport(report, existing).map((r, i) => ({ ...r, checked: picked.has(i) })), picked, existing, target, localUser), report.source)
  }

  const summaryCount =
    (report?.warnings.length ?? 0) + (report?.skipped.length ?? 0) + (report?.unsupportedKeys.length ? 1 : 0)

  return (
    <div className="absolute inset-0 z-50 flex justify-center">
      <div className="animate-scrim-in absolute inset-0 bg-surface-0/75 backdrop-blur-[2px]" aria-hidden />

      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="imp-title"
        className="animate-drop-in relative mt-10 flex h-[80vh] w-[60rem] max-w-[94vw] flex-col overflow-hidden rounded-panel border border-line-strong bg-surface-2 shadow-[0_24px_60px_-12px_rgba(0,0,0,0.75)]"
      >
        <header className="flex items-center gap-2 border-b border-line px-4 py-2.5">
          <Download size={15} className="shrink-0 text-accent" aria-hidden />
          <h2 id="imp-title" className="flex-1 text-[13.5px] font-medium text-ink">
            Import from SSH config / PuTTY
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

        {/* Source picker */}
        <div className="flex flex-wrap items-center gap-2 border-b border-line px-4 py-2 text-[12px] text-ink-dim">
          <div role="radiogroup" aria-label="Import source" className="flex overflow-hidden rounded border border-line">
            <SourceButton active={source === 'ssh-config'} onClick={() => pickSource('ssh-config')}>
              SSH config
            </SourceButton>
            {sources?.putty && (
              <SourceButton active={source === 'putty'} onClick={() => pickSource('putty')}>
                PuTTY sessions
              </SourceButton>
            )}
          </div>
          {source === 'ssh-config' && (
              <input
                value={path}
                onChange={(e) => setPath(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && scan('ssh-config', path)}
                aria-label="SSH config file"
                placeholder="~/.ssh/config"
                spellCheck={false}
                className="h-7 min-w-[16rem] flex-1 rounded border border-line bg-surface-0 px-2 font-mono text-[11.5px] text-ink focus:border-accent focus:outline-none"
              />
          )}
          {source === 'putty' && <span className="flex-1">Saved sessions of the current Windows user</span>}
          <button
            type="button"
            onClick={() => scan(source, path)}
            disabled={scanning}
            className="flex h-7 items-center gap-1.5 rounded border border-line bg-surface-1 px-2.5 text-ink hover:border-accent hover:text-accent disabled:opacity-50"
          >
            <RefreshCw size={12} className={scanning ? 'animate-spin' : undefined} aria-hidden />
            {scanning ? 'Reading…' : 'Read again'}
          </button>
        </div>

        {error && (
          <div role="alert" className="flex items-start gap-2 border-b border-warn bg-warn/20 px-4 py-2 text-[12px] text-ink">
            <AlertTriangle size={14} className="mt-0.5 shrink-0 text-warn" aria-hidden />
            <span className="min-w-0 flex-1 break-words">{error}</span>
          </div>
        )}

        {/* Summary of warnings and skipped items */}
        {report && summaryCount > 0 && (
          <div className="border-b border-line bg-surface-1 px-4 py-1.5 text-[11.5px] text-ink-dim">
            <button
              type="button"
              onClick={() => setShowSummary((v) => !v)}
              aria-expanded={showSummary}
              className="flex items-center gap-1 hover:text-ink"
            >
              {showSummary ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
              {report.warnings.length > 0 && `${report.warnings.length} warning${report.warnings.length === 1 ? '' : 's'}, `}
              {report.skipped.length} skipped
              {report.unsupportedKeys.length > 0 && `, ${report.unsupportedKeys.length} setting${report.unsupportedKeys.length === 1 ? '' : 's'} not imported`}
            </button>
            {showSummary && (
              <div className="mt-1 max-h-40 space-y-0.5 overflow-y-auto pb-1 pl-4">
                {report.warnings.map((w, i) => (
                  <p key={`w${i}`} className="text-warn">{w}</p>
                ))}
                {report.skipped.map((s, i) => (
                  <p key={`s${i}`}>Skipped: {s}</p>
                ))}
                {report.unsupportedKeys.length > 0 && (
                  <p>Not imported (no Hawser equivalent): {report.unsupportedKeys.join(', ')}</p>
                )}
                {report.filesRead.length > 0 && <p className="text-ink-faint">Read: {report.filesRead.join(', ')}</p>}
              </div>
            )}
          </div>
        )}

        {/* Host table */}
        <div className="min-h-0 flex-1 overflow-auto">
          {report && rows.length === 0 ? (
            <p className="px-4 py-8 text-center text-[12px] text-ink-faint">
              No importable hosts found{report.source === 'ssh-config' ? ' (only Host entries without wildcards become hosts)' : ''}.
            </p>
          ) : (
            <table className="w-full border-collapse text-left text-[12px]">
              <thead className="sticky top-0 bg-surface-2 text-[11px] text-ink-faint">
                <tr className="border-b border-line">
                  <th className="w-8 px-3 py-1.5">
                    <input type="checkbox" aria-label="Select all" checked={allChecked} onChange={() => void toggleAll()} disabled={selectable.length === 0} />
                  </th>
                  <th className="px-2 py-1.5 font-normal">Name</th>
                  <th className="px-2 py-1.5 font-normal">user@host:port</th>
                  <th className="px-2 py-1.5 font-normal">Key</th>
                  <th className="px-2 py-1.5 font-normal">Jump</th>
                  <th className="px-2 py-1.5 font-normal">Status</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <Row
                    key={r.index}
                    row={r}
                    checked={checked.has(r.index)}
                    jumpFor={selection.implied.get(r.index)}
                    onToggle={() => void toggle(r.index)}
                  />
                ))}
              </tbody>
            </table>
          )}
        </div>

        <footer className="flex flex-wrap items-center gap-2 border-t border-line px-4 py-2.5 text-[12px] text-ink-dim">
          <label className="flex items-center gap-1.5">
            Into
            <select
              value={targetSel}
              onChange={(e) => setTargetSel(e.target.value)}
              className="h-7 rounded border border-line bg-surface-0 px-1.5 text-ink focus:border-accent focus:outline-none"
            >
              <option value="new">New folder</option>
              <option value="top">Top level</option>
              {folders.map(([id, label]) => (
                <option key={id} value={id}>{label}</option>
              ))}
            </select>
          </label>
          {targetSel === 'new' && (
            <input
              value={folderName}
              onChange={(e) => setFolderName(e.target.value)}
              aria-label="New folder name"
              className="h-7 w-48 rounded border border-line bg-surface-0 px-2 text-ink focus:border-accent focus:outline-none"
            />
          )}
          <span className="flex-1 text-[11px] text-ink-faint">
            Addresses only: no passwords or key contents are imported.
          </span>
          <button
            type="button"
            onClick={onClose}
            className="h-7 rounded border border-line px-3 text-ink hover:bg-surface-3"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={doImport}
            disabled={!report || selection.picked.size === 0}
            className="h-7 rounded border border-accent bg-accent px-3 font-medium text-surface-0 hover:opacity-90 disabled:opacity-40"
          >
            Import {selection.picked.size} host{selection.picked.size === 1 ? '' : 's'}
          </button>
        </footer>
      </div>
    </div>
  )
}

function SourceButton({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      type="button"
      role="radio"
      aria-checked={active}
      onClick={onClick}
      className={`h-7 px-2.5 ${active ? 'bg-accent-soft text-ink' : 'bg-surface-1 text-ink-dim hover:text-ink'}`}
    >
      {children}
    </button>
  )
}

function Row({ row, checked, jumpFor, onToggle }: { row: ImportRow; checked: boolean; jumpFor?: string[]; onToggle: () => void }) {
  const s = row.scanned
  const id = `imp-row-${row.index}`
  const portPart = s.port !== 22 ? `:${s.port}` : ''
  const keyName = s.keyPath ? s.keyPath.split(/[\\/]/).pop() : ''
  return (
    <tr className={`border-b border-line/60 align-top ${checked || jumpFor ? '' : 'opacity-60'}`}>
      <td className="px-3 py-1.5">
        <input
          id={id}
          type="checkbox"
          checked={checked || !!jumpFor}
          disabled={row.status === 'blocked' || (!!jumpFor && !checked)}
          onChange={onToggle}
          aria-label={`Import ${s.name}`}
          title={jumpFor && !checked ? `Needed as the jump host of ${jumpFor.join(', ')}` : row.blockedReason}
        />
      </td>
      <td className="px-2 py-1.5 text-ink">
        <label htmlFor={id} className="cursor-pointer break-all">{s.name}</label>
        {row.warnings.length > 0 && (
          <ul className="mt-0.5 space-y-0.5 text-[11px] text-warn">
            {row.warnings.map((w, i) => (
              <li key={i}>{w}</li>
            ))}
          </ul>
        )}
      </td>
      <td className="px-2 py-1.5 font-mono text-[11.5px] text-ink-dim">
        <span className={row.userDefaulted ? 'italic' : undefined} title={row.userDefaulted ? 'No User set: your local account name is used' : undefined}>
          {row.username || '?'}
        </span>
        @{s.hostname}{portPart}
      </td>
      <td className="px-2 py-1.5 font-mono text-[11.5px] text-ink-dim" title={s.keyPath ?? undefined}>
        {keyName || <span className="text-ink-faint">—</span>}
      </td>
      <td className="px-2 py-1.5 text-ink-dim">{row.jumpLabel ?? <span className="text-ink-faint">—</span>}</td>
      <td className={`px-2 py-1.5 ${row.status === 'blocked' ? 'max-w-[18rem]' : 'whitespace-nowrap'}`}>
        {row.status === 'blocked' ? (
          <span className="text-warn" title={row.blockedReason}>cannot import: {row.blockedReason}</span>
        ) : jumpFor && !checked ? (
          <span className="text-accent" title={`Needed by ${jumpFor.join(', ')}`}>added as jump host</span>
        ) : row.status === 'route' ? (
          <span className="text-warn" title={s.unsupportedRoute ?? undefined}>
            route not supported ({(s.jumpHops ?? 0) > 1 ? `${s.jumpHops} hops` : 'ProxyCommand'})
          </span>
        ) : row.status === 'duplicate' ? (
          <span className="text-ink-faint">duplicate of {row.duplicateOf?.name}</span>
        ) : row.status === 'warning' ? (
          <span className="text-warn">warning</span>
        ) : (
          <span className="text-accent">new</span>
        )}
      </td>
    </tr>
  )
}
