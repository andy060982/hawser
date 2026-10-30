import { useEffect, useMemo, useRef, useState } from 'react'
import {
  ArrowDownToLine, ArrowUpFromLine, ArrowUp, ChevronDown, ChevronUp,
  Loader2, RefreshCw, TriangleAlert,
} from 'lucide-react'
import type { FileEntry, PaneSide } from '../types'
import { iconFor } from '../lib/fileIcons'
import { useDirectory, sortEntries, type SortKey } from '../hooks/useDirectory'

const fmtSize = (n: number, isDir: boolean) => {
  if (isDir) return '—'
  if (n < 1024) return `${n} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let v = n / 1024
  let u = 0
  while (v >= 1024 && u < units.length - 1) { v /= 1024; u++ }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${units[u]}`
}

const fmtTime = (epoch: number | null) => {
  if (!epoch) return '—'
  const d = new Date(epoch * 1000)
  // Fixed-width, sortable, unambiguous. Locale formats vary in width and make
  // the column ragged.
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}

interface Props {
  side: PaneSide
  sessionId: string
  initialPath: string
  focused: boolean
  onFocus: () => void
  onTransfer: (names: string[]) => void
  /** Lifted so the opposite pane's path can be used as a transfer destination. */
  onPathChange: (path: string) => void
  /** Pointer went down on a row: a drag MIGHT begin. The parent decides once
   *  the pointer moves far enough; plain clicks stay clicks. */
  onDragCandidate: (names: string[], x: number, y: number) => void
  /** Right-click on a row. */
  onRowMenu: (entry: FileEntry, x: number, y: number) => void
  /** Bump to force a directory re-read after an external mutation (rename,
   *  delete, mkdir happen in the parent, which owns the full paths). */
  refreshSignal: number
}

export function FilePane({
  side, sessionId, initialPath, focused, onFocus, onTransfer, onPathChange,
  onDragCandidate, onRowMenu, refreshSignal,
}: Props) {
  const dir = useDirectory(side, sessionId, initialPath)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [sortKey, setSortKey] = useState<SortKey>('name')
  const [asc, setAsc] = useState(true)

  const rows = useMemo(
    () => sortEntries(dir.entries, sortKey, asc),
    [dir.entries, sortKey, asc],
  )

  // External mutation happened (rename/delete/mkdir): re-read this directory.
  const firstSignal = useRef(true)
  useEffect(() => {
    if (firstSignal.current) {
      firstSignal.current = false
      return
    }
    dir.refresh()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [refreshSignal])

  useEffect(() => {
    onPathChange(dir.path)
    // Selection is per-directory. Carrying names across a navigation would
    // resolve them against the new path and transfer the wrong files.
    setSelected(new Set())
  }, [dir.path, onPathChange])

  // A refresh keeps the path, so names renamed/deleted away would otherwise
  // linger in the selection and get transferred (or fail) later. Keep the
  // same Set when nothing vanished to avoid a pointless re-render.
  useEffect(() => {
    setSelected((s) => {
      if (s.size === 0) return s
      const present = new Set(dir.entries.map((e) => e.name))
      const kept = [...s].filter((n) => present.has(n))
      return kept.length === s.size ? s : new Set(kept)
    })
  }, [dir.entries])

  const isLocal = side === 'local'

  const toggleSort = (key: SortKey) => {
    if (key === sortKey) setAsc((a) => !a)
    else { setSortKey(key); setAsc(true) }
  }

  /** Where the pointer went down, to tell a drag from a click: if it moved
   *  more than a few pixels before the click lands, the user was dragging and
   *  the click must not toggle selection. */
  const downAt = useRef<{ x: number; y: number } | null>(null)

  const rowPointerDown = (entry: FileEntry, e: React.PointerEvent) => {
    if (e.button !== 0 || entry.name === '..') return
    downAt.current = { x: e.clientX, y: e.clientY }
    // Drag the whole selection if the grabbed row is part of it; otherwise
    // just the grabbed row — matching every file manager since forever.
    const names = selected.has(entry.name) ? [...selected] : [entry.name]
    onDragCandidate(names, e.clientX, e.clientY)
  }

  const select = (entry: FileEntry, e: React.MouseEvent) => {
    // Directories ARE selectable now that transfers recurse — the backend
    // walks a directory tree on both upload and download. Only ".." is
    // excluded, since it is navigation, not a real entry. Double-click still
    // navigates into a folder; single-click selects it for transfer.
    if (entry.name === '..') return
    // A drag that ended on this row also fires click; swallow it.
    if (downAt.current) {
      const moved =
        Math.abs(e.clientX - downAt.current.x) + Math.abs(e.clientY - downAt.current.y)
      downAt.current = null
      if (moved > 6) return
    }
    setSelected((prev) => {
      const next = e.ctrlKey || e.metaKey ? new Set(prev) : new Set<string>()
      next.has(entry.name) ? next.delete(entry.name) : next.add(entry.name)
      return next
    })
  }

  return (
    <section
      onMouseDown={onFocus}
      aria-label={isLocal ? 'Local files' : 'Remote files'}
      className={`flex min-w-0 flex-1 flex-col bg-surface-0 transition-shadow ${
        focused ? 'ring-1 ring-accent/40 ring-inset' : ''
      }`}
    >
      {/* ------------------------------------------------------------ toolbar */}
      <header className="flex h-8 shrink-0 items-center gap-2 border-b border-line bg-surface-1 px-2">
        <span
          className={`shrink-0 rounded-sm px-1.5 py-px text-[10px] font-semibold uppercase tracking-wider ${
            isLocal ? 'bg-surface-3 text-ink-dim' : 'bg-accent-soft text-accent'
          }`}
        >
          {isLocal ? 'Local' : 'Remote'}
        </span>

        <button
          type="button"
          aria-label="Parent directory"
          title="Parent directory"
          onClick={() => dir.open({ name: '..', kind: 'directory', size: 0, modified: null, mode: '' }, dir.path)}
          className="grid h-6 w-6 shrink-0 place-items-center rounded border border-line text-ink-dim hover:bg-surface-3 hover:text-ink"
        >
          <ArrowUp size={12} />
        </button>

        <span
          className="selectable min-w-0 flex-1 truncate font-mono text-[11.5px] text-ink-dim"
          title={dir.path}
        >
          {dir.path}
        </span>

        {dir.loading && <Loader2 size={12} className="shrink-0 animate-spin text-accent" aria-label="Loading" />}

        <button
          type="button"
          disabled={selected.size === 0}
          onClick={() => onTransfer([...selected])}
          title={isLocal ? 'Upload selected' : 'Download selected'}
          className="flex h-6 shrink-0 items-center gap-1 rounded border border-line px-1.5 text-[11px] text-ink-dim enabled:hover:bg-surface-3 enabled:hover:text-ink disabled:opacity-40"
        >
          {isLocal ? <ArrowUpFromLine size={12} /> : <ArrowDownToLine size={12} />}
          {isLocal ? 'Upload' : 'Download'}
        </button>

        <button
          type="button"
          aria-label="Refresh"
          title="Refresh"
          onClick={dir.refresh}
          className="grid h-6 w-6 shrink-0 place-items-center rounded border border-line text-ink-dim hover:bg-surface-3 hover:text-ink"
        >
          <RefreshCw size={11} />
        </button>
      </header>

      {/* ------------------------------------------------------------- header */}
      <div className="grid shrink-0 grid-cols-[1fr_5rem_9rem_6rem] gap-2 border-b border-line bg-surface-1/60 px-2 py-1 text-[10.5px] font-medium uppercase tracking-wider text-ink-faint">
        <SortHeader label="Name" active={sortKey === 'name'} asc={asc} onClick={() => toggleSort('name')} />
        <SortHeader label="Size" align="right" active={sortKey === 'size'} asc={asc} onClick={() => toggleSort('size')} />
        <SortHeader label="Modified" active={sortKey === 'modified'} asc={asc} onClick={() => toggleSort('modified')} />
        <span>{isLocal ? 'Attr' : 'Mode'}</span>
      </div>

      {/* --------------------------------------------------------------- rows */}
      <div className="min-h-0 flex-1 overflow-y-auto">
        {dir.error ? (
          <div className="flex items-start gap-2 px-3 py-4 text-[12px] text-alert">
            <TriangleAlert size={14} className="mt-px shrink-0" aria-hidden />
            <div className="min-w-0">
              <p className="font-medium">Could not read directory</p>
              <p className="selectable mt-0.5 break-words text-ink-dim">{dir.error}</p>
              <button
                type="button"
                onClick={dir.refresh}
                className="mt-2 rounded border border-line px-2 py-0.5 text-ink-dim hover:bg-surface-3 hover:text-ink"
              >
                Retry
              </button>
            </div>
          </div>
        ) : rows.length === 0 && !dir.loading ? (
          <p className="px-3 py-6 text-center text-[12px] text-ink-faint">Empty directory</p>
        ) : (
          rows.map((entry) => (
            <Row
              key={entry.name}
              entry={entry}
              selected={selected.has(entry.name)}
              onSelect={(e) => select(entry, e)}
              onPointerDown={(e) => rowPointerDown(entry, e)}
              onMenu={(e) => {
                e.preventDefault()
                if (entry.name !== '..') onRowMenu(entry, e.clientX, e.clientY)
              }}
              onOpen={() => dir.open(entry, dir.path)}
            />
          ))
        )}
      </div>

      <footer className="flex h-6 shrink-0 items-center justify-between border-t border-line px-2 text-[10.5px] text-ink-faint">
        <span>{rows.filter((r) => r.name !== '..').length} items</span>
        {selected.size > 0 && <span className="text-accent">{selected.size} selected</span>}
      </footer>
    </section>
  )
}

function SortHeader({
  label, active, asc, onClick, align,
}: {
  label: string
  active: boolean
  asc: boolean
  onClick: () => void
  align?: 'right'
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`flex items-center gap-0.5 uppercase tracking-wider transition-colors hover:text-ink ${
        align === 'right' ? 'justify-end' : ''
      } ${active ? 'text-ink-dim' : ''}`}
    >
      {label}
      {active && (asc ? <ChevronUp size={10} /> : <ChevronDown size={10} />)}
    </button>
  )
}

function Row({
  entry, selected, onSelect, onOpen, onPointerDown, onMenu,
}: {
  entry: FileEntry
  selected: boolean
  onSelect: (e: React.MouseEvent) => void
  onOpen: () => void
  onPointerDown: (e: React.PointerEvent) => void
  onMenu: (e: React.MouseEvent) => void
}) {
  const { Icon, tint, label } = iconFor(entry)
  const isDir = entry.kind === 'directory'

  return (
    <div
      onClick={onSelect}
      onDoubleClick={onOpen}
      onPointerDown={onPointerDown}
      onContextMenu={onMenu}
      className={`grid cursor-default grid-cols-[1fr_5rem_9rem_6rem] items-center gap-2 px-2 py-[3px] text-[12px] transition-colors ${
        selected ? 'bg-accent-soft text-ink' : 'text-ink-dim hover:bg-surface-2'
      }`}
    >
      <span className="flex min-w-0 items-center gap-1.5">
        <Icon size={13} className={`shrink-0 ${tint}`} aria-label={label} />
        <span className={`selectable truncate ${isDir ? 'text-ink' : ''}`}>{entry.name}</span>
      </span>
      <span className="text-right font-mono tabular-nums text-ink-faint">
        {fmtSize(entry.size, isDir)}
      </span>
      <span className="font-mono text-[11px] tabular-nums text-ink-faint">
        {fmtTime(entry.modified)}
      </span>
      <span className="font-mono text-[11px] text-ink-faint">{entry.mode || '—'}</span>
    </div>
  )
}
