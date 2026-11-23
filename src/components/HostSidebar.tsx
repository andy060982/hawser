import { useEffect, useMemo, useRef, useState } from 'react'
import { ChevronsDownUp, Clock, Plus, Radar, Search, X } from 'lucide-react'
import { type Host, type HostNode } from '../types'
import { HostTree } from './HostTree'
import { allFolderIds, filterTree } from '../lib/tree'
import { anyModalOpen } from '../lib/modalStack'

interface Props {
  hosts: HostNode[]
  width: number
  onOpenHost: (host: Host) => void
  onSelectHost: (host: Host) => void
  onAddHost: () => void
  onEditHost: (host: Host) => void
  onOpenHistory: () => void
  onHostMenu: (host: Host, x: number, y: number) => void
  onFolderMenu: (folderId: string, name: string, x: number, y: number) => void
  /** Right-click on the sidebar's empty area (not on a host/folder row). */
  onSidebarMenu: (x: number, y: number) => void
  onProbe: () => void
  probing: boolean
  reachability: Record<string, { ok: boolean; ms?: number }>
  openHostIds?: Set<string>
  activeHostId?: string
}

export function HostSidebar({
  hosts, width, onOpenHost, onSelectHost, onAddHost, onEditHost, onOpenHistory,
  onHostMenu, onFolderMenu, onSidebarMenu, onProbe, probing, reachability, openHostIds, activeHostId,
}: Props) {
  const [query, setQuery] = useState('')
  const searchRef = useRef<HTMLInputElement>(null)
  const [manuallyExpanded, setManuallyExpanded] = useState<Set<string>>(
    () => new Set(['f-net', 'f-net-fw']),
  )

  // Ctrl+Shift+K focuses the filter. The footer has advertised this shortcut
  // since the sidebar was built, but nothing ever handled it — a label pointing
  // at a key that does nothing. Handled here, where the input ref lives, rather
  // than threaded up through AppLayout. Shift is required because a focused
  // terminal owns plain Ctrl+K (readline kill-to-end-of-line).
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.ctrlKey && e.shiftKey && !e.altKey && !e.metaKey && e.code === 'KeyK') {
        e.preventDefault()
        // Behind a modal, the hidden filter must not take the typing.
        if (anyModalOpen()) return
        searchRef.current?.focus()
        searchRef.current?.select()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  const { tree, expand } = useMemo(() => filterTree(hosts, query), [hosts, query])

  // While searching, the forced-expand set is unioned in so results are visible
  // without mutating the user's own expand/collapse choices.
  const expanded = useMemo(
    () => new Set([...manuallyExpanded, ...expand]),
    [manuallyExpanded, expand],
  )

  const toggle = (id: string) =>
    setManuallyExpanded((prev) => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })

  const collapseAll = () => {
    setQuery('')
    setManuallyExpanded(new Set())
  }

  return (
    <aside
      style={{ width }}
      className="flex shrink-0 flex-col border-r border-line bg-surface-1"
    >
      <div className="flex items-center gap-1 px-2 pt-2 pb-1.5">
        <div className="relative flex-1">
          <Search
            size={12}
            className="pointer-events-none absolute top-1/2 left-2 -translate-y-1/2 text-ink-faint"
            aria-hidden
          />
          <input
            ref={searchRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === 'Escape' && setQuery('')}
            placeholder="Filter hosts"
            aria-label="Filter hosts"
            className="h-7 w-full rounded border border-line bg-surface-2 pr-6 pl-7 text-[12px] text-ink placeholder:text-ink-faint focus:border-accent focus:outline-none"
          />
          {query && (
            <button
              type="button"
              aria-label="Clear filter"
              onClick={() => setQuery('')}
              className="absolute top-1/2 right-1.5 -translate-y-1/2 text-ink-faint hover:text-ink"
            >
              <X size={12} />
            </button>
          )}
        </div>
        <IconButton label="Collapse all" onClick={collapseAll}>
          <ChevronsDownUp size={13} />
        </IconButton>
        <IconButton
          label={probing ? 'Probing…' : 'Check reachability (TCP to each host’s SSH port)'}
          onClick={onProbe}
        >
          <Radar size={13} className={probing ? 'animate-pulse text-accent' : undefined} />
        </IconButton>
        <IconButton label="Session history" onClick={onOpenHistory}>
          <Clock size={13} />
        </IconButton>
        <IconButton label="Add host" onClick={onAddHost}>
          <Plus size={14} />
        </IconButton>
      </div>

      {/* min-h-0 is load-bearing: without it this flex child refuses to shrink
          and the tree scrolls the whole window instead of itself. */}
      <nav
        role="tree"
        aria-label="Saved hosts"
        className="min-h-0 flex-1 overflow-y-auto pb-2"
        onContextMenu={(e) => {
          // Only the empty area: a right-click on a host/folder row stops
          // propagation in HostTree, so this fires for the background alone.
          e.preventDefault()
          onSidebarMenu(e.clientX, e.clientY)
        }}
      >
        {hosts.length === 0 && !query ? (
          <div className="px-3 py-6 text-center text-[12px] text-ink-faint">
            <p>No saved hosts yet.</p>
            <button
              type="button"
              onClick={onAddHost}
              className="mt-2 inline-flex items-center gap-1 rounded border border-line px-2 py-1 text-[11.5px] text-ink-dim hover:bg-surface-3 hover:text-ink"
            >
              <Plus size={12} aria-hidden />
              Add host
            </button>
          </div>
        ) : tree.length === 0 ? (
          <p className="px-3 py-6 text-center text-[12px] text-ink-faint">
            No hosts match “{query}”.
          </p>
        ) : (
          <HostTree
            nodes={tree}
            expanded={expanded}
            onToggle={toggle}
            onOpen={onOpenHost}
            onSelect={onSelectHost}
            onEdit={onEditHost}
            onMenu={onHostMenu}
            onFolderMenu={onFolderMenu}
            reachability={reachability}
            openHostIds={openHostIds}
            activeHostId={activeHostId}
          />
        )}
      </nav>

      <footer className="flex items-center justify-between border-t border-line px-3 py-1.5 text-[11px] text-ink-faint">
        <span>{allFolderIds(hosts).length} folders</span>
        <span className="tabular-nums">Ctrl+Shift+K to search</span>
      </footer>
    </aside>
  )
}

function IconButton({
  children, onClick, label,
}: {
  children: React.ReactNode
  onClick: () => void
  label: string
}) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      onClick={onClick}
      className="grid h-7 w-7 shrink-0 place-items-center rounded border border-line bg-surface-2 text-ink-dim transition-colors hover:bg-surface-3 hover:text-ink"
    >
      {children}
    </button>
  )
}
