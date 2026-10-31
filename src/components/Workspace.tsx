import { FolderTree, Radio, ServerOff, SplitSquareHorizontal, SplitSquareVertical, SquareTerminal, Unlink } from 'lucide-react'
import type { Session, WorkspaceView } from '../types'
import { TerminalDeck } from './TerminalDeck'
import type { LayoutNode, SplitDir } from '../lib/paneLayout'
import { SftpView } from './SftpView'

interface Props {
  /** Every open session, so the terminal deck can keep them all alive. */
  sessions: Session[]
  session?: Session
  onChangeView: (view: WorkspaceView) => void
  onSize?: (sessionId: string, cols: number, rows: number) => void
  /** Sessions sharing the active session's group. */
  groupSessions: Session[]
  onFocusSession: (sessionId: string) => void
  /** Split the focused pane in the given direction, opening a new session. */
  onSplit: (dir: SplitDir) => void
  onSeparate: (sessionId: string) => void
  /** Close a single pane (session) within a split. */
  onClosePane: (sessionId: string) => void
  /** The active group's layout tree (null while the SFTP lens is up). */
  layout: LayoutNode | null
  onResizeSplit: (splitId: string, ratioDelta: number) => void
  onResetSplit: (splitId: string) => void
  onStartTransfer: (
    sessionId: string,
    direction: 'upload' | 'download',
    jobs: { name: string; local: string; remote: string }[],
  ) => void
  sftpPaths: Record<string, { local?: string; remote?: string }>
  onSftpPathsChange: (
    fn: (prev: Record<string, { local?: string; remote?: string }>) => Record<string, { local?: string; remote?: string }>,
  ) => void
  transferTick: number
  /** Accent hex of the active host, or null. Paints a frame as a wrong-window
   *  guard. */
  accentHex: string | null
  broadcast: boolean
  broadcastExcluded?: Set<string>
  onToggleBroadcast: () => void
  /** False for local terminals, which have no SFTP side. */
  filesAvailable?: boolean
}

export function Workspace({
  filesAvailable = true,
  sessions, session, onChangeView, onSize, groupSessions, onFocusSession, onSplit, onSeparate,
  onClosePane, layout, onResizeSplit, onResetSplit,
  onStartTransfer, sftpPaths, onSftpPathsChange, transferTick, accentHex, broadcast, broadcastExcluded, onToggleBroadcast,
}: Props) {
  if (!session || sessions.length === 0) return <EmptyState />

  return (
    <div
      className="flex min-h-0 flex-1 flex-col bg-surface-0"
      // A 2px inset frame in the host's accent colour. Cheap, always visible,
      // and the whole point of per-host colour: the wrong firewall looks wrong
      // before anything is typed. box-shadow rather than border so it does not
      // shift the layout by 2px when a plain host has no accent.
      style={accentHex ? { boxShadow: `inset 0 0 0 2px ${accentHex}` } : undefined}
    >
      {/* View switcher. Terminal and SFTP are two lenses on one connection, not
          two connections — the toggle lives here rather than in the tab strip so
          a tab keeps meaning "a host I am connected to". */}
      <div className="flex h-8 shrink-0 items-center gap-2 border-b border-line bg-surface-0 px-2">
        <div
          role="tablist"
          aria-label="Workspace view"
          className="flex items-center gap-0.5 rounded border border-line bg-surface-1 p-0.5"
        >
          <ViewTab
            active={session.view === 'terminal'}
            onClick={() => onChangeView('terminal')}
            icon={<SquareTerminal size={12} />}
            label="Terminal"
          />
          {filesAvailable && (
            <ViewTab
              active={session.view === 'sftp'}
              onClick={() => onChangeView('sftp')}
              icon={<FolderTree size={12} />}
              label="Files"
            />
          )}
        </div>
        <div className="ml-auto flex items-center gap-1">
          {session.view === 'terminal' && (
            <>
              {/* Split stays labeled (discoverable) and shrink-0 so it can never
                  be squeezed out of the toolbar when the pane actions appear. */}
              <button
                type="button"
                onClick={() => onSplit('row')}
                title="Split the focused pane — new session to the right"
                className="flex h-[22px] shrink-0 items-center gap-1 rounded border border-line px-1.5 text-[11.5px] text-ink-dim transition-colors hover:bg-surface-3 hover:text-ink"
              >
                <SplitSquareHorizontal size={12} aria-hidden />
                Split right
              </button>
              <button
                type="button"
                onClick={() => onSplit('col')}
                title="Split the focused pane — new session below"
                className="flex h-[22px] shrink-0 items-center gap-1 rounded border border-line px-1.5 text-[11.5px] text-ink-dim transition-colors hover:bg-surface-3 hover:text-ink"
              >
                <SplitSquareVertical size={12} aria-hidden />
                Split down
              </button>
              {/* Broadcast + Separate are icon-only: they only appear at 2+ panes,
                  which is exactly when the toolbar would otherwise overflow and
                  push the Split buttons off-screen. */}
              {groupSessions.length > 1 && (
                <button
                  type="button"
                  onClick={onToggleBroadcast}
                  aria-pressed={broadcast}
                  aria-label="Broadcast input to all panes"
                  title={broadcast ? 'Broadcasting — input goes to every pane' : 'Broadcast input to every pane in this tab'}
                  className={`grid h-[22px] w-[22px] shrink-0 place-items-center rounded border transition-colors ${
                    broadcast
                      ? 'border-warn/60 bg-warn/15 text-warn'
                      : 'border-line text-ink-dim hover:bg-surface-3 hover:text-ink'
                  }`}
                >
                  <Radio size={13} aria-hidden />
                </button>
              )}
              {groupSessions.length > 1 && (
                <button
                  type="button"
                  onClick={() => onSeparate(session.id)}
                  aria-label="Separate this pane into its own tab"
                  title="Move this pane out into its own tab"
                  className="grid h-[22px] w-[22px] shrink-0 place-items-center rounded border border-line text-ink-dim transition-colors hover:bg-surface-3 hover:text-ink"
                >
                  <Unlink size={13} aria-hidden />
                </button>
              )}
            </>
          )}
          <span className="ml-1 font-mono text-[11px] text-ink-faint">Ctrl+Shift+E</span>
        </div>
      </div>

      {/* Both surfaces are absolutely positioned siblings in one relative box.
          The terminal deck is always mounted; SFTP is layered over it when
          selected. Swapping which one is *rendered* would destroy terminal
          state on every view toggle. */}
      <div className="relative min-h-0 flex-1">
        <TerminalDeck
          sessions={sessions}
          layout={session.view === 'terminal' ? layout : null}
          focusedId={session.id}
          broadcast={broadcast}
          broadcastExcluded={broadcastExcluded}
          onResizeSplit={onResizeSplit}
          onResetSplit={onResetSplit}
          onClosePane={onClosePane}
          onFocus={onFocusSession}
          onSize={onSize}
        />
        {session.view === 'sftp' && (
          <div className="absolute inset-0">
            <SftpView
              key={session.id}
              session={session}
              onStartTransfer={onStartTransfer}
              savedPaths={sftpPaths[session.id]}
              onPathsChange={(local, remote) =>
                onSftpPathsChange((prev) => ({ ...prev, [session.id]: { local, remote } }))
              }
              transferTick={transferTick}
            />
          </div>
        )}
      </div>
    </div>
  )
}

function ViewTab({
  active, onClick, icon, label,
}: {
  active: boolean
  onClick: () => void
  icon: React.ReactNode
  label: string
}) {
  return (
    <button
      type="button"
      role="tab"
      aria-selected={active}
      onClick={onClick}
      className={`flex h-[22px] items-center gap-1.5 rounded-sm px-2 text-[11.5px] transition-colors ${
        active ? 'bg-surface-4 text-ink' : 'text-ink-dim hover:text-ink'
      }`}
    >
      {icon}
      {label}
    </button>
  )
}

function EmptyState() {
  return (
    <div className="flex min-h-0 flex-1 flex-col items-center justify-center gap-3 bg-surface-0 text-center">
      <ServerOff size={28} className="text-ink-faint" aria-hidden />
      <div>
        <p className="text-[13px] text-ink-dim">No active session</p>
        <p className="mt-1 text-[12px] text-ink-faint">
          Double-click a host in the sidebar to connect. Press{' '}
          <kbd className="rounded border border-line bg-surface-2 px-1 py-px font-mono text-[10.5px]">
            Ctrl+Shift+K
          </kbd>{' '}
          to search hosts.
        </p>
      </div>
    </div>
  )
}
