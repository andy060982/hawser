import { useCallback, useEffect, useRef, useState } from 'react'
import { ArrowDownToLine, ArrowUpFromLine } from 'lucide-react'
import type { FileEntry, PaneSide, Session } from '../types'
import { FilePane } from './FilePane'
import { ResizeHandle } from './ResizeHandle'
import { joinPath } from '../lib/sftp'
import { useDialogs } from '../lib/dialogs'
import { onFileDrop, safeInvoke } from '../lib/tauri'
import { ContextMenu, type MenuState } from './ContextMenu'
import { X } from 'lucide-react'
import { sep } from '@tauri-apps/api/path'

/** A valid, listable local starting directory for the current OS. The app opens
 *  the local pane at the filesystem root (as it already did on Windows with
 *  "C:\\"); this returns the correct root per platform instead of a hardcoded
 *  "C:\\" that doesn't exist on macOS/Linux. `sep()` distinguishes Windows
 *  ("\\") from POSIX ("/"). */
function defaultLocal(): string {
  try {
    return sep() === '\\' ? 'C:\\' : '/'
  } catch {
    return '/'
  }
}
/** True when the LOCAL side is Windows, where ':' in a file name means a drive
 *  letter or an alternate data stream. */
function localIsWindows(): boolean {
  try {
    return sep() === '\\'
  } catch {
    return false
  }
}
const DEFAULT_REMOTE = '/'

/** Dual-pane transfer surface: local on the left, remote on the right.
 *
 *  Paths are lifted here rather than kept inside each pane because a transfer
 *  needs both — the destination is always the *opposite* pane's current
 *  directory, which is the behaviour every dual-pane client has had since
 *  Norton Commander and the reason the layout exists at all.
 *
 *  The transfer QUEUE, by contrast, is deliberately NOT here: it lives in
 *  AppLayout so it outlives this component, which unmounts every time you
 *  switch to the terminal. This view only starts transfers and browses. */
export function SftpView({
  session,
  onStartTransfer,
  savedPaths,
  onPathsChange,
  transferTick,
}: {
  session: Session
  onStartTransfer: (
    sessionId: string,
    direction: 'upload' | 'download',
    jobs: { name: string; local: string; remote: string }[],
  ) => void
  /** Paths this session last browsed, restored so a terminal round-trip does
   *  not reset both panes to root. */
  savedPaths?: { local?: string; remote?: string }
  onPathsChange: (local: string, remote: string) => void
  /** Bumps when any transfer completes, so the destination pane re-reads. */
  transferTick: number
}) {
  const { confirm, alert, prompt } = useDialogs()
  const [ratio, setRatio] = useState(0.5)
  const [focus, setFocus] = useState<PaneSide>('local')
  const [localPath, setLocalPath] = useState(savedPaths?.local || defaultLocal())
  const [remotePath, setRemotePath] = useState(savedPaths?.remote ?? DEFAULT_REMOTE)
  // Current paths for the drop handler, which subscribes once.
  const remoteRef = useRef(remotePath)
  remoteRef.current = remotePath

  /* ------------------------------------------------ pane-to-pane drag
     Raw pointer events, not HTML5 drag-and-drop: Tauri's native drop layer
     (needed for Explorer file drops) swallows HTML5 drag events inside the
     webview on Windows, so the reliable way to drag BETWEEN panes is to do
     it by hand — a candidate armed on pointerdown, activated after 6px of
     travel, hit-tested against the panes on release. */
  const [drag, setDrag] = useState<{
    names: string[]
    from: PaneSide
    x: number
    y: number
    active: boolean
  } | null>(null)
  const dragRef = useRef(drag)
  dragRef.current = drag
  const localBoxRef = useRef<HTMLDivElement>(null)
  const remoteBoxRef = useRef<HTMLDivElement>(null)
  const [hoverTarget, setHoverTarget] = useState<PaneSide | null>(null)

  /* File context menu + properties + per-pane refresh signals. */
  const [menu, setMenu] = useState<MenuState | null>(null)
  const [props_, setProps_] = useState<{ entry: FileEntry; side: PaneSide; path: string } | null>(null)
  const [refreshLocal, setRefreshLocal] = useState(0)
  const [refreshRemote, setRefreshRemote] = useState(0)
  const bump = (side: PaneSide) =>
    side === 'local' ? setRefreshLocal((n) => n + 1) : setRefreshRemote((n) => n + 1)

  // A completed transfer landed on the opposite pane; re-read both so the new
  // file appears without a manual refresh. Cheap, and correct regardless of
  // which direction moved.
  useEffect(() => {
    if (transferTick === 0) return
    setRefreshLocal((n) => n + 1)
    setRefreshRemote((n) => n + 1)
  }, [transferTick])

  // Persist the browsed paths upward whenever they change.
  useEffect(() => {
    onPathsChange(localPath, remotePath)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [localPath, remotePath])

  const runOp = (side: PaneSide, op: Promise<unknown>) => {
    void op
      .then(() => bump(side))
      .catch((e) => void alert(e instanceof Error ? e.message : String(e)))
  }

  const openRowMenu = (side: PaneSide) => (entry: FileEntry, x: number, y: number) => {
    const base = side === 'local' ? localPath : remotePath
    const full = joinPath(side, base, entry.name)
    const isDir = entry.kind === 'directory'
    setMenu({
      x,
      y,
      items: [
        {
          label: side === 'local' ? 'Upload' : 'Download',
          onSelect: () => start(side, [entry.name]),
        },
        {
          label: 'Rename…',
          dividerBefore: true,
          onSelect: async () => {
            const next = (await prompt('New name', { title: 'Rename', defaultValue: entry.name }))?.trim()
            if (!next || next === entry.name) return
            if (/[\\/]/.test(next)) {
              void alert('Names cannot contain slashes.')
              return
            }
            const to = joinPath(side, base, next)
            runOp(side, safeInvoke(side === 'local' ? 'local_rename' : 'sftp_rename',
              side === 'local' ? { from: full, to } : { sessionId: session.id, from: full, to }))
          },
        },
        {
          label: 'New folder here…',
          onSelect: async () => {
            const name = (await prompt('Folder name', { title: 'New folder' }))?.trim()
            if (!name) return
            if (/[\\/]/.test(name)) {
              void alert('Names cannot contain slashes.')
              return
            }
            const target = joinPath(side, base, name)
            runOp(side, safeInvoke(side === 'local' ? 'local_mkdir' : 'sftp_mkdir',
              side === 'local' ? { path: target } : { sessionId: session.id, path: target }))
          },
        },
        {
          label: 'Properties…',
          onSelect: () => setProps_({ entry, side, path: full }),
        },
        {
          label: isDir ? 'Delete (empty folders only)' : 'Delete',
          danger: true,
          dividerBefore: true,
          onSelect: () => {
            // Non-recursive by design: rm -rf from a GUI click is how
            // production directories die. Non-empty folders fail server-side
            // and the error is shown.
            void confirm(`Delete ${entry.name}? This cannot be undone.`, {
              title: 'Delete',
              confirmLabel: 'Delete',
              danger: true,
            }).then((ok) => {
              if (!ok) return
              runOp(side, safeInvoke(side === 'local' ? 'local_delete' : 'sftp_delete',
                side === 'local'
                  ? { path: full, isDir }
                  : { sessionId: session.id, path: full, isDir }))
            })
          },
        },
      ],
    })
  }

  const armDrag = useCallback((from: PaneSide) => (names: string[], x: number, y: number) => {
    setDrag({ names, from, x, y, active: false })
  }, [])

  const paneAt = (x: number, y: number): PaneSide | null => {
    const inBox = (el: HTMLDivElement | null) => {
      if (!el) return false
      const r = el.getBoundingClientRect()
      return x >= r.left && x <= r.right && y >= r.top && y <= r.bottom
    }
    if (inBox(localBoxRef.current)) return 'local'
    if (inBox(remoteBoxRef.current)) return 'remote'
    return null
  }

  useEffect(() => {
    if (!drag) return

    const onMove = (e: PointerEvent) => {
      const d = dragRef.current
      if (!d) return
      // No button held: the press that armed this drag ended somewhere we did
      // not see. Never let plain hovering activate it.
      if ((e.buttons & 1) === 0) {
        document.body.classList.remove('hawser-dragging')
        setDrag(null)
        setHoverTarget(null)
        return
      }
      const dist = Math.abs(e.clientX - d.x) + Math.abs(e.clientY - d.y)
      if (!d.active && dist <= 6) return
      e.preventDefault()
      if (!d.active) {
        // The filenames are text-selectable for copying, so the browser's
        // native selection engine also responds to this same drag and paints
        // highlights across the pane. The instant OUR drag takes over, wipe
        // whatever it selected and suspend selection until the drop.
        window.getSelection()?.removeAllRanges()
        document.body.classList.add('hawser-dragging')
      }
      const over = paneAt(e.clientX, e.clientY)
      setHoverTarget(over && over !== d.from ? over : null)
      setDrag({ ...d, x: e.clientX, y: e.clientY, active: true })
    }

    const onUp = (e: PointerEvent) => {
      const d = dragRef.current
      document.body.classList.remove('hawser-dragging')
      setDrag(null)
      setHoverTarget(null)
      if (!d?.active) return
      const target = paneAt(e.clientX, e.clientY)
      // Only a drop on the OPPOSITE pane transfers; same-pane drops are a
      // no-op rather than a surprise move/rename.
      if (target && target !== d.from) start(d.from, d.names)
    }

    // The pointer stream can end WITHOUT a pointerup — a native text drag of
    // the selectable filename, an OS gesture, the window losing focus. Abandon
    // the drag then (never transfer), or it stays armed and the next unrelated
    // click over the other pane would start a transfer.
    const abandon = () => {
      document.body.classList.remove('hawser-dragging')
      setDrag(null)
      setHoverTarget(null)
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && dragRef.current) abandon()
    }

    window.addEventListener('pointermove', onMove)
    window.addEventListener('pointerup', onUp)
    window.addEventListener('pointercancel', abandon)
    window.addEventListener('blur', abandon)
    window.addEventListener('dragstart', abandon)
    window.addEventListener('keydown', onKey)
    return () => {
      // Covers unmount mid-drag too, so the class can never stick.
      document.body.classList.remove('hawser-dragging')
      window.removeEventListener('pointermove', onMove)
      window.removeEventListener('pointerup', onUp)
      window.removeEventListener('pointercancel', abandon)
      window.removeEventListener('blur', abandon)
      window.removeEventListener('dragstart', abandon)
      window.removeEventListener('keydown', onKey)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [drag !== null])

  /* Drag a file (or folder — uploads recurse) from Explorer anywhere onto this
     view and it uploads into the remote pane's current directory. Registered
     while the SFTP view is mounted, so a drop in terminal view does nothing —
     dropping a file with no visible file UI should never trigger a transfer. */
  useEffect(() => {
    let un: (() => void) | null = null
    let dead = false
    void onFileDrop((paths) => {
      const jobs = paths.map((p) => {
        const name = p.split(/[\\/]/).filter(Boolean).pop() ?? p
        return { name, local: p, remote: joinPath('remote', remoteRef.current, name) }
      })
      // Route through the shared guard so an Explorer drop honours the same
      // overwrite prompt and unsafe-name check as an in-app transfer.
      void confirmAndTransfer('upload', jobs)
    }).then((fn) => {
      if (dead) fn()
      else un = fn
    })
    return () => {
      dead = true
      un?.()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session.id])

  // Single choke point every transfer passes through — the in-app pane drag,
  // a pane menu "Transfer", and an Explorer drop all funnel here so none can
  // skip the unsafe-name check or silently clobber a file.
  const confirmAndTransfer = async (
    direction: 'upload' | 'download',
    jobs: { name: string; local: string; remote: string }[],
  ) => {
    // A download turns a server-chosen name into a LOCAL path. Reject any name
    // that is not a plain component — EITHER separator (`\` is the traversal
    // char on the Windows local side) or `.`/`..` — so a malicious server
    // cannot write outside the target folder. The backend enforces this too;
    // this is the friendly front-line message. ':' (drive letter / ADS) is a
    // hazard only for a download onto a Windows machine: on macOS/Linux it is
    // an ordinary name character (timestamped logs), and an upload's name
    // becomes a remote POSIX component.
    const colonUnsafe = direction === 'download' && localIsWindows()
    const unsafe = jobs.filter(
      (j) =>
        /[\\/]/.test(j.name) ||
        j.name === '.' ||
        j.name === '..' ||
        (colonUnsafe && j.name.includes(':')),
    )
    if (unsafe.length > 0) {
      void alert(`Refusing unsafe name(s): ${unsafe.map((j) => j.name).join(', ')}`)
      jobs = jobs.filter((j) => !unsafe.includes(j))
      if (jobs.length === 0) return
    }

    // Overwrite guard: check whether each name already exists at the
    // destination and confirm before clobbering. Silent overwrite on a tool
    // that touches production configs is exactly the surprise to avoid. The
    // check is best-effort — if it errors we proceed rather than block a
    // legitimate transfer.
    const kept: typeof jobs = []
    for (const job of jobs) {
      const destPath = direction === 'upload' ? job.remote : job.local
      let exists = false
      try {
        exists = Boolean(
          await safeInvoke<boolean>('path_exists', {
            sessionId: session.id,
            path: destPath,
            remote: direction === 'upload',
          }),
        )
      } catch {
        exists = false
      }
      if (
        exists &&
        !(await confirm(`${job.name} already exists at the destination. Overwrite it?`, {
          title: 'Overwrite?',
          confirmLabel: 'Overwrite',
          danger: true,
        }))
      ) {
        continue
      }
      kept.push(job)
    }
    if (kept.length > 0) onStartTransfer(session.id, direction, kept)
  }

  const start = (side: PaneSide, names: string[]) => {
    const direction = side === 'local' ? 'upload' : 'download'
    const jobs = names.map((name) => ({
      name,
      local: joinPath('local', localPath, name),
      remote: joinPath('remote', remotePath, name),
    }))
    void confirmAndTransfer(direction, jobs)
  }

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex min-h-0 flex-1">
        <div
          ref={localBoxRef}
          style={{ flex: ratio }}
          className={`flex min-w-0 ${hoverTarget === 'local' ? 'ring-2 ring-accent/60 ring-inset' : ''}`}
        >
          <FilePane
            side="local"
            sessionId={session.id}
            initialPath={savedPaths?.local || defaultLocal()}
            focused={focus === 'local'}
            onFocus={() => setFocus('local')}
            onPathChange={setLocalPath}
            onTransfer={(names) => start('local', names)}
            onDragCandidate={armDrag('local')}
            onRowMenu={openRowMenu('local')}
            refreshSignal={refreshLocal}
          />
        </div>

        <ResizeHandle
          aria-label="Resize file panes"
          onReset={() => setRatio(0.5)}
          onResize={(dx) =>
            setRatio((r) => Math.min(0.8, Math.max(0.2, r + dx / window.innerWidth)))
          }
        />

        <div
          ref={remoteBoxRef}
          style={{ flex: 1 - ratio }}
          className={`flex min-w-0 ${hoverTarget === 'remote' ? 'ring-2 ring-accent/60 ring-inset' : ''}`}
        >
          <FilePane
            side="remote"
            sessionId={session.id}
            initialPath={savedPaths?.remote ?? DEFAULT_REMOTE}
            focused={focus === 'remote'}
            onFocus={() => setFocus('remote')}
            onPathChange={setRemotePath}
            onTransfer={(names) => start('remote', names)}
            onDragCandidate={armDrag('remote')}
            onRowMenu={openRowMenu('remote')}
            refreshSignal={refreshRemote}
          />
        </div>
      </div>

      <ContextMenu menu={menu} onClose={() => setMenu(null)} />

      {props_ && (
        <div className="absolute inset-0 z-50 flex items-center justify-center">
          <div
            className="absolute inset-0 bg-surface-0/60"
            onMouseDown={() => setProps_(null)}
            aria-hidden
          />
          <div className="relative w-[24rem] max-w-[90vw] overflow-hidden rounded-panel border border-line-strong bg-surface-2 shadow-2xl">
            <header className="flex items-center gap-2 border-b border-line px-4 py-2.5">
              <span className="flex-1 truncate text-[13px] font-medium text-ink">
                {props_.entry.name}
              </span>
              <button
                type="button"
                aria-label="Close"
                onClick={() => setProps_(null)}
                className="grid h-6 w-6 place-items-center rounded text-ink-faint hover:bg-surface-3 hover:text-ink"
              >
                <X size={13} />
              </button>
            </header>
            <dl className="grid grid-cols-[6rem_1fr] gap-x-3 gap-y-1.5 px-4 py-3 text-[12.5px]">
              <dt className="text-ink-faint">Kind</dt>
              <dd className="capitalize text-ink-dim">{props_.entry.kind}</dd>
              <dt className="text-ink-faint">Location</dt>
              <dd className="selectable break-all font-mono text-[11.5px] text-ink-dim">{props_.path}</dd>
              <dt className="text-ink-faint">Size</dt>
              <dd className="font-mono tabular-nums text-ink-dim">
                {props_.entry.kind === 'directory'
                  ? '—'
                  : `${props_.entry.size.toLocaleString()} bytes`}
              </dd>
              <dt className="text-ink-faint">Modified</dt>
              <dd className="font-mono text-ink-dim">
                {props_.entry.modified
                  ? new Date(props_.entry.modified * 1000).toLocaleString()
                  : '—'}
              </dd>
              <dt className="text-ink-faint">{props_.side === 'local' ? 'Attributes' : 'Mode'}</dt>
              <dd className="font-mono text-ink-dim">{props_.entry.mode || '—'}</dd>
              <dt className="text-ink-faint">Side</dt>
              <dd className="text-ink-dim">{props_.side === 'local' ? 'This machine' : 'Remote host'}</dd>
            </dl>
          </div>
        </div>
      )}

      {/* Drag ghost: follows the pointer, names the action. Direction reads
          from the SOURCE pane, so the label is honest before the drop. */}
      {drag?.active && (
        <div
          className="pointer-events-none fixed z-[70] flex items-center gap-1.5 rounded border border-accent/60 bg-surface-2 px-2 py-1 text-[11.5px] text-ink shadow-lg"
          style={{ left: drag.x + 12, top: drag.y + 12 }}
        >
          {drag.from === 'local' ? (
            <ArrowUpFromLine size={11} className="text-accent" aria-hidden />
          ) : (
            <ArrowDownToLine size={11} className="text-accent" aria-hidden />
          )}
          {drag.names.length === 1
            ? drag.names[0]
            : `${drag.names.length} items`}
          <span className="text-ink-faint">
            — drop on the {drag.from === 'local' ? 'remote' : 'local'} pane to
            {drag.from === 'local' ? ' upload' : ' download'}
          </span>
        </div>
      )}
    </div>
  )
}
