import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { Host, HostNode, Session, Transfer, TransferProgressEvent, TransferFailureEvent, WorkspaceView } from '../types'
import {
  addFolder, allFolders, allHosts, countHosts, findHost, moveHost, reidentify,
  effectiveHostColor, removeFolder, removeHost, renameFolder, setFolderColor, upsertHost,
} from '../lib/tree'
import { resolveStartupCommands } from '../lib/startupPresets'
import { safeInvoke, safeListen } from '../lib/tauri'
import { transfer as runTransfer } from '../lib/sftp'
import { HOST_COLORS, hostColorHex } from '../lib/hostColors'
import { policyFor, useSettings } from '../lib/settings'
import { useDialogs } from '../lib/dialogs'
import { isDangerousCommand } from '../lib/dangerous'
import { clearLocal, emitLocal } from '../lib/localTerm'
import { TitleBar } from './TitleBar'
import { HostSidebar } from './HostSidebar'
import { ResizeHandle } from './ResizeHandle'
import { SessionTabs } from './SessionTabs'
import { Workspace } from './Workspace'
import {
  findRatio,
  leaf,
  reconcile,
  setRatio,
  splitLeaf,
  type LayoutNode,
  type SplitDir,
} from '../lib/paneLayout'
import { StatusBar } from './StatusBar'
import { HostKeyDialog } from './HostKeyDialog'
import { AuthPromptDialog } from './AuthPromptDialog'
import { HostEditor } from './HostEditor'
import { HistoryBrowser } from './HistoryBrowser'
import { SettingsDialog } from './SettingsDialog'
import { TunnelDialog } from './TunnelDialog'
import { FindBar } from './FindBar'
import { TransferBar } from './TransferBar'
import { ContextMenu, type MenuItem, type MenuState } from './ContextMenu'
import { NetToolsDialog } from './NetToolsDialog'
import { AiPanel } from './AiPanel'
import { ConfigHistoryDialog } from './ConfigHistoryDialog'
import { QuickConnect } from './QuickConnect'

/* ---------------------------------------------------------------------------
   AppLayout — the single owner of shell state.

   Structure (vertical), each region fixed except the workspace:

     ┌──────────────────────────────────────────────┐
     │ TitleBar                              32px   │
     ├──────────┬───────────────────────────────────┤
     │ Host     │ SessionTabs                 36px  │
     │ Sidebar  ├───────────────────────────────────┤
     │ (resiz.) │ Workspace  →  Terminal | SFTP     │
     │          │                            flex   │
     ├──────────┴───────────────────────────────────┤
     │ StatusBar                             24px   │
     └──────────────────────────────────────────────┘

   Two layout rules make or break this shell:

   1. Every flex/grid ancestor of a scrollable region carries `min-h-0`
      (or `min-w-0`). Flex items default to `min-height:auto`, which means they
      refuse to shrink below content size and the *window* scrolls instead of
      the pane. This is the #1 source of "why is my terminal pushing the status
      bar off screen".

   2. `overflow:hidden` on body, and exactly one scroll container per region.

   State lives here rather than in a store because the shell is small and the
   flows are all parent-owned. When session state starts being written from the
   Rust event stream (connection status, transfer progress), lift `sessions`
   into Zustand and keep this component purely compositional.
--------------------------------------------------------------------------- */

const SIDEBAR_MIN = 180
const SIDEBAR_MAX = 460
const SIDEBAR_DEFAULT = 260

interface Props {
  /** Seed catalogue, used only when no hosts.json exists yet. */
  hosts: HostNode[]
  initialSessions?: Session[]
}

export function AppLayout({ hosts: seedHosts, initialSessions = [] }: Props) {
  const [hosts, setHosts] = useState<HostNode[]>(seedHosts)
  const [editing, setEditing] = useState<{ host: Host | null } | null>(null)
  const [showHistory, setShowHistory] = useState(false)
  const [showFind, setShowFind] = useState(false)
  const [tunnelFor, setTunnelFor] = useState<Session | null>(null)
  const [netTools, setNetTools] = useState<{ target: string; port: number } | null>(null)
  const [configFor, setConfigFor] = useState<Host | null>(null)
  const [showQuickConnect, setShowQuickConnect] = useState(false)
  const [showAi, setShowAi] = useState(false)
  const [showSettings, setShowSettings] = useState(false)
  /** hostId -> probe outcome from the last reachability sweep. */
  const [reachability, setReachability] = useState<Record<string, { ok: boolean; ms?: number }>>({})
  const [probing, setProbing] = useState(false)
  const [menu, setMenu] = useState<MenuState | null>(null)
  /** Guards the first render from writing the seed back over a real file. */
  const loadedRef = useRef(false)
  const [sessions, setSessions] = useState<Session[]>(initialSessions)
  const [activeId, setActiveId] = useState<string | null>(
    initialSessions[0]?.id ?? null,
  )
  const [sidebarWidth, setSidebarWidth] = useState(SIDEBAR_DEFAULT)
  const [sizes, setSizes] = useState<Record<string, { cols: number; rows: number }>>({})
  /** The pane layout tree per group (tab). Kept here rather than in the deck so
   *  it survives tab switches and view toggles, and reconciled against the live
   *  session set below so a closed or separated pane leaves the tree cleanly. */
  const [layouts, setLayouts] = useState<Record<string, LayoutNode>>({})
  /** Last local/remote path per session, so switching to the terminal and
   *  back does not reset the file panes to root. */
  const [sftpPaths, setSftpPaths] = useState<Record<string, { local?: string; remote?: string }>>({})
  /** In-flight and finished file transfers, keyed globally. Owned here rather
   *  than in SftpView so they survive that component unmounting on a view
   *  switch — the bytes keep moving in Rust either way, and the queue should
   *  keep showing it. */
  const [transfers, setTransfers] = useState<Transfer[]>([])
  /** Bumped when any transfer completes, so the visible SFTP view can
   *  re-read both panes without the user hitting refresh. */
  const [transferTick, setTransferTick] = useState(0)
  /** Live mirrors for callbacks that must stay stable (not re-created on every
   *  state change) yet read the latest value. */
  const sessionsRef = useRef<Session[]>(initialSessions)
  sessionsRef.current = sessions
  const hostsRef = useRef<HostNode[]>(seedHosts)
  hostsRef.current = hosts
  const { settings } = useSettings()
  const settingsRef = useRef(settings)
  settingsRef.current = settings
  const { confirm, alert } = useDialogs()
  const sizesRef = useRef<Record<string, { cols: number; rows: number }>>({})
  sizesRef.current = sizes
  /** Sessions whose PTY has not been requested yet, keyed by session id.
   *  See the note on dialling at the measured size, below. */
  const pendingRef = useRef<
    Map<string, { host: Host; paneIndex: number; oneShotPassword?: string | null }>
  >(new Map())
  /** Hidden <input type=file> that backs "Import hosts". A file input is the
   *  one file-picking primitive the webview gives us without a dialog plugin,
   *  and reading is all import needs. */
  const importInputRef = useRef<HTMLInputElement>(null)

  const active = useMemo(
    () => sessions.find((s) => s.id === activeId),
    [sessions, activeId],
  )

  /** Effective colour of the active session's host (own, else inherited from a
   *  folder), for the wrong-window guard and the AI-off default. */
  const activeColor = useMemo(
    () => (active ? effectiveHostColor(hosts, active.hostId) : undefined),
    [active, hosts],
  )
  const activeAccent = hostColorHex(activeColor)

  /* Remember which hosts were open, so a restart can pick them up again.
     Only host ids and view mode: a TCP connection cannot be serialised, so
     "restore" means reconnect, not resume. Anything that was RUNNING on the
     remote is gone unless it was inside tmux/screen — see the on-connect
     command field. */
  useEffect(() => {
    if (!loadedRef.current) return
    // Persist everything except failed connections. Disconnected sessions are
    // kept on purpose: a dropped link or a dormant-restored tab should come
    // back next launch too, not just live ones. Only 'error' (auth failed, bad
    // host key) is dropped, since re-restoring a doomed connection is noise.
    const open = sessions
      .filter((s) => s.status !== 'error')
      .map((s) => ({ hostId: s.hostId, view: s.view, paneIndex: s.paneIndex }))
    void safeInvoke('sessions_save', { list: open })
  }, [sessions])

  /* Catalogue load. A missing file is a first run, not an error: keep the seed
     and write it out so the next launch has something to read. */
  useEffect(() => {
    void safeInvoke<HostNode[] | null>('hosts_load')
      .then((tree) => {
        if (Array.isArray(tree) && tree.length > 0) setHosts(tree)
        else void safeInvoke('hosts_save', { tree: seedHosts })
      })
      .finally(() => {
        loadedRef.current = true
      })
  }, [seedHosts])

  /* Reopen last session's tabs once the catalogue is in memory. Runs once. */
  const restoredRef = useRef(false)
  useEffect(() => {
    if (restoredRef.current || hosts.length === 0) return
    restoredRef.current = true

    void safeInvoke<
      { hostId: string; view: WorkspaceView; paneIndex?: number }[] | null
    >('sessions_load').then((list) => {
      if (!Array.isArray(list)) return
      list.forEach((entry, i) => {
        const host = findHost(hosts, entry.hostId)
        if (!host) return
        // Restore DORMANT, not connected. Auto-dialling on launch would open SSH
        // sessions to production firewalls the moment the app starts, before the
        // user has decided to touch anything — a bad default for live gear. The
        // tab comes back; the user clicks Reconnect when ready. `-${i}` keeps
        // ids unique when several restore in the same millisecond.
        const sid = `s-${host.id}-${Date.now()}-${i}`
        const session: Session = {
          id: sid,
          hostId: host.id,
          groupId: sid,
          paneIndex: entry.paneIndex ?? 1,
          title: host.name,
          status: 'disconnected',
          view: entry.view ?? 'terminal',
        }
        setSessions((prev) => [...prev, session])
        emitLocal(
          sid,
          `\x1b[38;5;244m${host.name} restored from your last session.\x1b[0m\r\n` +
            `\x1b[38;5;244mNot connected — press Reconnect (status bar) when ready.\x1b[0m\r\n`,
        )
      })
    })
    // openHost/findHost are stable; hosts is the trigger.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hosts])

  const persistHosts = useCallback((next: HostNode[]) => {
    setHosts(next)
    if (loadedRef.current) void safeInvoke('hosts_save', { tree: next })
  }, [])

  /* Byte-progress stream from Rust. Matches rows on (sessionId, path) — the
     backend keys progress by the path it was handed and has no notion of our
     row ids. Mounted once here, so it keeps updating even while SftpView is
     unmounted in terminal view. */
  useEffect(() => {
    const uns: (() => void)[] = []
    let dead = false
    const add = (p: Promise<() => void>) =>
      void p.then((fn) => (dead ? fn() : uns.push(fn)))

    add(
      safeListen<TransferProgressEvent>('sftp://progress', (p) => {
        setTransfers((list) =>
          list.map((t) =>
            t.sessionId === p.sessionId && t.path === p.filePath && t.status === 'active'
              ? { ...t, bytesDone: p.bytesTransferred, bytesTotal: p.totalBytes }
              : t,
          ),
        )
      }),
    )
    // Accumulate per-file failures onto the active folder transfer they belong
    // to (matched by the transfer's source path == the failure's root).
    add(
      safeListen<TransferFailureEvent>('sftp://failure', (f) => {
        setTransfers((list) =>
          list.map((t) =>
            t.sessionId === f.sessionId && t.path === f.root && t.status === 'active'
              ? {
                  ...t,
                  failures: [
                    ...(t.failures ?? []),
                    { name: f.name, local: f.local, remote: f.remote, reason: f.reason },
                  ],
                }
              : t,
          ),
        )
      }),
    )
    return () => {
      dead = true
      uns.forEach((fn) => fn())
    }
  }, [])

  /** Kick off one or more transfers. Runs them sequentially per call so a bulk
   *  selection does not open dozens of concurrent SFTP writes against one
   *  connection — appliances in particular do not love that. */
  const startTransfer = useCallback(
    async (
      sessionId: string,
      direction: 'upload' | 'download',
      jobs: { name: string; local: string; remote: string }[],
    ) => {
      for (const job of jobs) {
        // Progress is reported against the SOURCE path: local for upload,
        // remote for download. Match the row on the same.
        const path = direction === 'upload' ? job.local : job.remote
        const id = `${direction}-${sessionId}-${path}-${performance.now()}`

        setTransfers((t) => [
          {
            id,
            sessionId,
            direction,
            name: job.name,
            path,
            bytesDone: 0,
            bytesTotal: 0,
            status: 'active',
          },
          ...t,
        ])

        try {
          await runTransfer(direction, sessionId, job.local, job.remote)
          setTransfers((t) =>
            t.map((x) =>
              x.id === id ? { ...x, status: 'done', bytesDone: x.bytesTotal || x.bytesDone } : x,
            ),
          )
          setTransferTick((n) => n + 1)
        } catch (e) {
          setTransfers((t) =>
            t.map((x) =>
              x.id === id
                ? { ...x, status: 'error', error: e instanceof Error ? e.message : String(e) }
                : x,
            ),
          )
        }
      }
    },
    [],
  )

  /** Clear finished rows, keep anything still moving. */
  const clearTransfers = useCallback(
    () => setTransfers((t) => t.filter((x) => x.status === 'active')),
    [],
  )

  /** Re-run only the files that failed in a folder transfer. Drops the old
   *  errored row and starts a fresh transfer for the retryable failures (those
   *  with both paths — items skipped by name are not retryable). */
  const retryFailed = useCallback(
    (t: Transfer) => {
      const jobs = (t.failures ?? [])
        .filter((f) => f.local && f.remote)
        .map((f) => ({ name: f.name, local: f.local, remote: f.remote }))
      setTransfers((list) => list.filter((x) => x.id !== t.id))
      if (jobs.length > 0) void startTransfer(t.sessionId, t.direction, jobs)
    },
    [startTransfer],
  )

  /* ---------------------------------------------------------------- actions */

  /** Lowest unused 1-based pane number for a host.
   *
   *  Reuses gaps rather than always incrementing, so closing pane 1 of two and
   *  reopening lands back on `skiff-1` instead of drifting to `skiff-3` and
   *  orphaning tmux sessions on the server forever. */
  const nextPaneIndex = useCallback((hostId: string) => {
    const taken = new Set(
      sessionsRef.current.filter((s) => s.hostId === hostId).map((s) => s.paneIndex),
    )
    let i = 1
    while (taken.has(i)) i += 1
    return i
  }, [])

  /** Open a host.
   *
   *  `force` opens an ADDITIONAL session to a host that already has one. Without
   *  it, double-clicking a host you are already connected to focuses the existing
   *  tab instead of dialling again — which is what people expect, and what the
   *  transcript logs showed was going wrong: every return trip to a host was
   *  silently creating a second connection and a second log file, while the
   *  original tab sat untouched further along the strip. */
  const openHost = useCallback(async (host: Host, force = false, restoredPane?: number) => {
    if (!force) {
      const existing = sessionsRef.current.find(
        (s) => s.hostId === host.id && s.status !== 'disconnected' && s.status !== 'error',
      )
      if (existing) {
        setActiveId(existing.id)
        return
      }
    }

    // Colour policy: prompt before dialing a host whose colour (own or
    // inherited from its folder) is configured to confirm on connect.
    const policy = policyFor(settingsRef.current, effectiveHostColor(hostsRef.current, host.id))
    if (
      policy.confirmConnect &&
      !(await confirm(`Connect to ${host.name} (${host.hostname})?`, { title: 'Connect', confirmLabel: 'Connect' }))
    ) {
      return
    }

    const sid = `s-${host.id}-${Date.now()}`
    const session: Session = {
      id: sid,
      hostId: host.id,
      groupId: sid,
      paneIndex: restoredPane ?? nextPaneIndex(host.id),
      title: host.name,
      status: 'connecting',
      view: 'terminal',
    }
    setSessions((prev) => [...prev, session])
    setActiveId(session.id)

    // Replay the tail of this host's last transcript before connecting.
    //
    // On a device that cannot run tmux — which is most network gear — this is
    // the only continuity available: the box kept nothing, but we did. Dimmed
    // and fenced so it can never be mistaken for live output.
    void safeInvoke<string | null>('session_history', {
      host: host.hostname,
      maxBytes: 12_000,
    }).then((history) => {
      if (!history) return
      emitLocal(
        session.id,
        `\x1b[38;5;240m--- previous session on ${host.name} (history, not live) ---\x1b[0m\r\n` +
          `\x1b[38;5;244m${history.split('\n').join('\r\n')}\x1b[0m` +
          `\x1b[38;5;240m--- end of history ---\x1b[0m\r\n\r\n`,
      )
    })

    // Do NOT dial yet.
    //
    // The PTY is allocated once, at connect, and some programs latch onto that
    // first geometry: tmux sizes its window when a client attaches and a
    // detached session keeps the old size, so opening at 80x24 and resizing
    // afterwards leaves tmux boxed into a corner of the window no matter how
    // large it gets. A plain shell reflows and hides the problem.
    //
    // So the pane mounts first, measures itself, and `reportSize` performs the
    // connect with real dimensions. `connectPending` below is the continuation.
    pendingRef.current.set(session.id, { host, paneIndex: session.paneIndex })

    // Safety net: if the pane never reports (SFTP-first, zero-size layout), dial
    // anyway rather than leaving a tab that silently never connects.
    window.setTimeout(() => {
      if (pendingRef.current.has(session.id)) connectPending(session.id, 80, 24)
    }, 1500)
  }, [nextPaneIndex, confirm])

  /** Performs the deferred connect once a real terminal size is known. */
  const connectPending = useCallback((sessionId: string, cols: number, rows: number) => {
    const entry = pendingRef.current.get(sessionId)
    if (!entry) return
    const { host, paneIndex, oneShotPassword } = entry
    pendingRef.current.delete(sessionId)

    void safeInvoke('ssh_connect', {
      sessionId,
      // Credential sharing: the vault is keyed by this id, so pointing it at
      // another host's id is the whole feature — one entry, many hosts.
      hostId: host.credentialId ?? host.id,
      host: host.hostname,
      port: host.port,
      username: host.username,
      cols,
      rows,
      startupCommands: resolveStartupCommands(host, paneIndex),
      auth: host.auth,
      keyPath: host.keyPath ?? null,
      oneShotPassword: oneShotPassword ?? null,
      // ProxyJump: resolve the bastion's connection details from the
      // catalogue at dial time, so editing the bastion updates every host
      // that rides it. Self-reference and missing hosts degrade to direct.
      jump: (() => {
        if (!host.jumpHostId || host.jumpHostId === host.id) return null
        const j = findHost(hostsRef.current, host.jumpHostId)
        if (!j) return null
        return {
          hostId: j.id,
          host: j.hostname,
          port: j.port,
          username: j.username,
          auth: j.auth,
          keyPath: j.keyPath ?? null,
        }
      })(),
    })
      .then(() =>
        setSessions((prev) =>
          prev.map((s) => (s.id === sessionId ? { ...s, status: 'connected' } : s)),
        ),
      )
      .catch((e: unknown) => {
        setSessions((prev) =>
          prev.map((s) => (s.id === sessionId ? { ...s, status: 'error' } : s)),
        )
        // Write the failure INTO the terminal pane. A release build has no
        // devtools, so console.error here is indistinguishable from the app
        // doing nothing — which is exactly how this looked the first time it
        // ran against a real server: blank pane, blinking cursor, no clue.
        const msg = e instanceof Error ? e.message : String(e)
        emitLocal(sessionId, `\r\n\x1b[38;2;185;139;250m● connection failed\x1b[0m\r\n${msg}\r\n`)
      })
  }, [])

  /** Re-dial a dropped or dormant session, reusing its id so the terminal pane,
   *  scrollback, group, and pane number are all preserved — the pane never
   *  unmounted, only the backend connection went away. Redials at the pane's
   *  last known size (the ResizeObserver will not re-fire for an unchanged box,
   *  so the size must be supplied). */
  const reconnectSession = useCallback((sessionId: string) => {
    const s = sessionsRef.current.find((x) => x.id === sessionId)
    if (!s || s.status === 'connected' || s.status === 'connecting') return
    const host = findHost(hostsRef.current, s.hostId)
    if (!host) {
      // The saved host was deleted while this tab sat disconnected. Say so —
      // a button that silently does nothing reads as a broken button.
      emitLocal(
        sessionId,
        `\r\n\x1b[38;2;242;178;92m● cannot reconnect\x1b[0m the saved host for this tab was deleted\r\n`,
      )
      return
    }

    setSessions((prev) =>
      prev.map((x) => (x.id === sessionId ? { ...x, status: 'connecting' } : x)),
    )
    emitLocal(sessionId, `\r\n\x1b[38;5;244mreconnecting to ${host.name}…\x1b[0m\r\n`)

    pendingRef.current.set(sessionId, { host, paneIndex: s.paneIndex })
    const sz = sizesRef.current[sessionId]
    connectPending(sessionId, sz?.cols ?? 80, sz?.rows ?? 24)
  }, [connectPending])

  const saveHost = useCallback(
    (host: Host) => persistHosts(upsertHost(hosts, host)),
    [hosts, persistHosts],
  )

  const deleteHost = useCallback(
    (hostId: string) => persistHosts(removeHost(hosts, hostId)),
    [hosts, persistHosts],
  )

  /** Closes a whole tab: every pane in that session's group. */
  const closeSession = useCallback(async (id: string) => {
    // Confirm-close guard: if the setting is on and any pane in this tab is
    // still connected, make the user acknowledge before tearing it down.
    if (settingsRef.current.confirmCloseActive) {
      const cur = sessionsRef.current
      const t = cur.find((s) => s.id === id)
      const live = cur
        .filter((s) => (t ? s.groupId === t.groupId : s.id === id))
        .some((s) => s.status === 'connected' || s.status === 'connecting')
      if (
        live &&
        !(await confirm('This tab has a live connection. Close it?', {
          title: 'Close tab',
          confirmLabel: 'Close',
          danger: true,
        }))
      ) {
        return
      }
    }
    setSessions((prev) => {
      const target = prev.find((s) => s.id === id)
      const doomed = new Set(
        target ? prev.filter((s) => s.groupId === target.groupId).map((s) => s.id) : [id],
      )
      doomed.forEach((d) => {
        clearLocal(d)
        void safeInvoke('ssh_disconnect', { sessionId: d })
      })
      const next = prev.filter((s) => !doomed.has(s.id))
      setActiveId((cur) => {
        if (cur && !doomed.has(cur)) return cur
        // Focus the neighbour that took the closed tab's slot, else the last.
        const idx = prev.findIndex((s) => s.id === id)
        return next[Math.min(idx, next.length - 1)]?.id ?? null
      })
      return next
    })
  }, [confirm])

  const setView = useCallback(
    (view: WorkspaceView) =>
      setSessions((prev) =>
        prev.map((s) => (s.id === activeId ? { ...s, view } : s)),
      ),
    [activeId],
  )

  /* Connection lifecycle from the backend. This is the only way the UI learns a
     session died: a dropped VPN or an idle timeout produces no user action, so
     without this the tab keeps its "connected" dot indefinitely. */
  useEffect(() => {
    let un: (() => void) | null = null
    let dead = false

    void safeListen<{ sessionId: string; status: string; detail: string }>(
      'ssh://status',
      (ev) => {
        setSessions((prev) =>
          prev.map((s) =>
            s.id === ev.sessionId
              ? { ...s, status: ev.status === 'disconnected' ? 'disconnected' : 'error' }
              : s,
          ),
        )
      },
    ).then((fn) => {
      if (dead) fn()
      else un = fn
    })

    return () => {
      dead = true
      un?.()
    }
  }, [])

  /** Single click in the sidebar. Focuses the host's live session if it has
   *  one; otherwise does nothing but highlight. Deliberately does NOT connect —
   *  a single click that opens an SSH session to production gear is the kind of
   *  accident that only has to happen once. Double click still connects. */
  const selectHost = useCallback((host: Host) => {
    const existing = sessionsRef.current.find(
      (s) => s.hostId === host.id && s.status !== 'disconnected' && s.status !== 'error',
    )
    if (existing) setActiveId(existing.id)
  }, [])

  /** Sessions sharing the focused session's group, in creation order. */
  const groupSessions = useMemo(
    () => (active ? sessions.filter((s) => s.groupId === active.groupId) : []),
    [sessions, active],
  )

  /** Tab strip entries: one per group, not one per session. */
  const groups = useMemo(() => {
    const byGroup = new Map<string, Session[]>()
    for (const s of sessions) {
      const list = byGroup.get(s.groupId) ?? []
      list.push(s)
      byGroup.set(s.groupId, list)
    }
    return [...byGroup.entries()].map(([id, list]) => ({ id, sessions: list }))
  }, [sessions])

  /* Keep the layout trees in step with the live sessions. A directional split
   *  writes the tree precisely (see splitSession); everything else — a restored
   *  tab, a closed pane, a pane separated into its own tab — only changes the
   *  session set, and this reconciliation folds those in: it drops leaves whose
   *  session is gone and appends any session that has no leaf yet. reconcile
   *  returns the same reference when nothing changed, so this cannot loop. */
  useEffect(() => {
    setLayouts((prev) => {
      const next: Record<string, LayoutNode> = {}
      let changed = false
      for (const g of groups) {
        const tree = reconcile(prev[g.id], g.sessions.map((s) => s.id))
        if (tree) next[g.id] = tree
        if (tree !== prev[g.id]) changed = true
      }
      // A group that lost all its sessions drops out of `next` entirely.
      if (Object.keys(prev).length !== Object.keys(next).length) changed = true
      return changed ? next : prev
    })
  }, [groups])

  /** Open another session to a given session's host, in that session's tab.
   *
   *  Takes the target session id explicitly rather than reading `active`: the
   *  tab context menu fires this for the tab under the cursor, which need not
   *  be the focused one — and a stale closure over `active` was exactly the
   *  bug that made right-click Split act on the wrong tab. */
  const splitSession = useCallback((sessionId: string, dir: SplitDir = 'row') => {
    const target = sessionsRef.current.find((t) => t.id === sessionId)
    if (!target) return
    const host = findHost(hostsRef.current, target.hostId)
    if (!host) return
    const sid = `s-${host.id}-${Date.now()}`
    const session: Session = {
      id: sid,
      hostId: host.id,
      groupId: target.groupId, // the whole point: same tab, second pane
      paneIndex: nextPaneIndex(host.id),
      title: host.name,
      status: 'connecting',
      view: 'terminal',
    }
    setSessions((prev) => [...prev, session])
    // Place the new pane by splitting the focused one, so the split lands exactly
    // where the user is looking rather than tacking on at the end. Reconciliation
    // then sees the leaf already present and leaves it alone.
    setLayouts((prev) => {
      const base = prev[target.groupId] ?? leaf(target.id)
      return { ...prev, [target.groupId]: splitLeaf(base, target.id, sid, dir) }
    })
    setActiveId(sid)
    pendingRef.current.set(sid, { host, paneIndex: session.paneIndex })
    window.setTimeout(() => {
      if (pendingRef.current.has(sid)) connectPending(sid, 80, 24)
    }, 1500)
  }, [connectPending, nextPaneIndex])

  const splitActive = useCallback((dir: SplitDir) => {
    if (activeId) splitSession(activeId, dir)
  }, [activeId, splitSession])

  /** Send a snippet to the focused pane, as if typed. */
  const sendSnippet = useCallback(async (sessionId: string, command: string, autoRun: boolean) => {
    // Dangerous-command guard: a snippet carries a full command, so we can
    // check it before it hits the wire (unlike live keystrokes).
    if (settingsRef.current.dangerousGuard) {
      const reason = isDangerousCommand(command)
      if (
        reason &&
        !(await confirm(`This snippet looks destructive (${reason}). Send it?`, {
          title: 'Destructive snippet',
          confirmLabel: 'Send',
          danger: true,
        }))
      ) {
        return
      }
    }
    const text = autoRun ? `${command}
` : command
    const bytes = Array.from(new TextEncoder().encode(text))
    void safeInvoke('ssh_write', { sessionId, data: bytes }).catch((e: unknown) => {
      const msg = e instanceof Error ? e.message : String(e)
      emitLocal(sessionId, `\r\n\x1b[38;2;242;178;92m● snippet not sent\x1b[0m ${msg}\r\n`)
    })
  }, [confirm])

  /** Quick connect: an ephemeral host, never saved, password (if any) used
   *  once. The session looks like any other; the catalogue never learns. */
  const quickConnect = useCallback(
    (username: string, hostname: string, port: number, password: string | null) => {
      const host: Host = {
        kind: 'host',
        id: `qc-${Date.now().toString(36)}`,
        name: `${username}@${hostname}`,
        hostname,
        port,
        username,
        // With no password given, the agent is the only thing worth trying.
        auth: password ? 'password' : 'agent',
      }
      const sid = `s-${host.id}`
      const session: Session = {
        id: sid,
        hostId: host.id,
        groupId: sid,
        paneIndex: 1,
        title: host.name,
        status: 'connecting',
        view: 'terminal',
      }
      setSessions((prev) => [...prev, session])
      setActiveId(sid)
      pendingRef.current.set(sid, { host, paneIndex: 1, oneShotPassword: password })
      window.setTimeout(() => {
        if (pendingRef.current.has(sid)) connectPending(sid, 80, 24)
      }, 1500)
    },
    [connectPending],
  )

  /** Reachability sweep: one on-demand TCP probe of every host's SSH port.
   *  Never automatic — an app that continuously port-scans the management
   *  network is how you end up in your own IDS alerts. */
  const probeAll = useCallback(async () => {
    setProbing(true)
    try {
      const targets = allHosts(hostsRef.current).map(
        (h) => [h.id, h.hostname, h.port] as [string, string, number],
      )
      const results = await safeInvoke<{ id: string; reachable: boolean; ms?: number }[]>(
        'hosts_probe',
        { targets },
      )
      const map: Record<string, { ok: boolean; ms?: number }> = {}
      for (const r of results ?? []) map[r.id] = { ok: r.reachable, ms: r.ms }
      setReachability(map)
    } finally {
      setProbing(false)
    }
  }, [])

  /** Right-click on a host row in the sidebar. */
  const openHostMenu = useCallback((host: Host, x: number, y: number) => {
    const live = sessionsRef.current.find(
      (t) => t.hostId === host.id && (t.status === 'connected' || t.status === 'connecting'),
    )
    const items: MenuItem[] = [
      { label: 'Connect', onSelect: () => openHost(host) },
      { label: 'Connect in new session', onSelect: () => openHost(host, true) },
      {
        label: 'Focus open session',
        disabled: !live,
        onSelect: () => live && setActiveId(live.id),
      },
      { label: 'Edit host…', dividerBefore: true, onSelect: () => setEditing({ host }) },
      {
        label: 'Copy address',
        onSelect: () => void navigator.clipboard.writeText(`${host.hostname}:${host.port}`),
      },
      {
        label: 'Network tools…',
        dividerBefore: true,
        onSelect: () => setNetTools({ target: host.hostname, port: host.port }),
      },
      {
        label: 'Config snapshots…',
        onSelect: () => setConfigFor(host),
      },
      {
        label: 'Move to folder…',
        onSelect: () => {
          // Second-level menu: same anchor, new items. Cheaper and more
          // keyboard-predictable than nested hover submenus.
          const folders = allFolders(hostsRef.current)
          setMenu({
            x,
            y,
            items: [
              {
                label: '(top level)',
                onSelect: () => persistHosts(moveHost(hostsRef.current, host.id, null)),
              },
              ...folders.map((f) => ({
                label: f.name,
                onSelect: () => persistHosts(moveHost(hostsRef.current, host.id, f.id)),
              })),
            ],
          })
        },
      },
      {
        label: 'Delete host',
        danger: true,
        dividerBefore: true,
        // Deleting from a context menu must not be a single misclick on
        // something that also removes the stored password's referent.
        onSelect: () => {
          void confirm(
            `Delete "${host.name}"? Its saved password is kept in the OS keychain until removed there.`,
            { title: 'Delete host', confirmLabel: 'Delete', danger: true },
          ).then((ok) => {
            if (ok) deleteHost(host.id)
          })
        },
      },
    ]
    setMenu({ x, y, items })
  }, [openHost, deleteHost, persistHosts, confirm])

  /** Right-click on a tab in the strip. */
  const openTabMenu = useCallback((sessionId: string, x: number, y: number) => {
    const s = sessionsRef.current.find((t) => t.id === sessionId)
    if (!s) return
    const host = findHost(hostsRef.current, s.hostId)
    const dead = s.status === 'disconnected' || s.status === 'error'
    const items: MenuItem[] = [
      {
        label: 'Reconnect',
        disabled: !dead,
        onSelect: () => reconnectSession(sessionId),
      },
      {
        label: 'Split (new session, same tab)',
        disabled: !host,
        onSelect: () => splitSession(sessionId),
      },
      {
        label: 'Rename tab…',
        onSelect: () => {
          const next = window.prompt('Tab name', s.title)
          if (next === null) return
          const title = next.trim() || (host?.name ?? s.title)
          setSessions((prev) => prev.map((x) => (x.id === sessionId ? { ...x, title } : x)))
        },
      },
      {
        label: 'Port forwarding…',
        disabled: dead,
        onSelect: () => {
          const cur = sessionsRef.current.find((t) => t.id === sessionId)
          if (cur) setTunnelFor(cur)
        },
      },
      {
        label: 'Capture command output…',
        disabled: dead || !host,
        onSelect: () => {
          const command = window.prompt(
            'Command to run — its full output is saved to a file (e.g. show tech-support):',
          )?.trim()
          if (!command || !host) return
          void safeInvoke<{ path: string; bytes: number; lines: number }>('capture_output', {
            sessionId,
            host: host.name,
            command,
          })
            .then((r) => {
              if (r) void alert(`Saved ${r.lines} line(s), ${r.bytes} bytes to:\n${r.path}`)
            })
            .catch((e) => void alert(`Capture failed: ${e instanceof Error ? e.message : e}`))
        },
      },
      { label: 'Close tab', danger: true, dividerBefore: true, onSelect: () => closeSession(sessionId) },
    ]
    setMenu({ x, y, items })
  }, [reconnectSession, splitSession, closeSession])

  /** Right-click on a folder row in the sidebar. */
  const openFolderMenu = useCallback((folderId: string, name: string, x: number, y: number) => {
    setMenu({
      x,
      y,
      items: [
        {
          label: 'Rename folder…',
          onSelect: () => {
            const next = window.prompt('Folder name', name)
            if (next?.trim()) persistHosts(renameFolder(hostsRef.current, folderId, next.trim()))
          },
        },
        {
          label: 'Set color…',
          onSelect: () => {
            // Second-level menu at the same anchor — same pattern as move-to.
            setMenu({
              x,
              y,
              items: HOST_COLORS.map((c) => ({
                label: c.label,
                onSelect: () =>
                  persistHosts(setFolderColor(hostsRef.current, folderId, c.key)),
              })),
            })
          },
        },
        {
          label: 'Delete folder (keep hosts)',
          danger: true,
          dividerBefore: true,
          // Children are promoted, never deleted — so no confirm needed: the
          // destructive-looking action cannot actually lose a host.
          onSelect: () => persistHosts(removeFolder(hostsRef.current, folderId)),
        },
      ],
    })
  }, [persistHosts])

  /** App menu from the title bar — the discoverable home for everything that
   *  was previously only reachable by knowing where to click. */
  const openAppMenu = useCallback((x: number, y: number) => {
    const items: MenuItem[] = [
      { label: 'Quick connect… Ctrl+Shift+P', onSelect: () => setShowQuickConnect(true) },
      { label: 'Network tools…', onSelect: () => setNetTools({ target: '', port: 22 }) },
      { label: 'AI assistant… Ctrl+Shift+A', onSelect: () => setShowAi(true) },
      { label: 'Settings…', onSelect: () => setShowSettings(true) },
      { label: 'New host…', dividerBefore: true, onSelect: () => setEditing({ host: null }) },
      {
        label: 'New folder…',
        onSelect: () => {
          const name = window.prompt('Folder name')
          if (name?.trim()) persistHosts(addFolder(hostsRef.current, name.trim()))
        },
      },
      { label: 'Session history…', onSelect: () => setShowHistory(true) },
      {
        label: 'Export hosts…',
        dividerBefore: true,
        onSelect: () =>
          void safeInvoke<string>('hosts_export')
            .then((p) => {
              if (p) void alert(`Host catalogue exported to:
${p}

Passwords are NOT included — they stay in Windows Credential Manager.`)
            })
            .catch((err) =>
              void alert(`Export failed: ${err instanceof Error ? err.message : err}`),
            ),
      },
      {
        label: 'Import hosts…',
        onSelect: () => importInputRef.current?.click(),
      },
      {
        label: 'Open logs folder',
        onSelect: () => void safeInvoke('open_logs_folder'),
      },
      {
        label: 'Close current tab',
        dividerBefore: true,
        disabled: !activeId,
        onSelect: () => activeId && closeSession(activeId),
      },
    ]
    setMenu({ x, y, items })
  }, [activeId, closeSession, persistHosts])

  /** Right-click on the host sidebar's empty area: the fast path to a new
   *  connection without hunting for the "+" button. */
  const openSidebarMenu = useCallback((x: number, y: number) => {
    const items: MenuItem[] = [
      { label: 'New Connection…', onSelect: () => setEditing({ host: null }) },
      {
        label: 'New Folder…',
        onSelect: () => {
          const name = window.prompt('Folder name')
          if (name?.trim()) persistHosts(addFolder(hostsRef.current, name.trim()))
        },
      },
    ]
    setMenu({ x, y, items })
  }, [persistHosts])

  /** Move a pane out of its group and into a tab of its own.
   *
   *  Uses a FRESH group id, not the session's own id: a tab's group id is its
   *  first pane's id, so `groupId = s.id` would be a no-op for that anchor pane —
   *  it would silently stay in the split. A unique id separates any pane. */
  const separateSession = useCallback((sessionId: string) => {
    const newGid = `grp-${Date.now().toString(36)}-${sessionId}`
    setSessions((prev) =>
      prev.map((s) => (s.id === sessionId ? { ...s, groupId: newGid } : s)),
    )
    setActiveId(sessionId)
  }, [])

  /** Close a single pane (one session), leaving the rest of its tab to re-tile.
   *  The tab-level closeSession still closes every pane at once.
   *
   *  No confirm here on purpose: closing one pane of a split is low-stakes and
   *  instantly redone (reconnect), the way iTerm/VS Code close a pane without a
   *  prompt — and it keeps this off the synchronous window.confirm path, which is
   *  unreliable inside the webview. The whole-tab close keeps its guard. */
  const closePane = useCallback((sessionId: string) => {
    clearLocal(sessionId)
    void safeInvoke('ssh_disconnect', { sessionId })
    setSessions((prev) => {
      const closed = prev.find((s) => s.id === sessionId)
      const next = prev.filter((s) => s.id !== sessionId)
      setActiveId((cur) => {
        if (cur && cur !== sessionId) return cur
        // Prefer a sibling in the same tab, so closing a pane keeps you in that
        // tab rather than jumping away; else fall back to any remaining session.
        const sib = closed && next.find((s) => s.groupId === closed.groupId)
        return (sib ?? next[next.length - 1])?.id ?? null
      })
      return next
    })
  }, [])

  /** The active tab's layout tree. Falls back to a single leaf for the focused
   *  session on the one frame before the reconcile effect has populated it. */
  const activeLayout: LayoutNode | null = active
    ? (layouts[active.groupId] ?? leaf(active.id))
    : null

  /** Groups currently broadcasting input to all their panes. Cleared when a
   *  group drops to one pane, so a stale broadcast flag can't linger. */
  const [broadcastGroups, setBroadcastGroups] = useState<Set<string>>(new Set())
  const broadcast = active ? broadcastGroups.has(active.groupId) : false
  /** Sessions whose colour policy keeps them out of broadcast-to-panes. */
  const broadcastExcluded = useMemo(() => {
    const s = new Set<string>()
    for (const sess of sessions) {
      if (policyFor(settings, effectiveHostColor(hosts, sess.hostId)).excludeFromBroadcast) {
        s.add(sess.id)
      }
    }
    return s
  }, [sessions, hosts, settings])

  const toggleBroadcast = useCallback(() => {
    if (!active) return
    setBroadcastGroups((prev) => {
      const next = new Set(prev)
      next.has(active.groupId) ? next.delete(active.groupId) : next.add(active.groupId)
      return next
    })
  }, [active])

  /** Move a divider: nudge one split's ratio by a fraction of its own extent.
   *
   *  The delta is already normalised to the split (dPx / extentPx in the deck),
   *  so a split holds its proportions when the window resizes — dragging to
   *  70/30 and then maximising stays 70/30 rather than snapping back. */
  const resizeSplit = useCallback(
    (splitId: string, ratioDelta: number) => {
      if (!active) return
      setLayouts((prev) => {
        const tree = prev[active.groupId]
        if (!tree || tree.t !== 'split') return prev
        // Walk once to read the current ratio, then set the absolute value; the
        // helper clamps so neither side collapses.
        const cur = findRatio(tree, splitId)
        if (cur == null) return prev
        return { ...prev, [active.groupId]: setRatio(tree, splitId, cur + ratioDelta) }
      })
    },
    [active],
  )

  /** Double-click a divider: reset that split to an even 50/50. */
  const resetSplit = useCallback(
    (splitId: string) => {
      if (!active) return
      setLayouts((prev) => {
        const tree = prev[active.groupId]
        if (!tree || tree.t !== 'split') return prev
        return { ...prev, [active.groupId]: setRatio(tree, splitId, 0.5) }
      })
    },
    [active],
  )

  const openHostIds = useMemo(
    () =>
      new Set(
        sessions
          .filter((s) => s.status !== 'disconnected' && s.status !== 'error')
          .map((s) => s.hostId),
      ),
    [sessions],
  )

  const reportSize = useCallback(
    (sessionId: string, cols: number, rows: number) => {
      setSizes((prev) => ({ ...prev, [sessionId]: { cols, rows } }))
      // First real measurement for a session that has not dialled yet.
      connectPending(sessionId, cols, rows)
    },
    [connectPending],
  )

  const cycleTab = useCallback(
    (dir: 1 | -1) =>
      setActiveId((cur) => {
        if (sessions.length === 0) return cur
        const i = sessions.findIndex((s) => s.id === cur)
        return sessions[(i + dir + sessions.length) % sessions.length].id
      }),
    [sessions],
  )

  /* ------------------------------------------------------------- shortcuts */

  // Every shell shortcut is Ctrl+SHIFT+<key>, and that is not cosmetic.
  // A focused terminal forwards plain Ctrl chords to the remote shell, where
  // readline already owns them: Ctrl+W deletes a word, Ctrl+T transposes
  // characters, Ctrl+K kills to end of line, Ctrl+/ is undo. Binding tab
  // management to those would quietly break line editing over SSH. Terminals
  // cannot encode Ctrl+Shift+<letter> distinctly, so that space is free for the
  // UI — the same reason Windows Terminal and VS Code use it.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!e.ctrlKey || e.altKey) return

      // Ctrl+Tab cycles tabs; Shift reverses. Not a readline binding.
      if (e.key === 'Tab') {
        e.preventDefault()
        cycleTab(e.shiftKey ? -1 : 1)
        return
      }

      // Ctrl+1..9 jumps to a tab by ordinal — also unclaimed by readline.
      const n = Number(e.key)
      if (!e.shiftKey && Number.isInteger(n) && n >= 1 && n <= 9 && sessions[n - 1]) {
        e.preventDefault()
        setActiveId(sessions[n - 1].id)
        return
      }

      if (!e.shiftKey) return

      // Ctrl+Shift+<digit>: the focused host's snippet in that slot. Uses
      // e.code (Digit1..Digit9) because Shift+1 produces "!" in e.key.
      const slotMatch = /^Digit([1-9])$/.exec(e.code)
      if (slotMatch && activeId) {
        const cur = sessionsRef.current.find((t) => t.id === activeId)
        const host = cur && findHost(hostsRef.current, cur.hostId)
        const snip = host?.snippets?.find((sn) => sn.slot === Number(slotMatch[1]))
        if (snip) {
          e.preventDefault()
          sendSnippet(activeId, snip.command, snip.autoRun ?? false)
        }
        return
      }

      switch (e.code) {
        case 'KeyA': // AI assistant panel
          e.preventDefault()
          setShowAi((v) => !v)
          break
        case 'KeyP': // quick connect
          e.preventDefault()
          setShowQuickConnect(true)
          break
        case 'KeyF': // find in the focused terminal
          if (!activeId) break
          e.preventDefault()
          setShowFind(true)
          break
        case 'KeyE': // toggle Terminal <-> Files
          e.preventDefault()
          setView(active?.view === 'terminal' ? 'sftp' : 'terminal')
          break
        case 'KeyW':
          if (!activeId) break
          e.preventDefault()
          closeSession(activeId)
          break
        default:
          break
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [active?.view, activeId, sessions, setView, closeSession, cycleTab, sendSnippet])

  /* ---------------------------------------------------------------- render */

  return (
    <div className="relative flex h-full min-h-0 flex-col overflow-hidden bg-surface-0">
      <TitleBar subtitle={active?.title} onMenu={openAppMenu} />

      <div className="flex min-h-0 flex-1">
        <HostSidebar
          hosts={hosts}
          width={sidebarWidth}
          onOpenHost={openHost}
          onSelectHost={selectHost}
          onAddHost={() => setEditing({ host: null })}
          onEditHost={(h) => setEditing({ host: h })}
          onOpenHistory={() => setShowHistory(true)}
          onHostMenu={openHostMenu}
          onFolderMenu={openFolderMenu}
          onSidebarMenu={openSidebarMenu}
          onProbe={() => void probeAll()}
          probing={probing}
          reachability={reachability}
          openHostIds={openHostIds}
          activeHostId={active?.hostId}
        />

        <ResizeHandle
          aria-label="Resize sidebar"
          onReset={() => setSidebarWidth(SIDEBAR_DEFAULT)}
          onResize={(dx) =>
            setSidebarWidth((w) =>
              Math.min(SIDEBAR_MAX, Math.max(SIDEBAR_MIN, w + dx)),
            )
          }
        />

        {/* min-w-0 here stops a long terminal line from widening the whole
            shell and squashing the sidebar. */}
        <main className="flex min-h-0 min-w-0 flex-1 flex-col">
          <SessionTabs
            groups={groups}
            activeId={activeId}
            onTabMenu={openTabMenu}
            onSelect={setActiveId}
            onClose={closeSession}
            onNew={() => {
              // With no quick-connect UI yet, the most useful meaning of "+" is
              // a second session to the host you are already on. With nothing
              // open there is no host to duplicate, so offer to define one.
              const current = active && findHost(hosts, active.hostId)
              if (current) openHost(current, true)
              else setEditing({ host: null })
            }}
          />
          <Workspace
            sessions={sessions}
            session={active}
            onChangeView={setView}
            onSize={reportSize}
            groupSessions={groupSessions}
            onFocusSession={setActiveId}
            onSplit={splitActive}
            onSeparate={separateSession}
            onClosePane={closePane}
            layout={activeLayout}
            onResizeSplit={resizeSplit}
            onResetSplit={resetSplit}
            onStartTransfer={startTransfer}
            sftpPaths={sftpPaths}
            onSftpPathsChange={setSftpPaths}
            transferTick={transferTick}
            accentHex={activeAccent}
            broadcast={broadcast}
            broadcastExcluded={broadcastExcluded}
            onToggleBroadcast={toggleBroadcast}
          />
        </main>

        {showAi && (
          <AiPanel
            session={active}
            host={active ? findHost(hosts, active.hostId) : undefined}
            effectiveColor={activeColor}
            onClose={() => setShowAi(false)}
          />
        )}
      </div>

      <TransferBar transfers={transfers} onClear={clearTransfers} onRetry={retryFailed} />

      <StatusBar
        session={active}
        hostCount={countHosts(hosts)}
        size={activeId ? sizes[activeId] : undefined}
        onReconnect={activeId ? () => reconnectSession(activeId) : undefined}
      />

      {/* Rendered at the shell root so the modal covers the whole window; it
          self-hides until the backend raises a prompt. */}
      <HostKeyDialog />
      <AuthPromptDialog />

      {showHistory && <HistoryBrowser onClose={() => setShowHistory(false)} />}

      {showSettings && <SettingsDialog onClose={() => setShowSettings(false)} />}

      <ContextMenu menu={menu} onClose={() => setMenu(null)} />

      <input
        ref={importInputRef}
        type="file"
        accept=".json,application/json"
        className="hidden"
        onChange={(e) => {
          const file = e.target.files?.[0]
          e.target.value = '' // same file can be picked again later
          if (!file) return
          void file.text().then((text) => {
            try {
              const tree = JSON.parse(text) as HostNode[]
              // Minimal shape check: an array whose entries look like nodes.
              // Merging is deliberate — import ADDS to the catalogue rather
              // than replacing it, so a bad file cannot wipe existing hosts.
              if (!Array.isArray(tree) || tree.some((n) => typeof n !== 'object' || !('kind' in n))) {
                throw new Error('not a Skiff host export')
              }
              // Colliding ids (importing the same export twice, or an export
              // from this machine) get fresh ids at every depth, so a re-import
              // can never corrupt the tree or silently drop nested hosts.
              const fresh = reidentify(tree, hostsRef.current)
              persistHosts([...hostsRef.current, ...fresh])
              void alert(`Imported ${fresh.length} top-level entr${fresh.length === 1 ? 'y' : 'ies'}. Passwords are never in exports — set them per host after importing.`)
            } catch (err) {
              void alert(`Import failed: ${err instanceof Error ? err.message : err}`)
            }
          })
        }}
      />

      {netTools && (
        <NetToolsDialog
          initialTarget={netTools.target}
          initialPort={netTools.port}
          onClose={() => setNetTools(null)}
        />
      )}

      {configFor && (
        <ConfigHistoryDialog
          host={configFor}
          liveSessionId={
            sessions.find(
              (t) => t.hostId === configFor.id && t.status === 'connected',
            )?.id ?? null
          }
          onClose={() => setConfigFor(null)}
        />
      )}

      {showQuickConnect && (
        <QuickConnect onConnect={quickConnect} onClose={() => setShowQuickConnect(false)} />
      )}

      {tunnelFor && (
        <TunnelDialog
          sessionId={tunnelFor.id}
          sessionTitle={tunnelFor.title}
          onClose={() => setTunnelFor(null)}
        />
      )}

      {showFind && activeId && (
        <FindBar sessionId={activeId} onClose={() => setShowFind(false)} />
      )}

      {editing && (
        <HostEditor
          host={editing.host}
          catalogue={hosts}
          onSave={saveHost}
          onDelete={deleteHost}
          onClose={() => setEditing(null)}
        />
      )}
    </div>
  )
}
