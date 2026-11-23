import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { DialIdentity, Host, HostNode, Session, Transfer, TransferProgressEvent, TransferFailureEvent, WorkspaceView } from '../types'
import {
  addFolder, allFolders, allHosts, bindingChanged, catalogueProblem, countHosts,
  findHost, isBorrowed, moveHost, NarrowQueue, reidentify, sanitizeImport, setVaultFoldsCase,
  effectiveHostColor, removeFolder, removeHost, renameFolder, setFolderColor, upsertHost,
  jumpDependents, folderLabels,
} from '../lib/tree'
import { anyModalOpen } from '../lib/modalStack'
import { appShortcut } from '../lib/keyChords'
import { snippetText } from '../lib/termInput'
import { getTerm } from '../lib/termRegistry'
import { closeConfirmText } from '../lib/closeGuard'
import { setLocalRoot } from '../lib/localPath'
import { resolveStartupCommands } from '../lib/startupPresets'
import { inTauri, safeInvoke, safeListen } from '../lib/tauri'
import { transfer as runTransfer, cancelTransfer } from '../lib/sftp'
import {
  applyFailure, applyProgress, canRetry, clearFinished, markActive, markCancelled, markDone,
  markFailed, newTransferId, queuedRow, retryJobs, type TransferJob,
} from '../lib/transfers'
import { HOST_COLORS, hostColorHex } from '../lib/hostColors'
import { policyFor, useSettings } from '../lib/settings'
import { useDialogs } from '../lib/dialogs'
import { isDangerousCommand } from '../lib/dangerous'
import { clearLocal, emitLocal } from '../lib/localTerm'
import { ReplyGuard } from '../lib/replyGuard'
import { endpointKey } from '../lib/endpoint'
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
import { AuditDialog } from './AuditDialog'
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

/** A session id embedding a host id. Tauri event names allow only
 *  alphanumerics and - / : _, and the id becomes the `ssh://<id>` output topic,
 *  so an imported host id like `core.sw1` or `fw 01` would otherwise leave the
 *  pane silently blank. */
function sessionIdFor(hostId: string, ...suffix: (string | number)[]): string {
  return ['s', hostId.replace(/[^A-Za-z0-9_-]/g, '_'), ...suffix].join('-')
}

const SIDEBAR_MIN = 180
const SIDEBAR_MAX = 460
const SIDEBAR_DEFAULT = 260

/** What `config_check` reports (utils::configs::ConfigCheck). */
interface ConfigCheckResult {
  /** The endpoint identity the backend actually snapshotted: the identity of
   *  the connection it ran on, which a reconnect can have replaced since the
   *  request was made. Routes the notice. */
  endpoint?: string
  status: 'first' | 'unchanged' | 'changed'
  name: string | null
  previous: string | null
  previousModified: number | null
  added: number
  removed: number
}

interface Props {
  /** Seed catalogue, used only when no hosts.json exists yet. */
  hosts: HostNode[]
  initialSessions?: Session[]
}

export function AppLayout({ hosts: seedHosts, initialSessions = [] }: Props) {
  const [hosts, setHosts] = useState<HostNode[]>(seedHosts)
  const [editing, setEditing] = useState<{ host: Host | null } | null>(null)
  const [showHistory, setShowHistory] = useState(false)
  const [showAudit, setShowAudit] = useState(false)
  const [showFind, setShowFind] = useState(false)
  /** Bumped by each Ctrl+Shift+F, so an open find bar re-focuses its input. */
  const [findNonce, setFindNonce] = useState(0)
  const [tunnelFor, setTunnelFor] = useState<Session | null>(null)
  const [netTools, setNetTools] = useState<{ target: string; port: number } | null>(null)
  /** Config History target: the host (labels, capture command), the
   *  endpoint identity whose snapshots to show, and the live session to run
   *  lookups through, if one is connected to exactly that endpoint. */
  const [configFor, setConfigFor] = useState<
    { host: Host; endpoint: string; liveSessionId: string | null } | null
  >(null)
  /** Snapshots to preselect when the config dialog opens from the change chip. */
  const [configSelect, setConfigSelect] = useState<string[] | undefined>(undefined)
  /** Per session: what the on-connect config check found, when it found a change. */
  const [configChanges, setConfigChanges] = useState<
    Record<
      string,
      { hostId: string; endpoint: string; added: number; removed: number; previous: string; name: string }
    >
  >({})
  /** Endpoint identity → when its config was last checked, so split panes and
   *  quick reconnects to one box don't each run the capture command again. */
  const configCheckedRef = useRef(new Map<string, number>())
  /** Latest config check per session. Every (re)connect invalidates it, so a
   *  reply from before a redial — or for a closed tab — is ignored. */
  const configReplies = useRef(new ReplyGuard())
  /** Endpoint identity → a "changed" result whose reply arrived after its tab
   *  was closed or redialled. The backend had already saved it as the new
   *  baseline, so dropping it lost the change for good; it is shown on the
   *  next connect. Keyed by identity (lib/endpoint), not host id: once the
   *  entry is repointed at another device, a late result about the old one
   *  must not be reported as this device's change.
   *
   *  In memory only: an app exit after the backend saved the change but
   *  before the reply was delivered still loses the notice (the snapshot
   *  itself is on disk and shows in Config history). */
  const undeliveredChangeRef = useRef(new Map<string, ConfigCheckResult>())
  /** Session id → the endpoint identity its current connection dialled, as
   *  ssh_connect reported it. Lets a late config result find a tab by what it
   *  is actually connected to, not what its catalogue entry says now. */
  const dialledRef = useRef(new Map<string, DialIdentity>())
  const [showQuickConnect, setShowQuickConnect] = useState(false)
  const [showAi, setShowAi] = useState(false)
  const [showSettings, setShowSettings] = useState(false)
  /** hostId -> probe outcome from the last reachability sweep. */
  const [reachability, setReachability] = useState<Record<string, { ok: boolean; ms?: number }>>({})
  const [probing, setProbing] = useState(false)
  const [menu, setMenu] = useState<MenuState | null>(null)
  /** Guards the first render from writing the seed back over a real file. */
  const loadedRef = useRef(false)
  /** State twin of loadedRef, so the session-restore effect can wait for the
   *  real catalogue instead of running against the seed. */
  const [catalogueLoaded, setCatalogueLoaded] = useState(false)
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
  /** Rows the user cancelled; a queued job checks this before it starts. */
  const cancelledRef = useRef<Set<string>>(new Set())
  /** Bumped when any transfer completes, so the visible SFTP view can
   *  re-read both panes without the user hitting refresh. */
  const [transferTick, setTransferTick] = useState(0)
  /** Live mirrors for callbacks that must stay stable (not re-created on every
   *  state change) yet read the latest value. */
  const sessionsRef = useRef<Session[]>(initialSessions)
  sessionsRef.current = sessions
  const hostsRef = useRef<HostNode[]>(seedHosts)
  hostsRef.current = hosts
  /** Endpoint identity for transcripts, AI context, snapshots and captures
   *  (lib/endpoint), with the bastion resolved exactly as the dialer does. */
  const endpointFor = useCallback(
    (h: Host) => endpointKey(h, (id) => findHost(hostsRef.current, id)),
    [],
  )
  const { settings, ready: settingsReady, loadError: settingsLoadError, saveError: settingsSaveError } =
    useSettings()
  const settingsRef = useRef(settings)
  settingsRef.current = settings
  const { confirm, alert, prompt } = useDialogs()
  const sizesRef = useRef<Record<string, { cols: number; rows: number }>>({})
  sizesRef.current = sizes
  /** Sessions whose PTY has not been requested yet, keyed by session id.
   *  See the note on dialling at the measured size, below. */
  const pendingRef = useRef<
    Map<string, { host: Host; paneIndex: number; oneShotPassword?: string | null }>
  >(new Map())
  /** Quick-connect hosts, which never enter the catalogue, keyed by host id —
   *  so a quick-connect tab can still be reconnected or split. Never holds the
   *  one-shot password; a reconnect asks for it again. */
  const ephemeralHostsRef = useRef<Map<string, Host>>(new Map())
  /** Catalogue lookup that also knows quick-connect hosts. */
  const lookupHost = useCallback(
    (hostId: string) => findHost(hostsRef.current, hostId) ?? ephemeralHostsRef.current.get(hostId),
    [],
  )
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

  /* Settings that failed to load or save are said out loud once each (the
     Settings dialog keeps a banner, and the way to save anyway). */
  useEffect(() => {
    if (!settingsLoadError) return
    void alert(
      `Your settings could not be read, so the defaults are in use and changes will not be saved this session (open Settings to save over the file).\n\n${settingsLoadError}`,
      { title: 'Settings not loaded' },
    )
  }, [settingsLoadError, alert])
  useEffect(() => {
    if (!settingsSaveError) return
    void alert(`Your settings change could not be saved, and lasts only until Hawser closes.\n\n${settingsSaveError}`, {
      title: 'Settings not saved',
    })
  }, [settingsSaveError, alert])

  /* Remember which hosts were open, so a restart can pick them up again.
     Only host ids and view mode: a TCP connection cannot be serialised, so
     "restore" means reconnect, not resume. Anything that was RUNNING on the
     remote is gone unless it was inside tmux/screen — see the on-connect
     command field. */
  /** Set once sessions.json has been read (or found absent/unreadable): a
   *  save before then could write [] over the tabs it was about to restore
   *  (a startup local shell reaching "connected" was enough). */
  const [tabsRestored, setTabsRestored] = useState(false)
  /** A sessions save failed and the user was told; cleared by the next success. */
  const sessionsSaveFailedRef = useRef(false)
  useEffect(() => {
    if (!loadedRef.current || !tabsRestored) return
    // Persist everything except failed connections. Disconnected sessions are
    // kept on purpose: a dropped link or a dormant-restored tab should come
    // back next launch too, not just live ones. Only 'error' (auth failed, bad
    // host key) is dropped, since re-restoring a doomed connection is noise.
    // Local terminals are left out too: they are not catalogue hosts, so they
    // could never be restored (the "open at startup" setting covers them).
    const open = sessions
      .filter((s) => s.status !== 'error' && !s.hostId.startsWith('local-'))
      .map((s) => ({ hostId: s.hostId, view: s.view, paneIndex: s.paneIndex }))
    void safeInvoke('sessions_save', { list: open })
      .then(() => {
        sessionsSaveFailedRef.current = false
      })
      .catch((e) => {
        if (sessionsSaveFailedRef.current) return
        sessionsSaveFailedRef.current = true
        void alert(
          `Your open tabs could not be saved, so they will not be restored next time unless a later save succeeds.\n\n${e instanceof Error ? e.message : e}`,
          { title: 'Open tabs not saved' },
        )
      })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessions, tabsRestored])

  /* Catalogue load. Only a MISSING file (the backend's null) is a first run:
     keep the seed and write it out. A file that exists but cannot be read,
     decoded or parsed, or whose entries are malformed, is an error: the demo
     hosts are NOT shown, nothing is saved this session (so the real file can
     never be overwritten), and the user is told where the file and its backup
     copy are. The backend keeps that copy; the file itself is left alone. */
  useEffect(() => {
    // Where the local file pane starts (the system drive on Windows).
    void safeInvoke<string>('local_root').then(setLocalRoot).catch(() => {})
    // How the OS vault compares credential ids (folds case on Windows).
    void safeInvoke<boolean>('vault_id_rule')
      .then((f) => {
        if (typeof f === 'boolean') setVaultFoldsCase(f)
      })
      .catch(() => {})
    const failed = (why: string) => {
      setHosts([])
      // Nothing to restore against; startup actions waiting on it may run.
      setTabsRestored(true)
      void alert(
        `Your saved hosts could not be loaded, so none are shown and changes will NOT be saved until this is fixed (restart Hawser after repairing the file).\n\n${why}`,
        { title: 'Host catalogue not loaded' },
      )
    }
    const loaded = () => {
      loadedRef.current = true
      setCatalogueLoaded(true)
    }
    const load = (retry: boolean) =>
      void safeInvoke<unknown>('hosts_load')
        .then(async (tree) => {
          if (tree === undefined) {
            loaded() // no backend (browser preview)
            return
          }
          if (tree === null) {
            // First run: seed. An EMPTY saved list is the user's choice (they
            // deleted every host), not a first run. The seed is created only
            // if no file exists; one that appeared meanwhile is loaded.
            try {
              const created = await safeInvoke<boolean>('hosts_seed', { tree: seedHosts })
              if (created === false && retry) {
                load(false)
                return
              }
            } catch (e) {
              void alert(`Could not save the host catalogue: ${e instanceof Error ? e.message : e}`)
            }
            loaded()
            return
          }
          const problem = catalogueProblem(tree)
          if (problem) {
            // The backend's JSON check passed, so it kept no copy: keep one now.
            const copy = await safeInvoke<string | null>('hosts_keep_backup').then(
              (p) => (p ? ` A copy of it was kept at ${p}.` : ''),
              (e) => ` (No copy could be kept: ${e instanceof Error ? e.message : e}.)`,
            )
            failed(`hosts.json is not a valid host catalogue: ${problem}. It was left in place.${copy}`)
            return
          }
          setHosts(tree as HostNode[])
          loaded()
        })
        .catch((e) => failed(e instanceof Error ? e.message : String(e)))
    load(true)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [seedHosts])

  /* Reopen last session's tabs once the REAL catalogue is in memory. Runs
     once. Gated on the load finishing, not on hosts being non-empty: the seed
     is non-empty too, and restoring against it dropped every real host's tab
     (and the next save then overwrote sessions.json). */
  const restoredRef = useRef(false)
  useEffect(() => {
    if (restoredRef.current || !catalogueLoaded) return
    restoredRef.current = true

    void safeInvoke<
      { hostId: string; view: WorkspaceView; paneIndex?: number }[] | null
    >('sessions_load').then((list) => {
      if (!Array.isArray(list)) return
      const restored: Session[] = []
      list.forEach((entry, i) => {
        const host = findHost(hostsRef.current, entry.hostId)
        if (!host) return
        // Restore DORMANT, not connected. Auto-dialling on launch would open SSH
        // sessions to production firewalls the moment the app starts, before the
        // user has decided to touch anything — a bad default for live gear. The
        // tab comes back; the user clicks Reconnect when ready. `-${i}` keeps
        // ids unique when several restore in the same millisecond.
        const sid = sessionIdFor(host.id, Date.now(), i)
        const session: Session = {
          id: sid,
          hostId: host.id,
          groupId: sid,
          paneIndex: entry.paneIndex ?? 1,
          title: host.name,
          status: 'disconnected',
          view: entry.view ?? 'terminal',
        }
        restored.push(session)
        emitLocal(
          sid,
          `\x1b[38;5;244m${host.name} restored from your last session.\x1b[0m\r\n` +
            `\x1b[38;5;244mNot connected — press Reconnect (status bar) when ready.\x1b[0m\r\n`,
        )
      })
      if (restored.length === 0) return
      // Restored tabs come first in the strip, ahead of anything opened while
      // the load ran (a startup local shell), and one of them is selected so
      // the workspace never shows "No active session" beside a full strip.
      setSessions((prev) => [...restored, ...prev])
      setActiveId((cur) => cur ?? restored[0].id)
    })
      .catch((e) => {
        // Unreadable sessions.json: nothing to restore. Saving stays on (the
        // next save replaces it), but the user hears why the tabs are gone.
        void alert(`Your last session's tabs could not be restored: ${e instanceof Error ? e.message : e}`, {
          title: 'Tabs not restored',
        })
      })
      .finally(() => setTabsRestored(true))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [catalogueLoaded])

  /** Last save failure already reported, so a run of failing saves (a full
   *  disk) does not stack one dialog per edit. Cleared by the next success. */
  const saveFailedRef = useRef(false)
  /** Vault ids whose binding must shrink to the hosts that still use them.
   *  Sent with the catalogue save, which narrows them first and saves only
   *  if that worked; kept until a save that carried them succeeds. */
  const narrowQueueRef = useRef(new NarrowQueue())
  const persistHosts = useCallback((next: HostNode[], narrow: string[] = []) => {
    setHosts(next)
    const queue = narrowQueueRef.current
    queue.add(narrow)
    if (!loadedRef.current) return
    const batch = queue.take()
    safeInvoke('hosts_save', { tree: next, narrow: [...batch.keys()] })
      .then(() => {
        queue.settle(batch)
        saveFailedRef.current = false
      })
      .catch((e) => {
        if (saveFailedRef.current) return
        saveFailedRef.current = true
        void alert(
          `Your change to the host list could not be saved, and will be lost when Hawser closes unless a later save succeeds.\n\n${e instanceof Error ? e.message : e}`,
          { title: 'Hosts not saved' },
        )
      })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  /* Byte-progress and per-file failure streams from Rust, matched on the
     transfer id each row was started with (see lib/transfers.ts). Mounted
     once here, so they keep updating even while SftpView is unmounted in
     terminal view. */
  useEffect(() => {
    const uns: (() => void)[] = []
    let dead = false
    const add = (p: Promise<() => void>) =>
      void p.then((fn) => (dead ? fn() : uns.push(fn)))

    add(
      safeListen<TransferProgressEvent>('sftp://progress', (p) => {
        setTransfers((list) => applyProgress(list, p))
      }),
    )
    add(
      safeListen<TransferFailureEvent>('sftp://failure', (f) => {
        setTransfers((list) => applyFailure(list, f))
      }),
    )
    return () => {
      dead = true
      uns.forEach((fn) => fn())
    }
  }, [])

  /** Kick off one or more transfers. Runs them sequentially per call so a bulk
   *  selection does not open dozens of concurrent SFTP writes against one
   *  connection — appliances in particular do not love that. Every job gets
   *  its row (queued) at once, so any of them can be cancelled. */
  const startTransfer = useCallback(
    async (sessionId: string, direction: 'upload' | 'download', jobs: TransferJob[]) => {
      const rows = jobs.map((job) => ({ job, id: newTransferId() }))
      setTransfers((t) => [
        ...rows.map(({ job, id }) => queuedRow(id, sessionId, direction, job)).reverse(),
        ...t,
      ])
      for (const { job, id } of rows) {
        // Skipped if the user cancelled it while it waited.
        if (cancelledRef.current.delete(id)) continue
        setTransfers((t) => markActive(t, id))
        try {
          const out = await runTransfer(direction, sessionId, id, job)
          setTransfers((t) => markDone(t, id, out))
          setTransferTick((n) => n + 1)
        } catch (e) {
          setTransfers((t) => markFailed(t, id, e instanceof Error ? e.message : String(e)))
        }
        cancelledRef.current.delete(id)
      }
    },
    [],
  )

  /** Clear finished rows, keep anything still moving or waiting. */
  const clearTransfers = useCallback(() => setTransfers((t) => clearFinished(t)), [])

  /** Cancel a queued or running transfer. A running one stops at its next
   *  chunk and removes its staging files; its command then settles the row. */
  const cancelOne = useCallback((t: Transfer) => {
    if (t.status !== 'queued' && t.status !== 'active') return
    cancelledRef.current.add(t.id)
    // Sent for a queued row too: the loop may be starting it right now, and
    // the backend remembers a cancel that overtakes its transfer.
    void cancelTransfer(t.id).catch(() => {})
    setTransfers((list) => markCancelled(list, t.id))
  }, [])

  /** Re-run only the files that failed in a folder transfer, with the
   *  original overwrite policy. Offered only once that transfer has stopped
   *  (see canRetry). Drops the old row and starts a fresh transfer for the
   *  retryable failures (items skipped by name are not retryable). */
  const retryFailed = useCallback(
    (t: Transfer) => {
      if (!canRetry(t)) return
      const jobs = retryJobs(t)
      setTransfers((list) => list.filter((x) => x.id !== t.id))
      if (jobs.length > 0) void startTransfer(t.sessionId, t.direction, jobs)
    },
    [startTransfer],
  )

  /* ---------------------------------------------------------------- actions */

  /** Lowest unused 1-based pane number for a host.
   *
   *  Reuses gaps rather than always incrementing, so closing pane 1 of two and
   *  reopening lands back on `hawser-1` instead of drifting to `hawser-3` and
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

    const sid = sessionIdFor(host.id, Date.now())
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
    // Not for local terminals: a shell on this machine starts fresh, like any
    // other terminal app.
    void (host.local
      ? Promise.resolve(null)
      : safeInvoke<string | null>('session_history', { endpoint: endpointFor(host), maxBytes: 12_000 })
    ).then((history) => {
      // The tab may have closed while the read ran: buffering for it would
      // pin the text in localTerm forever.
      if (!history || !sessionsRef.current.some((s) => s.id === session.id)) return
      emitLocal(
        session.id,
        `\x1b[38;5;240m--- previous session on ${host.name} (history, not live) ---\x1b[0m\r\n` +
          `\x1b[38;5;244m${history.split('\n').join('\r\n')}\x1b[0m` +
          `\x1b[38;5;240m--- end of history ---\x1b[0m\r\n\r\n`,
      )
    }).catch(() => {
      // No replay is only a missing convenience; the connect proceeds.
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
  }, [nextPaneIndex, confirm, endpointFor])

  /** "What changed since my last visit": for hosts that opt in, capture the
   *  config over a side exec channel and compare it with the newest snapshot.
   *  Reported as a dim line in the terminal, plus a status-bar chip that opens
   *  the diff when something changed. */
  const checkConfigOnConnect = useCallback((sessionId: string, host: Host, dialled?: DialIdentity) => {
    const command = host.configCommand?.trim()
    if (!host.checkConfigOnConnect || !command) return

    const when = (epoch: number | null) => {
      if (!epoch) return 'your last snapshot'
      const d = new Date(epoch * 1000)
      return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
    }
    const note = (sid: string, text: string) => emitLocal(sid, `\x1b[38;5;244m● ${text}\x1b[0m\r\n`)
    const dropChip = (sid: string) =>
      setConfigChanges((m) => {
        if (!(sid in m)) return m
        const { [sid]: _gone, ...rest } = m
        return rest
      })
    const report = (sid: string, r: ConfigCheckResult, endpoint: string) => {
      if (r.status === 'first') {
        dropChip(sid)
        note(sid, 'config baseline saved; future connects will report changes against it')
      } else if (r.status === 'unchanged') {
        dropChip(sid)
        note(sid, `config unchanged since ${when(r.previousModified)}`)
      } else if (r.name && r.previous) {
        emitLocal(
          sid,
          `\x1b[38;2;242;178;92m● config changed since ${when(r.previousModified)}: ` +
            `+${r.added} −${r.removed} lines\x1b[0m \x1b[38;5;244m(status bar → view diff)\x1b[0m\r\n`,
        )
        const { name, previous } = r
        setConfigChanges((m) => ({
          ...m,
          [sid]: { hostId: host.id, endpoint, added: r.added, removed: r.removed, previous, name },
        }))
      }
    }

    // A change found by a check whose tab went away is reported here, in
    // place of a new check: one would only compare against the snapshot that
    // change already saved and say "unchanged".
    // The identity the backend dialled, so a catalogue edit made during the
    // dial cannot change which endpoint's notice this is. Recomputed from the
    // catalogue only when the backend did not report one.
    const ep = dialled ?? endpointFor(host)
    const missed = undeliveredChangeRef.current.get(ep)
    if (missed) {
      undeliveredChangeRef.current.delete(ep)
      configCheckedRef.current.set(ep, Date.now())
      report(sessionId, missed, ep)
      return
    }

    const last = configCheckedRef.current.get(ep)
    if (last !== undefined && Date.now() - last < 120_000) return
    configCheckedRef.current.set(ep, Date.now())
    const latest = configReplies.current.begin(sessionId)
    /* Only the latest check for a tab that still exists may write anything:
       a late reply must not print into (or badge) a closed or redialled tab. */
    const current = () => latest() && sessionsRef.current.some((s) => s.id === sessionId)

    // The backend keys the snapshot by this session's own dialled identity.
    void safeInvoke<ConfigCheckResult>('config_check', {
      sessionId,
      host: host.hostname,
      command,
    })
      .then((r) => {
        if (!r) return
        // Routed by what the backend actually snapshotted. If a reconnect
        // replaced this tab's connection before the check ran, that is the
        // new connection's endpoint, not the one this request was made for.
        const checked = r.endpoint || ep
        if (!current() || checked !== ep) {
          // Its tab closed or redialled before it landed. A change was already
          // saved as the new baseline, so it must still reach the user: in a
          // tab to this host that is already connected again, or else on the
          // next connect. Anything else is simply re-checked next time
          // instead of being throttled.
          if (r.status === 'changed') {
            // Only a tab whose host STILL resolves to the identity that was
            // checked; a repointed entry is another endpoint now.
            const live = sessionsRef.current.find((s) => {
              if (s.status !== 'connected') return false
              const dialledBy = dialledRef.current.get(s.id)
              if (dialledBy !== undefined) return dialledBy === checked
              const h = lookupHost(s.hostId)
              return !!h && endpointFor(h) === checked
            })
            if (live) report(live.id, r, checked)
            else undeliveredChangeRef.current.set(checked, r)
          } else {
            configCheckedRef.current.delete(checked)
          }
          return
        }
        report(sessionId, r, checked)
      })
      .catch((e: unknown) => {
        if (!current()) {
          configCheckedRef.current.delete(ep)
          return
        }
        note(sessionId, `config check failed: ${e instanceof Error ? e.message : String(e)}`)
      })
  }, [endpointFor, lookupHost])

  /* Closed tabs take their config-change chip and check token with them. */
  useEffect(() => {
    const live = new Set(sessions.map((s) => s.id))
    configReplies.current.retain(live)
    for (const id of dialledRef.current.keys()) if (!live.has(id)) dialledRef.current.delete(id)
    // Per-session UI state goes with its tab (these grew for the whole run).
    const prune = <T,>(m: Record<string, T>): Record<string, T> => {
      const stale = Object.keys(m).filter((id) => !live.has(id))
      if (stale.length === 0) return m
      const next = { ...m }
      for (const id of stale) delete next[id]
      return next
    }
    setSizes(prune)
    setSftpPaths(prune)
    const groupsLive = new Set(sessions.map((s) => s.groupId))
    for (const g of Object.keys(lastPaneRef.current)) {
      if (!groupsLive.has(g) || !live.has(lastPaneRef.current[g])) delete lastPaneRef.current[g]
    }
    setConfigChanges((m) => {
      const stale = Object.keys(m).filter((id) => !live.has(id))
      if (stale.length === 0) return m
      const next = { ...m }
      for (const id of stale) delete next[id]
      return next
    })
  }, [sessions])

  /** Performs the deferred connect once a real terminal size is known. */
  const connectPending = useCallback((sessionId: string, cols: number, rows: number) => {
    const entry = pendingRef.current.get(sessionId)
    if (!entry) return
    const { host, paneIndex, oneShotPassword } = entry
    pendingRef.current.delete(sessionId)
    // A new connection for this tab: any config check from the previous one is
    // stale, even if this connect ends up throttled and runs no check of its own.
    configReplies.current.invalidate(sessionId)
    dialledRef.current.delete(sessionId)

    // A jump host that no longer exists (deleted, or a hand-edited id) fails
    // the connect. Going direct instead would silently change the route, and
    // send the password straight to an internal address from this network.
    const jumpGone =
      !host.local && !!host.jumpHostId && host.jumpHostId !== host.id && !findHost(hostsRef.current, host.jumpHostId)
    const dial: Promise<unknown> = jumpGone
      ? Promise.reject(
          new Error(
            `${host.name} is set to connect through a jump host that no longer exists. Edit the host and pick another jump host (or "Direct connection").`,
          ),
        )
      : host.local
      ? safeInvoke('local_shell_start', {
          sessionId,
          profile: host.local.profile,
          cols,
          rows,
          record: settingsRef.current.recordLocalTranscripts,
        })
      : safeInvoke<DialIdentity>('ssh_connect', {
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
      // Names the transcript; see lib/endpoint.
      endpoint: endpointFor(host),
      // Shown in host-key and password prompts; the backend adds the dialled
      // user@host:port and bastion itself.
      label: host.name,
      // Quick-connect hosts are not in the catalogue: never offer to save a
      // typed password for them (no UI could ever delete it again).
      ephemeral: ephemeralHostsRef.current.has(host.id),
      // ProxyJump: resolve the bastion's connection details from the
      // catalogue at dial time, so editing the bastion updates every host
      // that rides it. A self-reference degrades to direct; a missing
      // bastion never gets here (jumpGone above).
      jump: (() => {
        if (!host.jumpHostId || host.jumpHostId === host.id) return null
        const j = findHost(hostsRef.current, host.jumpHostId)
        if (!j) return null
        return {
          // Same vault-key rule as the target: a bastion that borrows another
          // host's credential reads THAT entry.
          hostId: j.credentialId ?? j.id,
          host: j.hostname,
          port: j.port,
          username: j.username,
          auth: j.auth,
          keyPath: j.keyPath ?? null,
          name: j.name,
        }
      })(),
    })
    void dial
      .then((result) => {
        // The tab was closed while the connect was in flight: the backend has
        // just registered a session nothing owns, so tear it down.
        if (!sessionsRef.current.some((s) => s.id === sessionId)) {
          void safeInvoke('ssh_disconnect', { sessionId })
          return
        }
        // Promote only from 'connecting': a shell that closed at once may
        // already have reported 'disconnected', which must not be overwritten.
        setSessions((prev) =>
          prev.map((s) =>
            s.id === sessionId && s.status === 'connecting' ? { ...s, status: 'connected' } : s,
          ),
        )
        // ssh_connect reports the identity it dialled; anything else (a local
        // shell, no Tauri) leaves the catalogue-derived identity in use.
        const dialled: DialIdentity | undefined =
          !host.local && typeof result === 'string' && result ? result : undefined
        if (dialled) dialledRef.current.set(sessionId, dialled)
        checkConfigOnConnect(sessionId, host, dialled)
      })
      .catch((e: unknown) => {
        // A tab closed mid-connect fails here as "cancelled"; nothing to show.
        if (!sessionsRef.current.some((s) => s.id === sessionId)) return
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
  }, [checkConfigOnConnect, endpointFor])

  /** Re-dial a dropped or dormant session, reusing its id so the terminal pane,
   *  scrollback, group, and pane number are all preserved — the pane never
   *  unmounted, only the backend connection went away. Redials at the pane's
   *  last known size (the ResizeObserver will not re-fire for an unchanged box,
   *  so the size must be supplied). */
  const reconnectSession = useCallback((sessionId: string) => {
    const s = sessionsRef.current.find((x) => x.id === sessionId)
    if (!s || s.status === 'connected' || s.status === 'connecting') return
    const host = lookupHost(s.hostId)
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
  }, [connectPending, lookupHost])

  const saveHost = useCallback(
    (host: Host) => {
      const before = findHost(hosts, host.id)
      const next = upsertHost(hosts, host)
      // An edited address, account or shared credential: the old
      // destination must stop receiving the saved password. Narrowed with
      // the save itself (see persistHosts), never after it.
      persistHosts(next, before && bindingChanged(before, host) ? [before.credentialId ?? before.id] : [])
    },
    [hosts, persistHosts],
  )

  const deleteHost = useCallback(
    (hostId: string) => {
      const before = findHost(hosts, hostId)
      const next = removeHost(hosts, hostId)
      // Remove its saved password (and binding) from the OS vault too — unless
      // another host still borrows that entry via credentialId (compared with
      // the vault's id rule: on Windows `H-1` borrows `h-1`).
      const borrowed = isBorrowed(next, hostId)
      const narrow = [
        // Still borrowed: its own destination stops receiving the password.
        ...(borrowed ? [hostId] : []),
        // A borrower going away: the lender's password stops going to it.
        ...(before?.credentialId ? [before.credentialId] : []),
      ]
      persistHosts(next, narrow)
      if (!borrowed) {
        safeInvoke('credential_delete', { hostId }).catch((e) =>
          void alert(
            `The host was removed, but its saved password could not be deleted from the system credential store: ${e instanceof Error ? e.message : e}`,
          ),
        )
      }
    },
    [hosts, persistHosts, alert],
  )

  /** Delete a host after an explicit yes — from the sidebar menu and the
   *  editor alike. Names the hosts that ride it as their jump host: they are
   *  left pointing at it and refuse to connect until given another one (they
   *  never silently go direct). Resolves whether it deleted. */
  const requestDeleteHost = useCallback(
    async (hostId: string): Promise<boolean> => {
      const host = findHost(hostsRef.current, hostId)
      if (!host) return false
      const deps = jumpDependents(hostsRef.current, hostId)
      const depText =
        deps.length === 0
          ? ''
          : `\n\n${deps.length} host${deps.length === 1 ? ' uses' : 's use'} it as a jump host: ${deps
              .slice(0, 8)
              .map((d) => d.name)
              .join(', ')}${deps.length > 8 ? ', …' : ''}. ${
              deps.length === 1 ? 'It' : 'They'
            } will refuse to connect until you pick another jump host.`
      const ok = await confirm(
        `Delete "${host.name}"? Its saved password is removed from the system credential store too, unless another host shares it.${depText}`,
        { title: 'Delete host', confirmLabel: 'Delete', danger: true },
      )
      if (ok) deleteHost(hostId)
      return ok
    },
    [confirm, deleteHost],
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
    // Side effects run here, once, from the current list — not inside the
    // state updater, which StrictMode calls twice.
    const prev = sessionsRef.current
    const target = prev.find((s) => s.id === id)
    const doomed = new Set(
      target ? prev.filter((s) => s.groupId === target.groupId).map((s) => s.id) : [id],
    )
    doomed.forEach((d) => {
      clearLocal(d)
      // Disarm a connect that has not dialled yet, or its fallback timer
      // would open a shell for a tab that no longer exists.
      pendingRef.current.delete(d)
      void safeInvoke('ssh_disconnect', { sessionId: d })
    })
    const next = prev.filter((s) => !doomed.has(s.id))
    const idx = prev.findIndex((s) => s.id === id)
    const neighbour = next[Math.min(idx, next.length - 1)]?.id ?? null
    sessionsRef.current = next
    setSessions((cur) => cur.filter((s) => !doomed.has(s.id)))
    setActiveId((cur) => {
      if (cur && !doomed.has(cur)) return cur
      // Focus the neighbour that took the closed tab's slot, else the last.
      return neighbour
    })
  }, [confirm])

  const setView = useCallback(
    (view: WorkspaceView) =>
      setSessions((prev) =>
        prev.map((s) =>
          // Local terminals have no SFTP side; stay on the terminal.
          s.id === activeId && !(view === 'sftp' && lookupHost(s.hostId)?.local)
            ? { ...s, view }
            : s,
        ),
      ),
    [activeId, lookupHost],
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
    const host = lookupHost(target.hostId)
    if (!host) return
    const sid = sessionIdFor(host.id, Date.now())
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
  }, [connectPending, nextPaneIndex, lookupHost])

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
    // Through the pane's own input path: the same ordered write queue as typed
    // keys (a direct ssh_write could interleave with them), mirrored to the
    // other panes when broadcast is on, and Enter as CR like the keyboard.
    const text = snippetText(command, autoRun)
    const pane = getTerm(sessionId)
    if (pane) {
      pane.input(text)
      return
    }
    void safeInvoke('ssh_write', { sessionId, data: Array.from(new TextEncoder().encode(text)) }).catch(
      (e: unknown) => {
        const msg = e instanceof Error ? e.message : String(e)
        emitLocal(sessionId, `\r\n\x1b[38;2;242;178;92m● snippet not sent\x1b[0m ${msg}\r\n`)
      },
    )
  }, [confirm])

  /** Quick connect: an ephemeral host, never saved, password (if any) used
   *  once. The session looks like any other; the catalogue never learns. */
  /** Shells this machine offers (PowerShell, cmd, WSL, Git Bash / login shell…). */
  const [shellProfiles, setShellProfiles] = useState<{ id: string; label: string }[]>([])
  useEffect(() => {
    void safeInvoke<{ id: string; label: string }[]>('local_shell_profiles').then((p) =>
      setShellProfiles(p ?? []),
    )
  }, [])

  /** Open a local terminal tab. The tab rides on a synthetic host (one per
   *  shell profile, never saved to the catalogue), so splitting, restart,
   *  find, and transcripts all work as for SSH. AI access is off by default:
   *  a local shell sees the whole machine. */
  const openLocal = useCallback(
    (profileId?: string) => {
      const prof =
        shellProfiles.find((p) => p.id === (profileId ?? settingsRef.current.defaultLocalShell)) ??
        shellProfiles[0]
      if (!prof) return
      const host: Host = {
        kind: 'host',
        id: `local-${prof.id}`,
        name: prof.label,
        hostname: 'localhost',
        port: 0,
        username: '',
        auth: 'agent',
        aiAllowed: false,
        local: { profile: prof.id },
      }
      ephemeralHostsRef.current.set(host.id, host)
      void openHost(host, true)
    },
    [shellProfiles, openHost],
  )

  /* "Open a local terminal at startup": once, after settings and the shell
     list have loaded. */
  const startupLocalDone = useRef(false)
  useEffect(() => {
    // After the restored tabs, so the strip order does not depend on which
    // load finished first.
    if (startupLocalDone.current || !settingsReady || !tabsRestored || shellProfiles.length === 0) return
    startupLocalDone.current = true
    if (settingsRef.current.localShellOnStartup) openLocal()
  }, [settingsReady, tabsRestored, shellProfiles, openLocal])

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
        // Ad-hoc hosts carry no colour or per-host choice, so the AI assistant
        // stays off for them (as it always effectively was), rather than
        // inheriting the permissive default policy.
        aiAllowed: false,
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
      ephemeralHostsRef.current.set(host.id, host)
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
      // One out-of-range port (hand-edited hosts.json) would fail the whole
      // u16 deserialisation and leave every host without a result; skip it.
      const valid = targets.filter(([, , p]) => Number.isInteger(p) && p >= 1 && p <= 65535)
      const results = await safeInvoke<{ id: string; reachable: boolean; ms?: number }[]>(
        'hosts_probe',
        { targets: valid },
      )
      const map: Record<string, { ok: boolean; ms?: number }> = {}
      for (const r of results ?? []) map[r.id] = { ok: r.reachable, ms: r.ms }
      setReachability(map)
    } catch (e) {
      void alert(`Reachability check failed: ${e instanceof Error ? e.message : e}`)
    } finally {
      setProbing(false)
    }
  }, [alert])

  /** Move a host to a folder (null: top level). When that changes the
   *  host's effective colour, its colour policy (AI access, connect confirm,
   *  broadcast) changes with it, so the user confirms that first. */
  const moveHostChecked = useCallback(
    async (hostId: string, folderId: string | null) => {
      const before = effectiveHostColor(hostsRef.current, hostId)
      const next = moveHost(hostsRef.current, hostId, folderId)
      const after = effectiveHostColor(next, hostId)
      if ((before ?? 'none') !== (after ?? 'none')) {
        const name = findHost(hostsRef.current, hostId)?.name ?? 'This host'
        const ok = await confirm(
          `${name} changes colour from ${before ?? 'none'} to ${after ?? 'none'} with this move, and gets that colour's policy (AI access, connect confirmation, broadcast).`,
          { title: 'Colour policy changes', confirmLabel: 'Move' },
        )
        if (!ok) return
      }
      persistHosts(moveHost(hostsRef.current, hostId, folderId))
    },
    [confirm, persistHosts],
  )

  /** Config History for a saved host: its current endpoint, through a tab
   *  connected to exactly that endpoint if there is one. */
  const openConfigHistory = useCallback(
    (host: Host) => {
      const endpoint = endpointFor(host)
      const live = sessionsRef.current.find(
        (t) =>
          t.hostId === host.id &&
          t.status === 'connected' &&
          (dialledRef.current.get(t.id) ?? endpoint) === endpoint,
      )
      setConfigFor({ host, endpoint, liveSessionId: live?.id ?? null })
    },
    [endpointFor],
  )

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
        onSelect: () => openConfigHistory(host),
      },
      {
        label: 'Move to folder…',
        onSelect: () => {
          // Second-level menu: same anchor, new items. Cheaper and more
          // keyboard-predictable than nested hover submenus.
          // Folders are labelled by their path, so two folders that share a
          // name can be told apart.
          const labels = folderLabels(hostsRef.current)
          const folders = allFolders(hostsRef.current)
          setMenu({
            x,
            y,
            items: [
              {
                label: '(top level)',
                onSelect: () => void moveHostChecked(host.id, null),
              },
              ...folders.map((f) => ({
                label: labels.get(f.id) ?? f.name,
                onSelect: () => void moveHostChecked(host.id, f.id),
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
        onSelect: () => void requestDeleteHost(host.id),
      },
    ]
    setMenu({ x, y, items })
  }, [openHost, requestDeleteHost, moveHostChecked, openConfigHistory])

  /** Right-click on a tab in the strip. */
  const openTabMenu = useCallback((sessionId: string, x: number, y: number) => {
    const s = sessionsRef.current.find((t) => t.id === sessionId)
    if (!s) return
    const host = lookupHost(s.hostId)
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
        onSelect: async () => {
          const next = await prompt('Tab name', { title: 'Rename tab', defaultValue: s.title })
          if (next === null) return
          const title = next.trim() || (host?.name ?? s.title)
          setSessions((prev) => prev.map((x) => (x.id === sessionId ? { ...x, title } : x)))
        },
      },
      {
        label: 'Port forwarding…',
        disabled: dead || !!host?.local,
        onSelect: () => {
          const cur = sessionsRef.current.find((t) => t.id === sessionId)
          if (cur) setTunnelFor(cur)
        },
      },
      {
        label: 'Capture command output…',
        disabled: dead || !host || !!host.local,
        onSelect: async () => {
          const command = (
            await prompt('Command to run — its full output is saved to a file (e.g. show tech-support):', {
              title: 'Capture command output',
            })
          )?.trim()
          if (!command || !host) return
          // Keyed by the session's own dialled identity, backend-side.
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
  }, [reconnectSession, splitSession, closeSession, lookupHost])

  /** Right-click on a folder row in the sidebar. */
  const openFolderMenu = useCallback((folderId: string, name: string, x: number, y: number) => {
    setMenu({
      x,
      y,
      items: [
        {
          label: 'Rename folder…',
          onSelect: async () => {
            const next = await prompt('Folder name', { title: 'Rename folder', defaultValue: name })
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
          // Children are promoted, never deleted, so no host is lost. But a
          // coloured folder's hosts lose the colour they inherit (and its
          // policy): that one case is confirmed.
          onSelect: async () => {
            const cur = hostsRef.current
            const next = removeFolder(cur, folderId)
            const changed = allHosts(cur).filter(
              (h) => (effectiveHostColor(cur, h.id) ?? 'none') !== (effectiveHostColor(next, h.id) ?? 'none'),
            )
            if (
              changed.length > 0 &&
              !(await confirm(
                `${changed.length} host${changed.length === 1 ? '' : 's'} in "${name}" will lose the folder's colour, and with it its policy (AI access, connect confirmation, broadcast).`,
                { title: 'Delete folder', confirmLabel: 'Delete folder' },
              ))
            ) {
              return
            }
            persistHosts(removeFolder(hostsRef.current, folderId))
          },
        },
      ],
    })
  }, [persistHosts, confirm])

  /** App menu from the title bar — the discoverable home for everything that
   *  was previously only reachable by knowing where to click. */
  const openAppMenu = useCallback((x: number, y: number) => {
    const items: MenuItem[] = [
      { label: 'New local terminal  Ctrl+Shift+T', onSelect: () => openLocal() },
      ...shellProfiles.map((p) => ({ label: `    ${p.label}`, onSelect: () => openLocal(p.id) })),
      { label: 'Quick connect… Ctrl+Shift+P', dividerBefore: true, onSelect: () => setShowQuickConnect(true) },
      { label: 'Network tools…', onSelect: () => setNetTools({ target: '', port: 22 }) },
      { label: 'AI assistant… Ctrl+Shift+A', onSelect: () => setShowAi(true) },
      { label: 'Settings…', onSelect: () => setShowSettings(true) },
      { label: 'New host…', dividerBefore: true, onSelect: () => setEditing({ host: null }) },
      {
        label: 'New folder…',
        onSelect: async () => {
          const name = await prompt('Folder name', { title: 'New folder' })
          if (name?.trim()) persistHosts(addFolder(hostsRef.current, name.trim()))
        },
      },
      { label: 'Session history…', onSelect: () => setShowHistory(true) },
      { label: 'Audit log…', onSelect: () => setShowAudit(true) },
      {
        label: 'Export hosts…',
        dividerBefore: true,
        onSelect: () =>
          void safeInvoke<string>('hosts_export')
            .then((p) => {
              if (p) void alert(`Host catalogue exported to:
${p}

Passwords are NOT included — they stay in the system's credential store. On-connect commands and snippets ARE included: check them before sharing the file.`)
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
        onSelect: () =>
          void safeInvoke('open_logs_folder').catch((err) =>
            void alert(`Could not open the logs folder: ${err instanceof Error ? err.message : err}`),
          ),
      },
      {
        label: 'Close current tab',
        dividerBefore: true,
        disabled: !activeId,
        onSelect: () => activeId && closeSession(activeId),
      },
    ]
    setMenu({ x, y, items })
  }, [activeId, closeSession, persistHosts, openLocal, shellProfiles])

  /** Right-click on the host sidebar's empty area: the fast path to a new
   *  connection without hunting for the "+" button. */
  const openSidebarMenu = useCallback((x: number, y: number) => {
    const items: MenuItem[] = [
      { label: 'New Connection…', onSelect: () => setEditing({ host: null }) },
      {
        label: 'New Folder…',
        onSelect: async () => {
          const name = await prompt('Folder name', { title: 'New folder' })
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
    pendingRef.current.delete(sessionId)
    void safeInvoke('ssh_disconnect', { sessionId })
    const prev = sessionsRef.current
    const closed = prev.find((s) => s.id === sessionId)
    const next = prev.filter((s) => s.id !== sessionId)
    // Prefer a sibling in the same tab, so closing a pane keeps you in that
    // tab rather than jumping away; else fall back to any remaining session.
    const sib = closed && next.find((s) => s.groupId === closed.groupId)
    const fallback = (sib ?? next[next.length - 1])?.id ?? null
    sessionsRef.current = next
    setSessions((cur) => cur.filter((s) => s.id !== sessionId))
    setActiveId((cur) => (cur && cur !== sessionId ? cur : fallback))
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

  /* Make the comment above true: drop the flag for any group that no longer
     exists or is down to one pane. Otherwise closing the second pane hides the
     (still-on) toggle, and the next split silently mirrors keystrokes into the
     new shell. Returns the same Set when nothing changes, so it cannot loop. */
  useEffect(() => {
    setBroadcastGroups((prev) => {
      if (prev.size === 0) return prev
      const counts = new Map(groups.map((g) => [g.id, g.sessions.length]))
      const next = new Set([...prev].filter((gid) => (counts.get(gid) ?? 0) > 1))
      return next.size === prev.size ? prev : next
    })
  }, [groups])

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

  /** Remember the last focused pane per tab, so jumping back to a split tab
   *  lands on the pane the user left, not always its first. */
  const lastPaneRef = useRef<Record<string, string>>({})
  if (active) lastPaneRef.current[active.groupId] = active.id

  /** The pane to focus when tab `g` is selected by keyboard. */
  const paneForGroup = useCallback((g: { id: string; sessions: Session[] }) => {
    const last = lastPaneRef.current[g.id]
    return (g.sessions.find((s) => s.id === last) ?? g.sessions[0]).id
  }, [])

  /** Ctrl+Tab steps through TABS (groups), as the strip shows them — not
   *  through panes, which made a split tab eat extra presses. */
  const cycleTab = useCallback(
    (dir: 1 | -1) =>
      setActiveId((cur) => {
        if (groups.length === 0) return cur
        const curGroup = sessions.find((s) => s.id === cur)?.groupId
        const i = groups.findIndex((g) => g.id === curGroup)
        return paneForGroup(groups[(i + dir + groups.length) % groups.length])
      }),
    [groups, sessions, paneForGroup],
  )

  /* ------------------------------------------------------------- shortcuts */

  // Every shell shortcut is Ctrl+SHIFT+<key>, and that is not cosmetic.
  // A focused terminal forwards plain Ctrl chords to the remote shell, where
  // readline already owns them: Ctrl+W deletes a word, Ctrl+T transposes
  // characters, Ctrl+K kills to end of line, Ctrl+/ is undo. Binding tab
  // management to those would quietly break line editing over SSH. Terminals
  // cannot encode Ctrl+Shift+<letter> distinctly, so that space is free for the
  // UI — the same reason Windows Terminal and VS Code use it.
  // The chord table lives in lib/keyChords, shared with the terminal: a
  // focused terminal hands every one of these chords back unprocessed, so they
  // reach this listener and the remote never sees them.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const sc = appShortcut(e)
      if (!sc) return
      // Behind a modal, app shortcuts do nothing: Ctrl+Shift+W would close
      // the tab under a confirm, Ctrl+Shift+<digit> type a snippet into it.
      if (anyModalOpen()) {
        e.preventDefault()
        return
      }

      switch (sc.kind) {
        case 'cycleTab':
          e.preventDefault()
          cycleTab(sc.dir)
          return
        case 'gotoTab':
          // Ordinal of the TAB strip (groups), not of the flat pane list.
          e.preventDefault()
          if (groups[sc.index]) setActiveId(paneForGroup(groups[sc.index]))
          return
        case 'snippet': {
          e.preventDefault()
          if (!activeId) return
          const cur = sessionsRef.current.find((t) => t.id === activeId)
          const host = cur && findHost(hostsRef.current, cur.hostId)
          const snip = host?.snippets?.find((sn) => sn.slot === sc.slot)
          if (snip) void sendSnippet(activeId, snip.command, snip.autoRun ?? false)
          return
        }
        case 'command':
          break
      }

      switch (sc.code) {
        case 'KeyA': // AI assistant panel
          e.preventDefault()
          setShowAi((v) => !v)
          break
        case 'KeyP': // quick connect
          e.preventDefault()
          setShowQuickConnect(true)
          break
        case 'KeyT': // new local terminal (default shell)
          e.preventDefault()
          openLocal()
          break
        case 'KeyF': // find in the focused terminal
          if (!activeId) break
          e.preventDefault()
          // A fresh nonce each press: an open bar re-focuses its input.
          setFindNonce((n) => n + 1)
          setShowFind(true)
          break
        case 'KeyE': // toggle Terminal <-> Files
          e.preventDefault()
          setView(active?.view === 'terminal' ? 'sftp' : 'terminal')
          break
        case 'KeyW':
          if (!activeId) break
          e.preventDefault()
          void closeSession(activeId)
          break
        default:
          // KeyK belongs to the sidebar's own listener.
          break
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [active?.view, activeId, groups, paneForGroup, setView, closeSession, cycleTab, sendSnippet, openLocal])

  /* Closing the window — the title-bar X, Alt+F4, and on macOS the menu's
     Quit (Cmd+Q) — asks first while sessions are live (confirmCloseActive),
     like closing a tab does. Tauri holds the close while this listener is
     registered and destroys the window only if it is not prevented. */
  const closingRef = useRef(false)
  const confirmWindowClose = useCallback(async (): Promise<boolean> => {
    const text = closeConfirmText(sessionsRef.current, settingsRef.current.confirmCloseActive)
    if (!text) return true
    return confirm(text, { title: 'Quit Hawser?', confirmLabel: 'Quit', danger: true })
  }, [confirm])
  useEffect(() => {
    if (!inTauri()) return
    let un: (() => void) | null = null
    let dead = false
    void import('@tauri-apps/api/window')
      .then(({ getCurrentWindow }) =>
        getCurrentWindow().onCloseRequested(async (ev) => {
          // A second close while the first one's confirm is open: hold it.
          if (closingRef.current) {
            ev.preventDefault()
            return
          }
          closingRef.current = true
          try {
            if (!(await confirmWindowClose())) ev.preventDefault()
          } finally {
            closingRef.current = false
          }
        }),
      )
      .then((fn) => {
        if (dead) fn()
        else un = fn
      })
      .catch(() => {})
    return () => {
      dead = true
      un?.()
    }
  }, [confirmWindowClose])

  /* macOS app menu (lib.rs): Cmd+W closes the active TAB (with the tab's own
     confirm), never the window; Cmd+Q goes through the window close above. */
  const closeActiveRef = useRef<() => void>(() => {})
  closeActiveRef.current = () => {
    if (anyModalOpen()) return
    const id = activeId
    if (id) void closeSession(id)
  }
  useEffect(() => {
    const uns: (() => void)[] = []
    let dead = false
    const add = (p: Promise<() => void>) => void p.then((fn) => (dead ? fn() : uns.push(fn)))
    add(safeListen<null>('menu://close-tab', () => closeActiveRef.current()))
    add(
      safeListen<null>('menu://quit', () => {
        void import('@tauri-apps/api/window').then(({ getCurrentWindow }) => getCurrentWindow().close())
      }),
    )
    return () => {
      dead = true
      uns.forEach((fn) => fn())
    }
  }, [])

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
              const current = active && lookupHost(active.hostId)
              if (current?.local) openLocal(current.local.profile)
              else if (current && findHost(hosts, current.id)) openHost(current, true)
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
            filesAvailable={!(active && lookupHost(active.hostId)?.local)}
          />
        </main>

        {showAi && (
          <AiPanel
            session={active}
            host={active ? lookupHost(active.hostId) : undefined}
            endpoint={(() => {
              const h = active ? lookupHost(active.hostId) : undefined
              return h ? endpointFor(h) : undefined
            })()}
            effectiveColor={activeColor}
            onClose={() => setShowAi(false)}
          />
        )}
      </div>

      <TransferBar transfers={transfers} onClear={clearTransfers} onRetry={retryFailed} onCancel={cancelOne} />

      <StatusBar
        session={active}
        hostCount={countHosts(hosts)}
        size={activeId ? sizes[activeId] : undefined}
        onReconnect={activeId ? () => reconnectSession(activeId) : undefined}
        configChange={activeId ? configChanges[activeId] : undefined}
        local={!!(active && lookupHost(active.hostId)?.local)}
        onViewConfigChange={(() => {
          const sid = activeId
          const c = sid ? configChanges[sid] : undefined
          const h = c && lookupHost(c.hostId)
          if (!sid || !c || !h) return undefined
          return () => {
            // The notice's own endpoint, through this tab only while it is
            // still connected to exactly that endpoint: never the saved host's
            // first connected tab, which can be another device by now.
            const s = sessionsRef.current.find((t) => t.id === sid)
            const live = s?.status === 'connected' && dialledRef.current.get(sid) === c.endpoint
            setConfigSelect([c.previous, c.name])
            setConfigFor({ host: h, endpoint: c.endpoint, liveSessionId: live ? sid : null })
          }
        })()}
      />

      {/* Rendered at the shell root so the modal covers the whole window; it
          self-hides until the backend raises a prompt. */}
      <HostKeyDialog />
      <AuthPromptDialog />

      {showHistory && <HistoryBrowser onClose={() => setShowHistory(false)} />}
      {showAudit && <AuditDialog onClose={() => setShowAudit(false)} />}

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
          void file.text().then(async (text) => {
            try {
              if (!loadedRef.current) {
                throw new Error('your own host catalogue is not loaded, so nothing can be added to it')
              }
              const parsed: unknown = JSON.parse(text.replace(/^\uFEFF/, ''))
              // The whole tree is checked, at every depth. Merging is
              // deliberate — import ADDS to the catalogue rather than
              // replacing it, so a bad file cannot wipe existing hosts.
              const problem = catalogueProblem(parsed)
              if (problem) throw new Error(`not a Hawser host export (${problem})`)
              // Only known fields are kept. Fields that make a host act on
              // its own (commands on connect, a hidden config capture, AI
              // access, a local shell) need an explicit yes, host by host.
              const { risky } = sanitizeImport(parsed as HostNode[], false)
              let allowRisky = false
              if (risky.length > 0) {
                const list = risky
                  .slice(0, 12)
                  .map((r) => `• ${r.name}: ${r.enables.join('; ')}`)
                  .join('\n')
                const more = risky.length > 12 ? `\n…and ${risky.length - 12} more` : ''
                allowRisky = await confirm(
                  `These imported hosts would act on their own once you connect:\n\n${list}${more}\n\nKeep these settings? Choose Cancel to import the hosts without them.`,
                  { title: 'Imported hosts run commands', confirmLabel: 'Keep these settings' },
                )
              }
              const { tree } = sanitizeImport(parsed as HostNode[], allowRisky)
              // Colliding ids (importing the same export twice, or an export
              // from this machine) get fresh ids at every depth, so a re-import
              // can never corrupt the tree or silently drop nested hosts.
              const fresh = reidentify(tree, hostsRef.current)
              persistHosts([...hostsRef.current, ...fresh])
              const dropped = risky.length > 0 && !allowRisky ? ' Their on-connect commands, config checks, AI access and local-shell settings were left out.' : ''
              void alert(`Imported ${fresh.length} top-level entr${fresh.length === 1 ? 'y' : 'ies'}. Passwords are never in exports — set them per host after importing.${dropped}`)
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
          host={configFor.host}
          endpoint={configFor.endpoint}
          liveSessionId={configFor.liveSessionId}
          initialSelected={configSelect}
          onClose={() => {
            setConfigFor(null)
            setConfigSelect(undefined)
          }}
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
        <FindBar sessionId={activeId} focusNonce={findNonce} onClose={() => setShowFind(false)} />
      )}

      {editing && (
        <HostEditor
          host={editing.host}
          catalogue={hosts}
          onSave={saveHost}
          onDelete={requestDeleteHost}
          onClose={() => setEditing(null)}
        />
      )}
    </div>
  )
}
