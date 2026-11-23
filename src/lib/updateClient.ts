/** The Tauri side of self-update: one shared update state that the banner
 *  and Settings → Updates both read, and the actions that move it.
 *
 *  tauri-plugin-updater fetches latest.json, downloads the bundle and checks
 *  its minisign signature against the key in tauri.conf.json before it will
 *  install. Nothing here can turn that off. */
import { useSyncExternalStore } from 'react'
import { inTauri, safeInvoke } from './tauri'
import {
  DownloadTracker, canInstall, describeError, formatNotes, parseLastCheck, type InstallKind, type UpdateInfo, type UpdateState,
} from './updater'

const LAST_CHECK_KEY = 'hawser.update.lastCheck'

type UpdateHandle = import('@tauri-apps/plugin-updater').Update

let state: UpdateState = { phase: 'idle' }
// The current Tauri update handle and whether its bytes are downloaded.
const download = new DownloadTracker<UpdateHandle>()
let installKind: InstallKind | null = null
const listeners = new Set<() => void>()

function set(next: UpdateState) {
  state = next
  for (const l of listeners) l()
}

export function getUpdateState(): UpdateState {
  return state
}

function subscribe(l: () => void): () => void {
  listeners.add(l)
  return () => listeners.delete(l)
}

export function useUpdateState(): UpdateState {
  return useSyncExternalStore(subscribe, getUpdateState)
}

export function readLastCheck(): number | null {
  try {
    return parseLastCheck(window.localStorage.getItem(LAST_CHECK_KEY))
  } catch {
    return null
  }
}

function writeLastCheck(t: number) {
  try {
    window.localStorage.setItem(LAST_CHECK_KEY, String(t))
  } catch {
    // Storage unavailable: the next start simply checks again.
  }
}

async function getInstallKind(): Promise<InstallKind> {
  if (installKind) return installKind
  try {
    const k = await safeInvoke<InstallKind>('update_install_kind')
    installKind = k ?? { kind: 'manual', reason: 'not running in the desktop app' }
  } catch (e) {
    installKind = { kind: 'manual', reason: String(e) }
  }
  return installKind
}

let inFlight: Promise<void> | null = null

/** Check GitHub for a newer release. `manual` checks report "up to date" and
 *  errors; automatic ones stay silent unless an update is found. */
export function checkForUpdates(manual: boolean): Promise<void> {
  if (!inTauri()) {
    if (manual) set({ phase: 'error', manual, message: 'Updates are only available in the desktop app.' })
    return Promise.resolve()
  }
  // Never interrupt a download or install; join a check already running.
  if (state.phase === 'downloading' || state.phase === 'installing') return Promise.resolve()
  if (inFlight) return inFlight
  inFlight = (async () => {
    set({ phase: 'checking', manual })
    try {
      const { check } = await import('@tauri-apps/plugin-updater')
      const update = await check({ timeout: 30_000 })
      const now = Date.now()
      writeLastCheck(now)
      if (!update) {
        void download.handle?.close().catch(() => {})
        download.adopt(null)
        set({ phase: 'current', manual, checkedAt: now })
        return
      }
      // Closing the old handle drops its downloaded bytes; adopting the new
      // one marks it undownloaded, even when it offers the same version.
      const old = download.handle
      if (old && old !== update) void old.close().catch(() => {})
      download.adopt(update)
      const info: UpdateInfo = {
        version: update.version,
        currentVersion: update.currentVersion,
        notes: formatNotes(update.body),
        date: update.date,
      }
      set({ phase: 'available', info, install: await getInstallKind(), dismissed: false })
    } catch (e) {
      set({ phase: 'error', manual, message: describeError(e, 'check') })
    } finally {
      inFlight = null
    }
  })()
  return inFlight
}

/** "Later": hide the banner for this run. The next due check shows it again. */
export function dismissUpdate() {
  if (state.phase === 'available') set({ ...state, dismissed: true })
  else if (state.phase === 'current' || state.phase === 'error') set({ phase: 'idle' })
}

export async function openReleasesPage(): Promise<void> {
  try {
    await safeInvoke('update_open_releases')
  } catch (e) {
    set({ phase: 'error', manual: true, message: String(e) })
  }
}

/** "Install and restart". Downloads (with progress), asks before dropping
 *  live sessions, then installs and relaunches. Only ever called from a click. */
export async function installUpdate(confirmRestart: (version: string) => Promise<boolean>): Promise<void> {
  const update = download.handle
  if (!canInstall(state) || !update || state.phase !== 'available') return
  const { info, install } = state
  try {
    if (download.needsDownload(update)) {
      let received = 0
      let total: number | null = null
      set({ phase: 'downloading', info, install, received, total })
      await update.download((ev) => {
        if (ev.event === 'Started') total = ev.data.contentLength ?? null
        else if (ev.event === 'Progress') received += ev.data.chunkLength
        set({ phase: 'downloading', info, install, received, total })
      })
      download.markDownloaded(update)
    }
  } catch (e) {
    set({ phase: 'error', manual: true, info, install, message: describeError(e, 'download') })
    return
  }
  // The download is kept: declining here and clicking again goes straight on.
  if (!(await confirmRestart(info.version))) {
    set({ phase: 'available', info, install, dismissed: false })
    return
  }
  // Checks wait while a download is shown, but never install bytes this
  // handle no longer has: offer the update again instead.
  if (download.needsDownload(update)) {
    set({ phase: 'available', info, install, dismissed: false })
    return
  }
  set({ phase: 'installing', info, install })
  try {
    await safeInvoke('update_prepare_install', { version: info.version })
    // Windows: the plugin starts the installer and exits Hawser here.
    await update.install()
    const { relaunch } = await import('@tauri-apps/plugin-process')
    await relaunch()
  } catch (e) {
    set({ phase: 'error', manual: true, info, install, message: describeError(e, 'install') })
  }
}

/** After a failed download or install: show the offer again. */
export function retryUpdate() {
  if (state.phase === 'error' && state.info && state.install) {
    set({ phase: 'available', info: state.info, install: state.install, dismissed: false })
  } else {
    void checkForUpdates(true)
  }
}
