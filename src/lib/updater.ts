/** Update checks: pure state and banner logic, kept free of imports so
 *  `npm test` runs it directly. The Tauri calls live in updateClient.ts.
 *
 *  Safety rules this encodes:
 *  - Nothing installs without a click: the only path to `installing` is the
 *    banner's "Install and restart" (updateClient.install).
 *  - Signature checks belong to tauri-plugin-updater; nothing here can skip
 *    them, and a signature failure is reported as such, never retried. */

/** How long an automatic check waits after the last successful one. */
export const CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000

export const RELEASES_URL = 'https://github.com/andy060982/hawser/releases/latest'

/** Longest release-notes text the banner shows before linking out. */
export const NOTES_MAX = 1200

/** From the backend's update_install_kind. */
export interface InstallKind {
  kind: 'self' | 'manual'
  reason: string
}

export interface UpdateInfo {
  version: string
  currentVersion: string
  notes: string
  date?: string
}

export type UpdateState =
  | { phase: 'idle' }
  | { phase: 'checking'; manual: boolean }
  | { phase: 'current'; manual: boolean; checkedAt: number }
  | { phase: 'available'; info: UpdateInfo; install: InstallKind; dismissed: boolean }
  | { phase: 'downloading'; info: UpdateInfo; install: InstallKind; received: number; total: number | null }
  | { phase: 'installing'; info: UpdateInfo; install: InstallKind }
  | { phase: 'error'; message: string; manual: boolean; info?: UpdateInfo; install?: InstallKind }

/** Should startup run an automatic check now? Only with the setting on and
 *  at least 24 h since the last successful check. A missing, unreadable or
 *  future timestamp (clock moved back) counts as due. */
export function autoCheckDue(enabled: boolean, lastCheck: number | null, now: number): boolean {
  if (!enabled) return false
  if (lastCheck === null || !Number.isFinite(lastCheck) || lastCheck > now) return true
  return now - lastCheck >= CHECK_INTERVAL_MS
}

/** Parse a stored timestamp; anything else is "never". */
export function parseLastCheck(raw: string | null | undefined): number | null {
  if (!raw) return null
  const n = Number(raw)
  return Number.isFinite(n) && n > 0 ? n : null
}

/** Release notes for the banner: trimmed, capped, with a pointer to the full
 *  page when cut. Shown as plain text (React escapes it). */
export function formatNotes(body: string | undefined | null, max = NOTES_MAX): string {
  const t = (body ?? '').replace(/\r\n/g, '\n').trim()
  if (!t) return ''
  if (t.length <= max) return t
  const cut = t.slice(0, max)
  const nl = cut.lastIndexOf('\n')
  return `${(nl > max * 0.6 ? cut.slice(0, nl) : cut).trimEnd()}\n…\nFull notes on the releases page.`
}

/** Download progress as a whole percent, or null while the size is unknown. */
export function progressPercent(received: number, total: number | null): number | null {
  if (!total || total <= 0) return null
  return Math.max(0, Math.min(100, Math.floor((received / total) * 100)))
}

function mb(n: number): string {
  return `${(n / (1024 * 1024)).toFixed(1)} MB`
}

export function progressText(received: number, total: number | null): string {
  const pct = progressPercent(received, total)
  return pct === null ? `Downloading… ${mb(received)}` : `Downloading… ${pct}% (${mb(received)} of ${mb(total!)})`
}

/** A clear message for a failed check / download / install. */
export function describeError(e: unknown, stage: 'check' | 'download' | 'install'): string {
  const raw = e instanceof Error ? e.message : String(e ?? '')
  const s = raw.toLowerCase()
  if (/signature|minisign|pubkey|public key/.test(s)) {
    return 'The downloaded update failed its signature check, so it was not installed. Download Hawser from the releases page instead.'
  }
  if (/fallback platforms|`platforms` object|platform .*not found|target.*not found/.test(s)) {
    return 'No update has been published for this platform yet. Try again later.'
  }
  if (/valid release json|404|not found|status code/.test(s)) {
    return 'The update information could not be read from GitHub. Try again later.'
  }
  if (/network|dns|connect|timed? ?out|request|offline|resolve/.test(s)) {
    return 'Could not reach GitHub to check for updates. Check your connection and try again.'
  }
  if (/permission|access is denied|read-only|eacces|eperm/.test(s)) {
    return 'Hawser could not replace its own files (permission denied). Download the new version from the releases page.'
  }
  const what = stage === 'check' ? 'Checking for updates' : stage === 'download' ? 'Downloading the update' : 'Installing the update'
  return `${what} failed${raw ? `: ${raw}` : '.'}`
}

/** The confirm text before restarting into an update, or null when no
 *  session would be dropped. Mirrors closeGuard's wording. */
export function restartConfirmText(liveSessions: number, version: string): string | null {
  if (liveSessions <= 0) return null
  const n = liveSessions
  return `${n} session${n === 1 ? ' is' : 's are'} still connected. Restarting to install Hawser ${version} closes ${
    n === 1 ? 'it' : 'all of them'
  }.`
}

export type BannerAction = 'install' | 'download' | 'later' | 'retry' | 'dismiss'

export interface BannerModel {
  title: string
  notes: string
  detail: string | null
  progress: number | null
  busy: boolean
  actions: BannerAction[]
  tone: 'info' | 'error'
}

/** What the banner shows for a state, or null for no banner. Automatic checks
 *  that find nothing, or fail, stay silent; manual ones report back. */
export function bannerModel(state: UpdateState): BannerModel | null {
  switch (state.phase) {
    case 'idle':
    case 'checking':
      return null
    case 'current':
      return state.manual
        ? { title: 'Hawser is up to date.', notes: '', detail: null, progress: null, busy: false, actions: ['dismiss'], tone: 'info' }
        : null
    case 'available': {
      if (state.dismissed) return null
      const self = state.install.kind === 'self'
      return {
        title: `Hawser ${state.info.version} is available`,
        notes: state.info.notes,
        detail: self
          ? `You have ${state.info.currentVersion}.`
          : `You have ${state.info.currentVersion}. This copy can't update itself (${state.install.reason}).`,
        progress: null,
        busy: false,
        actions: [self ? 'install' : 'download', 'later'],
        tone: 'info',
      }
    }
    case 'downloading':
      return {
        title: `Hawser ${state.info.version} is available`,
        notes: state.info.notes,
        detail: progressText(state.received, state.total),
        progress: progressPercent(state.received, state.total),
        busy: true,
        actions: [],
        tone: 'info',
      }
    case 'installing':
      return {
        title: `Installing Hawser ${state.info.version}…`,
        notes: '',
        detail: 'Hawser restarts when the install finishes.',
        progress: 100,
        busy: true,
        actions: [],
        tone: 'info',
      }
    case 'error': {
      if (!state.manual && !state.info) return null
      const canDownload = !!state.info
      return {
        title: state.info ? `Hawser ${state.info.version} could not be installed` : 'Update check failed',
        notes: '',
        detail: state.message,
        progress: null,
        busy: false,
        actions: canDownload ? ['download', 'retry', 'later'] : ['retry', 'dismiss'],
        tone: 'error',
      }
    }
  }
}

/** Whether a download is allowed to start from this state (one click, one
 *  download; a self-updating copy only). */
export function canInstall(state: UpdateState): boolean {
  return state.phase === 'available' && state.install.kind === 'self'
}

/** Which update handle holds downloaded bytes. Each check returns a new
 *  handle and closes the one it replaces, which frees that handle's bytes, so
 *  "downloaded" belongs to a handle, never to a version: the same version
 *  offered again by a re-check must be downloaded again. */
export class DownloadTracker<H> {
  private current: H | null = null
  private downloaded = false

  /** The handle the next install uses. */
  get handle(): H | null {
    return this.current
  }

  /** Make `h` the current handle. A different handle starts undownloaded. */
  adopt(h: H | null): void {
    if (h === this.current) return
    this.current = h
    this.downloaded = false
  }

  /** `h` finished downloading. Ignored unless it is still the current one. */
  markDownloaded(h: H): void {
    if (h === this.current) this.downloaded = true
  }

  /** Must `h` download before it can install? */
  needsDownload(h: H): boolean {
    return h !== this.current || !this.downloaded
  }
}

/** Settings → Updates status line. */
export function statusLine(state: UpdateState, lastCheck: number | null, now: number): string {
  switch (state.phase) {
    case 'checking':
      return 'Checking…'
    case 'available':
    case 'downloading':
    case 'installing':
      return `Hawser ${state.info.version} is available.`
    case 'error':
      return state.message
    case 'current':
      return 'Hawser is up to date.'
    case 'idle':
      if (lastCheck === null) return 'Not checked yet.'
      return `Last checked ${relativeAge(now - lastCheck)}.`
  }
}

function relativeAge(ms: number): string {
  const min = Math.floor(Math.max(0, ms) / 60000)
  if (min < 1) return 'just now'
  if (min < 60) return `${min} min ago`
  const h = Math.floor(min / 60)
  if (h < 48) return `${h} h ago`
  return `${Math.floor(h / 24)} days ago`
}
