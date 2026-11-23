/** App-wide settings: host-color policies and a couple of safety toggles.
 *
 *  Persisted to %APPDATA%\hawser\settings.json via the settings_load/save IPC
 *  commands (same fail-closed contract as the host catalogue: an unreadable
 *  or corrupt file is a load error, and nothing is saved over it until the
 *  user explicitly chooses to). Exposed
 *  through a context so the cross-cutting consumers — connect flow, AI panel,
 *  broadcast, close guard — read one source of truth instead of threading
 *  props through the whole tree.
 *
 *  The point of colour policies: a colour is no longer just a hue with one
 *  hardcoded rule ("red disables AI"). Each colour carries a policy the user
 *  configures, so *they* decide what "production" means for their fleet.
 */
import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react'
import { safeInvoke } from './tauri'
import type { HostColor } from './hostColors'

/** AI availability for a colour: on = normal, off = disabled. */
export type AiPolicy = 'on' | 'off'

export interface ColorPolicy {
  ai: AiPolicy
  /** Prompt "connect to <host>?" before dialing a host of this colour. */
  confirmConnect: boolean
  /** Leave hosts of this colour out of broadcast-to-panes by default. */
  excludeFromBroadcast: boolean
}

export interface Settings {
  colorPolicies: Record<HostColor, ColorPolicy>
  /** Warn before sending a destructive command (rm -rf, reload, …). */
  dangerousGuard: boolean
  /** Confirm before closing a tab whose session is still connected. */
  confirmCloseActive: boolean
  /** Finishing a mouse selection copies it straight to the clipboard, so no
   *  Ctrl-chord or right-click is needed to copy (iTerm2 / PuTTY behaviour). */
  copyOnSelect: boolean
  /** Middle-click (mouse wheel button) pastes the clipboard, X11 / PuTTY style. */
  middleClickPaste: boolean
  /** Open a local terminal tab when Hawser starts — "use it as my terminal". */
  localShellOnStartup: boolean
  /** Profile id for new local terminals (Ctrl+Shift+T, startup). Unset means
   *  the first one the backend lists (PowerShell 7 / Windows PowerShell on
   *  Windows, the login shell elsewhere). */
  defaultLocalShell?: string
  /** Keep a transcript of local terminals, like SSH sessions, so session
   *  search covers them. Everything shown on screen is written to disk. */
  recordLocalTranscripts: boolean
  /** Check GitHub for a new release at startup (at most once a day). Never
   *  installs on its own: an update waits for "Install and restart". */
  autoUpdateCheck: boolean
}

const PERMISSIVE: ColorPolicy = { ai: 'on', confirmConnect: false, excludeFromBroadcast: false }

/** Sensible defaults: red is locked down (matches the old hardcoded behaviour
 *  plus a connect prompt), amber asks, everything else is permissive. All of it
 *  is overridable in Settings. */
function defaultPolicy(color: HostColor): ColorPolicy {
  switch (color) {
    case 'red':
      return { ai: 'off', confirmConnect: true, excludeFromBroadcast: false }
    default:
      return { ...PERMISSIVE }
  }
}

const ALL_COLORS: HostColor[] = [
  'none', 'red', 'orange', 'amber', 'lime', 'green', 'cyan', 'blue', 'violet', 'pink', 'slate',
]

export function defaultSettings(): Settings {
  const colorPolicies = {} as Record<HostColor, ColorPolicy>
  for (const c of ALL_COLORS) colorPolicies[c] = defaultPolicy(c)
  return {
    colorPolicies,
    dangerousGuard: true,
    confirmCloseActive: true,
    copyOnSelect: true,
    middleClickPaste: true,
    localShellOnStartup: false,
    recordLocalTranscripts: true,
    autoUpdateCheck: true,
  }
}

/** Merge a loaded (possibly partial / older) settings object onto the defaults
 *  so a missing field or a newly-added colour never reads as undefined. */
function hydrate(raw: unknown): Settings {
  const base = defaultSettings()
  if (!raw || typeof raw !== 'object') return base
  const r = raw as Partial<Settings>
  if (r.colorPolicies) {
    for (const c of ALL_COLORS) {
      if (r.colorPolicies[c]) base.colorPolicies[c] = { ...base.colorPolicies[c], ...r.colorPolicies[c] }
    }
  }
  if (typeof r.dangerousGuard === 'boolean') base.dangerousGuard = r.dangerousGuard
  if (typeof r.confirmCloseActive === 'boolean') base.confirmCloseActive = r.confirmCloseActive
  if (typeof r.copyOnSelect === 'boolean') base.copyOnSelect = r.copyOnSelect
  if (typeof r.middleClickPaste === 'boolean') base.middleClickPaste = r.middleClickPaste
  if (typeof r.localShellOnStartup === 'boolean') base.localShellOnStartup = r.localShellOnStartup
  if (typeof r.defaultLocalShell === 'string') base.defaultLocalShell = r.defaultLocalShell
  if (typeof r.recordLocalTranscripts === 'boolean') base.recordLocalTranscripts = r.recordLocalTranscripts
  if (typeof r.autoUpdateCheck === 'boolean') base.autoUpdateCheck = r.autoUpdateCheck
  return base
}

/** The policy for a colour, always defined. `undefined` colour → 'none'. */
export function policyFor(settings: Settings, color: HostColor | undefined): ColorPolicy {
  return settings.colorPolicies[color ?? 'none'] ?? PERMISSIVE
}

interface SettingsCtx {
  settings: Settings
  /** True once the saved settings have been read (startup actions wait for it). */
  ready: boolean
  update: (patch: Partial<Settings>) => void
  setColorPolicy: (color: HostColor, patch: Partial<ColorPolicy>) => void
  /** Why settings.json could not be read. While set, changes apply for this
   *  run but are NOT saved (saving defaults would overwrite the real file),
   *  until the user chooses `saveAnyway`. */
  loadError: string | null
  /** Why the last save failed; cleared by the next successful one. */
  saveError: string | null
  /** After a failed load: save the current settings over the unreadable
   *  file from now on. */
  saveAnyway: () => void
}

const Ctx = createContext<SettingsCtx | null>(null)

export function SettingsProvider({ children }: { children: ReactNode }) {
  const [settings, setSettings] = useState<Settings>(defaultSettings)
  // A ref so the stable callbacks below always see the latest settings.
  const settingsRef = useRef(settings)
  settingsRef.current = settings
  // Don't persist the first load (that would just rewrite defaults before the
  // real file is read); only persist genuine user changes.
  const loaded = useRef(false)
  const [ready, setReady] = useState(false)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [saveError, setSaveError] = useState<string | null>(null)

  useEffect(() => {
    void safeInvoke<unknown>('settings_load')
      .then((raw) => {
        setSettings(hydrate(raw))
        loaded.current = true
      })
      .catch((e: unknown) => {
        // Keep the defaults for this run, and say so: saving them would
        // replace the user's real (unreadable right now) settings file.
        setLoadError(e instanceof Error ? e.message : String(e))
      })
      .finally(() => setReady(true))
  }, [])

  const save = useCallback((next: Settings) => {
    void safeInvoke('settings_save', { settings: next })
      .then(() => setSaveError(null))
      .catch((e: unknown) => setSaveError(e instanceof Error ? e.message : String(e)))
  }, [])

  const persist = useCallback((next: Settings) => {
    setSettings(next)
    if (loaded.current) save(next)
  }, [save])

  const saveAnyway = useCallback(() => {
    loaded.current = true
    setLoadError(null)
    save(settingsRef.current)
  }, [save])

  const update = useCallback(
    (patch: Partial<Settings>) => persist({ ...settingsRef.current, ...patch }),
    [persist],
  )
  const setColorPolicy = useCallback(
    (color: HostColor, patch: Partial<ColorPolicy>) => {
      const cur = settingsRef.current
      persist({
        ...cur,
        colorPolicies: {
          ...cur.colorPolicies,
          [color]: { ...policyFor(cur, color), ...patch },
        },
      })
    },
    [persist],
  )

  return (
    <Ctx.Provider value={{ settings, ready, update, setColorPolicy, loadError, saveError, saveAnyway }}>
      {children}
    </Ctx.Provider>
  )
}

export function useSettings(): SettingsCtx {
  const c = useContext(Ctx)
  if (!c) throw new Error('useSettings must be used within SettingsProvider')
  return c
}
