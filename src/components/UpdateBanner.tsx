import { useEffect, useRef } from 'react'
import { Download, RefreshCw, X } from 'lucide-react'
import { liveSessionCount, type SessionLike } from '../lib/closeGuard'
import { useDialogs } from '../lib/dialogs'
import { useSettings } from '../lib/settings'
import { inTauri } from '../lib/tauri'
import {
  checkForUpdates, dismissUpdate, installUpdate, openReleasesPage, readLastCheck, retryUpdate, useUpdateState,
} from '../lib/updateClient'
import { autoCheckDue, bannerModel, restartConfirmText, type BannerAction } from '../lib/updater'

/* ---------------------------------------------------------------------------
   Non-blocking "Hawser X.Y.Z is available" banner, bottom-right above the
   status bar. Runs the once-a-day startup check (Settings → Updates can turn
   it off). Nothing installs until "Install and restart" is clicked; before
   the restart, live sessions are confirmed like closing the window.
--------------------------------------------------------------------------- */
export function UpdateBanner({ sessions }: { sessions: () => SessionLike[] }) {
  const state = useUpdateState()
  const { settings, ready } = useSettings()
  const { confirm } = useDialogs()

  const started = useRef(false)
  useEffect(() => {
    if (!ready || started.current || !inTauri()) return
    started.current = true
    if (autoCheckDue(settings.autoUpdateCheck, readLastCheck(), Date.now())) void checkForUpdates(false)
  }, [ready, settings.autoUpdateCheck])

  const model = bannerModel(state)
  if (!model) return null

  const confirmRestart = async (version: string) => {
    const text = restartConfirmText(liveSessionCount(sessions()), version)
    if (!text) return true
    return confirm(text, { title: 'Restart to update?', confirmLabel: 'Install and restart', danger: true })
  }

  const run = (a: BannerAction) => {
    if (a === 'install') void installUpdate(confirmRestart)
    else if (a === 'download') void openReleasesPage()
    else if (a === 'retry') retryUpdate()
    else dismissUpdate()
  }

  const label: Record<BannerAction, string> = {
    install: 'Install and restart',
    download: 'Download from GitHub',
    later: 'Later',
    retry: 'Try again',
    dismiss: 'Close',
  }
  const primary = (a: BannerAction) => a === 'install' || a === 'download'

  return (
    <div
      role="status"
      aria-live="polite"
      className="animate-drop-in absolute bottom-9 right-3 z-40 w-[22rem] max-w-[92vw] overflow-hidden rounded-panel border border-line-strong bg-surface-2 shadow-[0_16px_40px_-12px_rgba(0,0,0,0.7)]"
    >
      <div className={`h-[3px] w-full ${model.tone === 'error' ? 'bg-warn' : 'bg-accent'}`} />
      <div className="flex items-start gap-2 px-3 pt-2.5">
        {model.busy ? (
          <RefreshCw size={14} className="mt-0.5 shrink-0 animate-spin text-accent" aria-hidden />
        ) : (
          <Download size={14} className={`mt-0.5 shrink-0 ${model.tone === 'error' ? 'text-warn' : 'text-accent'}`} aria-hidden />
        )}
        <div className="min-w-0 flex-1">
          <p className="text-[12.5px] font-medium text-ink">{model.title}</p>
          {model.detail && (
            <p className={`mt-0.5 break-words text-[11px] ${model.tone === 'error' ? 'text-warn' : 'text-ink-faint'}`}>
              {model.detail}
            </p>
          )}
        </div>
        {!model.busy && (
          <button
            type="button"
            aria-label="Dismiss"
            onClick={dismissUpdate}
            className="grid h-5 w-5 shrink-0 place-items-center rounded text-ink-faint hover:bg-surface-3 hover:text-ink"
          >
            <X size={12} />
          </button>
        )}
      </div>

      {model.notes && (
        <pre className="mx-3 mt-2 max-h-40 overflow-y-auto whitespace-pre-wrap break-words rounded border border-line bg-surface-1 px-2 py-1.5 font-sans text-[11px] leading-snug text-ink-dim">
          {model.notes}
        </pre>
      )}

      {model.busy && model.progress !== null && (
        <div className="mx-3 mt-2 h-1 overflow-hidden rounded bg-surface-4" aria-hidden>
          <div className="h-full bg-accent transition-[width]" style={{ width: `${model.progress}%` }} />
        </div>
      )}

      <div className="flex justify-end gap-2 px-3 pb-2.5 pt-2.5">
        {model.actions.map((a) => (
          <button
            key={a}
            type="button"
            onClick={() => run(a)}
            className={
              primary(a)
                ? 'rounded border border-accent/60 bg-accent/15 px-2.5 py-1 text-[12px] font-medium text-accent hover:bg-accent/25'
                : 'rounded border border-line px-2.5 py-1 text-[12px] text-ink-dim hover:bg-surface-3 hover:text-ink'
            }
          >
            {label[a]}
          </button>
        ))}
      </div>
    </div>
  )
}
