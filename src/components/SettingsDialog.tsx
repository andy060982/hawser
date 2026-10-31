import { useEffect, useState } from 'react'
import { Settings2, X } from 'lucide-react'
import { HOST_COLORS, hostColorHex } from '../lib/hostColors'
import { policyFor, useSettings } from '../lib/settings'
import { safeInvoke } from '../lib/tauri'

/* ---------------------------------------------------------------------------
   App settings: host-colour policies + safety toggles.

   A colour is no longer just a hue with one hardcoded rule — each carries a
   policy the operator sets here, so "red = production, locked down" is a choice
   rather than something baked into the code.
--------------------------------------------------------------------------- */
export function SettingsDialog({ onClose }: { onClose: () => void }) {
  const { settings, update, setColorPolicy } = useSettings()
  const [shells, setShells] = useState<{ id: string; label: string; program: string }[]>([])
  useEffect(() => {
    void safeInvoke<{ id: string; label: string; program: string }[]>('local_shell_profiles').then(
      (p) => setShells(p ?? []),
    )
  }, [])

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKey, true)
    return () => window.removeEventListener('keydown', onKey, true)
  }, [onClose])

  return (
    <div className="absolute inset-0 z-50 flex justify-center">
      <div className="animate-scrim-in absolute inset-0 bg-surface-0/75 backdrop-blur-[2px]" aria-hidden onClick={onClose} />

      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="settings-title"
        className="animate-drop-in relative mt-10 flex max-h-[86vh] w-[48rem] max-w-[94vw] flex-col overflow-hidden rounded-panel border border-line-strong bg-surface-2 shadow-[0_24px_60px_-12px_rgba(0,0,0,0.75)]"
      >
        <header className="flex items-center gap-2 border-b border-line px-4 py-2.5">
          <Settings2 size={15} className="shrink-0 text-accent" aria-hidden />
          <h2 id="settings-title" className="flex-1 text-[13.5px] font-medium text-ink">
            Settings
          </h2>
          <button
            type="button"
            aria-label="Close"
            onClick={onClose}
            className="grid h-6 w-6 place-items-center rounded text-ink-faint hover:bg-surface-3 hover:text-ink"
          >
            <X size={14} />
          </button>
        </header>

        <div className="min-h-0 flex-1 overflow-y-auto p-4">
          {/* --- Host colour policies --- */}
          <section>
            <h3 className="mb-1 text-[10.5px] uppercase tracking-wider text-ink-faint">
              Host colour policies
            </h3>
            <p className="mb-2 text-[11px] text-ink-faint">
              What each colour does. A host&apos;s own per-host AI toggle still overrides its
              colour, and uncoloured hosts follow the folder they&apos;re in.
            </p>

            <div className="overflow-hidden rounded border border-line">
              <table className="w-full text-[12px]">
                <thead>
                  <tr className="border-b border-line bg-surface-1 text-ink-faint">
                    <th className="px-2.5 py-1.5 text-left font-medium">Colour</th>
                    <th className="px-2.5 py-1.5 text-center font-medium">AI</th>
                    <th className="px-2.5 py-1.5 text-center font-medium">Confirm connect</th>
                    <th className="px-2.5 py-1.5 text-center font-medium">No broadcast</th>
                  </tr>
                </thead>
                <tbody>
                  {HOST_COLORS.map((c) => {
                    const p = policyFor(settings, c.key)
                    const hex = hostColorHex(c.key)
                    return (
                      <tr key={c.key} className="border-b border-line/60 last:border-0">
                        <td className="px-2.5 py-1.5">
                          <span className="flex items-center gap-2">
                            <span
                              className="inline-block h-3 w-3 shrink-0 rounded-full border border-line"
                              style={{ background: hex ?? 'transparent' }}
                              aria-hidden
                            />
                            <span className="text-ink">{c.key === 'none' ? 'Uncoloured' : c.label}</span>
                          </span>
                        </td>
                        <td className="px-2.5 py-1.5 text-center">
                          <button
                            type="button"
                            onClick={() => setColorPolicy(c.key, { ai: p.ai === 'off' ? 'on' : 'off' })}
                            className={`rounded px-2 py-0.5 text-[11px] font-medium ${
                              p.ai === 'off'
                                ? 'bg-alert/15 text-alert'
                                : 'bg-ok/15 text-ok'
                            }`}
                          >
                            {p.ai === 'off' ? 'Off' : 'On'}
                          </button>
                        </td>
                        <td className="px-2.5 py-1.5 text-center">
                          <input
                            type="checkbox"
                            checked={p.confirmConnect}
                            onChange={(e) => setColorPolicy(c.key, { confirmConnect: e.target.checked })}
                            className="h-3.5 w-3.5 accent-[var(--color-accent)]"
                          />
                        </td>
                        <td className="px-2.5 py-1.5 text-center">
                          <input
                            type="checkbox"
                            checked={p.excludeFromBroadcast}
                            onChange={(e) => setColorPolicy(c.key, { excludeFromBroadcast: e.target.checked })}
                            className="h-3.5 w-3.5 accent-[var(--color-accent)]"
                          />
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </section>

          {/* --- Safety --- */}
          <section className="mt-4">
            <h3 className="mb-1 text-[10.5px] uppercase tracking-wider text-ink-faint">Safety</h3>
            <label className="flex cursor-pointer items-start gap-2 rounded px-1 py-1 hover:bg-surface-1">
              <input
                type="checkbox"
                checked={settings.dangerousGuard}
                onChange={(e) => update({ dangerousGuard: e.target.checked })}
                className="mt-[3px] h-3.5 w-3.5 accent-[var(--color-accent)]"
              />
              <span className="min-w-0">
                <span className="block text-[12.5px] text-ink">Warn before destructive commands</span>
                <span className="block text-[11px] text-ink-faint">
                  Pauses a paste, snippet, or broadcast containing <code className="font-mono">rm -rf</code>,{' '}
                  <code className="font-mono">reload</code>, <code className="font-mono">write erase</code>, etc.
                </span>
              </span>
            </label>
            <label className="flex cursor-pointer items-start gap-2 rounded px-1 py-1 hover:bg-surface-1">
              <input
                type="checkbox"
                checked={settings.confirmCloseActive}
                onChange={(e) => update({ confirmCloseActive: e.target.checked })}
                className="mt-[3px] h-3.5 w-3.5 accent-[var(--color-accent)]"
              />
              <span className="min-w-0">
                <span className="block text-[12.5px] text-ink">Confirm closing a live tab</span>
                <span className="block text-[11px] text-ink-faint">
                  Ask before closing a tab whose session is still connected.
                </span>
              </span>
            </label>
          </section>

          {/* --- Terminal: copy / paste --- */}
          <section className="mt-4">
            <h3 className="mb-1 text-[10.5px] uppercase tracking-wider text-ink-faint">Terminal</h3>
            <label className="flex cursor-pointer items-start gap-2 rounded px-1 py-1 hover:bg-surface-1">
              <input
                type="checkbox"
                checked={settings.copyOnSelect}
                onChange={(e) => update({ copyOnSelect: e.target.checked })}
                className="mt-[3px] h-3.5 w-3.5 accent-[var(--color-accent)]"
              />
              <span className="min-w-0">
                <span className="block text-[12.5px] text-ink">Copy on select</span>
                <span className="block text-[11px] text-ink-faint">
                  Highlighting text with the mouse copies it to the clipboard automatically — no
                  Ctrl-chord or right-click needed.
                </span>
              </span>
            </label>
            <label className="flex cursor-pointer items-start gap-2 rounded px-1 py-1 hover:bg-surface-1">
              <input
                type="checkbox"
                checked={settings.middleClickPaste}
                onChange={(e) => update({ middleClickPaste: e.target.checked })}
                className="mt-[3px] h-3.5 w-3.5 accent-[var(--color-accent)]"
              />
              <span className="min-w-0">
                <span className="block text-[12.5px] text-ink">Middle-click paste</span>
                <span className="block text-[11px] text-ink-faint">
                  Pressing the mouse wheel button pastes the clipboard. Right-click also pastes
                  (or copies the selection if one is active).
                </span>
              </span>
            </label>
          </section>

          {/* --- Local terminal --- */}
          <section className="mt-4">
            <h3 className="mb-1 text-[10.5px] uppercase tracking-wider text-ink-faint">
              Local terminal
            </h3>
            <label className="flex items-center gap-2 px-1 py-1 text-[12.5px] text-ink">
              <span className="w-32 shrink-0">Default shell</span>
              <select
                value={settings.defaultLocalShell ?? shells[0]?.id ?? ''}
                onChange={(e) => update({ defaultLocalShell: e.target.value || undefined })}
                className="h-7 min-w-0 flex-1 rounded border border-line bg-surface-1 px-1.5 text-[12px] text-ink focus:border-accent focus:outline-none"
              >
                {shells.map((p) => (
                  <option key={p.id} value={p.id} title={p.program}>
                    {p.label}
                  </option>
                ))}
              </select>
            </label>
            <p className="px-1 pb-1 text-[11px] text-ink-faint">
              New local terminal: Ctrl+Shift+T, or the app menu for a specific shell.
            </p>
            <label className="flex cursor-pointer items-start gap-2 rounded px-1 py-1 hover:bg-surface-1">
              <input
                type="checkbox"
                checked={settings.localShellOnStartup}
                onChange={(e) => update({ localShellOnStartup: e.target.checked })}
                className="mt-[3px] h-3.5 w-3.5 accent-[var(--color-accent)]"
              />
              <span className="min-w-0">
                <span className="block text-[12.5px] text-ink">Open a local terminal at startup</span>
                <span className="block text-[11px] text-ink-faint">
                  Use Hawser as your everyday terminal: it opens with your default shell ready.
                </span>
              </span>
            </label>
            <label className="flex cursor-pointer items-start gap-2 rounded px-1 py-1 hover:bg-surface-1">
              <input
                type="checkbox"
                checked={settings.recordLocalTranscripts}
                onChange={(e) => update({ recordLocalTranscripts: e.target.checked })}
                className="mt-[3px] h-3.5 w-3.5 accent-[var(--color-accent)]"
              />
              <span className="min-w-0">
                <span className="block text-[12.5px] text-ink">Record local terminal transcripts</span>
                <span className="block text-[11px] text-ink-faint">
                  Saves what local terminals show, like SSH sessions, so Session history can search
                  it. Everything on screen is written to disk. Applies to newly opened terminals.
                </span>
              </span>
            </label>
          </section>
        </div>
      </div>
    </div>
  )
}
