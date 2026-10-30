import { useEffect, useRef, useState } from 'react'
import { KeyRound, Plus, Server, Trash2, X } from 'lucide-react'
import type { AuthMethod, Host, HostNode, Snippet } from '../types'
import { allHosts } from '../lib/tree'
import {
  STARTUP_PRESETS,
  customCommands,
  rawStartupCommands,
} from '../lib/startupPresets'
import { DEVICE_PROFILES } from '../lib/deviceProfiles'
import { HOST_COLORS } from '../lib/hostColors'
import { safeInvoke } from '../lib/tauri'

/* ---------------------------------------------------------------------------
   Add / edit a saved host.

   The password field is the reason this component matters. Before it existed
   the only way to store a credential was `cmdkey /generic:hawser:host:<id>`,
   which is an unreasonable thing to ask of anyone.

   The secret goes straight to `credential_save`, which writes it to the Windows
   Credential Manager and returns nothing. It is never placed in the host tree,
   never written to hosts.json, and there is no command that reads it back — the
   field renders empty on reopen and shows "saved" state instead, because the
   plaintext genuinely cannot be retrieved into the webview.
--------------------------------------------------------------------------- */

interface Props {
  /** Existing host to edit, or null to create a new one. */
  host: Host | null
  /** Full catalogue, for the jump-host picker. */
  catalogue: HostNode[]
  onSave: (host: Host) => void
  onDelete?: (hostId: string) => void
  onClose: () => void
}

const blank = (): Host => ({
  kind: 'host',
  id: `h-${Date.now().toString(36)}`,
  name: '',
  hostname: '',
  port: 22,
  username: '',
  auth: 'password',
})

export function HostEditor({ host, catalogue, onSave, onDelete, onClose }: Props) {
  const [draft, setDraft] = useState<Host>(host ?? blank())
  const [password, setPassword] = useState('')
  /** Live list of on-connect commands: selected presets plus custom lines. */
  const [startup, setStartup] = useState<string[]>(() =>
    rawStartupCommands(host ?? {}),
  )
  const [snippets, setSnippets] = useState<Snippet[]>(() => host?.snippets ?? [])
  const [showAdvanced, setShowAdvanced] = useState(
    () => customCommands(rawStartupCommands(host ?? {})).length > 0,
  )
  /** null while the vault lookup for the current credKey is in flight. */
  const [hasSaved, setHasSaved] = useState<boolean | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  /** Public key from a just-generated pair, shown for copying to the server. */
  const [generatedPub, setGeneratedPub] = useState<string | null>(null)
  /** Masked password entry for "Install on host" — window.prompt can't mask. */
  const [installPw, setInstallPw] = useState<string | null>(null)
  /** Read by the window Escape handler, which runs in the capture phase BEFORE
   *  the install overlay's own handler and so must know the overlay is up. */
  const installPwRef = useRef(installPw)
  installPwRef.current = installPw
  const firstRef = useRef<HTMLInputElement>(null)

  /** The vault entry this host actually uses: a borrowed one when "Same as …"
   *  is chosen. Connect reads the vault by this id, so status and saves must
   *  use it too — saving under the host's own id stored a password that was
   *  never read. */
  const credKey = draft.credentialId ?? draft.id
  const lender = draft.credentialId
    ? allHosts(catalogue).find((h) => h.id === draft.credentialId)
    : undefined

  useEffect(() => {
    firstRef.current?.focus()
  }, [])

  // Whether a secret already exists, without ever decrypting it.
  useEffect(() => {
    let live = true
    // Unknown until this entry's lookup returns, so a stale answer for the
    // previous entry can never gate (or wave through) a save.
    setHasSaved(null)
    void safeInvoke<boolean>('credential_status', { hostId: credKey }).then((v) => {
      if (live) setHasSaved(Boolean(v))
    })
    return () => {
      live = false
    }
  }, [credKey])

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return
      e.preventDefault()
      // Esc in the install-password overlay cancels only the overlay; closing
      // the whole editor here discarded every unsaved edit (and the path of a
      // key generated a moment ago).
      if (installPwRef.current !== null) {
        setInstallPw(null)
        return
      }
      onClose()
    }
    window.addEventListener('keydown', onKey, true)
    return () => window.removeEventListener('keydown', onKey, true)
  }, [onClose])

  const set = <K extends keyof Host>(k: K, v: Host[K]) =>
    setDraft((d) => ({ ...d, [k]: v }))

  const valid =
    draft.name.trim() !== '' && draft.hostname.trim() !== '' && draft.username.trim() !== ''

  const submit = async () => {
    if (!valid) {
      // Say WHAT is missing instead of a dead button that looks like the app
      // ignored the click.
      const missing = [
        draft.name.trim() === '' && 'Name',
        draft.hostname.trim() === '' && 'Hostname',
        draft.username.trim() === '' && 'Username',
      ].filter(Boolean)
      setError(`Fill in required field(s): ${missing.join(', ')}`)
      return
    }
    // The input's min/max are not enforced while typing; an out-of-range or
    // fractional port would save, then fail every connect and the whole
    // reachability sweep (the backend takes a u16).
    if (!Number.isInteger(draft.port) || draft.port < 1 || draft.port > 65535) {
      setError('Port must be a whole number from 1 to 65535.')
      return
    }
    // A saved password is only ever sent to the destinations it was saved for
    // (the backend binding). A new destination for it — this host now sharing
    // another's credential, or its hostname/port/username edited — must be
    // confirmed by typing the password, or every connect would be refused.
    const destChanged =
      !host ||
      host.hostname !== draft.hostname ||
      host.port !== draft.port ||
      host.username !== draft.username ||
      (host.credentialId ?? host.id) !== credKey
    if (hasSaved === null) {
      setError('Still checking the saved password — try again in a moment.')
      return
    }
    if (draft.auth === 'password' && hasSaved && destChanged && !password) {
      setError(
        lender
          ? `Enter ${lender.name}'s password to let this host use it — a saved password is only sent to destinations it was saved for.`
          : 'Re-enter the password to confirm the new destination — a saved password is only sent to destinations it was saved for.',
      )
      return
    }
    setBusy(true)
    setError(null)
    try {
      if (password) {
        await safeInvoke('credential_save', {
          hostId: credKey,
          username: draft.username,
          password,
          // The backend binds this secret to this destination (see
          // credential_save): it may only ever be sent here (and to catalogue
          // hosts that borrow it), regardless of later hosts.json edits.
          host: draft.hostname,
          port: draft.port,
        })
      }
      // Write the array and clear the legacy single-command field, so the two
      // can never disagree about what runs.
      onSave({
        ...draft,
        // Clean once, here: trim, drop blank lines, and de-duplicate — the last
        // also repairs any host whose commands were stacked by the old toggle.
        startupCommands: [...new Set(startup.map((c) => c.trim()).filter(Boolean))],
        startupCommand: undefined,
        snippets: snippets.filter((sn) => sn.command.trim() !== ''),
      })
      onClose()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
      setBusy(false)
    }
  }

  return (
    <div className="absolute inset-0 z-50 flex justify-center">
      <div className="animate-scrim-in absolute inset-0 bg-surface-0/75 backdrop-blur-[2px]" aria-hidden />

      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="he-title"
        className="animate-drop-in relative mt-8 flex max-h-[88vh] w-[30rem] max-w-[92vw] flex-col overflow-hidden rounded-panel border border-line-strong bg-surface-2 shadow-[0_24px_60px_-12px_rgba(0,0,0,0.75)]"
      >
        <header className="flex shrink-0 items-center gap-2 border-b border-line px-5 py-3">
          <Server size={15} className="shrink-0 text-accent" aria-hidden />
          <h2 id="he-title" className="flex-1 text-[13.5px] font-medium text-ink">
            {host ? 'Edit host' : 'New host'}
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

        <div className="min-h-0 flex-1 space-y-3 overflow-y-auto px-5 py-4">
          <Field label="Display name">
            <input
              ref={firstRef}
              value={draft.name}
              onChange={(e) => set('name', e.target.value)}
              placeholder="core-sw-01"
              className={inputCls}
            />
          </Field>

          <div className="grid grid-cols-[1fr_6rem] gap-2">
            <Field label="Hostname or IP">
              <input
                value={draft.hostname}
                onChange={(e) => set('hostname', e.target.value)}
                placeholder="10.20.1.2"
                className={`${inputCls} font-mono`}
              />
            </Field>
            <Field label="Port">
              <input
                type="number"
                min={1}
                max={65535}
                value={draft.port}
                onChange={(e) => set('port', Number(e.target.value) || 22)}
                className={`${inputCls} font-mono`}
              />
            </Field>
          </div>

          <Field label="Username">
            <input
              value={draft.username}
              onChange={(e) => set('username', e.target.value)}
              placeholder="admin"
              className={`${inputCls} font-mono`}
            />
          </Field>

          <Field label="AI assistant">
            <label className="flex cursor-pointer items-start gap-2 text-[12px] text-ink-dim">
              <input
                type="checkbox"
                checked={draft.aiAllowed ?? draft.color !== 'red'}
                onChange={(e) => set('aiAllowed', e.target.checked)}
                className="mt-[2px] h-3 w-3 accent-[var(--color-accent)]"
              />
              <span>
                Allow the assistant to see this host&apos;s terminal output.
                <span className="block text-[10.5px] text-ink-faint">
                  Red-accented hosts default to off — enabling sends session
                  context to whatever AI provider is configured.
                </span>
              </span>
            </label>
          </Field>

          <Field
            label="Config capture command"
            hint="For Snapshot config. IOS: show running-config · PAN-OS: show config running · Linux: cat /etc/..."
          >
            <input
              value={draft.configCommand ?? ''}
              onChange={(e) => set('configCommand', e.target.value || undefined)}
              placeholder="show running-config"
              className={`${inputCls} font-mono`}
            />
          </Field>

          <Field
            label="Credential"
            hint="Sharing means one vault entry covers many hosts — one edit on password rotation."
          >
            <select
              value={draft.credentialId ?? ''}
              onChange={(e) => {
                // A password typed for the previous vault entry must not be
                // saved into the newly chosen one: typing A's password, then
                // picking "Same as B", would overwrite B's shared secret.
                setPassword('')
                set('credentialId', e.target.value || undefined)
              }}
              className={`${inputCls} appearance-none`}
            >
              <option value="">Own credential (this host&apos;s vault entry)</option>
              {allHosts(catalogue)
                .filter((h) => h.id !== draft.id && !h.credentialId)
                .map((h) => (
                  <option key={h.id} value={h.id}>
                    Same as {h.name}
                  </option>
                ))}
            </select>
          </Field>

          <Field
            label="Jump host (ProxyJump)"
            hint="Tunnel through another saved host. One level only."
          >
            <select
              value={draft.jumpHostId ?? ''}
              onChange={(e) => set('jumpHostId', e.target.value || undefined)}
              className={`${inputCls} appearance-none`}
            >
              <option value="">Direct connection</option>
              {allHosts(catalogue)
                .filter((h) => h.id !== draft.id)
                .map((h) => (
                  <option key={h.id} value={h.id}>
                    {h.name} ({h.username}@{h.hostname})
                  </option>
                ))}
            </select>
          </Field>

          <Field label="Accent colour">
            <div className="flex items-center gap-1.5">
              {HOST_COLORS.map((c) => {
                const on = (draft.color ?? 'none') === c.key
                return (
                  <button
                    key={c.key}
                    type="button"
                    onClick={() => set('color', c.key)}
                    title={c.label}
                    aria-label={c.label}
                    aria-pressed={on}
                    className={`grid h-6 w-6 place-items-center rounded-full border transition-transform ${
                      on ? 'scale-110 border-ink' : 'border-line hover:scale-105'
                    }`}
                  >
                    {c.key === 'none' ? (
                      <span className="text-[9px] text-ink-faint">off</span>
                    ) : (
                      <span
                        className="h-3.5 w-3.5 rounded-full"
                        style={{ backgroundColor: c.hex }}
                      />
                    )}
                  </button>
                )
              })}
            </div>
          </Field>

          <Field label="Authentication">
            <div className="flex gap-1">
              {(['password', 'key', 'agent'] as AuthMethod[]).map((m) => (
                <button
                  key={m}
                  type="button"
                  onClick={() => {
                    // One field serves as password AND key passphrase; a value
                    // typed for one method must not be saved as the other.
                    if (m !== draft.auth) setPassword('')
                    set('auth', m)
                  }}
                  className={`flex-1 rounded border px-2 py-1 text-[12px] capitalize transition-colors ${
                    draft.auth === m
                      ? 'border-accent/60 bg-accent/15 text-accent'
                      : 'border-line bg-surface-1 text-ink-dim hover:bg-surface-3 hover:text-ink'
                  }`}
                >
                  {m}
                </button>
              ))}
            </div>
          </Field>

          {draft.auth === 'password' && (
            <Field
              label="Password"
              hint={
                lender
                  ? `Shared with ${lender.name}: typing here replaces that shared password for every host using it.`
                  : hasSaved
                    ? 'A password is already saved in Windows Credential Manager. Type to replace it.'
                    : 'Stored in Windows Credential Manager, never in the host file.'
              }
            >
              <div className="relative">
                <KeyRound
                  size={12}
                  className="pointer-events-none absolute top-1/2 left-2 -translate-y-1/2 text-ink-faint"
                  aria-hidden
                />
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder={hasSaved ? '•••••••• (saved)' : ''}
                  autoComplete="off"
                  className={`${inputCls} pl-7 font-mono`}
                />
              </div>
            </Field>
          )}

          <div>
            <span className="mb-1 block text-[10.5px] uppercase tracking-wider text-ink-faint">
              Snippets
            </span>
            <div className="space-y-1.5">
              {snippets.map((sn, i) => (
                <div key={i} className="flex items-center gap-1.5">
                  {/* Slot: which Ctrl+Shift+digit fires this. Duplicate slots
                      are allowed in the UI but only the first match fires, so
                      warn by tinting the select when a slot repeats. */}
                  <select
                    value={sn.slot ?? ''}
                    onChange={(e) =>
                      setSnippets((list) =>
                        list.map((x, j) =>
                          j === i ? { ...x, slot: e.target.value ? Number(e.target.value) : null } : x,
                        ),
                      )
                    }
                    title="Ctrl+Shift+<digit> shortcut slot"
                    className={`h-7 w-14 shrink-0 rounded border bg-surface-0 px-1 text-[11px] focus:border-accent focus:outline-none ${
                      sn.slot !== null && snippets.some((o, j) => j !== i && o.slot === sn.slot)
                        ? 'border-warn text-warn'
                        : 'border-line text-ink-dim'
                    }`}
                  >
                    <option value="">—</option>
                    {[1, 2, 3, 4, 5, 6, 7, 8, 9].map((d) => (
                      <option key={d} value={d}>
                        ⌃⇧{d}
                      </option>
                    ))}
                  </select>
                  <input
                    value={sn.label}
                    onChange={(e) =>
                      setSnippets((list) =>
                        list.map((x, j) => (j === i ? { ...x, label: e.target.value } : x)),
                      )
                    }
                    placeholder="Label"
                    className="h-7 w-28 shrink-0 rounded border border-line bg-surface-0 px-2 text-[12px] text-ink placeholder:text-ink-faint focus:border-accent focus:outline-none"
                  />
                  <input
                    value={sn.command}
                    onChange={(e) =>
                      setSnippets((list) =>
                        list.map((x, j) => (j === i ? { ...x, command: e.target.value } : x)),
                      )
                    }
                    placeholder="show session info"
                    className="h-7 min-w-0 flex-1 rounded border border-line bg-surface-0 px-2 font-mono text-[12px] text-ink placeholder:text-ink-faint focus:border-accent focus:outline-none"
                  />
                  <label
                    className="flex shrink-0 items-center gap-1 text-[10.5px] text-ink-faint"
                    title="Press Enter after pasting, so the command runs immediately"
                  >
                    <input
                      type="checkbox"
                      checked={sn.autoRun ?? false}
                      onChange={(e) =>
                        setSnippets((list) =>
                          list.map((x, j) => (j === i ? { ...x, autoRun: e.target.checked } : x)),
                        )
                      }
                      className="h-3 w-3 accent-[var(--color-accent)]"
                    />
                    run
                  </label>
                  <button
                    type="button"
                    aria-label="Remove snippet"
                    onClick={() => setSnippets((list) => list.filter((_, j) => j !== i))}
                    className="grid h-6 w-6 shrink-0 place-items-center rounded text-ink-faint hover:bg-surface-3 hover:text-alert"
                  >
                    <X size={12} />
                  </button>
                </div>
              ))}
              <button
                type="button"
                onClick={() =>
                  setSnippets((list) => [...list, { label: '', command: '', slot: null }])
                }
                className="flex items-center gap-1 rounded border border-line px-2 py-1 text-[11.5px] text-ink-dim hover:bg-surface-3 hover:text-ink"
              >
                <Plus size={12} aria-hidden />
                Add snippet
              </button>
              {snippets.length > 0 && (
                <p className="text-[10.5px] text-ink-faint">
                  Without “run”, the snippet is typed onto the prompt for you to review
                  before pressing Enter yourself.
                </p>
              )}
            </div>
          </div>

          <div>
            <span className="mb-1 block text-[10.5px] uppercase tracking-wider text-ink-faint">
              On connect
            </span>
            {/* Device-type profile: one pick fills the on-connect + config-capture
                commands for a platform. Not stored — the commands it sets are. */}
            <select
              value=""
              onChange={(e) => {
                const prof = DEVICE_PROFILES.find((p) => p.id === e.target.value)
                if (!prof) return
                setStartup(prof.startupCommands)
                set('configCommand', prof.configCommand)
                setShowAdvanced(true)
              }}
              title="Fill on-connect and config-capture commands for a device type"
              className="mb-1.5 w-full rounded border border-line bg-surface-0 px-2 py-1 text-[12px] text-ink"
            >
              <option value="">Apply device type…</option>
              {DEVICE_PROFILES.map((p) => (
                <option key={p.id} value={p.id}>{p.label}</option>
              ))}
            </select>
            <div className="space-y-1 rounded border border-line bg-surface-1 p-2">
              {STARTUP_PRESETS.map((preset) => {
                const on = startup.includes(preset.command)
                return (
                  <label
                    key={preset.id}
                    className="flex cursor-pointer items-start gap-2 rounded px-1 py-0.5 hover:bg-surface-2"
                  >
                    <input
                      type="checkbox"
                      checked={on}
                      onChange={() =>
                        setStartup((list) =>
                          // Decide from the CURRENT list, not the render-time
                          // `on`: a stale closure or an already-present command
                          // must never stack a second (or fifth) copy.
                          list.includes(preset.command)
                            ? list.filter((c) => c !== preset.command)
                            : [...list, preset.command],
                        )
                      }
                      className="mt-[3px] h-3 w-3 shrink-0 accent-[var(--color-accent)]"
                    />
                    <span className="min-w-0">
                      <span className="block text-[12.5px] text-ink">{preset.label}</span>
                      <span className="block text-[11px] text-ink-faint">{preset.hint}</span>
                      {/* The literal command, always visible: nothing should run
                          against production equipment that the user cannot see. */}
                      <code className="selectable mt-0.5 block font-mono text-[10.5px] text-ink-dim">
                        {preset.command}
                      </code>
                    </span>
                  </label>
                )
              })}
            </div>

            <button
              type="button"
              onClick={() => setShowAdvanced((v) => !v)}
              className="mt-1.5 text-[11px] text-ink-faint hover:text-ink"
            >
              {showAdvanced ? 'Hide' : 'Show'} advanced commands
            </button>

            {showAdvanced && (
              <p className="mt-1 text-[11px] text-ink-faint">
                <code className="font-mono text-ink-dim">{'{pane}'}</code> expands
                to this pane&apos;s number (1, 2, …), so split panes get separate
                tmux sessions instead of fighting over one.
              </p>
            )}

            {showAdvanced && (
              <textarea
                rows={3}
                value={customCommands(startup).join('\n')}
                onChange={(e) => {
                  // Keep lines verbatim — no trim/filter here. Trimming on each
                  // keystroke would strip a trailing space or a new line the
                  // instant it is typed, making spaces between words and new
                  // lines impossible to enter. Cleaning happens once, on save.
                  const custom = e.target.value.split('\n')
                  // Presets keep their order; custom lines follow.
                  const presets = startup.filter((c) =>
                    STARTUP_PRESETS.some((p) => p.command === c),
                  )
                  setStartup([...presets, ...custom])
                }}
                placeholder={'One command per line, e.g.\nexport TERM=xterm-256color'}
                className="mt-1 w-full rounded border border-line bg-surface-0 px-2 py-1 font-mono text-[12px] text-ink placeholder:text-ink-faint focus:border-accent focus:outline-none"
              />
            )}
          </div>

          {draft.auth === 'key' && (
            <Field
              label="Private key file"
              hint="OpenSSH format (id_ed25519, id_rsa). PuTTY .ppk must be exported to OpenSSH format first."
            >
              <div className="flex gap-1.5">
                <input
                  value={draft.keyPath ?? ''}
                  onChange={(e) => set('keyPath', e.target.value || undefined)}
                  placeholder="C:\Users\you\.ssh\id_ed25519"
                  className={`${inputCls} min-w-0 flex-1 font-mono`}
                />
                <button
                  type="button"
                  title="Generate a new Ed25519 keypair in ~/.ssh and use it here"
                  onClick={() =>
                    void safeInvoke<{ privatePath: string; publicKey: string }>('ssh_keygen', {
                      comment: `hawser ${draft.username || 'user'}@${draft.hostname || draft.name}`,
                    })
                      .then((r) => {
                        if (!r) return
                        set('keyPath', r.privatePath)
                        setGeneratedPub(r.publicKey)
                      })
                      .catch((e) => setError(e instanceof Error ? e.message : String(e)))
                  }
                  className="h-7 shrink-0 rounded border border-line px-2 text-[11.5px] text-ink-dim hover:bg-surface-3 hover:text-ink"
                >
                  Generate
                </button>
              </div>
              {generatedPub && (
                <span className="mt-1.5 block space-y-2 rounded border border-line bg-surface-0 p-2">
                  <span className="block text-[11px] leading-relaxed text-ink-faint">
                    The server needs this key before key login works. Install it
                    now (enter the password once), or copy the ready-to-run
                    command for appliances that manage keys their own way.
                  </span>

                  {/* One click: install over a throwaway password connection. */}
                  <button
                    type="button"
                    disabled={busy || !draft.hostname.trim() || !draft.username.trim()}
                    onClick={() => setInstallPw('')}
                    className="flex w-full items-center justify-center gap-1.5 rounded border border-accent/60 bg-accent/15 py-1.5 text-[12px] font-medium text-accent hover:bg-accent/25 disabled:opacity-40"
                  >
                    <KeyRound size={12} aria-hidden />
                    {busy ? 'Installing…' : 'Install on host'}
                  </button>

                  <span className="block">
                    <span className="mb-1 flex items-center justify-between text-[10.5px] uppercase tracking-wider text-ink-faint">
                      Or run this on the server
                      <button
                        type="button"
                        onClick={() =>
                          void navigator.clipboard.writeText(
                            `mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '${generatedPub}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys`,
                          )
                        }
                        className="rounded px-1 text-accent hover:bg-surface-3"
                      >
                        Copy command
                      </button>
                    </span>
                    <code className="selectable block break-all font-mono text-[10.5px] text-ink-dim">
                      mkdir -p ~/.ssh &amp;&amp; echo &apos;{generatedPub.slice(0, 24)}…&apos; &gt;&gt;
                      ~/.ssh/authorized_keys
                    </code>
                  </span>
                </span>
              )}
            </Field>
          )}

          {draft.auth === 'key' && (
            <Field
              label="Key passphrase"
              hint={
                hasSaved
                  ? 'A passphrase is saved in Windows Credential Manager. Type to replace it; leave empty to keep it.'
                  : 'Only needed if the key file is encrypted. Stored in Windows Credential Manager.'
              }
            >
              <div className="relative">
                <KeyRound
                  size={12}
                  className="pointer-events-none absolute top-1/2 left-2 -translate-y-1/2 text-ink-faint"
                  aria-hidden
                />
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder={hasSaved ? '•••••••• (saved)' : ''}
                  autoComplete="off"
                  className={`${inputCls} pl-7 font-mono`}
                />
              </div>
            </Field>
          )}

          {draft.auth === 'agent' && (
            <p className="rounded border border-line bg-surface-1 px-3 py-2 text-[11.5px] text-ink-faint">
              Uses a running SSH agent — the Windows OpenSSH agent service or
              PuTTY&apos;s Pageant. Keys stay in the agent; nothing is stored here.
            </p>
          )}

          {error && (
            <p className="selectable rounded border border-alert/40 bg-alert/10 px-3 py-2 text-[12px] text-alert">
              {error}
            </p>
          )}
        </div>

        <footer className="flex shrink-0 items-center gap-2 border-t border-line bg-surface-1 px-5 py-3">
          {host && onDelete && (
            <button
              type="button"
              onClick={() => { onDelete(host.id); onClose() }}
              className="flex items-center gap-1.5 rounded border border-line px-2.5 py-1.5 text-[12.5px] text-ink-faint transition-colors hover:border-alert/50 hover:text-alert"
            >
              <Trash2 size={13} aria-hidden />
              Delete
            </button>
          )}
          <div className="flex-1" />
          <button
            type="button"
            onClick={onClose}
            className="rounded border border-line bg-surface-2 px-3 py-1.5 text-[12.5px] text-ink-dim hover:bg-surface-3 hover:text-ink"
          >
            Cancel
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() => void submit()}
            className="rounded border border-accent/60 bg-accent/15 px-3 py-1.5 text-[12.5px] font-medium text-accent transition-colors hover:bg-accent/25 disabled:opacity-40"
          >
            {busy ? 'Saving…' : 'Save host'}
          </button>
        </footer>
      </div>

      {/* Masked password entry for key install — layered over the editor so
          the field can be a real type=password (window.prompt cannot mask). */}
      {installPw !== null && (
        <div className="absolute inset-0 z-[60] flex items-start justify-center pt-24">
          <div
            className="absolute inset-0 bg-surface-0/70"
            onMouseDown={() => setInstallPw(null)}
            aria-hidden
          />
          <div className="relative w-[24rem] max-w-[90vw] rounded-panel border border-line-strong bg-surface-2 p-4 shadow-2xl">
            <p className="mb-2 text-[12.5px] text-ink-dim">
              Password for{' '}
              <span className="font-mono text-ink">
                {draft.username}@{draft.hostname}
              </span>{' '}
              — used once to install the key, not saved.
            </p>
            <input
              type="password"
              autoFocus
              value={installPw}
              onChange={(e) => setInstallPw(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Escape') setInstallPw(null)
                if (e.key !== 'Enter') return
                const pw = installPw
                setInstallPw(null)
                setBusy(true)
                setError(null)
                void safeInvoke('ssh_copy_id', {
                  host: draft.hostname,
                  port: draft.port,
                  username: draft.username,
                  password: pw,
                  publicKey: generatedPub,
                })
                  .then(() =>
                    setError('✓ Key installed on the host. Save and connect with key auth.'),
                  )
                  .catch((e) => setError(e instanceof Error ? e.message : String(e)))
                  .finally(() => setBusy(false))
              }}
              className={`${inputCls} font-mono`}
            />
            <p className="mt-1.5 text-[10.5px] text-ink-faint">Enter to install · Esc to cancel</p>
          </div>
        </div>
      )}
    </div>
  )
}

const inputCls =
  'h-7 w-full rounded border border-line bg-surface-0 px-2 text-[12.5px] text-ink placeholder:text-ink-faint focus:border-accent focus:outline-none'

function Field({
  label, hint, children,
}: {
  label: string
  hint?: string
  children: React.ReactNode
}) {
  return (
    <label className="block">
      <span className="mb-1 block text-[10.5px] uppercase tracking-wider text-ink-faint">
        {label}
      </span>
      {children}
      {hint && <span className="mt-1 block text-[11px] text-ink-faint">{hint}</span>}
    </label>
  )
}
