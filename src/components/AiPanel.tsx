import { useCallback, useEffect, useRef, useState } from 'react'
import {
  Bot, Check, Copy, CornerDownLeft, Loader2, Settings2, ShieldOff, Sparkles,
  TextSearch, X,
} from 'lucide-react'
import type { Host, Session } from '../types'
import type { HostColor } from '../lib/hostColors'
import { type ColorPolicy, policyFor, useSettings } from '../lib/settings'
import { safeInvoke, safeListen } from '../lib/tauri'
import { getTerm } from '../lib/termRegistry'
import { scanForSecrets, type SecretHit } from '../lib/secretScan'
import { ShieldAlert } from 'lucide-react'

interface AiConfig {
  kind: 'anthropic' | 'openai' | 'claude-code'
  baseUrl: string
  model: string
}

interface Msg {
  role: 'user' | 'assistant'
  content: string
  /** A local error notice shown in place of a reply. Never sent back to the
   *  provider as if the model had said it. */
  error?: boolean
}

interface AiEvent {
  runId: string
  delta: string
  done: boolean
  error: string | null
}

const PRESETS: { label: string; cfg: AiConfig }[] = [
  {
    label: 'Claude Code CLI (uses your Claude subscription)',
    cfg: { kind: 'claude-code', baseUrl: '', model: 'managed by Claude Code' },
  },
  { label: 'Anthropic (Claude)', cfg: { kind: 'anthropic', baseUrl: 'https://api.anthropic.com', model: 'claude-sonnet-4-5' } },
  { label: 'OpenAI', cfg: { kind: 'openai', baseUrl: 'https://api.openai.com/v1', model: 'gpt-4o-mini' } },
  { label: 'Ollama (local)', cfg: { kind: 'openai', baseUrl: 'http://localhost:11434/v1', model: 'llama3.1' } },
  { label: 'LM Studio (local)', cfg: { kind: 'openai', baseUrl: 'http://localhost:1234/v1', model: 'local-model' } },
]

/** Whether the assistant may see this host's terminal output. Red-accented
 *  hosts (production, by this app's own convention) default to NO — sending a
 *  production firewall's session to any endpoint should be a deliberate act. */
export function aiAllowedFor(
  host: Host | undefined,
  policy: ColorPolicy,
): boolean {
  if (!host) return false
  // An explicit per-host choice wins; otherwise the colour policy decides
  // (default: off for red, on for everything else — all user-configurable).
  return host.aiAllowed ?? policy.ai !== 'off'
}

/* ---------------------------------------------------------------------------
   AI assistant panel (Ctrl+Shift+A).

   Advisor only, by architecture rather than by policy:
   - Suggestions render as chips; Insert TYPES the command into the terminal
     with no newline. The human pressing Enter is the approval step.
   - Context is the visible tail of THIS session's transcript (~4 KB), shown
     as a labelled line so what leaves the machine is never a surprise.
   - The provider sees one session, never other tabs.
--------------------------------------------------------------------------- */
export function AiPanel({
  session,
  host,
  effectiveColor,
  onClose,
}: {
  session: Session | undefined
  host: Host | undefined
  effectiveColor?: HostColor
  onClose: () => void
}) {
  const [cfg, setCfg] = useState<AiConfig | null>(null)
  const [showSettings, setShowSettings] = useState(false)
  const [keySaved, setKeySaved] = useState(false)
  const [keyDraft, setKeyDraft] = useState('')
  // One conversation per session id, so switching panes/sessions and coming
  // back restores that session's thread instead of wiping it — while still
  // never showing one session's history under another (no cross-host bleed).
  const [threads, setThreads] = useState<Record<string, Msg[]>>({})
  const emptyThread = useRef<Msg[]>([])
  const sid = session?.id
  const messages = (sid && threads[sid]) || emptyThread.current
  // A ref so an in-flight stream lands in the session it started in, even if
  // the user has switched away by the time deltas arrive.
  const sidRef = useRef<string | undefined>(sid)
  sidRef.current = sid
  /** Update one session's thread by id (not necessarily the active one). */
  const setThreadMsgs = useCallback(
    (targetSid: string, updater: Msg[] | ((m: Msg[]) => Msg[])) => {
      setThreads((prev) => ({
        ...prev,
        [targetSid]:
          typeof updater === 'function'
            ? (updater as (m: Msg[]) => Msg[])(prev[targetSid] ?? [])
            : updater,
      }))
    },
    [],
  )
  const [input, setInput] = useState('')
  const [streaming, setStreaming] = useState(false)
  /** Held request awaiting the user's OK after a secret was detected in what
   *  would be sent. Null = nothing pending. */
  const [pendingSend, setPendingSend] = useState<{
    /** The session the question was asked in — the reply belongs there. */
    sid: string
    thread: Msg[]
    systemContext: string
    hits: SecretHit[]
  } | null>(null)
  const threadRef = useRef<HTMLDivElement>(null)
  const unlistenRef = useRef<(() => void) | null>(null)

  const { settings } = useSettings()
  const allowed = aiAllowedFor(host, policyFor(settings, effectiveColor))

  /* Provider config: load once; missing config opens settings. */
  useEffect(() => {
    void safeInvoke<AiConfig | null>('ai_config_load').then((c) => {
      // kind, not baseUrl: the Claude Code CLI provider has no URL at all.
      if (c && c.kind) setCfg(c)
      else setShowSettings(true)
    })
  }, [])

  useEffect(() => {
    void safeInvoke<boolean>('ai_key_status', { profile: 'default' }).then((v) =>
      setKeySaved(Boolean(v)),
    )
  }, [showSettings])

  useEffect(() => {
    threadRef.current?.scrollTo(0, threadRef.current.scrollHeight)
  }, [messages])

  useEffect(() => () => unlistenRef.current?.(), [])

  const saveSettings = async (next: AiConfig) => {
    setCfg(next)
    await safeInvoke('ai_config_save', { config: next })
    if (keyDraft.trim()) {
      // Pass the origin so the backend can bind the key to it (see save_key):
      // the key may then only be sent to this kind/base_url, regardless of any
      // later edit to ai.json.
      await safeInvoke('ai_key_save', {
        profile: 'default',
        key: keyDraft.trim(),
        kind: next.kind,
        baseUrl: next.baseUrl,
      })
      setKeyDraft('')
      setKeySaved(true)
    }
    setShowSettings(false)
  }

  /** Forget the saved key (and the origin it is bound to). The way out after
   *  moving to a provider that needs none, e.g. local Ollama. */
  const removeKey = async () => {
    await safeInvoke('ai_key_delete', { profile: 'default' })
    setKeySaved(false)
  }

  /** Actually fire the request — reached either directly, or after the user
   *  clears the secret-warning gate below. */
  const dispatch = useCallback(
    async (target: string, thread: Msg[], systemContext: string) => {
      // Bound to the session the question was ASKED in (captured by send()
      // before any await), so the reply lands in that thread even if the user
      // switched tabs before it was sent or while it streams. Reading the
      // current session here put one host's conversation into another's.
      // Drop any prior listener before registering a new one — a dispatch that
      // errored without ever emitting `done` would otherwise leak its ai://…
      // subscription until the panel unmounts.
      unlistenRef.current?.()
      unlistenRef.current = null
      setThreadMsgs(target, [...thread, { role: 'assistant', content: '' }])
      setStreaming(true)
      const runId = `ai-${Date.now()}`
      unlistenRef.current = await safeListen<AiEvent>(`ai://${runId}`, (ev) => {
        if (ev.error) {
          setThreadMsgs(target, (m) => {
            const copy = [...m]
            copy[copy.length - 1] = {
              role: 'assistant',
              content: `⚠ ${ev.error}`,
              error: true,
            }
            return copy
          })
        } else if (ev.delta) {
          setThreadMsgs(target, (m) => {
            const copy = [...m]
            copy[copy.length - 1] = {
              role: 'assistant',
              content: copy[copy.length - 1].content + ev.delta,
            }
            return copy
          })
        }
        if (ev.done) {
          setStreaming(false)
          unlistenRef.current?.()
          unlistenRef.current = null
        }
      })

      try {
        await safeInvoke('ai_chat', {
          runId,
          cfg,
          profile: 'default',
          systemContext,
          messages: thread,
        })
      } catch (e) {
        setStreaming(false)
        unlistenRef.current?.()
        unlistenRef.current = null
        setThreadMsgs(target, (m) => [
          ...m.slice(0, -1),
          { role: 'assistant', content: `⚠ ${e instanceof Error ? e.message : e}`, error: true },
        ])
      }
    },
    [cfg, setThreadMsgs],
  )

  const send = useCallback(
    async (text: string) => {
      // `allowed` is normally enforced by which branch renders the input, but
      // gate the sender explicitly too so a red/prod host can never have its
      // context sent to a provider, whatever calls send().
      if (!cfg || !session || !host || !allowed || streaming || !text.trim()) return
      const targetSid = session.id
      const userMsg: Msg = { role: 'user', content: text.trim() }
      // What goes back to the provider is the real conversation: local error
      // notices and replies that never streamed any text are not turns the
      // model took. An empty assistant turn is rejected outright by the
      // Anthropic API, which then broke every later message in the thread.
      const sendable = messages.filter(
        (m) => !(m.role === 'assistant' && (m.error || !m.content.trim())),
      )
      const thread = [...sendable, userMsg]
      setInput('')

      // Context: the transcript tail for THIS host. Labelled in the thread
      // header below so the user always knows what was shared.
      const tail =
        (await safeInvoke<string | null>('session_history', {
          host: host.hostname,
          maxBytes: 4000,
        })) ?? ''

      const systemContext =
        `Host: ${host.name} (${host.hostname}:${host.port}, user ${host.username}).\n` +
        (host.startupCommands?.length
          ? `On-connect commands (platform hint): ${host.startupCommands.join(' ; ')}\n`
          : '') +
        (tail ? `Recent terminal output (untrusted):\n${tail}` : '(no terminal output captured yet)')

      // Pre-send secret guard: if the context that is about to leave the
      // machine looks like it holds a credential, pause and make the user
      // confirm. Their own typed question is scanned too — a pasted password
      // in the prompt should trip it as readily as one in an on-connect line.
      const hits = scanForSecrets(systemContext + '\n' + text)
      if (hits.length > 0) {
        setPendingSend({ sid: targetSid, thread, systemContext, hits })
        return
      }
      void dispatch(targetSid, thread, systemContext)
    },
    [cfg, session, host, allowed, streaming, messages, dispatch],
  )

  const explainSelection = () => {
    if (!session) return
    const sel = getTerm(session.id)?.term.getSelection()?.trim()
    if (sel) void send(`Explain this output:\n\n${sel}`)
  }

  return (
    <aside className="flex w-[22.5rem] shrink-0 flex-col border-l border-line bg-surface-1">
      <header className="flex h-8 shrink-0 items-center gap-2 border-b border-line px-3">
        <Sparkles size={13} className="shrink-0 text-accent" aria-hidden />
        <span className="flex-1 text-[12.5px] font-medium text-ink">Assistant</span>
        <button
          type="button"
          aria-label="Provider settings"
          onClick={() => setShowSettings((v) => !v)}
          className="grid h-6 w-6 place-items-center rounded text-ink-faint hover:bg-surface-3 hover:text-ink"
        >
          <Settings2 size={13} />
        </button>
        <button
          type="button"
          aria-label="Close assistant"
          onClick={onClose}
          className="grid h-6 w-6 place-items-center rounded text-ink-faint hover:bg-surface-3 hover:text-ink"
        >
          <X size={13} />
        </button>
      </header>

      {showSettings ? (
        <SettingsForm
          cfg={cfg}
          keySaved={keySaved}
          keyDraft={keyDraft}
          setKeyDraft={setKeyDraft}
          onSave={saveSettings}
          onRemoveKey={removeKey}
        />
      ) : !session || !host ? (
        <p className="p-4 text-[12px] text-ink-faint">Open a session to use the assistant.</p>
      ) : !allowed ? (
        <div className="flex flex-1 flex-col items-center justify-center gap-2 p-4 text-center">
          <ShieldOff size={22} className="text-warn" aria-hidden />
          <p className="text-[12.5px] text-ink-dim">AI is disabled for {host.name}.</p>
          <p className="text-[11.5px] leading-relaxed text-ink-faint">
            Red-accented hosts default to off — the assistant would send this
            session&apos;s terminal output to the configured provider. Enable it
            per host in the host editor if that is acceptable here.
          </p>
        </div>
      ) : (
        <>
          <p className="border-b border-line px-3 py-1 text-[10.5px] text-ink-faint">
            Context: {host.name} + last ~4 KB of its transcript · {cfg?.model ?? 'no provider'}
          </p>

          <div ref={threadRef} className="min-h-0 flex-1 space-y-3 overflow-y-auto p-3">
            {messages.length === 0 && (
              <p className="text-[12px] leading-relaxed text-ink-faint">
                Ask about the session — &ldquo;how do I monitor CPU here&rdquo;,
                &ldquo;why did that command fail&rdquo;. Suggested commands appear
                as chips: <b>Insert</b> types them into the terminal, and nothing
                runs until you press Enter yourself.
              </p>
            )}
            {messages.map((m, i) => (
              <MessageView key={i} msg={m} sessionId={session.id} />
            ))}
            {streaming && (
              <Loader2 size={13} className="animate-spin text-accent" aria-label="thinking" />
            )}
          </div>

          <div className="shrink-0 border-t border-line p-2">
            <div className="mb-1.5 flex gap-1">
              <button
                type="button"
                onClick={explainSelection}
                title="Explain the text currently selected in the terminal"
                className="flex h-6 items-center gap-1 rounded border border-line px-1.5 text-[11px] text-ink-dim hover:bg-surface-3 hover:text-ink"
              >
                <TextSearch size={11} aria-hidden />
                Explain selection
              </button>
            </div>
            <div className="flex gap-1.5">
              <textarea
                rows={2}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault()
                    void send(input)
                  }
                }}
                placeholder="Ask about this session…"
                className="min-w-0 flex-1 resize-none rounded border border-line bg-surface-0 px-2 py-1.5 text-[12.5px] text-ink placeholder:text-ink-faint focus:border-accent focus:outline-none"
              />
              <button
                type="button"
                disabled={streaming || !input.trim()}
                onClick={() => void send(input)}
                aria-label="Send"
                className="grid w-9 shrink-0 place-items-center rounded border border-accent/60 bg-accent/15 text-accent hover:bg-accent/25 disabled:opacity-40"
              >
                <CornerDownLeft size={14} />
              </button>
            </div>
          </div>
        </>
      )}
      {pendingSend && (
        <div className="absolute inset-0 z-[70] flex items-center justify-center p-4">
          <div
            className="absolute inset-0 bg-surface-0/80"
            onMouseDown={() => setPendingSend(null)}
            aria-hidden
          />
          <div className="relative w-full max-w-[20rem] overflow-hidden rounded-panel border border-warn/50 bg-surface-2 shadow-2xl">
            <header className="flex items-center gap-2 border-b border-line px-3 py-2.5">
              <ShieldAlert size={15} className="shrink-0 text-warn" aria-hidden />
              <span className="text-[12.5px] font-medium text-ink">Possible secret in context</span>
            </header>
            <div className="space-y-2 px-3 py-3 text-[12px] text-ink-dim">
              <p>
                What would be sent to the AI provider looks like it contains a
                credential. Nothing has left this machine yet.
              </p>
              <ul className="space-y-1 rounded border border-line bg-surface-0 p-2">
                {pendingSend.hits.slice(0, 6).map((h, i) => (
                  <li key={i} className="min-w-0">
                    <span className="block text-[11px] text-warn">{h.reason}</span>
                    <code className="selectable block truncate font-mono text-[10.5px] text-ink-faint">
                      {h.preview}
                    </code>
                  </li>
                ))}
                {pendingSend.hits.length > 6 && (
                  <li className="text-[10.5px] text-ink-faint">
                    +{pendingSend.hits.length - 6} more
                  </li>
                )}
              </ul>
              <p className="text-[11px] text-ink-faint">
                Secrets belong in the credential vault, not in on-connect
                commands or snippets. Send anyway only if these are safe to
                share with the provider.
              </p>
            </div>
            <footer className="flex justify-end gap-2 border-t border-line bg-surface-1 px-3 py-2.5">
              <button
                type="button"
                onClick={() => setPendingSend(null)}
                className="rounded border border-line px-3 py-1 text-[12px] text-ink-dim hover:bg-surface-3 hover:text-ink"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => {
                  const p = pendingSend
                  setPendingSend(null)
                  void dispatch(p.sid, p.thread, p.systemContext)
                }}
                className="rounded border border-warn/60 bg-warn/15 px-3 py-1 text-[12px] font-medium text-warn hover:bg-warn/25"
              >
                Send anyway
              </button>
            </footer>
          </div>
        </div>
      )}
    </aside>
  )
}

/* ------------------------------------------------------------- rendering */

/** Message bodies split on ``` fences; code blocks become insertable chips. */
function MessageView({ msg, sessionId }: { msg: Msg; sessionId: string }) {
  const parts = msg.content.split('```')

  return (
    <div className={msg.role === 'user' ? 'text-right' : ''}>
      <div
        className={`inline-block max-w-full rounded-md px-2.5 py-1.5 text-left text-[12.5px] leading-relaxed ${
          msg.role === 'user'
            ? 'bg-accent-soft text-ink'
            : 'bg-surface-2 text-ink-dim'
        }`}
      >
        {msg.role === 'user' ? (
          <span className="selectable whitespace-pre-wrap">{msg.content}</span>
        ) : (
          parts.map((part, i) =>
            i % 2 === 0 ? (
              <span key={i} className="selectable whitespace-pre-wrap">
                {part}
              </span>
            ) : (
              <CommandChip key={i} raw={part} sessionId={sessionId} />
            ),
          )
        )}
      </div>
      {msg.role === 'assistant' && msg.content === '' ? null : null}
    </div>
  )
}

function CommandChip({ raw, sessionId }: { raw: string; sessionId: string }) {
  const [inserted, setInserted] = useState(false)
  // Strip an optional language tag line ("bash\n...") and trailing whitespace.
  const lines = raw.replace(/^\s*\n/, '').split('\n')
  const first = lines[0]?.trim() ?? ''
  const body = (/^[a-z0-9_-]{1,12}$/i.test(first) ? lines.slice(1) : lines)
    .join('\n')
    .trim()

  if (!body) return null

  const insert = () => {
    // Typed into the terminal input, NO trailing newline: the user reviews it
    // on their own prompt and presses Enter — or doesn't. That keystroke is
    // the entire approval model; never "improve" this by appending \n.
    const bytes = Array.from(new TextEncoder().encode(body))
    void safeInvoke('ssh_write', { sessionId, data: bytes }).then(() => {
      setInserted(true)
      getTerm(sessionId)?.term.focus()
      setTimeout(() => setInserted(false), 1600)
    })
  }

  return (
    <span className="my-1.5 block overflow-hidden rounded border border-line bg-surface-0">
      <code className="selectable block overflow-x-auto whitespace-pre px-2 py-1.5 font-mono text-[12px] text-ink">
        {body}
      </code>
      <span className="flex border-t border-line">
        <button
          type="button"
          onClick={insert}
          className="flex flex-1 items-center justify-center gap-1 py-1 text-[11px] text-accent hover:bg-accent/10"
        >
          {inserted ? <Check size={11} aria-hidden /> : <CornerDownLeft size={11} aria-hidden />}
          {inserted ? 'Typed — press Enter to run' : 'Insert into terminal'}
        </button>
        <button
          type="button"
          onClick={() => void navigator.clipboard.writeText(body)}
          className="flex items-center gap-1 border-l border-line px-2 py-1 text-[11px] text-ink-faint hover:bg-surface-3 hover:text-ink"
        >
          <Copy size={11} aria-hidden />
          Copy
        </button>
      </span>
    </span>
  )
}

/* -------------------------------------------------------------- settings */

function SettingsForm({
  cfg, keySaved, keyDraft, setKeyDraft, onSave, onRemoveKey,
}: {
  cfg: AiConfig | null
  keySaved: boolean
  keyDraft: string
  setKeyDraft: (v: string) => void
  onSave: (cfg: AiConfig) => void
  onRemoveKey: () => Promise<void>
}) {
  const [draft, setDraft] = useState<AiConfig>(
    cfg ?? PRESETS[0].cfg,
  )

  const inputCls =
    'h-7 w-full rounded border border-line bg-surface-0 px-2 font-mono text-[12px] text-ink placeholder:text-ink-faint focus:border-accent focus:outline-none'

  return (
    <div className="space-y-2.5 overflow-y-auto p-3">
      <label className="block">
        <span className="mb-1 block text-[10.5px] uppercase tracking-wider text-ink-faint">
          Preset
        </span>
        <select
          value=""
          onChange={(e) => {
            const p = PRESETS.find((x) => x.label === e.target.value)
            if (p) setDraft(p.cfg)
          }}
          className={`${inputCls} appearance-none`}
        >
          <option value="">Choose a preset…</option>
          {PRESETS.map((p) => (
            <option key={p.label} value={p.label}>{p.label}</option>
          ))}
        </select>
      </label>

      <label className="block">
        <span className="mb-1 block text-[10.5px] uppercase tracking-wider text-ink-faint">
          API style
        </span>
        <select
          value={draft.kind}
          onChange={(e) => setDraft({ ...draft, kind: e.target.value as AiConfig['kind'] })}
          className={`${inputCls} appearance-none`}
        >
          <option value="claude-code">Claude Code CLI (local)</option>
          <option value="anthropic">Anthropic API</option>
          <option value="openai">OpenAI-compatible API</option>
        </select>
      </label>

      {draft.kind === 'claude-code' && (
        <p className="rounded border border-line bg-surface-0 px-2.5 py-2 text-[11px] leading-relaxed text-ink-faint">
          Runs the <code className="font-mono">claude</code> CLI installed on
          this machine. Auth (API key or claude.ai subscription) is handled by
          Claude Code itself — nothing to configure here. Responses arrive in
          one piece rather than streaming.
        </p>
      )}

      <label className="block">
        <span className="mb-1 block text-[10.5px] uppercase tracking-wider text-ink-faint">
          Base URL
        </span>
        <input
          value={draft.baseUrl}
          onChange={(e) => setDraft({ ...draft, baseUrl: e.target.value })}
          className={inputCls}
        />
      </label>

      <label className="block">
        <span className="mb-1 block text-[10.5px] uppercase tracking-wider text-ink-faint">
          Model
        </span>
        <input
          value={draft.model}
          onChange={(e) => setDraft({ ...draft, model: e.target.value })}
          className={inputCls}
        />
      </label>

      <label className="block">
        <span className="mb-1 block text-[10.5px] uppercase tracking-wider text-ink-faint">
          API key
        </span>
        <input
          type="password"
          value={keyDraft}
          onChange={(e) => setKeyDraft(e.target.value)}
          placeholder={keySaved ? '•••••••• (saved — type to replace)' : 'not needed for local endpoints'}
          autoComplete="off"
          className={inputCls}
        />
        <span className="mt-1 block text-[10.5px] text-ink-faint">
          Stored in Windows Credential Manager, never in a file. Note: this is
          an API key (console.anthropic.com / platform.openai.com) — chat
          subscriptions (claude.ai, ChatGPT) have no third-party API. Local
          Ollama / LM Studio need no key and send nothing off this machine.
          A saved key is used only with the provider it was saved for — switch
          provider and re-enter the key, or remove it.
        </span>
        {keySaved && (
          <button
            type="button"
            onClick={() => void onRemoveKey()}
            className="mt-1 text-[10.5px] text-ink-faint underline hover:text-alert"
          >
            Remove saved key
          </button>
        )}
      </label>

      <button
        type="button"
        onClick={() => onSave(draft)}
        className="w-full rounded border border-accent/60 bg-accent/15 py-1.5 text-[12.5px] font-medium text-accent hover:bg-accent/25"
      >
        Save
      </button>

      <p className="flex items-start gap-1.5 text-[10.5px] leading-relaxed text-ink-faint">
        <Bot size={11} className="mt-px shrink-0" aria-hidden />
        The assistant sees this host&apos;s name and the visible tail of its
        transcript. It suggests; it cannot run anything — you press Enter.
      </p>
    </div>
  )
}
