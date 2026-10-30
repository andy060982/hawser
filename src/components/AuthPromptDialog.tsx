import { useEffect, useRef, useState } from 'react'
import { KeyRound, X } from 'lucide-react'
import { safeInvoke, safeListen } from '../lib/tauri'

interface AuthPromptField {
  prompt: string
  echo: boolean
}

interface AuthPromptRequest {
  requestId: string
  sessionId: string
  name: string
  instruction: string
  prompts: AuthPromptField[]
  /** When true, offer a "save to the OS vault" checkbox (up-front password
   *  prompt only — never for a single-use server challenge). */
  offerSave?: boolean
}

/* ---------------------------------------------------------------------------
   Keyboard-interactive challenge sheet (OTP / token / security question).

   Same oneshot bridge as the host-key prompt: the Rust auth task parks on a
   oneshot while this is open, so submitting is what unblocks the handshake, and
   the 120s backend timeout is why it can't hang open forever.

   The prompt that asks for the password is answered with the stored password
   entirely in the backend, so the password never crosses IPC. The user types
   only the live challenge (a token code, an SMS/TOTP one-time code, a security
   answer); a challenge the server marked no-echo (PAM's hidden "Verification
   code:") is masked.

   Cancel is the safe default (focus goes to the first field, Escape cancels the
   whole connection) — an unattended dialog must not silently accept anything.
--------------------------------------------------------------------------- */
export function AuthPromptDialog() {
  // A QUEUE, not a single slot: two sessions can hit a keyboard-interactive
  // challenge at once, each parked on its own backend oneshot. Overwriting the
  // visible request would strand the earlier one until its 120s timeout (same
  // bug HostKeyDialog avoids). Show the head; reveal the next after answering.
  const [queue, setQueue] = useState<AuthPromptRequest[]>([])
  const [answers, setAnswers] = useState<string[]>([])
  const [save, setSave] = useState(false)
  const [busy, setBusy] = useState(false)
  const firstRef = useRef<HTMLInputElement>(null)

  const request = queue[0] ?? null

  useEffect(() => {
    const uns: (() => void)[] = []
    let dead = false
    const add = (p: Promise<() => void>) =>
      void p.then((fn) => (dead ? fn() : uns.push(fn)))

    add(
      safeListen<AuthPromptRequest>('ssh://auth-prompt', (payload) => {
        // Append, de-duping by requestId so a re-emit can't enqueue twice.
        setQueue((q) => (q.some((r) => r.requestId === payload.requestId) ? q : [...q, payload]))
      }),
    )
    // The backend gave up on a prompt (120s timeout, or its tab was closed):
    // drop it so stale questions do not queue in front of live ones.
    add(
      safeListen<{ requestId: string }>('ssh://prompt-closed', ({ requestId }) => {
        setQueue((q) => q.filter((r) => r.requestId !== requestId))
      }),
    )

    return () => {
      dead = true
      uns.forEach((fn) => fn())
    }
  }, [])

  // Reset per-dialog state and focus whenever the HEAD changes.
  useEffect(() => {
    if (!request) return
    setAnswers(request.prompts.map(() => ''))
    setSave(false)
    setBusy(false)
    firstRef.current?.focus()

    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault()
        void cancel()
      }
    }
    window.addEventListener('keydown', onKey, true)
    return () => window.removeEventListener('keydown', onKey, true)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [request?.requestId])

  if (!request) return null

  async function submit(vals: string[]) {
    if (!request) return
    setBusy(true)
    await safeInvoke('auth_prompt_respond', {
      requestId: request.requestId,
      answers: vals,
      // Only meaningful when the save checkbox was offered; harmless otherwise.
      save: request.offerSave ? save : false,
    })
    // Drop THIS prompt (by id) so the next queued challenge shows.
    setQueue((q) => q.filter((r) => r.requestId !== request.requestId))
  }

  // Cancel must ABORT auth, not answer: an empty response would still let the
  // backend fill hidden prompts with the stored password (i.e. authenticate).
  // auth_prompt_cancel drops the backend oneshot so authentication fails.
  async function cancel() {
    if (!request) return
    setBusy(true)
    await safeInvoke('auth_prompt_cancel', { requestId: request.requestId })
    setQueue((q) => q.filter((r) => r.requestId !== request.requestId))
  }

  return (
    <div className="absolute inset-0 z-50 flex justify-center">
      <div
        className="animate-scrim-in absolute inset-0 bg-surface-0/75 backdrop-blur-[2px]"
        aria-hidden
      />

      <form
        onSubmit={(e) => {
          e.preventDefault()
          void submit(answers)
        }}
        role="dialog"
        aria-modal="true"
        aria-labelledby="ap-title"
        className="animate-drop-in relative mt-12 h-fit w-[30rem] max-w-[92vw] overflow-hidden rounded-panel border border-line-strong bg-surface-2 shadow-[0_24px_60px_-12px_rgba(0,0,0,0.75)]"
      >
        <div className="h-[3px] w-full bg-accent" />

        <header className="flex items-start gap-3 px-5 pt-4 pb-3">
          <div className="mt-px grid h-8 w-8 shrink-0 place-items-center rounded-full border border-accent/30 bg-accent/10">
            <KeyRound size={16} className="text-accent" aria-hidden />
          </div>
          <div className="min-w-0">
            <h2 id="ap-title" className="text-[14px] font-medium text-ink">
              Additional authentication
            </h2>
            <p className="mt-0.5 text-[12.5px] text-ink-dim">
              {request.name.trim() || 'The server is asking for another factor.'}
            </p>
          </div>
        </header>

        {request.instruction.trim() && (
          <p className="mx-5 mb-1 whitespace-pre-wrap text-[12px] leading-relaxed text-ink-faint">
            {request.instruction}
          </p>
        )}

        <div className="mx-5 mt-2 space-y-3">
          {request.prompts.map((p, i) => (
            <label key={i} className="block">
              <span className="mb-1 block text-[12px] text-ink-dim">
                {p.prompt.trim() || 'Response'}
              </span>
              <input
                ref={i === 0 ? firstRef : undefined}
                type={p.echo ? 'text' : 'password'}
                value={answers[i] ?? ''}
                onChange={(e) =>
                  setAnswers((a) => a.map((v, j) => (j === i ? e.target.value : v)))
                }
                autoComplete="off"
                autoCorrect="off"
                autoCapitalize="off"
                spellCheck={false}
                className="h-8 w-full rounded border border-line bg-surface-1 px-2 font-mono text-[13px] text-ink focus:border-accent focus:outline-none"
              />
            </label>
          ))}
        </div>

        {request.offerSave && (
          <label className="mx-5 mt-3 flex cursor-pointer items-center gap-2 text-[12.5px] text-ink-dim">
            <input
              type="checkbox"
              checked={save}
              onChange={(e) => setSave(e.target.checked)}
              className="h-3.5 w-3.5 accent-[var(--color-accent)]"
            />
            Save this password to your OS keychain
          </label>
        )}

        <footer className="mt-4 flex justify-end gap-2 border-t border-line bg-surface-1 px-5 py-3">
          <button
            type="button"
            disabled={busy}
            onClick={() => void cancel()}
            className="flex items-center gap-1.5 rounded border border-line bg-surface-2 px-3 py-1.5 text-[12.5px] text-ink-dim transition-colors hover:bg-surface-3 hover:text-ink disabled:opacity-50"
          >
            <X size={13} aria-hidden />
            Cancel connection
          </button>
          <button
            type="submit"
            disabled={busy}
            className="flex items-center gap-1.5 rounded border border-accent/60 bg-accent/15 px-3 py-1.5 text-[12.5px] font-medium text-accent transition-colors hover:bg-accent/25 disabled:opacity-50"
          >
            <KeyRound size={13} aria-hidden />
            Submit
          </button>
        </footer>
      </form>
    </div>
  )
}
