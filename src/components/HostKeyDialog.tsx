import { useEffect, useRef, useState } from 'react'
import { Check, Fingerprint, ShieldAlert, X } from 'lucide-react'
import { safeInvoke, safeListen } from '../lib/tauri'

interface HostKeyRequest {
  requestId: string
  host: string
  ip: string
  port: number
  keyType: string
  /** OpenSSH-style SHA256 fingerprint, identical to `ssh-keygen -lf` output. */
  fingerprint: string
}

/* ---------------------------------------------------------------------------
   Host-key confirmation sheet.

   The Rust handler parks on a oneshot while this is open, so answering is what
   unblocks the connection — and the 120s backend timeout is why there is no
   way to leave it open indefinitely.

   Three deliberate UX choices, all of them security decisions wearing UI
   clothes:

   1. **Cancel is the default focus, not Trust.** A dialog dismissed by reflex
      is worth nothing. The keyboard path of least resistance must be the safe
      one, and Escape also cancels.
   2. **The fingerprint is selectable and monospaced, in its own field.**
      Comparing 43 base64 characters by eye is error-prone; the realistic
      workflow is copy, then diff against the server console. Making that easy
      is the difference between a check and a ritual.
   3. **No "don't ask again" affordance.** Accepting already records the key, so
      the prompt appears exactly once per host. A broader suppression toggle
      would only ever be used to silence the thing worth reading.

   Only *unknown* keys reach this component. A changed key is refused in Rust
   and never prompts.
--------------------------------------------------------------------------- */
export function HostKeyDialog() {
  // A QUEUE, not a single slot. Two connections to unknown hosts each park on
  // their own backend oneshot and can prompt concurrently; overwriting the
  // visible request would strand the earlier one (it would sit until its 120s
  // timeout) and could show one host's fingerprint while resolving another's.
  // We show the head and reveal the next only after the current is answered.
  const [queue, setQueue] = useState<HostKeyRequest[]>([])
  const [busy, setBusy] = useState(false)
  const [copied, setCopied] = useState(false)
  const cancelRef = useRef<HTMLButtonElement>(null)

  const request = queue[0] ?? null

  useEffect(() => {
    const uns: (() => void)[] = []
    let dead = false
    const add = (p: Promise<() => void>) =>
      void p.then((fn) => (dead ? fn() : uns.push(fn)))

    add(
      safeListen<HostKeyRequest>('ssh://host-key-prompt', (payload) => {
        // Append, de-duping by requestId so a re-emitted event cannot enqueue
        // the same prompt twice.
        setQueue((q) => (q.some((r) => r.requestId === payload.requestId) ? q : [...q, payload]))
      }),
    )
    // The backend gave up on a prompt (120s timeout, or its tab was closed).
    // Drop it so a dead question does not sit at the head of the queue in
    // front of live ones — answering it would do nothing anyway.
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

  // Whenever the HEAD changes, reset per-dialog state, focus the safe action,
  // and wire Escape to deny — for each queued prompt in turn.
  useEffect(() => {
    if (!request) return
    setBusy(false)
    setCopied(false)
    cancelRef.current?.focus()

    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault()
        void respond(false)
      }
    }
    window.addEventListener('keydown', onKey, true)
    return () => window.removeEventListener('keydown', onKey, true)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [request?.requestId])

  if (!request) return null

  async function respond(accept: boolean) {
    if (!request) return
    setBusy(true)
    await safeInvoke('host_key_respond', { requestId: request.requestId, accept })
    // Remove THIS prompt (by id, not position) so the next queued one shows.
    setQueue((q) => q.filter((r) => r.requestId !== request.requestId))
  }

  const copyFingerprint = async () => {
    await navigator.clipboard.writeText(request.fingerprint)
    setCopied(true)
    setTimeout(() => setCopied(false), 1600)
  }

  // Split "SHA256:base64" so the algorithm label does not compete with the
  // digits the user is actually comparing.
  const [algo, digest] = request.fingerprint.includes(':')
    ? [request.fingerprint.slice(0, request.fingerprint.indexOf(':')),
       request.fingerprint.slice(request.fingerprint.indexOf(':') + 1)]
    : ['SHA256', request.fingerprint]

  return (
    <div className="absolute inset-0 z-50 flex justify-center">
      {/* Scrim: dims the shell without hiding it, so the user keeps the context
          of which window raised this. */}
      <div
        className="animate-scrim-in absolute inset-0 bg-surface-0/75 backdrop-blur-[2px]"
        aria-hidden
      />

      <div
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="hk-title"
        aria-describedby="hk-desc"
        className="animate-drop-in relative mt-12 h-fit w-[32rem] max-w-[92vw] overflow-hidden rounded-panel border border-line-strong bg-surface-2 shadow-[0_24px_60px_-12px_rgba(0,0,0,0.75)]"
      >
        {/* Accent rule: amber, not red — this is a decision point, not a
            failure, and red is reserved for the refused-changed-key path. */}
        <div className="h-[3px] w-full bg-warn" />

        <header className="flex items-start gap-3 px-5 pt-4 pb-3">
          <div className="mt-px grid h-8 w-8 shrink-0 place-items-center rounded-full border border-warn/30 bg-warn/10">
            <ShieldAlert size={16} className="text-warn" aria-hidden />
          </div>
          <div className="min-w-0">
            <h2 id="hk-title" className="text-[14px] font-medium text-ink">
              Unrecognised host key
            </h2>
            <p id="hk-desc" className="mt-0.5 text-[12.5px] text-ink-dim">
              Skiff has not connected to this server before.
              {queue.length > 1 && (
                <span className="ml-1 text-ink-faint">
                  ({queue.length - 1} more {queue.length - 1 === 1 ? 'prompt' : 'prompts'} waiting)
                </span>
              )}
            </p>
          </div>
        </header>

        {/* Identity block */}
        <dl className="mx-5 grid grid-cols-[5.5rem_1fr] gap-x-3 gap-y-1.5 rounded border border-line bg-surface-1 px-4 py-3 text-[12.5px]">
          <dt className="text-ink-faint">Hostname</dt>
          <dd className="selectable truncate font-mono text-ink" title={request.host}>
            {request.host}
          </dd>

          <dt className="text-ink-faint">Address</dt>
          <dd className="selectable font-mono text-ink-dim">
            {request.ip}
            <span className="text-ink-faint">:{request.port}</span>
          </dd>

          <dt className="text-ink-faint">Key type</dt>
          <dd className="font-mono uppercase text-ink-dim">{request.keyType}</dd>
        </dl>

        {/* Fingerprint: the thing the user is actually here to verify, so it
            gets its own field, the largest monospace size in the sheet, and a
            one-click copy. */}
        <div className="mx-5 mt-3 rounded border border-line bg-surface-0 px-4 py-3">
          <div className="mb-1.5 flex items-center justify-between">
            <span className="flex items-center gap-1.5 text-[10.5px] uppercase tracking-wider text-ink-faint">
              <Fingerprint size={11} aria-hidden />
              {algo} fingerprint
            </span>
            <button
              type="button"
              onClick={() => void copyFingerprint()}
              className="rounded px-1.5 py-0.5 text-[11px] text-ink-faint transition-colors hover:bg-surface-3 hover:text-ink"
            >
              {copied ? 'Copied' : 'Copy'}
            </button>
          </div>
          <p className="selectable break-all font-mono text-[13px] leading-relaxed text-ink">
            {digest}
          </p>
        </div>

        <p className="mx-5 mt-3 text-[12px] leading-relaxed text-ink-faint">
          Confirm this matches the output of{' '}
          <code className="selectable rounded bg-surface-3 px-1 font-mono text-[11px] text-ink-dim">
            ssh-keygen -lf /etc/ssh/ssh_host_{request.keyType.replace(/^ssh-/, '')}_key.pub
          </code>{' '}
          run on the server console. If it does not match, someone may be
          intercepting this connection.
        </p>

        <footer className="mt-4 flex justify-end gap-2 border-t border-line bg-surface-1 px-5 py-3">
          <button
            ref={cancelRef}
            type="button"
            disabled={busy}
            onClick={() => void respond(false)}
            className="flex items-center gap-1.5 rounded border border-line bg-surface-2 px-3 py-1.5 text-[12.5px] text-ink-dim transition-colors hover:bg-surface-3 hover:text-ink disabled:opacity-50"
          >
            <X size={13} aria-hidden />
            Cancel connection
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() => void respond(true)}
            className="flex items-center gap-1.5 rounded border border-accent/60 bg-accent/15 px-3 py-1.5 text-[12.5px] font-medium text-accent transition-colors hover:bg-accent/25 disabled:opacity-50"
          >
            <Check size={13} aria-hidden />
            Trust &amp; connect
          </button>
        </footer>
      </div>
    </div>
  )
}
