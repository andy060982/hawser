/** In-app confirm / alert dialogs.
 *
 *  The webview's native `window.confirm` / `window.alert` do not reliably show
 *  inside this Tauri/wry WebView — confirm returns false without a prompt, which
 *  silently blocked every confirm-gated action (closing a live tab, the
 *  destructive-command guard, SFTP delete/overwrite). These replace them with a
 *  real in-app modal. `prompt()` replaces `window.prompt` the same way (wry
 *  does not reliably show it either), resolving the typed text or null.
 *
 *  `confirm()` returns a Promise<boolean>: it enqueues a request, stashes the
 *  promise's resolver, and the modal's buttons settle it. That keeps the call
 *  sites in the familiar `if (!(await confirm(msg))) return` shape. A queue (not
 *  a single slot) means two overlapping prompts don't clobber each other — the
 *  head shows, the next appears after it is answered.
 */
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from 'react'
import { AlertTriangle, X } from 'lucide-react'

export interface ConfirmOptions {
  title?: string
  confirmLabel?: string
  cancelLabel?: string
  /** Paint the confirm button as destructive (red). */
  danger?: boolean
}

export interface PromptOptions {
  title?: string
  defaultValue?: string
  confirmLabel?: string
}

interface DialogRequest {
  id: number
  kind: 'confirm' | 'alert' | 'prompt'
  message: string
  defaultValue?: string
  title?: string
  confirmLabel?: string
  cancelLabel?: string
  danger?: boolean
  /** `value` carries the typed text for a prompt. */
  resolve: (ok: boolean, value?: string) => void
}

interface DialogsApi {
  /** Resolves true if the user confirms, false if they cancel / dismiss. */
  confirm: (message: string, opts?: ConfirmOptions) => Promise<boolean>
  /** Resolves when the user acknowledges. */
  alert: (message: string, opts?: { title?: string }) => Promise<void>
  /** Resolves the entered text, or null if the user cancels / dismisses. */
  prompt: (message: string, opts?: PromptOptions) => Promise<string | null>
}

const Ctx = createContext<DialogsApi | null>(null)

export function DialogProvider({ children }: { children: ReactNode }) {
  const [queue, setQueue] = useState<DialogRequest[]>([])
  const idRef = useRef(0)

  const confirm = useCallback(
    (message: string, opts?: ConfirmOptions) =>
      new Promise<boolean>((resolve) => {
        setQueue((q) => [
          ...q,
          { id: ++idRef.current, kind: 'confirm', message, resolve, ...opts },
        ])
      }),
    [],
  )

  const alert = useCallback(
    (message: string, opts?: { title?: string }) =>
      new Promise<void>((resolve) => {
        setQueue((q) => [
          ...q,
          { id: ++idRef.current, kind: 'alert', message, title: opts?.title, resolve: () => resolve() },
        ])
      }),
    [],
  )

  const prompt = useCallback(
    (message: string, opts?: PromptOptions) =>
      new Promise<string | null>((resolve) => {
        setQueue((q) => [
          ...q,
          {
            id: ++idRef.current,
            kind: 'prompt',
            message,
            ...opts,
            resolve: (ok, value) => resolve(ok ? (value ?? '') : null),
          },
        ])
      }),
    [],
  )

  const head = queue[0] ?? null
  const settle = useCallback((ok: boolean, value?: string) => {
    setQueue((q) => {
      const [first, ...rest] = q
      first?.resolve(ok, value)
      return rest
    })
  }, [])

  return (
    <Ctx.Provider value={{ confirm, alert, prompt }}>
      {children}
      {head && <DialogModal key={head.id} req={head} onSettle={settle} />}
    </Ctx.Provider>
  )
}

export function useDialogs(): DialogsApi {
  const c = useContext(Ctx)
  if (!c) throw new Error('useDialogs must be used within DialogProvider')
  return c
}

function DialogModal({
  req,
  onSettle,
}: {
  req: DialogRequest
  onSettle: (ok: boolean, value?: string) => void
}) {
  const confirmRef = useRef<HTMLButtonElement>(null)
  const cancelRef = useRef<HTMLButtonElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  const isPrompt = req.kind === 'prompt'
  // A prompt has a Cancel button just like a confirm.
  const isConfirm = req.kind === 'confirm' || isPrompt
  const [value, setValue] = useState(req.defaultValue ?? '')
  const valueRef = useRef(value)
  valueRef.current = value
  // Danger prompts (destructive-command guard, delete/overwrite) can pop up
  // asynchronously while the user is typing; a reflexive Enter must not approve
  // them. Like HostKeyDialog, they default to Cancel and a bare Enter only
  // activates whichever button actually has focus.
  const safeDefault = isConfirm && !!req.danger

  // Focus the default action, and wire Enter / Escape. Reset whenever the head
  // request changes (keyed by id below).
  useEffect(() => {
    if (isPrompt) {
      inputRef.current?.focus()
      inputRef.current?.select()
    } else {
      ;(safeDefault ? cancelRef : confirmRef).current?.focus()
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault()
        onSettle(false)
      } else if (e.key === 'Enter') {
        e.preventDefault()
        if (isPrompt) onSettle(true, valueRef.current)
        else if (!safeDefault) onSettle(true)
        // Explicit Tab-to-confirm + Enter still confirms; anything else cancels.
        else onSettle(document.activeElement === confirmRef.current)
      }
    }
    window.addEventListener('keydown', onKey, true)
    return () => window.removeEventListener('keydown', onKey, true)
  }, [onSettle, safeDefault, isPrompt])

  return (
    <div className="absolute inset-0 z-[60] flex justify-center">
      <div
        className="animate-scrim-in absolute inset-0 bg-surface-0/75 backdrop-blur-[2px]"
        aria-hidden
        onClick={() => onSettle(false)}
      />

      <div
        role={isConfirm ? 'alertdialog' : 'dialog'}
        aria-modal="true"
        aria-labelledby="dlg-title"
        className="animate-drop-in relative mt-16 h-fit w-[28rem] max-w-[92vw] overflow-hidden rounded-panel border border-line-strong bg-surface-2 shadow-[0_24px_60px_-12px_rgba(0,0,0,0.75)]"
      >
        <div className={`h-[3px] w-full ${req.danger ? 'bg-alert' : 'bg-accent'}`} />

        <header className="flex items-start gap-3 px-5 pt-4 pb-2">
          <div
            className={`mt-px grid h-8 w-8 shrink-0 place-items-center rounded-full border ${
              req.danger ? 'border-alert/30 bg-alert/10' : 'border-accent/30 bg-accent/10'
            }`}
          >
            <AlertTriangle size={16} className={req.danger ? 'text-alert' : 'text-accent'} aria-hidden />
          </div>
          <h2 id="dlg-title" className="mt-1 text-[14px] font-medium text-ink">
            {req.title ?? (isPrompt ? 'Enter a value' : isConfirm ? 'Please confirm' : 'Notice')}
          </h2>
        </header>

        <p className="mx-5 mb-4 whitespace-pre-wrap text-[12.5px] leading-relaxed text-ink-dim">
          {req.message}
        </p>

        {isPrompt && (
          <input
            ref={inputRef}
            type="text"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            spellCheck={false}
            autoComplete="off"
            aria-labelledby="dlg-title"
            className="mx-5 mb-4 w-[calc(100%-2.5rem)] rounded border border-line bg-surface-1 px-2.5 py-1.5 text-[12.5px] text-ink outline-none focus:border-accent/60"
          />
        )}

        <footer className="flex justify-end gap-2 border-t border-line bg-surface-1 px-5 py-3">
          {isConfirm && (
            <button
              ref={cancelRef}
              type="button"
              onClick={() => onSettle(false)}
              className="flex items-center gap-1.5 rounded border border-line bg-surface-2 px-3 py-1.5 text-[12.5px] text-ink-dim transition-colors hover:bg-surface-3 hover:text-ink"
            >
              <X size={13} aria-hidden />
              {req.cancelLabel ?? 'Cancel'}
            </button>
          )}
          <button
            ref={confirmRef}
            type="button"
            onClick={() => onSettle(true, isPrompt ? value : undefined)}
            className={`flex items-center gap-1.5 rounded border px-3 py-1.5 text-[12.5px] font-medium transition-colors ${
              req.danger
                ? 'border-alert/60 bg-alert/15 text-alert hover:bg-alert/25'
                : 'border-accent/60 bg-accent/15 text-accent hover:bg-accent/25'
            }`}
          >
            {req.confirmLabel ?? (isPrompt ? 'OK' : isConfirm ? 'Confirm' : 'OK')}
          </button>
        </footer>
      </div>
    </div>
  )
}
