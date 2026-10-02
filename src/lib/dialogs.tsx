/** In-app confirm / alert dialogs.
 *
 *  The webview's native `window.confirm` / `window.alert` do not reliably show
 *  inside this Tauri/wry WebView — confirm returns false without a prompt, which
 *  silently blocked every confirm-gated action (closing a live tab, the
 *  destructive-command guard, SFTP delete/overwrite). These replace them with a
 *  real in-app modal.
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

interface DialogRequest {
  id: number
  kind: 'confirm' | 'alert'
  message: string
  title?: string
  confirmLabel?: string
  cancelLabel?: string
  danger?: boolean
  resolve: (ok: boolean) => void
}

interface DialogsApi {
  /** Resolves true if the user confirms, false if they cancel / dismiss. */
  confirm: (message: string, opts?: ConfirmOptions) => Promise<boolean>
  /** Resolves when the user acknowledges. */
  alert: (message: string, opts?: { title?: string }) => Promise<void>
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

  const head = queue[0] ?? null
  const settle = useCallback((ok: boolean) => {
    setQueue((q) => {
      const [first, ...rest] = q
      first?.resolve(ok)
      return rest
    })
  }, [])

  return (
    <Ctx.Provider value={{ confirm, alert }}>
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

function DialogModal({ req, onSettle }: { req: DialogRequest; onSettle: (ok: boolean) => void }) {
  const confirmRef = useRef<HTMLButtonElement>(null)
  const isConfirm = req.kind === 'confirm'

  // Focus the primary action, and wire Enter = confirm, Escape = cancel. Reset
  // whenever the head request changes (keyed by id below).
  useEffect(() => {
    confirmRef.current?.focus()
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault()
        onSettle(false)
      } else if (e.key === 'Enter') {
        e.preventDefault()
        onSettle(true)
      }
    }
    window.addEventListener('keydown', onKey, true)
    return () => window.removeEventListener('keydown', onKey, true)
  }, [onSettle])

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
            {req.title ?? (isConfirm ? 'Please confirm' : 'Notice')}
          </h2>
        </header>

        <p className="mx-5 mb-4 whitespace-pre-wrap text-[12.5px] leading-relaxed text-ink-dim">
          {req.message}
        </p>

        <footer className="flex justify-end gap-2 border-t border-line bg-surface-1 px-5 py-3">
          {isConfirm && (
            <button
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
            onClick={() => onSettle(true)}
            className={`flex items-center gap-1.5 rounded border px-3 py-1.5 text-[12.5px] font-medium transition-colors ${
              req.danger
                ? 'border-alert/60 bg-alert/15 text-alert hover:bg-alert/25'
                : 'border-accent/60 bg-accent/15 text-accent hover:bg-accent/25'
            }`}
          >
            {req.confirmLabel ?? (isConfirm ? 'Confirm' : 'OK')}
          </button>
        </footer>
      </div>
    </div>
  )
}
