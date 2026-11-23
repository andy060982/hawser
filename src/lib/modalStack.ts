/** Which modal is on top.
 *
 *  Every modal (editor, settings, confirm, host-key prompt…) used to listen for
 *  Escape on `window` in the capture phase, so one Escape closed every modal
 *  in the stack at once: an alert raised over the Host editor took the editor
 *  (and its unsaved edits) down with it. Each modal now registers a layer and
 *  acts on a key only while it is the top one; app shortcuts check `size` and
 *  stay off while any modal is open. Pure (no React) so it is tested directly;
 *  the hook lives in useModalLayer.ts. */
export class ModalStack {
  private layers: { id: number; priority: number }[] = []
  private next = 0

  /** Open a layer at `priority` (its z-order tier, see LAYER). It is on top
   *  of every layer of a lower tier whenever it was opened, and of layers of
   *  its own tier opened before it. Registration order alone used to decide,
   *  so a host-key prompt that arrived after the quit confirm took Escape and
   *  Enter while it was painted underneath. */
  push(priority: number = LAYER.panel): number {
    const id = ++this.next
    this.layers.push({ id, priority })
    return id
  }

  /** Close a layer, wherever it is in the stack. */
  remove(id: number): void {
    this.layers = this.layers.filter((l) => l.id !== id)
  }

  /** The layer that gets keys: highest tier, latest within it. */
  top(): number | null {
    let best: { id: number; priority: number } | null = null
    for (const l of this.layers) if (!best || l.priority >= best.priority) best = l
    return best ? best.id : null
  }

  isTop(id: number): boolean {
    return id !== 0 && this.top() === id
  }

  get size(): number {
    return this.layers.length
  }
}

/** Z-order tiers. Each modal registers with the tier that matches its CSS
 *  z-index, so the layer painted on top is the one that receives Escape and
 *  Enter. SSH prompts (host key, keyboard-interactive auth) are above
 *  everything: they arrive asynchronously from a dial, block it until
 *  answered, and must never sit hidden under an app dialog. */
export const LAYER = {
  /** Editors, settings, history, audit, quick connect…: z-50. */
  panel: 50,
  /** Context menu: z-[60]. */
  menu: 60,
  /** confirm / alert / prompt (lib/dialogs): z-[65]. */
  dialog: 65,
  /** The AI panel's secret warning: z-[70]. */
  aiWarning: 70,
  /** Host-key and auth prompts: z-[80]. */
  sshPrompt: 80,
} as const

/** The app's one stack. */
export const modals = new ModalStack()

/** True while any modal is open: app shortcuts must not act behind it. */
export const anyModalOpen = (): boolean => modals.size > 0

/** What Enter does in a confirm / prompt / alert, given what has focus.
 *
 *  A focused button always means itself: Tab to Cancel, press Enter, and the
 *  dialog cancels (it used to confirm, because the window handler ran first
 *  and ignored focus). Otherwise a prompt submits its text, an alert is
 *  acknowledged, an ordinary confirm confirms, and a danger confirm does
 *  nothing (a reflexive Enter must never approve a destructive action). */
export type EnterOutcome = 'confirm' | 'cancel' | 'none'

export function enterOutcome(
  kind: 'confirm' | 'alert' | 'prompt',
  danger: boolean,
  focused: 'confirm' | 'cancel' | 'input' | 'other',
): EnterOutcome {
  if (focused === 'cancel') return 'cancel'
  if (focused === 'confirm') return 'confirm'
  if (kind === 'prompt') return focused === 'input' ? 'confirm' : 'none'
  if (kind === 'alert') return 'confirm'
  return danger ? 'none' : 'confirm'
}

/** Whether a click on a dialog was meant for it.
 *
 *  A click counts only if this dialog saw both halves of it: the pointerdown
 *  AND the pointerup, after it mounted. The second click of a double-click
 *  aimed at the previous dialog's button has its pointerdown on this one,
 *  but `MouseEvent.detail` says it is click 2 of a series whose first press
 *  this dialog never saw, so it is refused too. A keyboard-activated click
 *  (Enter or Space on a focused button, `detail` 0) always counts. There is
 *  no timer: a deliberate first click is never discarded for being quick.
 *
 *  Feed it pointerdown/pointerup from the dialog's root (capture phase) and
 *  ask `accepts(e.detail)` in each click handler. */
export class PressGuard {
  private downs = 0
  private released = false

  pointerDown(): void {
    this.downs += 1
    this.released = false
  }

  pointerUp(): void {
    if (this.downs > 0) this.released = true
  }

  accepts(detail: number): boolean {
    if (detail === 0) return true
    return this.released && this.downs >= detail
  }
}
