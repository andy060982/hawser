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
  private layers: number[] = []
  private next = 0

  /** Open a layer above every current one. */
  push(): number {
    const id = ++this.next
    this.layers.push(id)
    return id
  }

  /** Close a layer, wherever it is in the stack. */
  remove(id: number): void {
    this.layers = this.layers.filter((l) => l !== id)
  }

  isTop(id: number): boolean {
    return this.layers.length > 0 && this.layers[this.layers.length - 1] === id
  }

  get size(): number {
    return this.layers.length
  }
}

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

/** A pointer click this soon after a dialog appeared is treated as aimed at
 *  whatever was there before (the second click of a double-click on the
 *  previous dialog's button), not at this dialog. */
export const CLICK_GUARD_MS = 350

export function clickTooSoon(shownAt: number, now: number, pointer: boolean): boolean {
  return pointer && now - shownAt < CLICK_GUARD_MS
}
