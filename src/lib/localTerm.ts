/** A tiny frontend-only channel for writing into a session's terminal pane.
 *
 *  Backend output arrives over the Tauri event `ssh://{id}`, but some text
 *  originates in the webview — a connect failure, a local notice — and has no
 *  business round-tripping through Rust just to be displayed.
 *
 *  Messages are buffered until a pane subscribes. That is the whole point: a
 *  connect error frequently lands BEFORE TerminalPane has mounted and attached
 *  its listener, and an unbuffered bus would drop exactly the message the user
 *  most needs to see. */

type Handler = (text: string) => void

const subscribers = new Map<string, Set<Handler>>()
const pending = new Map<string, string[]>()
/** Buffered text on its way to a pane that just subscribed. Delivered on a
 *  microtask, not inside onLocal: React StrictMode mounts a pane, unmounts it
 *  and mounts it again in one go, and a synchronous flush handed the buffered
 *  notices ("restored…", "connection failed") to the throwaway first mount.
 *  Text emitted meanwhile queues behind it, so order is kept. */
const flushing = new Map<string, string[]>()

export function emitLocal(sessionId: string, text: string): void {
  const inFlight = flushing.get(sessionId)
  if (inFlight) {
    inFlight.push(text)
    return
  }
  const subs = subscribers.get(sessionId)
  if (subs && subs.size > 0) {
    subs.forEach((h) => h(text))
    return
  }
  const queue = pending.get(sessionId) ?? []
  queue.push(text)
  pending.set(sessionId, queue)
}

export function onLocal(sessionId: string, handler: Handler): () => void {
  const subs = subscribers.get(sessionId) ?? new Set<Handler>()
  subs.add(handler)
  subscribers.set(sessionId, subs)

  // Flush anything that arrived before this pane existed, to whichever pane
  // is subscribed once the current commit settles.
  const queued = pending.get(sessionId)
  if (queued?.length && !flushing.has(sessionId)) {
    pending.delete(sessionId)
    flushing.set(sessionId, queued)
    queueMicrotask(() => {
      const list = flushing.get(sessionId)
      flushing.delete(sessionId)
      if (!list || list.length === 0) return
      const live = subscribers.get(sessionId)
      if (live && live.size > 0) list.forEach((t) => live.forEach((h) => h(t)))
      else pending.set(sessionId, [...list, ...(pending.get(sessionId) ?? [])])
    })
  }

  return () => {
    subs.delete(handler)
    // Only if the id still maps to THIS set: after clearLocal and a new pane
    // subscribing under the same id, deleting by id would drop the new
    // pane's set and its notices would be buffered forever.
    if (subs.size === 0 && subscribers.get(sessionId) === subs) subscribers.delete(sessionId)
  }
}

/** Drop any buffered text for a closed session so it cannot leak into a later
 *  session that happens to reuse the id. */
export function clearLocal(sessionId: string): void {
  pending.delete(sessionId)
  flushing.delete(sessionId)
  subscribers.delete(sessionId)
}

/** Whether text is buffered for a session no pane has picked up (tests). */
export function hasPendingLocal(sessionId: string): boolean {
  return (pending.get(sessionId)?.length ?? 0) > 0
}
