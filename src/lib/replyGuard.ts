/* Latest-reply-wins tokens for async work tied to a reusable key (a session id
   that is redialled, or closed and reused).

   `begin(key)` starts a piece of work and returns a checker that stays true only
   while that work is still the latest for the key: a later `begin`,
   `invalidate` (e.g. a reconnect starting), or `forget` turns it false. Tokens
   come from one counter shared by every key, so a forgotten-then-reused key can
   never match an old checker again. */
export class ReplyGuard {
  #next = 0
  #latest = new Map<string, number>()

  begin(key: string): () => boolean {
    const token = ++this.#next
    this.#latest.set(key, token)
    return () => this.#latest.get(key) === token
  }

  /** Any reply already in flight for `key` is now stale. */
  invalidate(key: string): void {
    this.#latest.set(key, ++this.#next)
  }

  /** Drop every key not in `live` (closed tabs). Their replies become stale. */
  retain(live: Set<string>): void {
    for (const key of [...this.#latest.keys()]) {
      if (!live.has(key)) this.#latest.delete(key)
    }
  }
}
