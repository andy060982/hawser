import type { Terminal } from '@xterm/xterm'
import type { SearchAddon } from '@xterm/addon-search'

/** Live xterm instances by session id.
 *
 *  Exists so shell-level features (find bar, snippet paste) can reach the
 *  focused pane's Terminal without threading refs through five components.
 *  A module-level map rather than context because the terminals live outside
 *  React's render cycle anyway — they are imperative objects that mount once
 *  and survive re-renders by design. */
export interface TermEntry {
  term: Terminal
  search: SearchAddon
  /** Send text as user input: through the pane's ordered write queue, and
   *  mirrored to its siblings when broadcast is on (snippets use this). */
  input: (text: string) => void
}

const terms = new Map<string, TermEntry>()

export function registerTerm(sessionId: string, entry: TermEntry): void {
  terms.set(sessionId, entry)
}

export function unregisterTerm(sessionId: string): void {
  terms.delete(sessionId)
}

export function getTerm(sessionId: string): TermEntry | undefined {
  return terms.get(sessionId)
}
