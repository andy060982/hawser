/** When closing the window (title-bar X, Alt+F4, Cmd+Q) must ask first. */

export interface SessionLike {
  status: string
}

/** Sessions that closing would drop: connected, or still connecting. */
export function liveSessionCount(sessions: SessionLike[]): number {
  return sessions.filter((s) => s.status === 'connected' || s.status === 'connecting').length
}

/** The confirm text for closing the window, or null when no confirm is due
 *  (nothing live, or the user turned confirm-on-close off). */
export function closeConfirmText(sessions: SessionLike[], confirmCloseActive: boolean): string | null {
  if (!confirmCloseActive) return null
  const n = liveSessionCount(sessions)
  if (n === 0) return null
  return `${n} session${n === 1 ? ' is' : 's are'} still connected. Quitting Hawser closes ${
    n === 1 ? 'it' : 'all of them'
  }.`
}
