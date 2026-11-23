import { useCallback, useEffect, useRef, useState } from 'react'
import type { FileEntry, PaneSide } from '../types'
import { listDirectory, parentPath, joinPath } from '../lib/sftp'

export type SortKey = 'name' | 'size' | 'modified'

interface State {
  path: string
  entries: FileEntry[]
  loading: boolean
  error: string | null
  /** The path whose read failed (the shown listing is still `path`'s). */
  failedTarget: string | null
  /** The backend capped the listing. */
  truncated: boolean
}

/** Owns one pane's directory state: where it is, what is in it, and whether the
 *  last read failed.
 *
 *  Two things this guards that a naive useEffect+fetch does not:
 *
 *  - Out-of-order responses. Clicking quickly through directories can land an
 *    older listing after a newer one. Each read carries a sequence number and
 *    stale results are dropped, otherwise the pane shows the wrong folder's
 *    contents under the right folder's path.
 *  - Failed navigation. A denied directory must leave the pane where it was
 *    rather than stranding it on a path it never reached. `path` is committed
 *    only once a read succeeds. */
export function useDirectory(side: PaneSide, sessionId: string, initialPath: string) {
  const [state, setState] = useState<State>({
    path: initialPath,
    entries: [],
    loading: true,
    error: null,
    failedTarget: null,
    truncated: false,
  })
  const seq = useRef(0)
  /** Last path asked for and last path actually shown, so an `initialPath`
   *  that merely echoes our own navigation back (the parent persists the
   *  pane's path and feeds it in again) does not list the directory twice. */
  const requestedRef = useRef<string | null>(null)
  const committedRef = useRef<string | null>(null)
  /** The target of the read in flight, if any. */
  const pendingRef = useRef<string | null>(null)

  const read = useCallback(
    async (target: string) => {
      const ticket = ++seq.current
      requestedRef.current = target
      pendingRef.current = target
      setState((s) => ({ ...s, loading: true }))
      try {
        const listing = await listDirectory(side, sessionId, target)
        if (ticket !== seq.current) return // superseded
        pendingRef.current = null
        committedRef.current = listing.path
        setState({
          path: listing.path,
          entries: listing.entries,
          loading: false,
          error: null,
          failedTarget: null,
          truncated: Boolean(listing.truncated),
        })
      } catch (e) {
        if (ticket !== seq.current) return
        pendingRef.current = null
        // Keep the previous path and entries (the pane still shows them); only
        // surface the failure, and remember what failed so Retry retries it.
        setState((s) => ({
          ...s,
          loading: false,
          error: e instanceof Error ? e.message : String(e),
          failedTarget: target,
        }))
      }
    },
    [side, sessionId],
  )

  // Initial read, and a fresh read when the session (hence `read`) or a
  // genuinely new initialPath arrives — but not for an initialPath that is just
  // the pane's own current location round-tripped through the parent.
  const lastReadFn = useRef<typeof read | null>(null)
  useEffect(() => {
    const sameSource = lastReadFn.current === read
    lastReadFn.current = read
    if (
      sameSource &&
      (initialPath === committedRef.current || initialPath === requestedRef.current)
    ) {
      return
    }
    void read(initialPath)
  }, [read, initialPath])

  const open = useCallback((entry: FileEntry, currentPath: string) => {
    if (entry.kind === 'file') return
    const target =
      entry.name === '..'
        ? parentPath(side, currentPath)
        : joinPath(side, currentPath, entry.name)
    void read(target)
  }, [read, side])

  return {
    ...state,
    // A refresh (after a transfer, say) while a navigation is still loading
    // re-reads where the user is GOING, not the old folder: otherwise it would
    // supersede the navigation and strand the pane where it was.
    refresh: useCallback(
      () => void read(pendingRef.current ?? state.path),
      [read, state.path],
    ),
    /** Retry the read that failed (not the folder still shown). */
    retry: useCallback(
      () => void read(state.failedTarget ?? state.path),
      [read, state.failedTarget, state.path],
    ),
    dismissError: useCallback(
      () => setState((s) => ({ ...s, error: null, failedTarget: null })),
      [],
    ),
    navigate: useCallback((p: string) => void read(p), [read]),
    open,
  }
}

/** Directories first, then the chosen key. Applied as a view over entries so
 *  the backend never has to care about presentation order. */
export function sortEntries(
  entries: FileEntry[],
  key: SortKey,
  asc: boolean,
): FileEntry[] {
  const dir = asc ? 1 : -1
  return [...entries].sort((a, b) => {
    // ".." is always the first row; it is navigation, not content.
    if (a.name === '..') return -1
    if (b.name === '..') return 1

    const aDir = a.kind === 'directory'
    const bDir = b.kind === 'directory'
    if (aDir !== bDir) return aDir ? -1 : 1

    switch (key) {
      case 'size':
        return (a.size - b.size) * dir
      case 'modified':
        return ((a.modified ?? 0) - (b.modified ?? 0)) * dir
      default:
        return a.name.localeCompare(b.name, undefined, { numeric: true }) * dir
    }
  })
}
