import { useCallback, useEffect, useRef, useState } from 'react'
import type { FileEntry, PaneSide } from '../types'
import { listDirectory, parentPath, joinPath } from '../lib/sftp'

export type SortKey = 'name' | 'size' | 'modified'

interface State {
  path: string
  entries: FileEntry[]
  loading: boolean
  error: string | null
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
  })
  const seq = useRef(0)
  /** Last path asked for and last path actually shown, so an `initialPath`
   *  that merely echoes our own navigation back (the parent persists the
   *  pane's path and feeds it in again) does not list the directory twice. */
  const requestedRef = useRef<string | null>(null)
  const committedRef = useRef<string | null>(null)

  const read = useCallback(
    async (target: string) => {
      const ticket = ++seq.current
      requestedRef.current = target
      setState((s) => ({ ...s, loading: true, error: null }))
      try {
        const listing = await listDirectory(side, sessionId, target)
        if (ticket !== seq.current) return // superseded
        committedRef.current = listing.path
        setState({
          path: listing.path,
          entries: listing.entries,
          loading: false,
          error: null,
        })
      } catch (e) {
        if (ticket !== seq.current) return
        // Keep the previous path and entries; only surface the failure.
        setState((s) => ({
          ...s,
          loading: false,
          error: e instanceof Error ? e.message : String(e),
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
    refresh: useCallback(() => void read(state.path), [read, state.path]),
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
