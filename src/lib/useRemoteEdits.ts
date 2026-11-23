/** The live remote edits and kept copies, from the backend's events. Used by
 *  the Editing section of TransferBar, which is mounted once at the shell root
 *  (so edits keep updating while SftpView is unmounted). */
import { useCallback, useEffect, useState } from 'react'
import type { EditClosed, EditInfo, EditLeftover } from '../types'
import { safeInvoke, safeListen } from './tauri'
import {
  EDIT_CLOSED_EVENT, EDIT_EVENT, LEFTOVERS_EVENT, applyClosed, applyEdit, applyList, emptyEdits, mergeLeftovers,
  type EditsState,
} from './remoteEdit'

export function useRemoteEdits() {
  const [state, setState] = useState<EditsState>(emptyEdits)
  const [leftovers, setLeftovers] = useState<EditLeftover[]>([])

  useEffect(() => {
    let dead = false
    const offs: (() => void)[] = []
    const keep = (p: Promise<() => void>) =>
      void p.then((un) => (dead ? un() : offs.push(un)))
    keep(safeListen<EditInfo>(EDIT_EVENT, (info) => setState((s) => applyEdit(s, info))))
    keep(safeListen<EditClosed>(EDIT_CLOSED_EVENT, (c) => setState((s) => applyClosed(s, c))))
    // The backend sends its whole list: it replaces ours.
    keep(safeListen<EditLeftover[]>(LEFTOVERS_EVENT, (list) => setLeftovers(list)))
    // Edits opened (or copies kept by an earlier run) before this mounted.
    void safeInvoke<EditInfo[]>('edit_list').then((list) => {
      if (!dead && list) setState((s) => applyList(s, list))
    })
    void safeInvoke<EditLeftover[]>('edit_leftovers').then((list) => {
      if (!dead && list) setLeftovers((cur) => mergeLeftovers(cur, list))
    })
    return () => {
      dead = true
      offs.forEach((un) => un())
    }
  }, [])

  /** A command answered with the edit's new state (it is also emitted; the
   *  answer just lands sooner). */
  const update = useCallback((info: EditInfo | undefined) => {
    if (info) setState((s) => applyEdit(s, info))
  }, [])
  const closed = useCallback((editId: string) => setState((s) => applyClosed(s, { editId })), [])
  const dropLeftover = useCallback((id: string) => setLeftovers((l) => l.filter((x) => x.id !== id)), [])

  return { edits: state.edits, leftovers, update, closed, dropLeftover }
}
