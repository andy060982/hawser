/** Remote editing ("Edit in local editor" on a remote file): the pure rules
 *  the SFTP menu and the Editing panel share. The backend is
 *  src-tauri/src/utils/remote_edit.rs; it enforces every one of these again. */
import type { EditClosed, EditInfo, EditLeftover, EditStatus, FileEntry } from '../types'

/** Mirrors MAX_EDIT_BYTES in remote_edit.rs. */
export const MAX_EDIT_BYTES = 20 * 1024 * 1024

export const EDIT_EVENT = 'sftp://edit'
export const EDIT_CLOSED_EVENT = 'sftp://edit-closed'
export const LEFTOVERS_EVENT = 'sftp://edit-leftovers'

/** Whether "Edit" is offered for a remote entry at all: files, and links
 *  (the backend follows a link and refuses one that is not to a file). */
export function editOffered(entry: Pick<FileEntry, 'kind'>): boolean {
  return entry.kind === 'file' || entry.kind === 'symlink'
}

/** Why an offered entry cannot be opened, or null. A link's listed size is
 *  the link's own, so only a plain file is size-checked here. */
export function editBlockReason(entry: Pick<FileEntry, 'kind' | 'size' | 'name'>): string | null {
  if (!editOffered(entry)) return 'Only files can be edited.'
  if (entry.kind === 'file' && entry.size > MAX_EDIT_BYTES) {
    return `${entry.name} is ${Math.ceil(entry.size / (1024 * 1024))} MB. Files over ${
      MAX_EDIT_BYTES / (1024 * 1024)
    } MB are not opened for editing — download it instead.`
  }
  return null
}

/** The live edits as the panel holds them. `closed` remembers ended ids, so a
 *  status event that was already in flight when an edit ended cannot bring
 *  its row back. */
export interface EditsState {
  edits: EditInfo[]
  closed: ReadonlySet<string>
}

export const emptyEdits = (): EditsState => ({ edits: [], closed: new Set() })

/** An `sftp://edit` event (or command result): replace the row in place, or
 *  append a new one. Ignored for an edit that already ended. */
export function applyEdit(state: EditsState, info: EditInfo): EditsState {
  if (state.closed.has(info.editId)) return state
  const i = state.edits.findIndex((e) => e.editId === info.editId)
  const edits = i < 0 ? [...state.edits, info] : state.edits.map((e, j) => (j === i ? info : e))
  return { ...state, edits }
}

/** An edit ended (`sftp://edit-closed`, or a stop that went through). */
export function applyClosed(state: EditsState, closed: Pick<EditClosed, 'editId'>): EditsState {
  const ids = new Set(state.closed)
  ids.add(closed.editId)
  return { edits: state.edits.filter((e) => e.editId !== closed.editId), closed: ids }
}

/** A fresh `edit_list` answer: the backend's list wins, minus ended ids. */
export function applyList(state: EditsState, list: EditInfo[]): EditsState {
  return { ...state, edits: list.filter((e) => !state.closed.has(e.editId)) }
}

/** Whether the conflict prompt shows for an edit. "Keep editing" records the
 *  conflict it dismissed (`dismissed[editId] = conflictSeq`); a NEW conflict
 *  (the next save into a changed file) prompts again. */
export function conflictPromptDue(edit: EditInfo, dismissed: Readonly<Record<string, number>>): boolean {
  return edit.status === 'conflict' && dismissed[edit.editId] !== edit.conflictSeq
}

/** The status word a row shows. */
export function editStatusLabel(edit: Pick<EditInfo, 'status' | 'dirty'>): string {
  const labels: Record<EditStatus, string> = {
    synced: edit.dirty ? 'changed' : 'synced',
    uploading: 'uploading…',
    conflict: 'conflict',
    error: 'error',
  }
  return labels[edit.status]
}

/** The name "Save a copy" uses first (the backend picks `.conflict.2`, … when
 *  that is taken). */
export function conflictCopyName(name: string): string {
  return `${name}.conflict`
}

/** The confirm shown when stopping an edit the backend says is unsynced. */
export function discardPrompt(edit: Pick<EditInfo, 'name' | 'remotePath'>): string {
  return `${edit.name} has changes that were not uploaded to ${edit.remotePath}. Discard them?`
}

/** Kept copies, newest list from the backend, by id. */
export function mergeLeftovers(current: EditLeftover[], incoming: EditLeftover[]): EditLeftover[] {
  const seen = new Set<string>()
  const out: EditLeftover[] = []
  for (const l of [...incoming, ...current]) {
    if (seen.has(l.id)) continue
    seen.add(l.id)
    out.push(l)
  }
  return out
}
