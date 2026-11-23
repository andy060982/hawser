import type {
  OverwritePolicy,
  Transfer,
  TransferDirection,
  TransferFailureEvent,
  TransferOutcome,
  TransferProgressEvent,
} from '../types'

/* ---------------------------------------------------------------------------
   Pure transfer-queue logic, kept apart from React and Tauri so it can be
   tested (src/lib/frontend.test.mjs). Rows are matched on their id, which is
   also the backend's transfer id: two transfers of the same source (the same
   folder downloaded twice) never update each other's row.
--------------------------------------------------------------------------- */

export interface TransferJob {
  name: string
  local: string
  remote: string
  overwrite: OverwritePolicy
}

let seq = 0
/** A fresh transfer id, unique within this window. */
export function newTransferId(): string {
  seq += 1
  const rand =
    typeof crypto !== 'undefined' && 'randomUUID' in crypto
      ? crypto.randomUUID()
      : Math.random().toString(36).slice(2)
  return `xfer-${seq}-${rand}`
}

export function queuedRow(
  id: string,
  sessionId: string,
  direction: TransferDirection,
  job: TransferJob,
): Transfer {
  return {
    id,
    sessionId,
    direction,
    name: job.name,
    // Progress is reported against the SOURCE: local for upload, remote for
    // download.
    path: direction === 'upload' ? job.local : job.remote,
    dest: direction === 'upload' ? job.remote : job.local,
    overwrite: job.overwrite,
    bytesDone: 0,
    bytesTotal: 0,
    status: 'queued',
  }
}

const update = (list: Transfer[], id: string, f: (t: Transfer) => Transfer): Transfer[] => {
  let changed = false
  const next = list.map((t) => {
    if (t.id !== id) return t
    changed = true
    return f(t)
  })
  return changed ? next : list
}

/** A progress event: only a row still moving takes it (a late event after
 *  completion must not rewind the bar). */
export function applyProgress(list: Transfer[], p: TransferProgressEvent): Transfer[] {
  return update(list, p.transferId, (t) =>
    t.status === 'active' || t.status === 'queued'
      ? {
          ...t,
          status: 'active',
          bytesDone: p.bytesTransferred,
          bytesTotal: p.totalBytes,
          // A live warning sticks until a newer one replaces it: later
          // progress events carry none.
          note: p.note ?? t.note,
        }
      : t,
  )
}

/** A per-file failure. Attached whatever the row's status: the command's own
 *  result and these events travel on different IPC channels, so a failure can
 *  arrive after the row already settled, and must still be counted. */
export function applyFailure(list: Transfer[], f: TransferFailureEvent): Transfer[] {
  return update(list, f.transferId, (t) => ({
    ...t,
    failures: [
      ...(t.failures ?? []),
      { name: f.name, local: f.local, remote: f.remote, reason: f.reason },
    ],
  }))
}

export function markActive(list: Transfer[], id: string): Transfer[] {
  return update(list, id, (t) => (t.status === 'queued' ? { ...t, status: 'active' } : t))
}

export function markDone(list: Transfer[], id: string, out: TransferOutcome | null | undefined): Transfer[] {
  return update(list, id, (t) => ({
    ...t,
    status: 'done',
    bytesDone: out?.bytes ?? (t.bytesTotal || t.bytesDone),
    notes: out?.notes?.length ? out.notes : undefined,
  }))
}

/** The backend's text for a cancelled transfer (SshError::TransferCancelled). */
export const isCancelledError = (msg: string) => /transfer cancelled/i.test(msg)

export function markFailed(list: Transfer[], id: string, message: string): Transfer[] {
  return update(list, id, (t) =>
    isCancelledError(message) || t.status === 'cancelled'
      ? { ...t, status: 'cancelled', error: undefined }
      : { ...t, status: 'error', error: message },
  )
}

export function markCancelled(list: Transfer[], id: string): Transfer[] {
  return update(list, id, (t) =>
    t.status === 'queued' || t.status === 'active' ? { ...t, status: 'cancelled' } : t,
  )
}

export const isLive = (t: Transfer) => t.status === 'active' || t.status === 'queued'

/** Keep anything still moving or waiting. */
export const clearFinished = (list: Transfer[]) => list.filter(isLive)

/** Failures a retry can rebuild (items skipped by name or as symlinks carry
 *  an empty side and are not retryable). */
export const retryableFailures = (t: Transfer) =>
  (t.failures ?? []).filter((f) => f.local && f.remote)

/** Retry is offered only once the transfer has stopped: while it runs, more
 *  failures are still arriving, and a retry would run beside the original. */
export const canRetry = (t: Transfer) => !isLive(t) && retryableFailures(t).length > 0

/** Jobs for "Retry failed", carrying the original overwrite policy: a retry
 *  never replaces a file the first attempt was not allowed to. */
export function retryJobs(t: Transfer): TransferJob[] {
  return retryableFailures(t).map((f) => ({
    name: f.name,
    local: f.local,
    remote: f.remote,
    overwrite: t.overwrite,
  }))
}

/** The overwrite policy for one job, from the existence check's answer:
 *  `true` and the user agreed -> confirmed; absent -> never; and a check that
 *  failed (`null`) -> never as well, so the backend refuses rather than
 *  clobbers whatever turns out to be there. */
export function policyFor(exists: boolean | null, agreed: boolean): OverwritePolicy | null {
  if (exists === true) return agreed ? 'confirmed' : null
  return 'never'
}

/* ------------------------------------------------------------- validation */

/** Parse a port field. Empty -> `emptyAs` (e.g. 0 = "pick a free one");
 *  otherwise a whole number 1-65535, or null when invalid. */
export function parsePort(raw: string, emptyAs: number | null): number | null {
  const s = raw.trim()
  if (s === '') return emptyAs
  if (!/^\d{1,5}$/.test(s)) return null
  const n = Number(s)
  return n >= 1 && n <= 65535 ? n : null
}

export interface ForwardRequest {
  localPort: number
  remoteHost: string
  remotePort: number
}

/** Validate the tunnel dialog's fields; a string is the error to show. */
export function validateForward(
  mode: 'local' | 'socks',
  localPort: string,
  remoteHost: string,
  remotePort: string,
): ForwardRequest | string {
  const lp = parsePort(localPort, 0)
  if (lp === null) return 'Local port must be 1-65535, or empty to pick a free one.'
  if (mode === 'socks') return { localPort: lp, remoteHost: '', remotePort: 0 }
  const host = remoteHost.trim()
  if (!host) return 'Remote host is required.'
  if (/\s/.test(host)) return 'Remote host cannot contain spaces.'
  const rp = parsePort(remotePort, null)
  if (rp === null) return 'Remote port must be 1-65535.'
  return { localPort: lp, remoteHost: host, remotePort: rp }
}

/** The network tools' target rule, mirroring validate_target in nettools.rs,
 *  so a bad target is explained before anything runs. Null = valid. */
export function netTargetError(raw: string): string | null {
  const t = raw.trim()
  if (!t) return 'Enter a hostname or IP address.'
  if (t.length > 253) return 'That name is too long.'
  if (t.startsWith('-')) return "A target cannot start with '-'."
  if (!/^[A-Za-z0-9.\-:_]+$/.test(t)) return 'Only letters, digits and . - : _ are allowed.'
  return null
}
