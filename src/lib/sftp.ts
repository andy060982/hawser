import { sep } from '@tauri-apps/api/path'
import type { DirListing, PaneSide, TransferOutcome } from '../types'
import type { TransferJob } from './transfers'
import { safeInvoke, inTauri } from './tauri'
import { mockLocalListing, mockRemoteListing } from '../data/mockHosts'

/** Separator for LOCAL paths — the current machine's, via Tauri. Remote paths
 *  are always POSIX. Falls back to "/" outside the Tauri runtime (browser
 *  preview / tests) so this never throws. */
function localSep(): string {
  try {
    return sep()
  } catch {
    return '/'
  }
}

/* ---------------------------------------------------------------------------
   The only module that knows command names. Everything above it works in terms
   of "list this directory", so renaming a Rust command is a one-file change and
   the browser-fallback path lives in exactly one place.
--------------------------------------------------------------------------- */

export async function listDirectory(
  side: PaneSide,
  sessionId: string,
  path: string,
): Promise<DirListing> {
  if (!inTauri()) {
    // Layout work in a plain browser: serve the fixtures, ignore the path.
    return side === 'local' ? mockLocalListing : mockRemoteListing
  }

  const cmd = side === 'local' ? 'local_list' : 'sftp_list'
  const res = await safeInvoke<DirListing>(cmd, { sessionId, path })
  if (!res) throw new Error(`${cmd} returned nothing`)
  return res
}

/** Run one transfer under `transferId` (the queue row's id: events carry it
 *  and `cancelTransfer` takes it), with an explicit overwrite policy the
 *  backend enforces when the file is committed. */
export async function transfer(
  direction: 'upload' | 'download',
  sessionId: string,
  transferId: string,
  job: TransferJob,
): Promise<TransferOutcome | null> {
  const cmd = direction === 'upload' ? 'sftp_put' : 'sftp_get'
  return (
    (await safeInvoke<TransferOutcome>(cmd, {
      sessionId,
      localPath: job.local,
      remotePath: job.remote,
      transferId,
      overwrite: job.overwrite,
    })) ?? null
  )
}

/** Stop a running transfer; its staging files are removed on both sides. */
export async function cancelTransfer(transferId: string): Promise<void> {
  await safeInvoke('sftp_cancel', { transferId })
}

/* --------------------------------------------------------------- path utils */

/** Join for display and navigation. Local paths are Windows-flavoured, remote
 *  paths are always POSIX — mixing the two separators is the most common source
 *  of "file not found" in a dual-pane client. */
export function joinPath(side: PaneSide, base: string, name: string): string {
  if (side === 'remote') {
    return base === '/' ? `/${name}` : `${base.replace(/\/+$/, '')}/${name}`
  }
  const s = localSep()
  return base.endsWith(s) ? `${base}${name}` : `${base}${s}${name}`
}

export function parentPath(side: PaneSide, path: string): string {
  if (side === 'remote') {
    const trimmed = path.replace(/\/+$/, '')
    const cut = trimmed.lastIndexOf('/')
    return cut <= 0 ? '/' : trimmed.slice(0, cut)
  }
  if (localSep() === '/') {
    // POSIX local (macOS/Linux): same rules as a remote POSIX path.
    const trimmed = path.replace(/\/+$/, '')
    const cut = trimmed.lastIndexOf('/')
    return cut <= 0 ? '/' : trimmed.slice(0, cut)
  }
  const trimmed = path.replace(/\\+$/, '')
  // Drive root ("C:" or "C:\") stays at the drive root — "C:" alone is a
  // drive-*relative* path, not the root, so keep the trailing separator.
  if (/^[A-Za-z]:$/.test(trimmed)) return `${trimmed}\\`
  // UNC share root ("\\server\share") — there is nothing above the share, so
  // stay put rather than returning the invalid "\\server".
  if (/^\\\\[^\\]+\\[^\\]+$/.test(trimmed)) return trimmed
  const cut = trimmed.lastIndexOf('\\')
  if (cut < 0) return `${trimmed}\\`
  const parent = trimmed.slice(0, cut)
  // Going up to a drive root keeps its separator ("C:\dir" -> "C:\").
  return /^[A-Za-z]:$/.test(parent) ? `${parent}\\` : parent
}

export function basename(side: PaneSide, path: string): string {
  const separator = side === 'remote' ? '/' : localSep()
  const parts = path.split(separator).filter(Boolean)
  return parts[parts.length - 1] ?? path
}
