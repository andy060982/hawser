import type { Host } from '../types'

/* Stable identity of the endpoint a tab connects to, used by the backend to key
   transcripts, AI context, config snapshots and captures (see
   src-tauri/src/utils/artifacts.rs).

   The hostname alone is not an identity: the same RFC1918 address behind two
   bastions, two port-forwards on 127.0.0.1, or one box as `admin` and as
   `readonly` are different endpoints with different AI policies and configs.

   - a saved host:   `host:<id>` (stable across hostname/port edits)
   - quick connect:  `qc:<user>@<host>:<port>` (its id is per-dial, so the
                     address is the only stable thing)
   - local shell:    `local:<profile>`
   - plus `|via:<bastion identity>` when the dial rides a jump host, resolved
     exactly as the dialer resolves it, so the key names the path actually used. */

/** Quick-connect hosts carry a per-dial id and are never in the catalogue. */
export const isEphemeralHost = (h: Host): boolean => h.id.startsWith('qc-')

const self = (h: Host): string =>
  isEphemeralHost(h) ? `qc:${h.username}@${h.hostname.trim().toLowerCase()}:${h.port}` : `host:${h.id}`

export function endpointKey(host: Host, findJump: (id: string) => Host | undefined): string {
  if (host.local) return `local:${host.local.profile}`
  // Mirrors connectPending's jump resolution: self-reference and missing
  // bastions dial direct, so they key as direct too.
  const jump = host.jumpHostId && host.jumpHostId !== host.id ? findJump(host.jumpHostId) : undefined
  return jump ? `${self(host)}|via:${self(jump)}` : self(host)
}
