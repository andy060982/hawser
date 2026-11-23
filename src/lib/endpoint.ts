import type { Host } from '../types'

/* Identity of the endpoint a tab connects to, used by the backend to key
   transcripts, AI context, config snapshots and captures (see
   src-tauri/src/utils/artifacts.rs).

   The hostname alone is not an identity: the same RFC1918 address behind two
   bastions, two port-forwards on 127.0.0.1, or one box as `admin` and as
   `readonly` are different endpoints with different AI policies and configs.
   Nor is the catalogue id alone: repointing an entry at another device, or
   editing its bastion's address or account, must not hand the new device the
   old one's transcript and config baseline. So every hop names both the entry
   and where it actually dials:

   - a saved host:   `host:<id>=<user>@<host>:<port>`
   - quick connect:  `qc:<user>@<host>:<port>` (its id is per-dial)
   - local shell:    `local:<profile>`
   - plus `|via:<bastion hop>` when the dial rides a jump host, resolved
     exactly as the dialer resolves it.

   The backend derives the same string for a LIVE session from the
   parameters it dialled (`dial_identity`) and uses that for every lookup made
   for the session. This copy is for lookups without one: the replay before a
   dial, and the history of a host that is not connected. The two must agree
   exactly; frontend.test.mjs and artifacts.rs share test vectors. */

/** Quick-connect hosts carry a per-dial id and are never in the catalogue. */
export const isEphemeralHost = (h: Host): boolean => h.id.startsWith('qc-')

/** Trimmed, ASCII-only lowercase: what Rust's `to_ascii_lowercase` does.
 *  `toLowerCase` folds non-ASCII too and would disagree with the backend. */
const normHost = (s: string): string => s.trim().replace(/[A-Z]/g, (c) => c.toLowerCase())

/** Ids carrying the identity format's own separators are not used as ids. */
// eslint-disable-next-line no-control-regex
const validId = (id: string): boolean => id.length > 0 && !/[=|@\x00-\x1f\x7f-\x9f]/.test(id)

/** One hop: what the backend's `hop_identity` produces. */
export function hopIdentity(catalogueId: string | null, user: string, host: string, port: number): string {
  const dest = `${user}@${normHost(host)}:${port}`
  return catalogueId !== null && validId(catalogueId) ? `host:${catalogueId}=${dest}` : `qc:${dest}`
}

const self = (h: Host): string =>
  hopIdentity(isEphemeralHost(h) ? null : h.id, h.username, h.hostname, h.port)

export function endpointKey(host: Host, findJump: (id: string) => Host | undefined): string {
  if (host.local) return `local:${host.local.profile}`
  // Mirrors connectPending's jump resolution: self-reference and missing
  // bastions dial direct, so they key as direct too.
  const jump = host.jumpHostId && host.jumpHostId !== host.id ? findJump(host.jumpHostId) : undefined
  return jump ? `${self(host)}|via:${self(jump)}` : self(host)
}
