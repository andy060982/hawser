import type { Host, HostFolder, HostNode } from '../types'

/* A local copy of types.ts's guard: this module imports types only, so the
   node test runner (npm test) can load it without resolving '../types'. */
const isFolder = (n: HostNode): n is HostFolder => n.kind === 'folder'
import type { HostColor } from './hostColors'

/* ------------------------------------------------------------- vault ids */

/** Whether the OS vault folds the case of ids. The backend says which
 *  (`vault_id_rule`: Windows Credential Manager folds, the macOS Keychain and
 *  the Secret Service do not); until it answers, fold, the cautious choice for
 *  the delete-time borrower check (a password is never deleted from under a
 *  borrower that differs only in case). */
let vaultFolds = true

export function setVaultFoldsCase(folds: boolean): void {
  vaultFolds = folds
}

/** The one comparator for credential ids, with the vault's own rule: ASCII
 *  case-folded where the vault folds (ids there are ASCII-only, as the
 *  backend enforces), exact elsewhere. Two ids name the same saved password
 *  exactly when their keys are equal. */
export function vaultIdKey(id: string): string {
  return vaultFolds ? id.replace(/[A-Z]/g, (c) => c.toLowerCase()) : id
}

export const sameVaultId = (a: string | undefined, b: string): boolean =>
  a !== undefined && vaultIdKey(a) === vaultIdKey(b)

/** Parse a dotted-quad to a u32, or null if it isn't a valid IPv4. */
function parseIpv4(s: string): number | null {
  const parts = s.split('.')
  if (parts.length !== 4) return null
  let v = 0
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null
    const n = Number(p)
    if (n > 255) return null
    v = (v << 8) | n
  }
  return v >>> 0
}

const isCidr = (s: string) => /^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(s)

/** True if an IPv4 hostname falls inside a `a.b.c.d/n` subnet. Non-IPv4
 *  hostnames (DNS names) never match a CIDR query. */
function cidrMatch(hostname: string, cidr: string): boolean {
  const [net, bitsStr] = cidr.split('/')
  const bits = Number(bitsStr)
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return false
  const netN = parseIpv4(net)
  const hostN = parseIpv4(hostname)
  if (netN === null || hostN === null) return false
  if (bits === 0) return true
  const mask = (0xffffffff << (32 - bits)) >>> 0
  return (netN & mask) === (hostN & mask)
}

/** Depth-first prune: keep a host if it matches, keep a folder if its name
 *  matches or any descendant survives. Returns the pruned tree plus the ids of
 *  every folder that must be force-expanded to reveal a match — searching a
 *  collapsed tree is useless if the results stay hidden. */
export function filterTree(
  nodes: HostNode[],
  query: string,
): { tree: HostNode[]; expand: Set<string> } {
  const q = query.trim().toLowerCase()
  const expand = new Set<string>()
  if (!q) return { tree: nodes, expand }

  // A CIDR query (10.20.0.0/16) matches hosts by IP-subnet membership instead
  // of substring — the network-engineer's "show me everything in this range".
  const cidr = isCidr(query.trim()) ? query.trim() : null

  const matches = (n: HostNode) => {
    if (cidr) return n.kind === 'host' && cidrMatch(n.hostname, cidr)
    return n.kind === 'host'
      ? n.name.toLowerCase().includes(q) ||
          n.hostname.toLowerCase().includes(q) ||
          n.username.toLowerCase().includes(q) ||
          (n.tag?.toLowerCase().includes(q) ?? false)
      : n.name.toLowerCase().includes(q)
  }

  const walk = (list: HostNode[]): HostNode[] =>
    list.flatMap<HostNode>((node) => {
      if (!isFolder(node)) return matches(node) ? [node] : []
      const kids = walk(node.children)
      if (kids.length === 0 && !matches(node)) return []
      expand.add(node.id)
      // A folder matching by its own name shows its full contents.
      return [{ ...node, children: kids.length ? kids : node.children }]
    })

  return { tree: walk(nodes), expand }
}

/** Count hosts (not folders) beneath a node — used for the folder badge. */
export function countHosts(nodes: HostNode[]): number {
  return nodes.reduce(
    (sum, n) => sum + (isFolder(n) ? countHosts(n.children) : 1),
    0,
  )
}

/** Collect every folder id, for expand-all / collapse-all. */
export function allFolderIds(nodes: HostNode[]): string[] {
  return nodes.flatMap((n) =>
    isFolder(n) ? [n.id, ...allFolderIds(n.children)] : [],
  )
}

/** Replace a host in place if its id already exists anywhere in the tree,
 *  otherwise append it at the root.
 *
 *  In-place replacement matters: editing a host that lives three folders deep
 *  must not silently relocate it to the top level, which is what a naive
 *  "filter out, then push" would do. */
export function upsertHost(nodes: HostNode[], host: HostNode & { kind: 'host' }): HostNode[] {
  let replaced = false

  const walk = (list: HostNode[]): HostNode[] =>
    list.map((n) => {
      if (isFolder(n)) return { ...n, children: walk(n.children) }
      if (n.id === host.id) {
        replaced = true
        return host
      }
      return n
    })

  const next = walk(nodes)
  return replaced ? next : [...next, host]
}

/** Remove a host by id, at any depth. Folders are left in place even if they
 *  become empty — deleting a folder is a separate, explicit action. */
export function removeHost(nodes: HostNode[], hostId: string): HostNode[] {
  return nodes.flatMap<HostNode>((n) => {
    if (isFolder(n)) return [{ ...n, children: removeHost(n.children, hostId) }]
    return n.id === hostId ? [] : [n]
  })
}

/** Find a host by id, at any depth. */
export function findHost(
  nodes: HostNode[],
  hostId: string,
): (HostNode & { kind: 'host' }) | undefined {
  for (const n of nodes) {
    if (isFolder(n)) {
      const hit = findHost(n.children, hostId)
      if (hit) return hit
    } else if (n.id === hostId) {
      return n
    }
  }
  return undefined
}

/** Every host in the tree, flattened in display order — for pickers. */
export function allHosts(nodes: HostNode[]): (HostNode & { kind: 'host' })[] {
  return nodes.flatMap((n) => (isFolder(n) ? allHosts(n.children) : [n]))
}

/** Add an empty folder at the root. Root-level on purpose: nesting is created
 *  by moving hosts, and a deep empty scaffold is clutter nobody asked for. */
export function addFolder(nodes: HostNode[], name: string): HostNode[] {
  return [
    ...nodes,
    { kind: 'folder', id: `f-${Date.now().toString(36)}`, name, children: [] },
  ]
}

/** Move a host into a folder (or to the root with null), preserving the host
 *  itself untouched. No-op if the host or target folder is missing. */
export function moveHost(
  nodes: HostNode[],
  hostId: string,
  targetFolderId: string | null,
): HostNode[] {
  const host = findHost(nodes, hostId)
  if (!host) return nodes
  const without = removeHost(nodes, hostId)

  if (targetFolderId === null) return [...without, host]

  let placed = false
  const walk = (list: HostNode[]): HostNode[] =>
    list.map((n) => {
      if (!isFolder(n)) return n
      if (n.id === targetFolderId) {
        placed = true
        return { ...n, children: [...n.children, host] }
      }
      return { ...n, children: walk(n.children) }
    })
  const next = walk(without)
  // Target folder vanished between menu open and click: keep the host at root
  // rather than silently deleting it.
  return placed ? next : [...without, host]
}

/** Remove a folder. Its children are promoted to the parent level rather than
 *  deleted — removing a folder must never remove hosts. */
export function removeFolder(nodes: HostNode[], folderId: string): HostNode[] {
  return nodes.flatMap<HostNode>((n) => {
    if (!isFolder(n)) return [n]
    if (n.id === folderId) return n.children
    return [{ ...n, children: removeFolder(n.children, folderId) }]
  })
}

/** Rename a folder in place. */
export function renameFolder(nodes: HostNode[], folderId: string, name: string): HostNode[] {
  return nodes.map((n) => {
    if (!isFolder(n)) return n
    if (n.id === folderId) return { ...n, name }
    return { ...n, children: renameFolder(n.children, folderId, name) }
  })
}

/** A colour that actually overrides its folder's. `'none'` (the editor's
 *  "off" chip, or an older hosts.json) means "no colour of my own", never
 *  "opt out of my folder's policy": a host inside a red Production folder
 *  stays red. Opting a host out of a red folder's policy takes moving it out
 *  of the folder, a visible act. */
export function ownColor(c: HostColor | undefined): HostColor | undefined {
  return c && c !== 'none' ? c : undefined
}

/** The colour a host would inherit from its nearest coloured ancestor folder
 *  (undefined at top level or when the host is not found). */
export function inheritedHostColor(nodes: HostNode[], hostId: string): HostColor | undefined {
  const SEARCHING = Symbol('searching')
  const walk = (
    list: HostNode[],
    inherited: HostColor | undefined,
  ): HostColor | undefined | typeof SEARCHING => {
    for (const n of list) {
      if (isFolder(n)) {
        const res = walk(n.children, ownColor(n.color) ?? inherited)
        if (res !== SEARCHING) return res
      } else if (n.id === hostId) {
        return inherited
      }
    }
    return SEARCHING
  }
  const r = walk(nodes, undefined)
  return r === SEARCHING ? undefined : r
}

/** A host's effective colour: its own if set, else the nearest ancestor
 *  folder's. Returns undefined when neither the host (nor a coloured ancestor)
 *  is found. Used for the wrong-window frame and every colour policy. */
export function effectiveHostColor(nodes: HostNode[], hostId: string): HostColor | undefined {
  const host = findHost(nodes, hostId)
  if (!host) return undefined
  return ownColor(host.color) ?? inheritedHostColor(nodes, hostId)
}

/** Set (or clear, with 'none'/undefined) a folder's accent colour. */
export function setFolderColor(
  nodes: HostNode[],
  folderId: string,
  color: HostColor | undefined,
): HostNode[] {
  return nodes.map((n) => {
    if (!isFolder(n)) return n
    if (n.id === folderId) return { ...n, color: color === 'none' ? undefined : color }
    return { ...n, children: setFolderColor(n.children, folderId, color) }
  })
}

/** All folders flattened, for "move to" pickers. */
export function allFolders(nodes: HostNode[]): HostFolder[] {
  return nodes.flatMap((n) =>
    isFolder(n) ? [n, ...allFolders(n.children)] : [],
  )
}

/** Prepare imported nodes for merging into an existing catalogue.
 *
 *  Any node whose id already exists (at any depth, host or folder) gets a
 *  fresh id. Skipping duplicates instead would silently drop nested hosts,
 *  and keeping them would corrupt the tree: duplicate ids break findHost,
 *  folder-move targets, and React keys all at once. Imported hosts have no
 *  saved credential on this machine either way, so a new id costs nothing.
 */
export function reidentify(imported: HostNode[], existing: HostNode[]): HostNode[] {
  // Ids are compared with the vault's rule: where it folds case (Windows),
  // `H-ABC` beside an existing `h-abc` would address (and on delete, remove)
  // the existing host's saved password.
  const key = vaultIdKey
  const taken = new Set<string>()
  const collect = (list: HostNode[]) => {
    for (const n of list) {
      taken.add(key(n.id))
      if (isFolder(n)) collect(n.children)
    }
  }
  collect(existing)

  let counter = 0
  const freshId = (prefix: string) => {
    let id: string
    do {
      id = `${prefix}-imp-${Date.now().toString(36)}-${counter++}`
    } while (taken.has(key(id)))
    taken.add(key(id))
    return id
  }

  const existingIds = new Set(taken)
  /** Imported id, EXACTLY as spelled -> the id it ends up with (itself when
   *  it did not collide). Host references (`jumpHostId`) resolve through this
   *  map only: the app looks hosts up by exact id, so a file holding distinct
   *  `h-jump` and `H-JUMP` hosts (exported where the vault is case-sensitive)
   *  keeps each client on the bastion it named, even when one of the two is
   *  re-id'd here. */
  const exact = new Map<string, string>()
  /** The same, keyed by vault key (first spelling wins). Credential
   *  references (`credentialId`, a vault slot) fall back to it, so a borrower
   *  spelled in another case (`H-LENDER` borrowing `h-lender`, one entry where
   *  the vault folds case) follows the lender's rename too. */
  const byVaultKey = new Map<string, string>()

  const walk = (list: HostNode[]): HostNode[] =>
    list.map((n) => {
      const id =
        taken.has(key(n.id)) || !usableImportedId(n.id)
          ? freshId(isFolder(n) ? 'f' : 'h')
          : (taken.add(key(n.id)), n.id)
      if (!exact.has(n.id)) exact.set(n.id, id)
      if (!byVaultKey.has(key(n.id))) byVaultKey.set(key(n.id), id)
      return isFolder(n)
        ? { ...n, id, children: walk(n.children) }
        : { ...n, id }
    })

  // Cross-references (bastion, shared credential) must follow the renames: a
  // host whose jump host was re-id'd would otherwise keep the OLD id and bind
  // to whatever LOCAL host owns it — tunnelling through the wrong bastion. A
  // reference that points outside the import at an id this machine already
  // uses is dropped rather than bound to an unrelated local host.
  const outside = (ref: string): string | undefined =>
    existingIds.has(key(ref)) || !usableImportedId(ref) ? undefined : ref
  const fixHost = (ref: string | undefined): string | undefined => {
    if (ref === undefined) return undefined
    return exact.has(ref) ? exact.get(ref) : outside(ref)
  }
  const fixCredential = (ref: string | undefined): string | undefined => {
    if (ref === undefined) return undefined
    if (exact.has(ref)) return exact.get(ref)
    return byVaultKey.has(key(ref)) ? byVaultKey.get(key(ref)) : outside(ref)
  }
  const relink = (list: HostNode[]): HostNode[] =>
    list.map((n) =>
      isFolder(n)
        ? { ...n, children: relink(n.children) }
        : { ...n, jumpHostId: fixHost(n.jumpHostId), credentialId: fixCredential(n.credentialId) },
    )

  return relink(walk(imported))
}

/** Whether an id from an imported file may be kept as is: printable ASCII
 *  (what the app generates, and what every credential vault stores the same
 *  way), and outside the namespaces the app uses for synthetic tabs and its
 *  own vault items (quick connect `qc-`, local terminals `local-`, `ai:`,
 *  `hawser:`). Anything else is given a fresh id. */
export function usableImportedId(id: string): boolean {
  return /^[\x21-\x7e]{1,200}$/.test(id) && !/^(qc-|local-|ai:|hawser:)/i.test(id)
}

/* ------------------------------------------------------ catalogue checks */

const isObj = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v)

/** Why a parsed hosts.json cannot be used, or null when it can. Checks, at
 *  every depth, the shape the tree helpers rely on — each node an object with
 *  a known kind and a string id (unique across the tree); a folder with a name
 *  and a children list; a host with name, hostname, username and a valid port
 *  — so a hand-edited file with a `null` entry or a folder without children is
 *  reported instead of blanking the UI. Optional fields, when present, must
 *  have their types. */
export function catalogueProblem(value: unknown): string | null {
  if (!Array.isArray(value)) return 'the top level is not a list of hosts and folders'
  const ids = new Set<string>()
  const optional: Record<string, (v: unknown) => boolean> = {
    keyPath: (v) => typeof v === 'string',
    jumpHostId: (v) => typeof v === 'string',
    credentialId: (v) => typeof v === 'string',
    tag: (v) => typeof v === 'string',
    color: (v) => typeof v === 'string',
    startupCommand: (v) => typeof v === 'string',
    startupCommands: (v) => Array.isArray(v) && v.every((c) => typeof c === 'string'),
    aiAllowed: (v) => typeof v === 'boolean',
    configCommand: (v) => typeof v === 'string',
    checkConfigOnConnect: (v) => typeof v === 'boolean',
    snippets: (v) =>
      Array.isArray(v) &&
      v.every((s) => isObj(s) && typeof s.command === 'string' && typeof s.label === 'string'),
    local: (v) => isObj(v) && typeof v.profile === 'string',
  }
  const walk = (list: unknown[], where: string, depth: number): string | null => {
    if (depth > 64) return `${where}: folders are nested too deeply`
    for (let i = 0; i < list.length; i++) {
      const n = list[i]
      const at = `${where}[${i}]`
      if (!isObj(n)) return `${at} is not a host or folder`
      if (typeof n.id !== 'string' || n.id === '') return `${at} has no id`
      if (ids.has(n.id)) return `${at}: the id "${n.id}" is used twice`
      ids.add(n.id)
      if (n.kind === 'folder') {
        if (typeof n.name !== 'string') return `${at} (folder) has no name`
        if (!Array.isArray(n.children)) return `${at} (folder "${n.name}") has no children list`
        const inner = walk(n.children, `${at}.children`, depth + 1)
        if (inner) return inner
      } else if (n.kind === 'host') {
        for (const f of ['name', 'hostname', 'username'] as const) {
          if (typeof n[f] !== 'string') return `${at} (host) has no ${f}`
        }
        if (!Number.isInteger(n.port) || (n.port as number) < 1 || (n.port as number) > 65535) {
          return `${at} (host "${n.name}") has an invalid port`
        }
        if (n.auth !== undefined && !['agent', 'password', 'key'].includes(n.auth as string)) {
          return `${at} (host "${n.name}") has an unknown auth method`
        }
        for (const [f, ok] of Object.entries(optional)) {
          if (n[f] !== undefined && !ok(n[f])) return `${at} (host "${n.name}"): ${f} has the wrong type`
        }
      } else {
        return `${at} has an unknown kind`
      }
    }
    return null
  }
  return walk(value, 'entry', 0)
}

/** What an imported host would do on its own, without the user clicking
 *  anything visible: run commands on connect, a hidden config capture, send
 *  output to the AI, or open a local shell instead of SSH. */
export interface ImportRisk {
  name: string
  enables: string[]
}

const HOST_FIELDS = [
  'kind', 'id', 'name', 'hostname', 'port', 'username', 'auth', 'keyPath', 'jumpHostId',
  'tag', 'color', 'credentialId', 'snippets',
] as const
/** Copied only with an explicit yes. `aiAllowed` and `local` are handled
 *  separately below (an AI opt-out is always kept; `local` is rebuilt). */
const RISKY_FIELDS = ['startupCommands', 'startupCommand', 'configCommand', 'checkConfigOnConnect'] as const
const FOLDER_FIELDS = ['kind', 'id', 'name', 'color', 'children'] as const

/** Copy an imported tree keeping only the fields a host or folder may carry
 *  (anything else in the file is dropped), and list the hosts whose import
 *  would turn on something that acts without a visible click. With
 *  `allowRisky` false those fields are dropped too. Call on a tree that
 *  passed `catalogueProblem`. */
export function sanitizeImport(
  tree: HostNode[],
  allowRisky: boolean,
): { tree: HostNode[]; risky: ImportRisk[] } {
  const risky: ImportRisk[] = []
  const pick = (n: Record<string, unknown>, fields: readonly string[]) => {
    const out: Record<string, unknown> = {}
    for (const f of fields) if (n[f] !== undefined) out[f] = n[f]
    return out
  }
  const walk = (list: HostNode[]): HostNode[] =>
    list.map((node) => {
      const n = node as unknown as Record<string, unknown>
      if (node.kind === 'folder') {
        const f = pick(n, FOLDER_FIELDS) as unknown as HostFolder
        return { ...f, children: walk(node.children) }
      }
      const h = pick(n, HOST_FIELDS) as Record<string, unknown>
      if (Array.isArray(h.snippets)) {
        h.snippets = (h.snippets as Record<string, unknown>[]).map((s) => ({
          label: s.label,
          command: s.command,
          slot: Number.isInteger(s.slot) && (s.slot as number) >= 1 && (s.slot as number) <= 9 ? s.slot : null,
          ...(s.autoRun === true ? { autoRun: true } : {}),
        }))
      }
      const enables: string[] = []
      const cmds = [
        ...(Array.isArray(n.startupCommands) ? (n.startupCommands as string[]) : []),
        ...(typeof n.startupCommand === 'string' ? [n.startupCommand] : []),
      ].filter((c) => c.trim() !== '')
      if (cmds.length) enables.push(`runs on connect: ${cmds.join(' ; ')}`)
      if (typeof n.configCommand === 'string' && n.configCommand.trim() !== '') {
        enables.push(
          `${n.checkConfigOnConnect === true ? 'runs on every connect (hidden)' : 'config snapshot command'}: ${n.configCommand}`,
        )
      }
      if (n.aiAllowed === true) enables.push('shares its terminal output with the AI assistant')
      if (isObj(n.local)) enables.push(`opens a local shell (${String(n.local.profile)}) instead of SSH`)
      const keep = enables.length > 0 && allowRisky
      if (enables.length) {
        risky.push({ name: String(n.name), enables })
        if (keep) Object.assign(h, pick(n, RISKY_FIELDS))
      }
      // AI: an opt-out is safe and always kept. An opt-in needs the yes; on
      // a no it becomes an explicit opt-out, never "unset" (which would
      // inherit the local colour policy, usually "allowed").
      if (n.aiAllowed === false) h.aiAllowed = false
      else if (n.aiAllowed === true) h.aiAllowed = keep
      // A local profile is rebuilt from its one known field, never copied.
      if (keep && isObj(n.local) && typeof n.local.profile === 'string') h.local = { profile: n.local.profile }
      return h as unknown as HostNode
    })
  return { tree: walk(tree), risky }
}

/** The destinations (host, port, username) that use vault entry `credKey`:
 *  every host whose effective credential (its `credentialId`, else its own
 *  id) is that entry. The exact set a saved password may be sent to; passed
 *  to the backend when it is saved or narrowed, so an edited host's old
 *  address is revoked. */
export function credentialDestinations(
  nodes: HostNode[],
  credKey: string,
): { host: string; port: number; username: string }[] {
  const out: { host: string; port: number; username: string }[] = []
  for (const h of allHosts(nodes)) {
    if (!sameVaultId(h.credentialId ?? h.id, credKey)) continue
    const d = { host: h.hostname, port: h.port, username: h.username }
    if (!out.some((o) => o.host === d.host && o.port === d.port && o.username === d.username)) out.push(d)
  }
  return out
}

/** Whether an edit changed anything a credential binding depends on. */
export function bindingChanged(before: Host, after: Host): boolean {
  return (
    before.hostname !== after.hostname ||
    before.port !== after.port ||
    before.username !== after.username ||
    !sameVaultId(before.credentialId ?? before.id, after.credentialId ?? after.id)
  )
}

/** Whether any host in `nodes` still borrows vault entry `credKey` (through
 *  `credentialId`), by the vault's id rule: deleting the owner must not take
 *  the password from under it. */
export function isBorrowed(nodes: HostNode[], credKey: string): boolean {
  return allHosts(nodes).some((h) => sameVaultId(h.credentialId, credKey))
}

/** Vault ids whose binding must shrink with the next catalogue save, kept
 *  until a save that carried them succeeds: a failed save (narrowing refused,
 *  disk full) leaves them queued, so the next save of any edit retries them
 *  rather than leaving an old destination authorized. */
export class NarrowQueue {
  private gen = new Map<string, number>()
  private n = 0

  /** Queue ids (compared by `vaultIdKey`); returns everything queued. */
  add(ids: Iterable<string>): string[] {
    for (const id of ids) {
      const k = vaultIdKey(id)
      const had = [...this.gen.keys()].find((x) => vaultIdKey(x) === k)
      if (had !== undefined) this.gen.delete(had)
      this.gen.set(id, ++this.n)
    }
    return this.pending()
  }

  pending(): string[] {
    return [...this.gen.keys()]
  }

  /** A snapshot to send with a save. */
  take(): Map<string, number> {
    return new Map(this.gen)
  }

  /** The save that carried `batch` succeeded: drop those ids unless they
   *  were queued again since (a newer save carries them). */
  settle(batch: Map<string, number>): void {
    for (const [id, g] of batch) if (this.gen.get(id) === g) this.gen.delete(id)
  }
}

/** The backend's answer to a save older than the last one it published
 *  (utils::hosts::STALE_SAVE), with that last generation. */
const STALE = /stale catalogue save \(generation \d+; last saved (\d+)\)/

function staleBase(e: unknown): number | null {
  const m = STALE.exec(e instanceof Error ? e.message : String(e))
  return m ? Number(m[1]) : null
}

/** Serialises catalogue saves: at most one in flight, the next one sent only
 *  after it settles, and every tree queued meanwhile coalesced into the
 *  newest. Each save carries a generation that only grows (seeded from the
 *  clock, so a reloaded page continues above its predecessor), and the
 *  backend refuses one that is not newer than the last it published. So an
 *  older tree can never publish after a newer one. Vault ids to narrow ride
 *  the save that carries them (`NarrowQueue`). */
export class SaveQueue<T> {
  private latest: { tree: T } | null = null
  private gen = 0
  private pumping: Promise<void> | null = null
  private readonly send: (tree: T, narrow: string[], generation: number) => Promise<unknown>
  private readonly narrow: NarrowQueue
  private readonly onResult: (error: unknown) => void
  private readonly now: () => number

  /** `onResult` is called once per save that was sent: `null` on success. */
  constructor(
    send: (tree: T, narrow: string[], generation: number) => Promise<unknown>,
    narrow: NarrowQueue,
    onResult: (error: unknown) => void,
    now: () => number = Date.now,
  ) {
    this.send = send
    this.narrow = narrow
    this.onResult = onResult
    this.now = now
  }

  /** Queue `tree` (replacing any not sent yet) and the ids to narrow with
   *  it. Resolves once everything queued so far has been sent. */
  save(tree: T, ids: Iterable<string> = []): Promise<void> {
    this.narrow.add(ids)
    this.latest = { tree }
    if (!this.pumping) this.pumping = this.pump()
    return this.pumping
  }

  private next(): number {
    this.gen = Math.max(this.gen + 1, this.now())
    return this.gen
  }

  private async pump(): Promise<void> {
    // try/finally in this one function: the reset runs in the same tick as
    // the last check for a queued tree, so a save() after it starts a new
    // pump and none is ever left unsent. The first await comes before any
    // work, so `pumping` is always set before this can finish.
    try {
      await null
      while (this.latest) {
        const { tree } = this.latest
        this.latest = null
        const batch = this.narrow.take()
        let error: unknown = null
        let saved = false
        for (let attempt = 0; ; attempt++) {
          try {
            await this.send(tree, [...batch.keys()], this.next())
            saved = true
            break
          } catch (e) {
            error = e
            const base = staleBase(e)
            // Refused as stale: the backend published a generation above ours
            // (a reloaded page, a clock step back). Nothing of ours is in
            // flight, so continue above it, once; a newer queued tree (sent
            // next, with these ids still queued) supersedes this one anyway.
            if (base === null || attempt > 0) break
            this.gen = Math.max(this.gen, base)
            if (this.latest) {
              error = null
              break
            }
          }
        }
        if (saved) this.narrow.settle(batch)
        if (saved || error !== null) this.onResult(saved ? null : error)
      }
    } finally {
      this.pumping = null
    }
  }
}

/** Hosts that ride `hostId` as their jump host (ProxyJump). */
export function jumpDependents(nodes: HostNode[], hostId: string): Host[] {
  return allHosts(nodes).filter((h) => h.id !== hostId && h.jumpHostId === hostId)
}

/** A display label per folder id: its name, or its full path ("Sites / East")
 *  whenever another folder shares that name, so pickers can tell them apart. */
export function folderLabels(nodes: HostNode[]): Map<string, string> {
  const paths = new Map<string, string[]>()
  const walk = (list: HostNode[], trail: string[]) => {
    for (const n of list) {
      if (!isFolder(n)) continue
      const path = [...trail, n.name]
      paths.set(n.id, path)
      walk(n.children, path)
    }
  }
  walk(nodes, [])
  const count = new Map<string, number>()
  for (const p of paths.values()) count.set(p[p.length - 1], (count.get(p[p.length - 1]) ?? 0) + 1)
  const labels = new Map<string, string>()
  const used = new Map<string, number>()
  for (const [id, p] of paths) {
    const name = p[p.length - 1]
    let label = (count.get(name) ?? 0) > 1 ? p.join(' / ') : name
    // Same name at the same path: number them in tree order.
    const seen = (used.get(label) ?? 0) + 1
    used.set(label, seen)
    if (seen > 1) label = `${label} (${seen})`
    labels.set(id, label)
  }
  return labels
}

/** Who else uses the vault slot a host's draft points at, for the key-
 *  passphrase guard (a passphrase lives in the same slot as a password).
 *
 *  Judged by the effective slot (`credentialId ?? id`), never by the draft's
 *  own id: two hosts borrowing the slot of a lender that was deleted share it
 *  with each other although neither can name a lender, and a lender id that
 *  differs only in case is the same slot where the vault folds case. A draft
 *  that borrows any slot other than its own counts as shared even when
 *  nobody else is found: the slot was some other host's. */
export function vaultSlotSharing(
  nodes: HostNode[],
  draft: { id: string; credentialId?: string },
): { shared: boolean; lender?: Host; others: Host[]; orphaned: boolean } {
  const credKey = draft.credentialId ?? draft.id
  const hosts = allHosts(nodes)
  const borrowing = !!draft.credentialId && !sameVaultId(draft.credentialId, draft.id)
  const lender = borrowing
    ? hosts.find((h) => h.id !== draft.id && sameVaultId(h.id, credKey))
    : undefined
  const others = hosts.filter(
    (h) => h.id !== draft.id && h !== lender && sameVaultId(h.credentialId ?? h.id, credKey),
  )
  return { shared: borrowing || others.length > 0, lender, others, orphaned: borrowing && !lender }
}

/* ------------------------------------------ ssh config / PuTTY import */

/** Where an "Import from SSH config / PuTTY" scan came from. */
export type ImportSource = 'ssh-config' | 'putty'

/** A scanned host's ProxyJump, as the backend reports it (ssh_import.rs). */
export type ScannedJump =
  | { kind: 'alias'; alias: string }
  | { kind: 'literal'; host: string; port: number; user: string | null; keyPath?: string | null }

export interface ScannedHost {
  name: string
  hostname: string
  port: number
  user: string | null
  keyPath: string | null
  jump: ScannedJump | null
  /** Jump hosts ssh would really go through (0 or absent: direct). */
  jumpHops?: number
  /** Set when the configured route cannot be reproduced with Hawser's one
   *  jump host: `jump` is then the first hop only. */
  unsupportedRoute?: string | null
  warnings: string[]
  origin: string
}

export interface ScanReport {
  source: ImportSource
  hosts: ScannedHost[]
  warnings: string[]
  skipped: string[]
  unsupportedKeys: string[]
  filesRead: string[]
  localUser: string
}

/** One row of the import preview. */
export interface ImportRow {
  index: number
  scanned: ScannedHost
  /** The login the host gets: the scanned user, else the local account
   *  name (what OpenSSH would use). */
  username: string
  userDefaulted: boolean
  /** An existing catalogue host with the same host, port and user. */
  duplicateOf?: { id: string; name: string }
  /** What the jump column shows; undefined for no jump. */
  jumpLabel?: string
  warnings: string[]
  /** `route`: the ProxyJump chain is longer than one hop (unchecked; asks
   *  before importing it with the first hop only). `blocked`: the jump host
   *  is not in this import, so the row cannot be imported (it would
   *  otherwise be saved as a direct route). */
  status: 'new' | 'duplicate' | 'warning' | 'route' | 'blocked'
  /** Why a `blocked` row cannot be imported. */
  blockedReason?: string
  /** Whether the row starts checked: everything except duplicates, routes
   *  Hawser cannot follow, and blocked rows. */
  checked: boolean
}

/** Same destination: hostname (case-insensitive), port, user. */
export const importEndpointKey = (host: string, port: number, user: string): string =>
  `${user}@${host.toLowerCase()}:${port}`

export const importFolderName = (source: ImportSource): string =>
  source === 'putty' ? 'Imported (PuTTY)' : 'Imported (ssh config)'

const hostKey = (h: Host) => importEndpointKey(h.hostname, h.port, h.username)

/** The literal jump's endpoint key, with the local account as the default
 *  user, as for the hosts themselves. */
const literalJumpKey = (j: Extract<ScannedJump, { kind: 'literal' }>, localUser: string) =>
  importEndpointKey(j.host, j.port, j.user ?? localUser)

const literalLabel = (j: Extract<ScannedJump, { kind: 'literal' }>, localUser: string) =>
  `${j.user ?? localUser}@${j.host}${j.port !== 22 ? `:${j.port}` : ''}`

/** Turn a scan into preview rows: the effective user, duplicates of existing
 *  catalogue hosts (unchecked by default), and a jump label. Pure. */
export function planImport(report: ScanReport, existing: HostNode[]): ImportRow[] {
  const byKey = new Map<string, Host>()
  for (const h of allHosts(existing)) if (!byKey.has(hostKey(h))) byKey.set(hostKey(h), h)
  const local = report.localUser
  const rowKeys = report.hosts.map((s) => importEndpointKey(s.hostname, s.port, s.user ?? local))
  const rows = report.hosts.map((s, index): ImportRow => {
    const username = s.user ?? local
    const warnings = [...s.warnings]
    if (s.user === null && !local) warnings.push('no user name; set it after importing')
    const dup = byKey.get(rowKeys[index])
    let jumpLabel: string | undefined
    let blockedReason: string | undefined
    if (s.jump?.kind === 'alias') {
      jumpLabel = s.jump.alias
      const target = jumpAliasRow(report.hosts, s.jump.alias)
      if (target < 0 || target === index) {
        blockedReason = `its jump host ${s.jump.alias} is not in this import, and importing it without one would connect directly`
      }
    } else if (s.jump?.kind === 'literal') {
      const key = literalJumpKey(s.jump, local)
      const ex = byKey.get(key)
      const row = rowKeys.indexOf(key)
      jumpLabel = ex
        ? `${ex.name} (existing)`
        : row >= 0 && row !== index
          ? report.hosts[row].name
          : `${literalLabel(s.jump, local)} (new)`
    }
    const route = !!s.unsupportedRoute || (s.jumpHops ?? 0) > 1
    const status: ImportRow['status'] = blockedReason
      ? 'blocked'
      : dup
        ? 'duplicate'
        : route
          ? 'route'
          : warnings.length
            ? 'warning'
            : 'new'
    return {
      index,
      scanned: s,
      username,
      userDefaulted: s.user === null,
      duplicateOf: dup ? { id: dup.id, name: dup.name } : undefined,
      jumpLabel,
      warnings,
      status,
      ...(blockedReason ? { blockedReason } : {}),
      checked: !dup && !route && !blockedReason,
    }
  })
  // A host riding a blocked row (that is not an existing host either) is
  // blocked too: it could only be saved as a direct route.
  for (let changed = true; changed; ) {
    changed = false
    for (const r of rows) {
      const j = r.scanned.jump
      if (r.status === 'blocked' || j?.kind !== 'alias') continue
      const t = rows[jumpAliasRow(report.hosts, j.alias)]
      if (t && t.status === 'blocked' && !t.duplicateOf) {
        r.status = 'blocked'
        r.blockedReason = `its jump host ${j.alias} cannot be imported (${t.blockedReason})`
        r.checked = false
        changed = true
      }
    }
  }
  return rows
}

/** The row of the import an alias jump names (case-insensitive, first
 *  wins), or -1. */
function jumpAliasRow(hosts: ScannedHost[], alias: string): number {
  const a = alias.toLowerCase()
  return hosts.findIndex((h) => h.name.toLowerCase() === a)
}

/** The rows an import really takes for a set of checked rows.
 *
 *  Blocked rows are never taken. A checked host whose jump alias is
 *  another row of the import that is NOT checked, and that does not
 *  duplicate an existing catalogue host, takes that row too ("added as jump
 *  host"): saving the destination without it would silently make it a
 *  direct connection. Transitively, so a jump host's own jump alias comes
 *  along as well. `implied` maps each such added row to the names of the
 *  hosts that need it. */
export function importSelection(
  rows: ImportRow[],
  checked: ReadonlySet<number>,
): { picked: Set<number>; implied: Map<number, string[]> } {
  const byIndex = new Map(rows.map((r) => [r.index, r]))
  const picked = new Set<number>()
  for (const i of checked) if (byIndex.get(i) && byIndex.get(i)!.status !== 'blocked') picked.add(i)
  const implied = new Map<number, string[]>()
  const queue = [...picked]
  while (queue.length) {
    const r = byIndex.get(queue.shift()!)!
    const j = r.scanned.jump
    if (j?.kind !== 'alias') continue
    const t = rows.find((x) => x.scanned.name.toLowerCase() === j.alias.toLowerCase())
    if (!t || t.index === r.index || t.status === 'blocked') continue
    if (picked.has(t.index) && !implied.has(t.index)) continue
    if (!picked.has(t.index) && t.duplicateOf) continue
    implied.set(t.index, [...(implied.get(t.index) ?? []), r.scanned.name])
    if (!picked.has(t.index)) {
      picked.add(t.index)
      queue.push(t.index)
    }
  }
  return { picked, implied }
}

/** Checked rows whose ProxyJump chain is longer than Hawser's one jump
 *  host: importing them needs an explicit confirmation. */
export function routeRowsToConfirm(rows: ImportRow[], checked: ReadonlySet<number>): ImportRow[] {
  return rows.filter((r) => checked.has(r.index) && r.status === 'route')
}

/** The confirmation text for `routeRowsToConfirm`. */
export function routeConfirmText(rows: ImportRow[]): string {
  const lines = rows.slice(0, 8).map((r) => {
    const hops = r.scanned.jumpHops ?? 0
    return `• ${r.scanned.name}: ${hops > 1 ? `${hops} hops` : 'a route Hawser cannot follow'}; will connect via ${r.jumpLabel ?? 'the first hop'} only`
  })
  if (rows.length > 8) lines.push(`…and ${rows.length - 8} more`)
  return `${rows.length === 1 ? 'This host uses' : 'These hosts use'} a ProxyJump route Hawser cannot reproduce (it supports one jump host). If imported, ${rows.length === 1 ? 'it' : 'each'} will connect via the first hop only, which may not reach the same server or may expose it differently.\n\n${lines.join('\n')}\n\nImport with the first hop only?`
}

/** Where imported hosts go. */
export type ImportTarget =
  | { kind: 'new-folder'; name: string }
  | { kind: 'folder'; id: string }
  | { kind: 'top' }

/** Temp ids are deliberately not usable as kept ids (a NUL is not printable
 *  ASCII), so reidentify gives every imported node a fresh catalogue id. */
const TEMP = '\u0000imp-'

/** Put `children` at the end of folder `folderId` (anywhere in the tree). */
function appendToFolder(nodes: HostNode[], folderId: string, children: HostNode[]): HostNode[] {
  return nodes.map((n) =>
    isFolder(n)
      ? n.id === folderId
        ? { ...n, children: [...n.children, ...children] }
        : { ...n, children: appendToFolder(n.children, folderId, children) }
      : n,
  )
}

/** Build the catalogue that results from importing the checked rows.
 *
 *  Imported hosts carry only address fields (name, hostname, port, user,
 *  auth, key path, jump host): never on-connect commands, config checks, an
 *  AI opt-in or a local shell, and no credential reference. AI access is left
 *  unset so the default colour policy applies. Auth is `key` when a key file
 *  was found, else `password` (asked for on connect, never stored here).
 *
 *  Jump hosts: an alias of the same import links to that row when it is
 *  checked, or to the existing host it duplicates; a literal `user@host:port`
 *  links to an existing host with that endpoint, else a checked row with it,
 *  else a jump host entry is created (once per endpoint). Every node gets a
 *  fresh id through `reidentify`. */
export function buildImport(
  rows: ImportRow[],
  checked: ReadonlySet<number>,
  existing: HostNode[],
  target: ImportTarget,
  localUser: string,
): { catalogue: HostNode[]; added: number; notes: string[] } {
  const notes: string[] = []
  // Blocked rows dropped; jump hosts a checked row needs added.
  const { picked: take, implied } = importSelection(rows, checked)
  // A row whose alias jump host is neither taken nor an existing host is
  // refused, never saved as a direct route; repeated so a refusal also
  // refuses the hosts that ride it.
  const byLower = new Map<string, ImportRow>()
  for (const r of rows) if (!byLower.has(r.scanned.name.toLowerCase())) byLower.set(r.scanned.name.toLowerCase(), r)
  for (let changed = true; changed; ) {
    changed = false
    for (const i of take) {
      const r = rows.find((x) => x.index === i)!
      const j = r.scanned.jump
      if (j?.kind !== 'alias') continue
      const t = byLower.get(j.alias.toLowerCase())
      const ok = !!t && t.index !== r.index && (take.has(t.index) || !!t.duplicateOf)
      if (!ok) {
        take.delete(i)
        notes.push(`${r.scanned.name}: not imported, its jump host ${j.alias} is not available (it would otherwise connect directly)`)
        changed = true
      }
    }
  }
  const picked = rows.filter((r) => take.has(r.index))
  for (const [i, needs] of implied) notes.push(`${rows.find((r) => r.index === i)!.scanned.name}: added as jump host for ${needs.join(', ')}`)
  for (const r of picked) {
    if (r.status === 'route') notes.push(`${r.scanned.name}: imported with the first hop only (${r.jumpLabel ?? 'jump host'})`)
  }
  const tempId = (i: number) => `${TEMP}${i}`
  const byName = new Map<string, ImportRow>()
  for (const r of rows) if (!byName.has(r.scanned.name.toLowerCase())) byName.set(r.scanned.name.toLowerCase(), r)
  const pickedByKey = new Map<string, ImportRow>()
  for (const r of picked) {
    const k = importEndpointKey(r.scanned.hostname, r.scanned.port, r.username)
    if (!pickedByKey.has(k)) pickedByKey.set(k, r)
  }
  const existingByKey = new Map<string, Host>()
  for (const h of allHosts(existing)) if (!existingByKey.has(hostKey(h))) existingByKey.set(hostKey(h), h)

  /** temp id -> existing catalogue id, applied after reidentify (which
   *  drops references that leave the import). */
  const external = new Map<string, string>()
  const created = new Map<string, Host>()
  const hosts: Host[] = picked.map((r) => {
    const s = r.scanned
    const id = tempId(r.index)
    const h: Host = {
      kind: 'host',
      id,
      name: s.name,
      hostname: s.hostname,
      port: s.port,
      username: r.username,
      auth: s.keyPath ? 'key' : 'password',
      ...(s.keyPath ? { keyPath: s.keyPath } : {}),
    }
    if (s.jump?.kind === 'alias') {
      const target = byName.get(s.jump.alias.toLowerCase())
      if (target && target.index !== r.index && take.has(target.index)) {
        h.jumpHostId = tempId(target.index)
      } else if (target?.duplicateOf) {
        external.set(id, target.duplicateOf.id)
      }
      // No other case: rows without a usable jump host were refused above.
    } else if (s.jump?.kind === 'literal') {
      const key = literalJumpKey(s.jump, localUser)
      const ex = existingByKey.get(key)
      const row = pickedByKey.get(key)
      if (ex) {
        external.set(id, ex.id)
      } else if (row && row.index !== r.index) {
        h.jumpHostId = tempId(row.index)
      } else if (!row) {
        let jh = created.get(key)
        if (!jh) {
          jh = {
            kind: 'host',
            id: `${TEMP}j${created.size}`,
            name: literalLabel(s.jump, localUser),
            hostname: s.jump.host,
            port: s.jump.port,
            username: s.jump.user ?? localUser,
            // The IdentityFile ssh would use for that hop; else a password
            // asked for on connect.
            auth: s.jump.keyPath ? 'key' : 'password',
            ...(s.jump.keyPath ? { keyPath: s.jump.keyPath } : {}),
          }
          created.set(key, jh)
          notes.push(`created jump host ${jh.name}`)
        }
        h.jumpHostId = jh.id
      }
    }
    return h
  })
  const all: HostNode[] = [...hosts, ...created.values()]
  // Defence in depth: the same allowlist as a JSON import, risky fields off.
  const { tree: clean } = sanitizeImport(all, false)
  const wrapped: HostNode[] =
    target.kind === 'new-folder'
      ? [{ kind: 'folder', id: `${TEMP}folder`, name: target.name.trim() || 'Imported', children: clean }]
      : clean
  const fresh = reidentify(wrapped, existing)

  // Map temp ids to fresh ones (same shape, same order) and apply the links
  // to existing hosts.
  const renamed = new Map<string, string>()
  const zip = (a: HostNode[], b: HostNode[]) =>
    a.forEach((n, i) => {
      renamed.set(n.id, b[i].id)
      if (isFolder(n)) zip(n.children, (b[i] as HostFolder).children)
    })
  zip(wrapped, fresh)
  const linkTo = new Map<string, string>()
  for (const [t, ex] of external) linkTo.set(renamed.get(t) ?? t, ex)
  const link = (list: HostNode[]): HostNode[] =>
    list.map((n) =>
      isFolder(n)
        ? { ...n, children: link(n.children) }
        : linkTo.has(n.id)
          ? { ...n, jumpHostId: linkTo.get(n.id) }
          : n,
    )
  const linked = link(fresh)

  const catalogue =
    target.kind === 'folder' && allFolders(existing).some((f) => f.id === target.id)
      ? appendToFolder(existing, target.id, linked)
      : [...existing, ...linked]
  return { catalogue, added: all.length, notes }
}
