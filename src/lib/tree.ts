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

/** A host's effective colour: its own if set, else the nearest ancestor
 *  folder's. Returns undefined when neither the host (nor a coloured ancestor)
 *  is found. Used for the wrong-window frame and the AI-off default. */
export function effectiveHostColor(nodes: HostNode[], hostId: string): HostColor | undefined {
  const SEARCHING = Symbol('searching')
  const walk = (
    list: HostNode[],
    inherited: HostColor | undefined,
  ): HostColor | undefined | typeof SEARCHING => {
    for (const n of list) {
      if (isFolder(n)) {
        const res = walk(n.children, n.color ?? inherited)
        if (res !== SEARCHING) return res
      } else if (n.id === hostId) {
        return n.color ?? inherited
      }
    }
    return SEARCHING
  }
  const r = walk(nodes, undefined)
  return r === SEARCHING ? undefined : r
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
  /** Imported id -> the id it ends up with (itself when it did not collide). */
  const remap = new Map<string, string>()

  const walk = (list: HostNode[]): HostNode[] =>
    list.map((n) => {
      const id =
        taken.has(key(n.id)) || !usableImportedId(n.id)
          ? freshId(isFolder(n) ? 'f' : 'h')
          : (taken.add(key(n.id)), n.id)
      if (!remap.has(n.id)) remap.set(n.id, id)
      return isFolder(n)
        ? { ...n, id, children: walk(n.children) }
        : { ...n, id }
    })

  // Cross-references (bastion, shared credential) must follow the renames: a
  // host whose jump host was re-id'd would otherwise keep the OLD id and bind
  // to whatever LOCAL host owns it — tunnelling through the wrong bastion. A
  // reference that points outside the import at an id this machine already
  // uses is dropped rather than bound to an unrelated local host.
  const fix = (ref: string | undefined): string | undefined => {
    if (ref === undefined) return undefined
    if (remap.has(ref)) return remap.get(ref)
    return existingIds.has(key(ref)) || !usableImportedId(ref) ? undefined : ref
  }
  const relink = (list: HostNode[]): HostNode[] =>
    list.map((n) =>
      isFolder(n)
        ? { ...n, children: relink(n.children) }
        : { ...n, jumpHostId: fix(n.jumpHostId), credentialId: fix(n.credentialId) },
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
