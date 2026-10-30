import { type HostFolder, type HostNode, isFolder } from '../types'
import type { HostColor } from './hostColors'

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
  const taken = new Set<string>()
  const collect = (list: HostNode[]) => {
    for (const n of list) {
      taken.add(n.id)
      if (isFolder(n)) collect(n.children)
    }
  }
  collect(existing)

  let counter = 0
  const freshId = (prefix: string) => {
    let id: string
    do {
      id = `${prefix}-imp-${Date.now().toString(36)}-${counter++}`
    } while (taken.has(id))
    taken.add(id)
    return id
  }

  const existingIds = new Set(taken)
  /** Imported id -> the id it ends up with (itself when it did not collide). */
  const remap = new Map<string, string>()

  const walk = (list: HostNode[]): HostNode[] =>
    list.map((n) => {
      const id = taken.has(n.id) ? freshId(isFolder(n) ? 'f' : 'h') : (taken.add(n.id), n.id)
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
    return existingIds.has(ref) ? undefined : ref
  }
  const relink = (list: HostNode[]): HostNode[] =>
    list.map((n) =>
      isFolder(n)
        ? { ...n, children: relink(n.children) }
        : { ...n, jumpHostId: fix(n.jumpHostId), credentialId: fix(n.credentialId) },
    )

  return relink(walk(imported))
}
