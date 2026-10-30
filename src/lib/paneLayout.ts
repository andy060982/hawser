/* ---------------------------------------------------------------------------
   Pane layout tree.

   A tab (session "group") is no longer a flat row or column of panes with one
   shared orientation — it is a binary split tree, so a tab can hold arbitrary
   mixed layouts: two panes side by side on top, one full-width below, and so
   on (the tmux / iTerm2 model).

   A node is either a LEAF (one session) or a SPLIT of exactly two children in
   a direction ('row' = side by side, 'col' = stacked) at a ratio (the fraction
   of space the first child gets).

   The tree carries only geometry. It never owns the xterm instances: the deck
   renders one always-mounted TerminalPane per session and merely positions the
   leaves' rectangles, so restructuring the tree never remounts a terminal and
   scrollback survives every split, close, and resize.
--------------------------------------------------------------------------- */

export type SplitDir = 'row' | 'col'

export interface LeafNode {
  t: 'leaf'
  /** The session id this pane shows. */
  id: string
}

export interface SplitNode {
  t: 'split'
  /** Stable id so a divider drag and a React key address the same split across
   *  renders. Regenerating this per render would make resizing jump. */
  id: string
  dir: SplitDir
  /** Fraction of the split's extent given to child `a` (0..1). */
  ratio: number
  a: LayoutNode
  b: LayoutNode
}

export type LayoutNode = LeafNode | SplitNode

/** Smallest fraction a pane may shrink to on either side of a divider. A pane
 *  that can collapse to zero is a pane you cannot get back. */
const MIN_RATIO = 0.1

function newSplitId(): string {
  try {
    return crypto.randomUUID()
  } catch {
    return `sp-${Math.random().toString(36).slice(2)}-${Date.now().toString(36)}`
  }
}

export function leaf(id: string): LeafNode {
  return { t: 'leaf', id }
}

function split(dir: SplitDir, a: LayoutNode, b: LayoutNode, ratio = 0.5): SplitNode {
  return { t: 'split', id: newSplitId(), dir, ratio, a, b }
}

/** All session ids in the tree, left-to-right / top-to-bottom order. */
export function collectLeafIds(node: LayoutNode | null): string[] {
  if (!node) return []
  if (node.t === 'leaf') return [node.id]
  return [...collectLeafIds(node.a), ...collectLeafIds(node.b)]
}

/** Replace the leaf `targetId` with a split of [target, new] in `dir`. Returns
 *  the same node reference when the target is not present, so callers can cheaply
 *  detect a no-op. */
export function splitLeaf(
  node: LayoutNode,
  targetId: string,
  newId: string,
  dir: SplitDir,
): LayoutNode {
  if (node.t === 'leaf') {
    return node.id === targetId ? split(dir, leaf(targetId), leaf(newId)) : node
  }
  const a = splitLeaf(node.a, targetId, newId, dir)
  const b = a === node.a ? splitLeaf(node.b, targetId, newId, dir) : node.b
  if (a === node.a && b === node.b) return node
  return { ...node, a, b }
}

/** Append a new leaf by splitting the whole tree; `null` seeds the first leaf. */
export function appendLeaf(
  node: LayoutNode | null,
  newId: string,
  dir: SplitDir = 'row',
): LayoutNode {
  if (!node) return leaf(newId)
  return split(dir, node, leaf(newId))
}

/** Remove a leaf and collapse its parent split onto the surviving sibling.
 *  Returns null when the tree becomes empty. */
export function removeLeaf(node: LayoutNode, id: string): LayoutNode | null {
  if (node.t === 'leaf') return node.id === id ? null : node
  const a = removeLeaf(node.a, id)
  if (a === null) return node.b
  const b = removeLeaf(node.b, id)
  if (b === null) return a
  if (a === node.a && b === node.b) return node
  return { ...node, a, b }
}

/** Set a split's ratio by its id, clamped so neither side collapses. */
export function setRatio(node: LayoutNode, splitId: string, ratio: number): LayoutNode {
  if (node.t === 'leaf') return node
  if (node.id === splitId) {
    const clamped = Math.min(1 - MIN_RATIO, Math.max(MIN_RATIO, ratio))
    return clamped === node.ratio ? node : { ...node, ratio: clamped }
  }
  const a = setRatio(node.a, splitId, ratio)
  const b = a === node.a ? setRatio(node.b, splitId, ratio) : node.b
  if (a === node.a && b === node.b) return node
  return { ...node, a, b }
}

/** Current ratio of a split by id, or null if not found. */
export function findRatio(node: LayoutNode, splitId: string): number | null {
  if (node.t === 'leaf') return null
  if (node.id === splitId) return node.ratio
  return findRatio(node.a, splitId) ?? findRatio(node.b, splitId)
}

/** Bring a tree into agreement with the group's actual session ids: drop leaves
 *  whose session is gone (closed / separated), append any session with no leaf
 *  yet (restore, generic split). Returns the SAME reference when nothing changed
 *  so an effect can bail without re-setting state and looping.
 *
 *  `ids` is the group's sessions in creation order. */
export function reconcile(node: LayoutNode | null | undefined, ids: string[]): LayoutNode | null {
  const want = new Set(ids)
  const have = new Set(collectLeafIds(node ?? null))

  const extra = [...have].filter((id) => !want.has(id))
  const missing = ids.filter((id) => !have.has(id))
  if (extra.length === 0 && missing.length === 0) return node ?? null

  let next: LayoutNode | null = node ?? null
  for (const id of extra) {
    if (next) next = removeLeaf(next, id)
  }
  for (const id of missing) {
    next = appendLeaf(next, id, 'row')
  }
  return next
}

export interface Rect {
  /** All in 0..1 fractions of the deck box. */
  left: number
  top: number
  width: number
  height: number
}

/** Map every leaf session id to its rectangle within `rect` (fractions). */
export function computeRects(
  node: LayoutNode,
  rect: Rect = { left: 0, top: 0, width: 1, height: 1 },
  out: Map<string, Rect> = new Map(),
): Map<string, Rect> {
  if (node.t === 'leaf') {
    out.set(node.id, rect)
    return out
  }
  if (node.dir === 'row') {
    const w = rect.width * node.ratio
    computeRects(node.a, { ...rect, width: w }, out)
    computeRects(node.b, { left: rect.left + w, top: rect.top, width: rect.width - w, height: rect.height }, out)
  } else {
    const h = rect.height * node.ratio
    computeRects(node.a, { ...rect, height: h }, out)
    computeRects(node.b, { left: rect.left, top: rect.top + h, width: rect.width, height: rect.height - h }, out)
  }
  return out
}

export interface Divider {
  splitId: string
  /** Axis the divider MOVES on: 'x' for a side-by-side split, 'y' for stacked. */
  axis: 'x' | 'y'
  /** Position of the divider line and its extent, all 0..1 fractions. For an
   *  'x' divider: a vertical line at `pos` spanning [start, start+length] of y.
   *  For 'y': a horizontal line at `pos` spanning [start, start+length] of x. */
  pos: number
  start: number
  length: number
  /** The split's own extent along `axis` (fraction of the deck), so a pixel drag
   *  can be converted back to a ratio delta: dRatio = dPx / (extent * boxPx). */
  extent: number
}

/** Every split boundary as a draggable divider, positioned in deck fractions. */
export function collectDividers(
  node: LayoutNode,
  rect: Rect = { left: 0, top: 0, width: 1, height: 1 },
  out: Divider[] = [],
): Divider[] {
  if (node.t === 'leaf') return out
  if (node.dir === 'row') {
    const boundary = rect.left + rect.width * node.ratio
    out.push({ splitId: node.id, axis: 'x', pos: boundary, start: rect.top, length: rect.height, extent: rect.width })
    const w = rect.width * node.ratio
    collectDividers(node.a, { ...rect, width: w }, out)
    collectDividers(node.b, { left: rect.left + w, top: rect.top, width: rect.width - w, height: rect.height }, out)
  } else {
    const boundary = rect.top + rect.height * node.ratio
    out.push({ splitId: node.id, axis: 'y', pos: boundary, start: rect.left, length: rect.width, extent: rect.height })
    const h = rect.height * node.ratio
    collectDividers(node.a, { ...rect, height: h }, out)
    collectDividers(node.b, { left: rect.left, top: rect.top + h, width: rect.width, height: rect.height - h }, out)
  }
  return out
}
