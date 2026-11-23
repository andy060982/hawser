/* Case-insensitive match ranges in the ORIGINAL string.

   The fold must stay identical to the backend search's `fold_char`
   (src-tauri/src/utils/session_log.rs), so what it highlights is what matched:
   - per-character lowercase, with no context;
   - final sigma ς folded to σ ('ΠΑΝΕΠΙΣ' finds 'ΠΑΝΕΠΙΣΤΗΜΙΟ', 'οδοσ' finds 'οδος');
   - the combining dot U+0307 after an 'i' dropped ('İstanbul' lowercases to
     'i̇stanbul', and must match 'istanbul');
   - the common full case folds in FULL_FOLDS expanded ('Straße' finds
     'STRASSE', the 'ﬁ' ligature finds 'fi'). The same table is in Rust.
   Limits, shared with the backend: no Unicode normalisation, no other full
   folds, and per-character lowercase follows each runtime's Unicode tables,
   which can differ for characters added in very recent Unicode versions.
   Folding can change length, so every folded UTF-16 unit records which
   original character it came from. */

/** Full case folds beyond lowercase, applied to each lowercased character.
 *  Must match `FULL_FOLDS` in session_log.rs exactly. */
const FULL_FOLDS: Record<string, string> = {
  'ß': 'ss',
  'ﬀ': 'ff',
  'ﬁ': 'fi',
  'ﬂ': 'fl',
  'ﬃ': 'ffi',
  'ﬄ': 'ffl',
  'ﬅ': 'st',
  'ﬆ': 'st',
  'ŉ': 'ʼn',
}

function foldChar(ch: string, state: { prevI: boolean }, out: string[]): number {
  let n = 0
  for (const l of ch.toLowerCase()) {
    if (l === '\u0307' && state.prevI) {
      state.prevI = false
      continue
    }
    const f = l === 'ς' ? 'σ' : (FULL_FOLDS[l] ?? l)
    for (const u of f) {
      out.push(u)
      n += u.length
    }
    state.prevI = f.endsWith('i')
  }
  return n
}

/** `text` folded the same way the backend search folds it. */
export function fold(text: string): string {
  const out: string[] = []
  const state = { prevI: false }
  for (const ch of text) foldChar(ch, state, out)
  return out.join('')
}

export function foldMatches(text: string, query: string): [number, number][] {
  const needle = fold(query.trim())
  if (!needle) return []

  const parts: string[] = []
  const srcStart: number[] = []
  const srcLen: number[] = []
  const state = { prevI: false }
  let i = 0
  for (const ch of text) {
    const units = foldChar(ch, state, parts)
    for (let k = 0; k < units; k++) {
      srcStart.push(i)
      srcLen.push(ch.length)
    }
    i += ch.length
  }
  const lower = parts.join('')

  const out: [number, number][] = []
  let shown = 0
  for (let at = lower.indexOf(needle); at !== -1; at = lower.indexOf(needle, at + needle.length)) {
    const last = at + needle.length - 1
    const start = srcStart[at]
    // Exclusive end = just past the original character holding the last unit.
    const end = srcStart[last] + srcLen[last]
    if (start >= shown) {
      out.push([start, end])
      shown = end
    }
  }
  return out
}
