/* Case-insensitive match ranges in the ORIGINAL string.

   Lowercasing can change length ('İ' becomes 'i' + U+0307) and can depend on
   context (Greek final sigma: 'ΟΣ' -> 'ος', but 'Σ' alone -> 'σ'). Matching on a
   lowercased copy and slicing the original at the same offsets would drift or
   mark nothing, so every lowercased UTF-16 unit records which original
   character it came from. */
export function foldMatches(text: string, query: string): [number, number][] {
  const needle = query.trim().toLowerCase()
  if (!needle) return []

  const perChar: string[] = []
  const srcStart: number[] = []
  const srcLen: number[] = []
  let i = 0
  for (const ch of text) {
    const l = ch.toLowerCase()
    perChar.push(l)
    for (let k = 0; k < l.length; k++) {
      srcStart.push(i)
      srcLen.push(ch.length)
    }
    i += ch.length
  }
  // Whole-string lowercasing applies contextual rules (final sigma). When it
  // has the same length as the per-char form, units line up one-to-one and the
  // contextual string is what the backend matched; otherwise use per-char.
  const whole = text.toLowerCase()
  const lower = whole.length === srcStart.length ? whole : perChar.join('')

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
