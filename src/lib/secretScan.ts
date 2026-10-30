/** Heuristic secret detection for the AI pre-send guard.
 *
 *  The assistant's context includes on-connect commands and the transcript
 *  tail — either can contain a password the user typed. Before that context
 *  leaves the machine for a provider, scan it and, on a hit, make the user
 *  confirm. This is a *warning*, not a filter: it cannot catch everything and
 *  must not pretend to, so it errs toward flagging obvious credential shapes
 *  and lets the user decide.
 *
 *  Patterns are deliberately tight — a scanner that cries wolf on every line
 *  gets click-through fatigue and protects nobody. Each returns a short reason
 *  so the dialog can show WHAT tripped, never the secret value itself.
 */
export interface SecretHit {
  reason: string
  /** The line it matched on, with the sensitive tail masked for display. */
  preview: string
}

const RULES: { re: RegExp; reason: string }[] = [
  { re: /\bsshpass\b/i, reason: 'sshpass (password on the command line)' },
  { re: /(pass(word|wd)?|secret|token|api[_-]?key)\s*[:=]\s*\S/i, reason: 'password/secret/token assignment' },
  { re: /--?password[= ]\S/i, reason: 'password flag with a value' },
  { re: /\benable\s+secret\b/i, reason: 'Cisco "enable secret"' },
  { re: /\bpassword\s+[0-7]\s+\S/i, reason: 'Cisco type-N password' },
  { re: /-----BEGIN[A-Z ]*PRIVATE KEY-----/, reason: 'embedded private key' },
  { re: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/, reason: 'AWS access key id' },
  { re: /\bxox[baprs]-[0-9A-Za-z-]{10,}/, reason: 'Slack token' },
  { re: /\bgh[pousr]_[0-9A-Za-z]{20,}/, reason: 'GitHub token' },
]

const MASK = '•'.repeat(6)

/** Keep only the first 3 chars of the first token (the command/label, for
 *  context) and replace every later token with a fixed-width mask. Masking by
 *  position rather than token length matters: a length threshold let short
 *  secrets (`Password: hunter`, `sshpass -p s3cret`) through in clear text.
 *  Bare short flags like `-p` carry no secret and stay visible for context. */
function maskLine(line: string): string {
  const tokens = line.trim().slice(0, 120).split(/\s+/)
  return tokens
    .map((tok, i) => {
      if (i === 0) return tok.length > 3 ? tok.slice(0, 3) + MASK : tok
      return /^--?[A-Za-z]{1,2}$/.test(tok) ? tok : MASK
    })
    .join(' ')
}

/** Scan text; return one hit per matching line (deduped by reason+line). */
export function scanForSecrets(text: string): SecretHit[] {
  const hits: SecretHit[] = []
  const seen = new Set<string>()
  for (const line of text.split('\n')) {
    for (const rule of RULES) {
      if (rule.re.test(line)) {
        const key = rule.reason + '|' + line
        if (!seen.has(key)) {
          seen.add(key)
          hits.push({ reason: rule.reason, preview: maskLine(line) })
        }
        break // one reason per line is enough
      }
    }
  }
  return hits
}
