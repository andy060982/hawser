// Run: npm test  (node --experimental-strip-types --test)
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ReplyGuard } from './replyGuard.ts'
import { foldMatches } from './foldMatch.ts'

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
