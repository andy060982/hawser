// Run: npm test. Update logic (src/lib/updater.ts) and the latest.json
// tooling (scripts/latest-json.mjs).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  CHECK_INTERVAL_MS, autoCheckDue, bannerModel, canInstall, describeError, formatNotes, parseLastCheck,
  progressPercent, progressText, restartConfirmText, statusLine,
} from './updater.ts'
import {
  assertSignedBy, buildManifest, carriedPlatforms, desktopPlatforms, downloadUrl, macKeys, mergePlatforms, pubkeyId,
  releaseNotes, signatureKeyId,
} from '../../scripts/latest-json.mjs'

// A throwaway minisign keypair made for these tests only (tauri signer
// generate); key A signed SIG, key B signed nothing.
const A_PUB = 'dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IEM1OUUyOTI5RkZFMkQzQzcKUldUSDArTC9LU21leGJnZkFSbnlHcmZXdiszWXBDWFU2QS96WGMxWDdyU2lSa2lONVN6cDhRZ3AK'
const B_PUB = 'dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDU1NDcyMjE2OUNGQkZFMkEKUldRcS92dWNGaUpIVlhEN2hKcENFT0dhemY5NWlyMFo3U1YvcjljWHlGeXZEcmZ1RTlkclRPVXkK'
const SIG = 'dW50cnVzdGVkIGNvbW1lbnQ6IHNpZ25hdHVyZSBmcm9tIHRhdXJpIHNlY3JldCBrZXkKUlVUSDArTC9LU21leGZzQUNubVI1VmpkODVTWlllSEtHZUkrRU1IMmZzeStrU2dOMnEwVnc3amZ0TVhSMTZiQXpvRmErUXZobWlQTmJMb1R4aURvTldya1VTQy9zWSszTHdrPQp0cnVzdGVkIGNvbW1lbnQ6IHRpbWVzdGFtcDoxNzk1NDE4MTgwCWZpbGU6Zi5iaW4KZ0FTRFlnMVc3WEdwZU5RMHVqSDZyckxmYlFGeTh0ZzhOVnZudWpycm5TMWtQQ3U2VFVvTlNJK1p6U3RiM2xieFdEUkp4d2l2aWx6Njk0VnBtWkdJQnc9PQo='

const info = { version: '0.7.0', currentVersion: '0.6.0', notes: 'Fixes.' }
const SELF = { kind: 'self', reason: 'app bundle' }
const MANUAL = { kind: 'manual', reason: 'portable copy (not installed with the Windows installer)' }

test('automatic checks run at most once a day, and only when enabled', () => {
  const now = 1_800_000_000_000
  assert.equal(autoCheckDue(true, null, now), true, 'never checked')
  assert.equal(autoCheckDue(false, null, now), false, 'setting off')
  assert.equal(autoCheckDue(true, now - 1000, now), false, 'checked a second ago')
  assert.equal(autoCheckDue(true, now - CHECK_INTERVAL_MS + 1, now), false, 'just under 24 h')
  assert.equal(autoCheckDue(true, now - CHECK_INTERVAL_MS, now), true, '24 h')
  assert.equal(autoCheckDue(true, now + 60_000, now), true, 'clock moved back: check')
  assert.equal(autoCheckDue(true, Number.NaN, now), true)
  assert.equal(parseLastCheck(null), null)
  assert.equal(parseLastCheck('garbage'), null)
  assert.equal(parseLastCheck('-5'), null)
  assert.equal(parseLastCheck(String(now)), now)
})

test('a self-updating copy is offered install, a manual one the download page', () => {
  const self = bannerModel({ phase: 'available', info, install: SELF, dismissed: false })
  assert.equal(self.title, 'Hawser 0.7.0 is available')
  assert.deepEqual(self.actions, ['install', 'later'])
  assert.equal(self.notes, 'Fixes.')
  const manual = bannerModel({ phase: 'available', info, install: MANUAL, dismissed: false })
  assert.deepEqual(manual.actions, ['download', 'later'])
  assert.match(manual.detail, /can't update itself \(portable copy/)
  assert.equal(canInstall({ phase: 'available', info, install: SELF, dismissed: false }), true)
  assert.equal(canInstall({ phase: 'available', info, install: MANUAL, dismissed: false }), false)
  assert.equal(canInstall({ phase: 'downloading', info, install: SELF, received: 0, total: null }), false, 'one download at a time')
  assert.equal(canInstall({ phase: 'idle' }), false)
})

test('the banner hides on Later and stays silent for quiet automatic checks', () => {
  assert.equal(bannerModel({ phase: 'available', info, install: SELF, dismissed: true }), null)
  assert.equal(bannerModel({ phase: 'idle' }), null)
  assert.equal(bannerModel({ phase: 'checking', manual: true }), null)
  assert.equal(bannerModel({ phase: 'current', manual: false, checkedAt: 1 }), null)
  assert.equal(bannerModel({ phase: 'current', manual: true, checkedAt: 1 }).title, 'Hawser is up to date.')
  assert.equal(bannerModel({ phase: 'error', manual: false, message: 'x' }), null, 'auto-check failures are silent')
  const manualErr = bannerModel({ phase: 'error', manual: true, message: 'offline' })
  assert.deepEqual(manualErr.actions, ['retry', 'dismiss'])
  assert.equal(manualErr.tone, 'error')
  const failedInstall = bannerModel({ phase: 'error', manual: true, message: 'bad sig', info, install: SELF })
  assert.deepEqual(failedInstall.actions, ['download', 'retry', 'later'])
  assert.match(failedInstall.title, /0\.7\.0 could not be installed/)
})

test('download progress and the install step show no buttons', () => {
  const d = bannerModel({ phase: 'downloading', info, install: SELF, received: 5 * 1048576, total: 20 * 1048576 })
  assert.equal(d.progress, 25)
  assert.equal(d.busy, true)
  assert.deepEqual(d.actions, [])
  assert.equal(d.detail, 'Downloading… 25% (5.0 MB of 20.0 MB)')
  assert.equal(progressPercent(10, null), null)
  assert.equal(progressPercent(10, 0), null)
  assert.equal(progressPercent(30, 20), 100)
  assert.equal(progressText(1048576, null), 'Downloading… 1.0 MB')
  assert.deepEqual(bannerModel({ phase: 'installing', info, install: SELF }).actions, [])
})

test('errors read clearly, and a bad signature says it was not installed', () => {
  assert.match(describeError(new Error('Signature verification failed'), 'download'), /signature check, so it was not installed/)
  assert.match(describeError('minisign_verify error', 'install'), /not installed/)
  assert.match(
    describeError('None of the fallback platforms `["darwin-aarch64-app","darwin-aarch64"]` were found in the response `platforms` object', 'check'),
    /No update has been published for this platform yet/,
  )
  assert.match(describeError('the platform `linux-x86_64` was not found in the response `platforms` object', 'check'), /this platform/)
  assert.match(describeError('Could not fetch a valid release JSON from the remote', 'check'), /could not be read from GitHub/)
  assert.match(describeError('error sending request for url', 'check'), /Could not reach GitHub/)
  assert.match(describeError('Access is denied. (os error 5)', 'install'), /permission denied/)
  assert.equal(describeError('weird', 'install'), 'Installing the update failed: weird')
  assert.equal(describeError(undefined, 'check'), 'Checking for updates failed.')
})

test('restart asks only while sessions are live, in the close-guard wording', () => {
  assert.equal(restartConfirmText(0, '0.7.0'), null)
  assert.equal(restartConfirmText(1, '0.7.0'), '1 session is still connected. Restarting to install Hawser 0.7.0 closes it.')
  assert.equal(restartConfirmText(3, '0.7.0'), '3 sessions are still connected. Restarting to install Hawser 0.7.0 closes all of them.')
})

test('release notes are trimmed and capped', () => {
  assert.equal(formatNotes('  hi\r\nthere  '), 'hi\nthere')
  assert.equal(formatNotes(undefined), '')
  const long = Array.from({ length: 100 }, (_, i) => `- line ${i} with some words`).join('\n')
  const f = formatNotes(long, 300)
  assert.ok(f.length < 360)
  assert.match(f, /Full notes on the releases page\.$/)
  assert.ok(!f.includes('line 99'))
})

test('Settings shows a status line for every state', () => {
  const now = 1_800_000_000_000
  assert.equal(statusLine({ phase: 'idle' }, null, now), 'Not checked yet.')
  assert.equal(statusLine({ phase: 'idle' }, now - 5 * 60000, now), 'Last checked 5 min ago.')
  assert.equal(statusLine({ phase: 'idle' }, now - 3 * 3600000, now), 'Last checked 3 h ago.')
  assert.equal(statusLine({ phase: 'idle' }, now - 72 * 3600000, now), 'Last checked 3 days ago.')
  assert.equal(statusLine({ phase: 'checking', manual: true }, null, now), 'Checking…')
  assert.equal(statusLine({ phase: 'available', info, install: SELF, dismissed: true }, now, now), 'Hawser 0.7.0 is available.')
  assert.equal(statusLine({ phase: 'error', manual: true, message: 'offline' }, now, now), 'offline')
})

/* ---------------------------------------------------------- latest.json */

const CHANGELOG = `# Changelog

## [0.7.0] - 2026-12-01

### Added

- Self-update.

## [0.6.0] - 2026-11-01

- Old.
`

test('release notes come from the CHANGELOG section, with a link', () => {
  const url = 'https://github.com/o/r/releases/tag/v0.7.0'
  assert.equal(releaseNotes(CHANGELOG, '0.7.0', url), `### Added\n\n- Self-update.\n\nFull release notes: ${url}`)
  assert.equal(releaseNotes(CHANGELOG, '0.6.0', url), `- Old.\n\nFull release notes: ${url}`)
  assert.equal(releaseNotes(CHANGELOG, '0.8.0', url), `Full release notes: ${url}`, 'no section: just the link')
  assert.equal(releaseNotes(CHANGELOG, '0.7', url), `Full release notes: ${url}`, '0.7 is not 0.7.0')
  const big = `## [1.0.0]\n${'x'.repeat(9000)}`
  assert.ok(releaseNotes(big, '1.0.0', url).length < 4200)
})

test('signatures are checked against the app key before they are published', () => {
  assert.equal(pubkeyId(A_PUB), signatureKeyId(SIG))
  assert.notEqual(pubkeyId(B_PUB), signatureKeyId(SIG))
  assert.doesNotThrow(() => assertSignedBy(SIG, A_PUB, 'x'))
  assert.throws(() => assertSignedBy(SIG, B_PUB, 'Hawser.app.tar.gz.sig'), /signed by key .* but the app trusts key/)
  assert.throws(() => signatureKeyId(Buffer.from('hello').toString('base64')), /not a minisign signature/)
  assert.throws(() => pubkeyId(Buffer.from('nope').toString('base64')), /not a minisign public key/)
})

test('the CI manifest maps the NSIS installer and the AppImage to their targets', () => {
  const sigs = { 'Hawser_0.7.0_x64-setup.exe': `${SIG}\n`, 'Hawser_0.7.0_amd64.AppImage': SIG }
  const p = desktopPlatforms({ sigs, repo: 'o/r', tag: 'v0.7.0', pubkey: A_PUB })
  assert.deepEqual(Object.keys(p).sort(), ['linux-x86_64', 'linux-x86_64-appimage', 'windows-x86_64', 'windows-x86_64-nsis'])
  assert.equal(p['windows-x86_64'].url, 'https://github.com/o/r/releases/download/v0.7.0/Hawser_0.7.0_x64-setup.exe')
  assert.equal(p['linux-x86_64'].url, 'https://github.com/o/r/releases/download/v0.7.0/Hawser_0.7.0_amd64.AppImage')
  assert.equal(p['windows-x86_64'].signature, SIG, 'the .sig contents, trimmed')
  assert.throws(() => desktopPlatforms({ sigs: { 'Hawser_0.7.0_x64-setup.exe': SIG }, repo: 'o/r', tag: 'v0.7.0', pubkey: A_PUB }), /AppImage/)
  assert.throws(
    () => desktopPlatforms({ sigs: { ...sigs, 'Hawser_0.6.0_x64-setup.exe': SIG }, repo: 'o/r', tag: 'v0.7.0', pubkey: A_PUB }),
    /found 2/,
    'a stale installer is refused, not guessed between',
  )
  assert.throws(() => desktopPlatforms({ sigs, repo: 'o/r', tag: 'v0.7.0', pubkey: B_PUB }), /trusts key/)
  const m = buildManifest({ version: '0.7.0', notes: 'n', pubDate: '2026-12-01T00:00:00Z', platforms: p })
  assert.deepEqual(Object.keys(m), ['version', 'notes', 'pub_date', 'platforms'])
  assert.equal(downloadUrl('o/r', 'v1.0.0', 'a b.exe'), 'https://github.com/o/r/releases/download/v1.0.0/a%20b.exe')
})

test('the macOS merge adds darwin targets and refuses another version', () => {
  const m = { version: '0.7.0', notes: 'n', pub_date: 'd', platforms: { 'windows-x86_64': { signature: 's', url: 'u' } } }
  const e = { signature: SIG, url: 'mac' }
  const merged = mergePlatforms(m, '0.7.0', Object.fromEntries(macKeys('universal').map((k) => [k, e])))
  assert.deepEqual(Object.keys(merged.platforms).sort(), ['darwin-aarch64', 'darwin-aarch64-app', 'darwin-x86_64', 'darwin-x86_64-app', 'windows-x86_64'])
  assert.equal(m.platforms['darwin-aarch64'], undefined, 'input not mutated')
  assert.deepEqual(macKeys('aarch64'), ['darwin-aarch64-app', 'darwin-aarch64'])
  assert.throws(() => macKeys('arm64'), /unknown macOS arch/)
  assert.throws(() => mergePlatforms(m, '0.7.1', {}), /latest\.json is for 0\.7\.0, not 0\.7\.1/)
  assert.throws(() => mergePlatforms({ version: '0.7.0' }, '0.7.0', {}), /no platforms/)
})

test('a CI re-run keeps the macOS entries of the same version only', () => {
  const produced = { 'windows-x86_64': { signature: 'new', url: 'w' } }
  const prev = { version: '0.7.0', platforms: { 'windows-x86_64': { signature: 'old', url: 'w' }, 'darwin-aarch64': { signature: 'm', url: 'm' } } }
  assert.deepEqual(carriedPlatforms(prev, '0.7.0', produced), { 'darwin-aarch64': { signature: 'm', url: 'm' } })
  assert.deepEqual(carriedPlatforms(prev, '0.7.1', produced), {}, 'older release: nothing carried')
  assert.deepEqual(carriedPlatforms(null, '0.7.0', produced), {})
})
