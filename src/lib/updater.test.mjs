// Run: npm test. Update logic (src/lib/updater.ts) and the latest.json
// tooling (scripts/latest-json.mjs).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import {
  CHECK_INTERVAL_MS, DownloadTracker, autoCheckDue, bannerModel, canInstall, describeError, formatNotes, parseLastCheck,
  progressPercent, progressText, restartConfirmText, statusLine,
} from './updater.ts'
import {
  assertAssetVersion, assertReleaseSignature, assertSignedBy, buildManifest, carriedPlatforms, desktopPlatforms,
  downloadUrl, macKeys, mergePlatforms, pubkeyId, releaseNotes, signatureKeyId, signedVersion, verifyMinisign,
} from '../../scripts/latest-json.mjs'

// A throwaway minisign keypair made for these tests only (tauri signer
// generate, CLI 2.11.5, no password; the secret half was discarded). Key A
// signed the fixtures below; key B signed nothing.
//   EXE_SIG    EXE bytes, tauri signer sign --app-version 0.7.0
//   APPIMG_SIG APPIMG bytes, --app-version 0.7.0
//   OLD_SIG    EXE bytes, --app-version 0.6.0
//   LEGACY_SIG LEGACY bytes, no --app-version (no version: field)
const A_PUB = 'dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDdFNzUyNTQyQ0MzQzkzOTQKUldTVWt6ek1RaVYxZnVLOVRsZ1Z1SE9aTFR6Qmc1QTBQV3oybkRGTTZqRnhtdlFmak9VNCswUUcK'
const B_PUB = 'dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDU1NDcyMjE2OUNGQkZFMkEKUldRcS92dWNGaUpIVlhEN2hKcENFT0dhemY5NWlyMFo3U1YvcjljWHlGeXZEcmZ1RTlkclRPVXkK'
const EXE = Buffer.from('hawser test bundle\n')
const APPIMG = Buffer.from('hawser test appimage\n')
const LEGACY = Buffer.from('legacy\n')
const EXE_SIG = 'dW50cnVzdGVkIGNvbW1lbnQ6IHNpZ25hdHVyZSBmcm9tIHRhdXJpIHNlY3JldCBrZXkKUlVTVWt6ek1RaVYxZm01cnIySUJhSzAzWXJsbDg5d3hGZEFuSVVXSDFNN1dTUGdPVVV0dXdKdW91QnB2eUk2YnYyNjBSVm5BMzZBQ1JMN2x3S0hwbzAyYUU0Ym85dWNuM3c0PQp0cnVzdGVkIGNvbW1lbnQ6IHRpbWVzdGFtcDoxNzk1NDE5MTY2CWZpbGU6SGF3c2VyXzAuNy4wX3g2NC1zZXR1cC5leGUJdmVyc2lvbjowLjcuMApVK1B0Vk96SFRoTGtUQXcrLzFXcEpYc0drbCt6UVo3VERldE9qQTZhUGV0SU1IaTJ0dzJQSGpoNHJZbmtoNlZmVWw5SDdFaDJyWUw1RVdyVEIwQ1lCQT09Cg=='
const APPIMG_SIG = 'dW50cnVzdGVkIGNvbW1lbnQ6IHNpZ25hdHVyZSBmcm9tIHRhdXJpIHNlY3JldCBrZXkKUlVTVWt6ek1RaVYxZnRMSTdMMDJWQkVieHRrdUUxUGtMcFA3SEE3bHZyOWFENUQwQkt6b2ttWnYxZWpkTjdVSlpXQmYyOHRJaW54M3N5a1FRK3FWQ2IvdVJXVDZXNmdZZUE0PQp0cnVzdGVkIGNvbW1lbnQ6IHRpbWVzdGFtcDoxNzk1NDE5Mjk5CWZpbGU6SGF3c2VyXzAuNy4wX2FtZDY0LkFwcEltYWdlCXZlcnNpb246MC43LjAKVU5ZNlhycjN0bnI1YytSckU5QkprRVI0WmovMjJCVHVKbE9HOTZYVnI5amQ3ekxqc0d3VW80UWluTk9MelZDZXNBKy9obW9XUzdqQUhoSEFsVTdqRHc9PQo='
const OLD_SIG = 'dW50cnVzdGVkIGNvbW1lbnQ6IHNpZ25hdHVyZSBmcm9tIHRhdXJpIHNlY3JldCBrZXkKUlVTVWt6ek1RaVYxZm5KLzZqQ3JYbGNvNmNVUmZpNjZ3MzYxTERlVmJvdjFmbExNdTVoZVJjVmo2cm85WlNKWVFub0lMYm52TFNXYkN2ajZGbE1sdjFHa0h1QWJpZVUyYWdRPQp0cnVzdGVkIGNvbW1lbnQ6IHRpbWVzdGFtcDoxNzk1NDE5MzAwCWZpbGU6SGF3c2VyXzAuNy4wX3g2NC1zZXR1cC5leGUJdmVyc2lvbjowLjYuMApMU0ErdjZ0TFFtYkdIbERTWkFKS25SeDdsTkpRbm0yeXljSGhDeWk5NWQyZVQ5bFdRUXUwWUxEaWFYTmR6Q0tOTEZVZE5QVEZEUWlIL0IvNHdMRzBBdz09Cg=='
const LEGACY_SIG = 'dW50cnVzdGVkIGNvbW1lbnQ6IHNpZ25hdHVyZSBmcm9tIHRhdXJpIHNlY3JldCBrZXkKUlVTVWt6ek1RaVYxZmduQVd1b2JscnVhb3JRRlNoYVJLa2wzQTJVTDErd2VYMWgxS0Z6S2M2eXZhdU5IM3hLa2xPRGFlNTkxVFpyYjRWb21kMnJ6R3o2RGZrZW9BRmx5dnd3PQp0cnVzdGVkIGNvbW1lbnQ6IHRpbWVzdGFtcDoxNzk1NDE5MTY3CWZpbGU6bGVnYWN5LmJpbgpkenlrWXFCWUxMQ1B0T2JyNm5TcWFlVzk1bkFmM1lQSFk0TmxLYU16UHRQT1RoUktHM29xZVlVdnNhVWplZmdEcU1PWlJiVDNiU3ZqSExub3d1UnZEUT09Cg=='
const SIG = EXE_SIG

/** Re-encode a .sig with its trusted comment replaced (signatures untouched). */
function withTrustedComment(sigB64, comment) {
  const lines = Buffer.from(sigB64, 'base64').toString('utf8').split('\n')
  lines[2] = `trusted comment: ${comment}`
  return Buffer.from(lines.join('\n')).toString('base64')
}

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
  const sigs = { 'Hawser_0.7.0_x64-setup.exe': `${EXE_SIG}\n`, 'Hawser_0.7.0_amd64.AppImage': APPIMG_SIG }
  const files = { 'Hawser_0.7.0_x64-setup.exe': EXE, 'Hawser_0.7.0_amd64.AppImage': APPIMG }
  const readAsset = (n) => files[n]
  const base = { sigs, readAsset, repo: 'o/r', tag: 'v0.7.0', version: '0.7.0', pubkey: A_PUB }
  const p = desktopPlatforms(base)
  assert.deepEqual(Object.keys(p).sort(), ['linux-x86_64', 'linux-x86_64-appimage', 'windows-x86_64', 'windows-x86_64-nsis'])
  assert.equal(p['windows-x86_64'].url, 'https://github.com/o/r/releases/download/v0.7.0/Hawser_0.7.0_x64-setup.exe')
  assert.equal(p['linux-x86_64'].url, 'https://github.com/o/r/releases/download/v0.7.0/Hawser_0.7.0_amd64.AppImage')
  assert.equal(p['windows-x86_64'].signature, EXE_SIG, 'the .sig contents, trimmed')
  assert.throws(() => desktopPlatforms({ ...base, sigs: { 'Hawser_0.7.0_x64-setup.exe': EXE_SIG } }), /AppImage/)
  assert.throws(
    () => desktopPlatforms({ ...base, sigs: { ...sigs, 'Hawser_0.6.0_x64-setup.exe': EXE_SIG } }),
    /found 2/,
    'a stale installer is refused, not guessed between',
  )
  assert.throws(() => desktopPlatforms({ ...base, pubkey: B_PUB }), /trusts key/)
  // The .sig of one bundle beside another bundle: right key, wrong bytes.
  assert.throws(
    () => desktopPlatforms({ ...base, readAsset: (n) => (n.endsWith('.AppImage') ? EXE : files[n]) }),
    /Hawser_0\.7\.0_amd64\.AppImage does not match the file/,
  )
  assert.throws(
    () => desktopPlatforms({ ...base, sigs: { ...sigs, 'Hawser_0.7.0_x64-setup.exe': OLD_SIG } }),
    /signed for version 0\.6\.0, not 0\.7\.0/,
  )
  assert.throws(
    () => desktopPlatforms({ ...base, tag: 'v0.7.1', version: '0.7.1' }),
    /does not carry the release version 0\.7\.1/,
    'a bundle named for another version is refused before its signature is read',
  )
  const m = buildManifest({ version: '0.7.0', notes: 'n', pubDate: '2026-12-01T00:00:00Z', platforms: p })
  assert.deepEqual(Object.keys(m), ['version', 'notes', 'pub_date', 'platforms'])
  assert.equal(downloadUrl('o/r', 'v1.0.0', 'a b.exe'), 'https://github.com/o/r/releases/download/v1.0.0/a%20b.exe')
})

test('minisign signatures are verified in full against the file bytes', () => {
  const ok = verifyMinisign(EXE_SIG, A_PUB, EXE)
  assert.equal(ok.version, '0.7.0')
  assert.match(ok.trustedComment, /^timestamp:\d+\tfile:Hawser_0\.7\.0_x64-setup\.exe\tversion:0\.7\.0$/)
  assert.equal(verifyMinisign(LEGACY_SIG, A_PUB, LEGACY).version, null, 'a legacy signature verifies but carries no version')
  assert.throws(() => verifyMinisign(EXE_SIG, A_PUB, Buffer.concat([EXE, Buffer.from('x')])), /does not match the file/)
  assert.throws(() => verifyMinisign(EXE_SIG, A_PUB, APPIMG), /does not match the file/)
  assert.throws(() => verifyMinisign(EXE_SIG, B_PUB, EXE), /trusts key/)
  // Editing the trusted comment (e.g. adding or changing version:) breaks the
  // global signature, with or without the file.
  const forged = withTrustedComment(LEGACY_SIG, 'timestamp:1795419167\tfile:legacy.bin\tversion:9.9.9')
  assert.throws(() => verifyMinisign(forged, A_PUB, LEGACY), /forged or altered trusted comment/)
  const relabelled = withTrustedComment(OLD_SIG, 'timestamp:1795419300\tfile:Hawser_0.7.0_x64-setup.exe\tversion:0.7.0')
  assert.throws(() => verifyMinisign(relabelled, A_PUB), /forged/, 'a 0.6.0 signature relabelled 0.7.0')
  assert.equal(verifyMinisign(EXE_SIG, A_PUB).version, '0.7.0', 'without bytes only the trusted comment is checked')
  assert.throws(() => verifyMinisign('not base64 at all', A_PUB, EXE), /not a minisign signature/)
})

test('a release signature must be bound to the release version', () => {
  const r = { pubkey: A_PUB, what: 'x.sig' }
  assert.doesNotThrow(() => assertReleaseSignature({ ...r, signature: EXE_SIG, data: EXE, version: '0.7.0' }))
  assert.throws(() => assertReleaseSignature({ ...r, signature: LEGACY_SIG, data: LEGACY, version: '0.7.0' }), /not bound to a version .*--app-version 0\.7\.0/)
  assert.throws(() => assertReleaseSignature({ ...r, signature: OLD_SIG, data: EXE, version: '0.7.0' }), /signed for version 0\.6\.0/)
  assert.throws(() => assertReleaseSignature({ ...r, signature: EXE_SIG, data: EXE, version: '0.7.0-rc.1' }), /signed for version 0\.7\.0/)
  assert.equal(signedVersion('timestamp:1\tfile:a\tversion:1.2.3'), '1.2.3')
  assert.equal(signedVersion('timestamp:1\tfile:app-version:2.zip'), null, 'only a whole field counts')
  assert.equal(signedVersion('timestamp:1\tfile:a'), null)
  assert.doesNotThrow(() => assertAssetVersion('Hawser_0.7.0_universal.app.tar.gz', '0.7.0'))
  assert.throws(() => assertAssetVersion('Hawser_0.7.0_universal.app.tar.gz', '0.7.1'), /does not carry/)
  assert.throws(() => assertAssetVersion('Hawser_10.7.0_x64-setup.exe', '0.7.0'), /does not carry/)
})

test('the app requires signed versions and is built with a CLI that writes them', () => {
  const conf = JSON.parse(readFileSync(new URL('../../src-tauri/tauri.conf.json', import.meta.url), 'utf8'))
  assert.equal(conf.plugins.updater.requireSignedVersion, true)
  const lock = JSON.parse(readFileSync(new URL('../../package-lock.json', import.meta.url), 'utf8'))
  const cli = lock.packages['node_modules/@tauri-apps/cli'].version.split('.').map(Number)
  // 2.11.5 is the first CLI that binds signatures to the app version.
  assert.ok(cli[0] > 2 || (cli[0] === 2 && (cli[1] > 11 || (cli[1] === 11 && cli[2] >= 5))), `@tauri-apps/cli ${cli.join('.')} is too old`)
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
  const mac = { signature: APPIMG_SIG, url: 'm' }
  const prev = { version: '0.7.0', platforms: { 'windows-x86_64': { signature: 'old', url: 'w' }, 'darwin-aarch64': mac } }
  assert.deepEqual(carriedPlatforms(prev, '0.7.0', produced, A_PUB), { 'darwin-aarch64': mac })
  assert.deepEqual(carriedPlatforms(prev, '0.7.1', produced, A_PUB), {}, 'older release: nothing carried')
  assert.deepEqual(carriedPlatforms(null, '0.7.0', produced, A_PUB), {})
  const legacy = { ...prev, platforms: { ...prev.platforms, 'darwin-aarch64': { signature: LEGACY_SIG, url: 'm' } } }
  assert.throws(() => carriedPlatforms(legacy, '0.7.0', produced, A_PUB), /existing darwin-aarch64 entry is not bound to a version/)
  assert.throws(() => carriedPlatforms(prev, '0.7.0', produced, B_PUB), /trusts key/)
})

test('download state belongs to the update handle, not the version', () => {
  const t = new DownloadTracker()
  const first = { version: '0.7.0' }
  assert.equal(t.handle, null)
  t.adopt(first)
  assert.equal(t.needsDownload(first), true)
  t.markDownloaded(first)
  assert.equal(t.needsDownload(first), false, 'declining the restart keeps the download')
  t.adopt(first)
  assert.equal(t.needsDownload(first), false, 're-adopting the same handle keeps it')
  // A re-check offers the same version on a new handle (the old one is
  // closed, its bytes gone): install must download again.
  const second = { version: '0.7.0' }
  t.adopt(second)
  assert.equal(t.handle, second)
  assert.equal(t.needsDownload(second), true)
  assert.equal(t.needsDownload(first), true, 'the replaced handle never counts as downloaded')
  t.markDownloaded(first)
  assert.equal(t.needsDownload(second), true, 'a late finish on the old handle does not mark the new one')
  t.markDownloaded(second)
  assert.equal(t.needsDownload(second), false)
  t.adopt(null)
  assert.equal(t.handle, null)
  assert.equal(t.needsDownload(second), true, 'up to date: nothing is downloaded')
})
