#!/usr/bin/env node
// latest.json for tauri-plugin-updater: shared helpers plus the CI entry point.
//
//   node scripts/latest-json.mjs build --tag v0.6.1 --sigdir sigs \
//        --changelog CHANGELOG.md --repo andy060982/hawser --out latest.json
//
// `build` is run by the `manifest` job in .github/workflows/release.yml after
// the Windows and Linux bundles are on the release. It reads the downloaded
// .sig files (each named <asset>.sig) and the assets themselves, verifies
// every signature (minisign, Ed25519) against the exact asset bytes with the
// public key in src-tauri/tauri.conf.json, requires each signature to be bound
// to the release version (the "version:" field of its trusted comment, which
// the app enforces with requireSignedVersion), and writes the manifest.
// scripts/add-macos-to-latest.mjs reuses the helpers for the macOS entries.
// Nothing here reads or prints a private key.
import { createHash, createPublicKey, verify as edVerify } from 'node:crypto'
import { existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'

export const NOTES_MAX = 4000

/** Which uploaded bundle serves which updater target. The plugin looks for
 *  `{os}-{arch}-{installer}` first, then `{os}-{arch}`; both are published so
 *  a copy whose bundle type is unknown (portable exe, .deb) still sees the
 *  release and is offered the download page. */
export const DESKTOP_TARGETS = [
  { suffix: '-setup.exe', keys: ['windows-x86_64-nsis', 'windows-x86_64'] },
  { suffix: '.AppImage', keys: ['linux-x86_64-appimage', 'linux-x86_64'] },
]

export function macKeys(arch) {
  if (arch === 'universal') return ['darwin-aarch64-app', 'darwin-aarch64', 'darwin-x86_64-app', 'darwin-x86_64']
  if (arch === 'aarch64' || arch === 'x86_64') return [`darwin-${arch}-app`, `darwin-${arch}`]
  throw new Error(`unknown macOS arch '${arch}' (aarch64, x86_64 or universal)`)
}

/** The CHANGELOG section for `version` ("## [0.6.1] - ..." up to the next
 *  "## "), capped, with a link to the release. Falls back to the link. */
export function releaseNotes(changelog, version, releaseUrl) {
  const lines = String(changelog ?? '').replace(/\r\n/g, '\n').split('\n')
  const esc = version.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const head = new RegExp(`^##\\s+\\[?v?${esc}\\]?(\\s|$)`)
  const start = lines.findIndex((l) => head.test(l))
  const link = `Full release notes: ${releaseUrl}`
  if (start < 0) return link
  let end = lines.findIndex((l, i) => i > start && /^##\s/.test(l))
  if (end < 0) end = lines.length
  let body = lines.slice(start + 1, end).join('\n').trim()
  if (!body) return link
  if (body.length > NOTES_MAX) {
    const cut = body.slice(0, NOTES_MAX)
    const nl = cut.lastIndexOf('\n')
    body = `${(nl > NOTES_MAX / 2 ? cut.slice(0, nl) : cut).trimEnd()}\n…`
  }
  return `${body}\n\n${link}`
}

export function downloadUrl(repo, tag, asset) {
  return `https://github.com/${repo}/releases/download/${encodeURIComponent(tag)}/${encodeURIComponent(asset)}`
}

/* Minisign, as tauri signer writes it (both files base64-encoded once more):
 *
 *   public key   untrusted comment: ...
 *                base64( "Ed" | key id [8] | Ed25519 public key [32] )
 *   signature    untrusted comment: ...
 *                base64( alg [2] | key id [8] | Ed25519 signature [64] )
 *                trusted comment: <text>
 *                base64( Ed25519 signature of (signature [64] | <text>) )
 *
 * alg "ED" signs the BLAKE2b-512 hash of the file (what tauri signer makes);
 * legacy "Ed" signs the file itself. Both are accepted, as the plugin does. */

function decodeOuter(b64) {
  const text = Buffer.from(String(b64 ?? '').trim(), 'base64').toString('utf8')
  return text.replace(/\r\n/g, '\n').split('\n')
}

/** Parse a minisign public key as tauri.conf.json stores it. */
export function parsePublicKey(pubkeyB64) {
  const lines = decodeOuter(pubkeyB64).map((l) => l.trim())
  const line = lines.find((l) => l && !l.startsWith('untrusted comment:'))
  const raw = Buffer.from(line ?? '', 'base64')
  if (raw.length !== 42 || raw.subarray(0, 2).toString('latin1') !== 'Ed') {
    throw new Error('the updater public key is not a minisign public key')
  }
  const key = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: raw.subarray(10).toString('base64url') }, format: 'jwk' })
  return { keyId: raw.subarray(2, 10).toString('hex'), key }
}

/** Key id (8 bytes, hex) of a minisign public key. */
export function pubkeyId(pubkeyB64) {
  return parsePublicKey(pubkeyB64).keyId
}

/** Parse a Tauri .sig (base64 of a minisign signature file). Throws when it
 *  is not one. Nothing returned is trustworthy until verifyMinisign passes. */
export function parseSignature(sigB64) {
  const lines = decodeOuter(sigB64)
  if (!lines[0]?.startsWith('untrusted comment:') || !lines[2]?.startsWith('trusted comment: ')) {
    throw new Error('not a minisign signature (expected the contents of a .sig file made by tauri signer)')
  }
  const raw = Buffer.from(lines[1].trim(), 'base64')
  if (raw.length !== 74) throw new Error('malformed minisign signature line')
  const alg = raw.subarray(0, 2).toString('latin1')
  if (alg !== 'ED' && alg !== 'Ed') throw new Error(`unsupported minisign signature algorithm '${alg}'`)
  const globalSig = Buffer.from((lines[3] ?? '').trim(), 'base64')
  if (globalSig.length !== 64) throw new Error('malformed minisign global signature')
  return {
    alg,
    keyId: raw.subarray(2, 10).toString('hex'),
    sig: raw.subarray(10),
    trustedComment: lines[2].slice('trusted comment: '.length),
    globalSig,
  }
}

/** Key id of the key that made a Tauri .sig. */
export function signatureKeyId(sigB64) {
  return parseSignature(sigB64).keyId
}

/** Throw unless `sig` names the key behind `pubkey` (a quick, early check;
 *  verifyMinisign is the real one). */
export function assertSignedBy(sig, pubkey, what) {
  const want = pubkeyId(pubkey)
  const got = signatureKeyId(sig)
  if (got !== want) throw new Error(`${what} is signed by key ${got}, but the app trusts key ${want}`)
}

/** The `version:` field of a trusted comment (tab-separated key:value
 *  pairs), as tauri-plugin-updater reads it; null when there is none. */
export function signedVersion(trustedComment) {
  for (const field of String(trustedComment).split('\t')) {
    if (field.startsWith('version:')) return field.slice('version:'.length)
  }
  return null
}

/** Verify a minisign signature with `pubkey`. With `data` (a Buffer of the
 *  exact file bytes) the file signature is checked too; without it only the
 *  global signature, which authenticates the trusted comment. Returns the
 *  now-authenticated trusted comment and signed version. */
export function verifyMinisign(sigB64, pubkeyB64, data, what = 'signature') {
  const pub = parsePublicKey(pubkeyB64)
  const s = parseSignature(sigB64)
  if (s.keyId !== pub.keyId) throw new Error(`${what} is signed by key ${s.keyId}, but the app trusts key ${pub.keyId}`)
  if (data !== undefined) {
    const msg = s.alg === 'ED' ? createHash('blake2b512').update(data).digest() : Buffer.from(data)
    if (!edVerify(null, msg, pub.key, s.sig)) throw new Error(`${what} does not match the file it is published with`)
  }
  const global = Buffer.concat([s.sig, Buffer.from(s.trustedComment, 'utf8')])
  if (!edVerify(null, global, pub.key, s.globalSig)) throw new Error(`${what} has a forged or altered trusted comment`)
  return { trustedComment: s.trustedComment, version: signedVersion(s.trustedComment) }
}

/** Everything the app will check, done before publishing: the signature is
 *  the app key's, matches `data`, and is bound to `version`. */
export function assertReleaseSignature({ signature, pubkey, data, version, what }) {
  const v = verifyMinisign(signature, pubkey, data, what).version
  if (v === null) {
    throw new Error(`${what} is not bound to a version (re-sign with: tauri signer sign --app-version ${version} ...); the app requires signed versions`)
  }
  if (v !== version) throw new Error(`${what} was signed for version ${v}, not ${version}`)
}

/** Refuse an asset whose file name names another version (Hawser_0.6.0_...
 *  on the 0.6.1 release): a second guard against publishing a stale bundle. */
export function assertAssetVersion(asset, version) {
  if (!String(asset).includes(`_${version}_`)) {
    throw new Error(`${asset} does not carry the release version ${version} in its name (expected Hawser_${version}_...)`)
  }
}

/** Platform entries for every signature found: `sigs` maps an asset name to
 *  its .sig contents, `readAsset(name)` returns that asset's bytes. Each
 *  signature is verified against those bytes and must be bound to `version`. */
export function desktopPlatforms({ sigs, readAsset, repo, tag, version, pubkey }) {
  const platforms = {}
  for (const t of DESKTOP_TARGETS) {
    const matches = Object.keys(sigs).filter((n) => n.endsWith(t.suffix))
    if (matches.length !== 1) {
      throw new Error(`expected one signed *${t.suffix} on the release, found ${matches.length} (${matches.join(', ') || 'none'})`)
    }
    const asset = matches[0]
    const signature = sigs[asset].trim()
    assertAssetVersion(asset, version)
    assertReleaseSignature({ signature, pubkey, data: readAsset(asset), version, what: asset })
    for (const k of t.keys) platforms[k] = { signature, url: downloadUrl(repo, tag, asset) }
  }
  return platforms
}

/** Entries from an earlier latest.json for the same version that this build
 *  does not produce (the macOS ones Andy adds by hand), so re-running the CI
 *  job never drops them. A manifest for another version contributes nothing. */
export function carriedPlatforms(existing, version, produced, pubkey) {
  if (!existing || existing.version !== version || typeof existing.platforms !== 'object' || !existing.platforms) return {}
  const kept = Object.entries(existing.platforms).filter(([k]) => !(k in produced))
  // Their bytes were verified when they were added; re-check that each is
  // still the app key's and bound to this version (no download needed: the
  // global signature covers the trusted comment).
  for (const [k, e] of kept) assertReleaseSignature({ signature: e?.signature, pubkey, data: undefined, version, what: `the existing ${k} entry` })
  return Object.fromEntries(kept)
}

export function buildManifest({ version, notes, pubDate, platforms }) {
  return { version, notes, pub_date: pubDate, platforms }
}

/** Add (or replace) platform entries, refusing a manifest for another version. */
export function mergePlatforms(manifest, version, entries) {
  if (!manifest || typeof manifest !== 'object' || !manifest.platforms) throw new Error('latest.json has no platforms object')
  if (manifest.version !== version) {
    throw new Error(`latest.json is for ${manifest.version}, not ${version}: build and publish the matching release first`)
  }
  return { ...manifest, platforms: { ...manifest.platforms, ...entries } }
}

function args(argv) {
  const out = {}
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a.startsWith('--')) {
      const next = argv[i + 1]
      if (next === undefined || next.startsWith('--')) out[a.slice(2)] = true
      else out[a.slice(2)] = argv[++i]
    } else (out._ ??= []).push(a)
  }
  return out
}

export function readPubkey(confPath) {
  const conf = JSON.parse(readFileSync(confPath, 'utf8'))
  const key = conf?.plugins?.updater?.pubkey
  if (!key) throw new Error(`${confPath} has no plugins.updater.pubkey`)
  return { pubkey: key, version: conf.version }
}

function main() {
  const a = args(process.argv.slice(2))
  if (a._?.[0] !== 'build') {
    console.error('usage: latest-json.mjs build --tag vX.Y.Z --sigdir DIR --repo OWNER/NAME [--assetdir DIR] [--changelog CHANGELOG.md] [--conf src-tauri/tauri.conf.json] [--existing old-latest.json] [--out latest.json]')
    process.exit(2)
  }
  const tag = String(a.tag ?? '')
  const repo = String(a.repo ?? '')
  if (!/^v\d/.test(tag) || !/^[\w.-]+\/[\w.-]+$/.test(repo) || !a.sigdir) throw new Error('--tag, --repo and --sigdir are required')
  const version = tag.slice(1)
  const { pubkey, version: confVersion } = readPubkey(String(a.conf ?? 'src-tauri/tauri.conf.json'))
  if (confVersion !== version) throw new Error(`tag ${tag} does not match tauri.conf.json version ${confVersion}`)
  const sigs = {}
  for (const f of readdirSync(String(a.sigdir))) {
    if (f.endsWith('.sig')) sigs[f.slice(0, -4)] = readFileSync(join(String(a.sigdir), f), 'utf8')
  }
  let changelog = ''
  try {
    changelog = readFileSync(String(a.changelog ?? 'CHANGELOG.md'), 'utf8')
  } catch {
    // No changelog: the notes are just the link.
  }
  let existing = null
  if (typeof a.existing === 'string') {
    try {
      existing = JSON.parse(readFileSync(a.existing, 'utf8'))
    } catch {
      // None yet (first run for this release).
    }
  }
  const releaseUrl = `https://github.com/${repo}/releases/tag/${tag}`
  const assetdir = String(a.assetdir ?? a.sigdir)
  const readAsset = (name) => {
    const p = join(assetdir, name)
    if (!existsSync(p)) throw new Error(`${name} was not downloaded to ${assetdir}: its signature cannot be verified`)
    return readFileSync(p)
  }
  const produced = desktopPlatforms({ sigs, readAsset, repo, tag, version, pubkey })
  const manifest = buildManifest({
    version,
    notes: releaseNotes(changelog, version, releaseUrl),
    pubDate: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
    platforms: { ...carriedPlatforms(existing, version, produced, pubkey), ...produced },
  })
  const out = String(a.out ?? 'latest.json')
  writeFileSync(out, `${JSON.stringify(manifest, null, 2)}\n`)
  console.log(`wrote ${out}: ${version}, targets ${Object.keys(manifest.platforms).join(', ')}`)
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try {
    main()
  } catch (e) {
    console.error(`latest-json: ${e instanceof Error ? e.message : e}`)
    process.exit(1)
  }
}
