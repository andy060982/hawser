#!/usr/bin/env node
// latest.json for tauri-plugin-updater: shared helpers plus the CI entry point.
//
//   node scripts/latest-json.mjs build --tag v0.6.1 --sigdir sigs \
//        --changelog CHANGELOG.md --repo andy060982/hawser --out latest.json
//
// `build` is run by the `manifest` job in .github/workflows/release.yml after
// the Windows and Linux bundles are on the release. It reads the downloaded
// .sig files (each named <asset>.sig), checks every signature was made by the
// key whose public half is in src-tauri/tauri.conf.json, and writes the
// manifest. scripts/add-macos-to-latest.mjs reuses the helpers for the macOS
// entries. Nothing here reads or prints a private key.
import { readFileSync, readdirSync, writeFileSync } from 'node:fs'
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

/** Key id (8 bytes, hex) of a minisign public key as tauri.conf.json stores it
 *  (base64 of the .pub file). */
export function pubkeyId(pubkeyB64) {
  const text = Buffer.from(pubkeyB64.trim(), 'base64').toString('utf8')
  const line = text.split('\n').map((l) => l.trim()).find((l) => l && !l.startsWith('untrusted comment:'))
  const raw = Buffer.from(line ?? '', 'base64')
  if (raw.length !== 42) throw new Error('the updater public key is not a minisign public key')
  return raw.subarray(2, 10).toString('hex')
}

/** Key id of the key that made a Tauri .sig (base64 of a minisign signature
 *  file). Throws when it is not one. */
export function signatureKeyId(sigB64) {
  const text = Buffer.from(String(sigB64).trim(), 'base64').toString('utf8')
  const lines = text.split('\n').map((l) => l.trim())
  if (!lines[0]?.startsWith('untrusted comment:') || !lines.some((l) => l.startsWith('trusted comment:'))) {
    throw new Error('not a minisign signature (expected the contents of a .sig file made by tauri signer)')
  }
  const raw = Buffer.from(lines[1] ?? '', 'base64')
  if (raw.length !== 74) throw new Error('malformed minisign signature line')
  return raw.subarray(2, 10).toString('hex')
}

/** Throw unless `sig` was made by the key behind `pubkey`. */
export function assertSignedBy(sig, pubkey, what) {
  const want = pubkeyId(pubkey)
  const got = signatureKeyId(sig)
  if (got !== want) throw new Error(`${what} is signed by key ${got}, but the app trusts key ${want}`)
}

/** Platform entries for every signature found: `sigs` maps an asset name to
 *  its .sig contents. */
export function desktopPlatforms({ sigs, repo, tag, pubkey }) {
  const platforms = {}
  for (const t of DESKTOP_TARGETS) {
    const matches = Object.keys(sigs).filter((n) => n.endsWith(t.suffix))
    if (matches.length !== 1) {
      throw new Error(`expected one signed *${t.suffix} on the release, found ${matches.length} (${matches.join(', ') || 'none'})`)
    }
    const asset = matches[0]
    const signature = sigs[asset].trim()
    assertSignedBy(signature, pubkey, asset)
    for (const k of t.keys) platforms[k] = { signature, url: downloadUrl(repo, tag, asset) }
  }
  return platforms
}

/** Entries from an earlier latest.json for the same version that this build
 *  does not produce (the macOS ones Andy adds by hand), so re-running the CI
 *  job never drops them. A manifest for another version contributes nothing. */
export function carriedPlatforms(existing, version, produced) {
  if (!existing || existing.version !== version || typeof existing.platforms !== 'object' || !existing.platforms) return {}
  return Object.fromEntries(Object.entries(existing.platforms).filter(([k]) => !(k in produced)))
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
    console.error('usage: latest-json.mjs build --tag vX.Y.Z --sigdir DIR --repo OWNER/NAME [--changelog CHANGELOG.md] [--conf src-tauri/tauri.conf.json] [--existing old-latest.json] [--out latest.json]')
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
  const produced = desktopPlatforms({ sigs, repo, tag, pubkey })
  const manifest = buildManifest({
    version,
    notes: releaseNotes(changelog, version, releaseUrl),
    pubDate: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
    platforms: { ...carriedPlatforms(existing, version, produced), ...produced },
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
