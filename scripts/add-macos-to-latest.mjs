#!/usr/bin/env node
// Add the macOS updater bundle to a published release's latest.json.
//
// Run on the Mac after CI has published the Windows/Linux release for the
// same version, and after building, signing and notarizing the macOS app
// with updater artifacts. See RELEASING.md for the full sequence.
//
//   node scripts/add-macos-to-latest.mjs --arch universal \
//     --bundle src-tauri/target/universal-apple-darwin/release/bundle/macos/Hawser.app.tar.gz
//
// Options:
//   --arch aarch64 | x86_64 | universal   which darwin targets the bundle serves
//   --bundle PATH                         the .app.tar.gz (its .sig must sit beside it)
//   --sig PATH                            the signature, if not PATH.sig
//   --repo OWNER/NAME                     default andy060982/hawser
//   --dry-run                             print the merged latest.json, upload nothing
//
// Repeat with another --arch/--bundle to add a second architecture.
//
// It refuses a bundle whose signature was not made by the key in
// tauri.conf.json (an update the app would reject), and a latest.json for a
// different version. The bundle and .sig are uploaded BEFORE latest.json, so
// the manifest never points at a missing file. Requires the GitHub CLI (gh),
// logged in with write access to the repo.
import { execFileSync } from 'node:child_process'
import { copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { assertSignedBy, downloadUrl, macKeys, mergePlatforms, readPubkey } from './latest-json.mjs'

function args(argv) {
  const out = {}
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (!a.startsWith('--')) continue
    const next = argv[i + 1]
    if (next === undefined || next.startsWith('--')) out[a.slice(2)] = true
    else out[a.slice(2)] = argv[++i]
  }
  return out
}

function gh(argv, opts = {}) {
  return execFileSync('gh', argv, { stdio: ['ignore', 'pipe', 'inherit'], encoding: 'utf8', ...opts })
}

function main() {
  const a = args(process.argv.slice(2))
  const root = resolve(new URL('..', import.meta.url).pathname)
  const repo = String(a.repo ?? 'andy060982/hawser')
  const arch = String(a.arch ?? '')
  const bundle = a.bundle ? resolve(String(a.bundle)) : ''
  if (!bundle) throw new Error('--bundle PATH/Hawser.app.tar.gz is required')
  if (!bundle.endsWith('.app.tar.gz')) throw new Error(`${bundle} is not an .app.tar.gz updater bundle`)
  const sigPath = a.sig ? resolve(String(a.sig)) : `${bundle}.sig`
  if (!existsSync(bundle)) throw new Error(`no bundle at ${bundle}`)
  if (!existsSync(sigPath)) throw new Error(`no signature at ${sigPath} (sign with: npx tauri signer sign -f ~/.tauri/hawser.key "${bundle}")`)
  const keys = macKeys(arch)

  const { pubkey, version } = readPubkey(join(root, 'src-tauri', 'tauri.conf.json'))
  const tag = `v${version}`
  const signature = readFileSync(sigPath, 'utf8').trim()
  assertSignedBy(signature, pubkey, sigPath)

  // Versioned, per-arch asset name, so architectures and releases never clash.
  const asset = `Hawser_${version}_${arch}.app.tar.gz`
  const work = mkdtempSync(join(tmpdir(), 'hawser-latest-'))
  try {
    gh(['release', 'download', tag, '--repo', repo, '--pattern', 'latest.json', '--dir', work, '--clobber'])
    const manifest = JSON.parse(readFileSync(join(work, 'latest.json'), 'utf8'))
    const entry = { signature, url: downloadUrl(repo, tag, asset) }
    const merged = mergePlatforms(manifest, version, Object.fromEntries(keys.map((k) => [k, entry])))
    const text = `${JSON.stringify(merged, null, 2)}\n`

    if (a['dry-run']) {
      console.log(text)
      console.log(`dry run: would upload ${asset}, ${asset}.sig and latest.json to ${repo} ${tag}`)
      return
    }
    const staged = join(work, asset)
    copyFileSync(bundle, staged)
    writeFileSync(`${staged}.sig`, `${signature}\n`)
    gh(['release', 'upload', tag, staged, `${staged}.sig`, '--repo', repo, '--clobber'])
    writeFileSync(join(work, 'latest.json'), text)
    gh(['release', 'upload', tag, join(work, 'latest.json'), '--repo', repo, '--clobber'])
    console.log(`latest.json for ${tag} now serves ${keys.join(', ')} from ${asset}`)
  } finally {
    rmSync(work, { recursive: true, force: true })
  }
}

try {
  main()
} catch (e) {
  console.error(`add-macos-to-latest: ${e instanceof Error ? e.message : e}`)
  process.exit(1)
}
