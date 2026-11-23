# Releasing Hawser

Hawser updates itself through `tauri-plugin-updater`. Each release publishes a
`latest.json` manifest, and installed copies read it from:

    https://github.com/andy060982/hawser/releases/latest/download/latest.json

`releases/latest` never resolves to a pre-release. A hyphenated tag such as
`v0.7.0-beta.1` is published as a pre-release with its own `latest.json`, but no
installed copy is offered it.

Every bundle is signed with the minisign key `~/.tauri/hawser.key`. Its public
half is `plugins.updater.pubkey` in `src-tauri/tauri.conf.json`. The app
installs only bundles whose signature matches that key. **If the private key
or its password is lost, no installed copy can update itself again.** Users
would have to download a build signed with a new key by hand. Keep a backup of
the key file and its password outside this machine.

### Signatures are bound to a version

The app sets `plugins.updater.requireSignedVersion: true`. Each `.sig` must
carry the version it was signed for in its trusted comment
(`timestamp:…\tfile:…\tversion:X.Y.Z`), and that version must equal the
`version` in `latest.json`. The trusted comment is covered by the signature,
so a tampered `latest.json` can't pair "0.9.0" with the URL and signature of
an older genuine bundle. It's rejected before anything is installed.

- `tauri build` writes the version itself, from `@tauri-apps/cli` 2.11.5
  onwards (package.json pins `~2.11.5`, matching the `tauri` 2.11 runtime).
- `tauri signer sign` writes it **only with `--app-version X.Y.Z`**. Without
  the flag it prints a warning, and the app would refuse the bundle.
- Both release scripts check this before publishing (see below). A
  signature without a version, or for another version, stops the release.

0.6.0, the first release with an updater, is the first to be signed with this
key, so there are no older, version-less signatures by this key for anyone to
replay. That stays true only as long as every bundle signed with the key goes
through `tauri build` or `tauri signer sign --app-version`. Never sign anything
else with `~/.tauri/hawser.key`.

## Who handles what

| Platform | Built by | Updater bundle | `latest.json` targets |
|---|---|---|---|
| Windows | CI (`release.yml`) | `Hawser_X.Y.Z_x64-setup.exe` + `.sig` | `windows-x86_64-nsis`, `windows-x86_64` |
| Linux | CI (`release.yml`) | `Hawser_X.Y.Z_amd64.AppImage` + `.sig` | `linux-x86_64-appimage`, `linux-x86_64` |
| macOS | Andy's Mac | `Hawser_X.Y.Z_<arch>.app.tar.gz` + `.sig` | `darwin-aarch64(-app)`, `darwin-x86_64(-app)` |

Tauri 2 (with `createUpdaterArtifacts: true`) signs the NSIS installer and the
AppImage directly. It does not create `.nsis.zip` or `.AppImage.tar.gz`, which
were the Tauri 1 formats. The portable `hawser.exe` and the `.deb` are still
uploaded, but they can't update themselves. In those builds the update banner
offers "Download from GitHub" instead.

## 1. Prepare

1. Bump the version in `package.json`, `src-tauri/Cargo.toml` and
   `src-tauri/tauri.conf.json`. The `check` job refuses a tag that doesn't
   match all three.
2. Date the `## [X.Y.Z]` section in `CHANGELOG.md`. The manifest job copies
   that section into `latest.json`, and the app's update banner shows it.
3. Commit, then tag and push:

   ```sh
   git tag vX.Y.Z && git push origin vX.Y.Z
   ```

## 2. CI (automatic)

`.github/workflows/release.yml` runs three jobs:

1. **check**: the tag matches the version, and the frontend tests pass.
2. **release** (Windows and Linux): builds with `TAURI_SIGNING_PRIVATE_KEY`
   and `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` from the repo secrets. It checks
   that the `.sig` files exist, then uploads the installers, the portable exe,
   the `.deb`, the AppImage and both `.sig` files to the release.
3. **manifest**: downloads the `.sig` files and the updater bundles
   (`*-setup.exe`, `*.AppImage`) from the release, then runs
   `scripts/latest-json.mjs build`. Before writing anything, that script
   verifies each minisign signature (Ed25519, in Node) against the exact
   bytes users will download, with the key in `tauri.conf.json`. It requires
   each signature to be bound to the release version, and each bundle's file
   name to carry that version. The job then uploads `latest.json`. If it is
   re-run, it keeps any macOS entries already merged for the same version,
   after checking that each one is still signed by the app key for this
   version.

When the run finishes, Windows and Linux users are offered the update. macOS
users are not offered anything yet: their check reports that no update has
been published for their platform, and an automatic check stays silent.

## 3. macOS (manual, on the Mac)

Load the signing key into the shell. The variable can hold a path or the key
contents. Don't put the password on the command line or in shell history:

```sh
export TAURI_SIGNING_PRIVATE_KEY=~/.tauri/hawser.key
read -s TAURI_SIGNING_PRIVATE_KEY_PASSWORD && export TAURI_SIGNING_PRIVATE_KEY_PASSWORD
```

Build, codesign and notarize the way you already do. With the key exported,
`tauri build` also writes the updater bundle and its signature:

```sh
npm run tauri build -- --target universal-apple-darwin
# -> src-tauri/target/universal-apple-darwin/release/bundle/macos/Hawser.app.tar.gz
# -> src-tauri/target/universal-apple-darwin/release/bundle/macos/Hawser.app.tar.gz.sig
```

If you notarize and staple `Hawser.app` *after* `tauri build` (rather than
letting the build notarize it through the `APPLE_*` variables), the generated
tarball holds the un-stapled app. In that case, rebuild the tarball and sign it
again:

```sh
V=$(node -p "require('./src-tauri/tauri.conf.json').version")   # from the repo root
cd src-tauri/target/universal-apple-darwin/release/bundle/macos
rm -f Hawser.app.tar.gz Hawser.app.tar.gz.sig
COPYFILE_DISABLE=1 tar -czf Hawser.app.tar.gz Hawser.app
# --app-version is required: the app refuses a signature without it.
npx tauri signer sign --app-version "$V" -f ~/.tauri/hawser.key Hawser.app.tar.gz   # prompts for the password
cd -
```

Merge the macOS entries into the release's `latest.json`. You need the GitHub
CLI (`gh`), logged in with write access. Do a dry run first:

```sh
B=src-tauri/target/universal-apple-darwin/release/bundle/macos/Hawser.app.tar.gz
node scripts/add-macos-to-latest.mjs --arch universal --bundle "$B" --dry-run
node scripts/add-macos-to-latest.mjs --arch universal --bundle "$B"
```

The script:

- reads the version from `tauri.conf.json` and works on release `vX.Y.Z`;
- verifies the `.sig` against the bundle's bytes with the app's key, and
  requires it to be bound to that version. A bundle signed without
  `--app-version` is refused;
- refuses a `latest.json` for any other version;
- uploads `Hawser_X.Y.Z_universal.app.tar.gz` and its `.sig` **first**, then
  the merged `latest.json` with `gh release upload --clobber`, so the manifest
  never points at a file that isn't there yet.

For separate per-architecture builds, run it once per bundle, with
`--arch aarch64` and `--arch x86_64`.

Clean up the shell afterwards:

```sh
unset TAURI_SIGNING_PRIVATE_KEY TAURI_SIGNING_PRIVATE_KEY_PASSWORD
```

## 4. Verify

```sh
curl -sL https://github.com/andy060982/hawser/releases/latest/download/latest.json \
  | node -e 'const m=JSON.parse(require("fs").readFileSync(0));console.log(m.version,Object.keys(m.platforms))'
```

Then, in an installed copy of the previous version, open Settings → Updates →
Check for updates. The banner should offer the new version.

## Local builds

Because `createUpdaterArtifacts` is on, `npm run tauri build` fails at the
signing step unless `TAURI_SIGNING_PRIVATE_KEY` is set. For an unsigned local
build, use one of these:

```sh
npm run tauri build -- --no-bundle
npm run tauri build -- -c '{"bundle":{"createUpdaterArtifacts":false}}'
```
