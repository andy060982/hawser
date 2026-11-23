/** Local-path rules that differ between Windows and POSIX, kept pure (no
 *  Tauri imports) so they are testable. `windows` is whether the LOCAL side is
 *  Windows; remote paths are always POSIX. */

/** The last component of a local path. Windows splits on either separator;
 *  on POSIX a backslash is an ordinary file-name character (`a\b` is one
 *  name), so only `/` separates. */
export function localBaseName(path: string, windows: boolean): string {
  const parts = path.split(windows ? /[\\/]/ : /\//).filter(Boolean)
  return parts.pop() ?? path
}

/** Whether a transfer's file name cannot be used as a single path component
 *  at its destination. `.`/`..` and `/` never can. An upload's name becomes a
 *  remote POSIX component, where `\` and `:` are ordinary characters (a
 *  macOS/Linux file named `a\b` uploads as itself). A download's name becomes
 *  a LOCAL one: `\` is refused everywhere (the backend refuses it too, as the
 *  Windows separator), and `:` (drive letter, alternate data stream) on a
 *  Windows machine. */
export function unsafeTransferName(
  name: string,
  direction: 'upload' | 'download',
  windows: boolean,
): boolean {
  if (name === '' || name === '.' || name === '..' || name.includes('/') || name.includes('\0')) return true
  if (direction === 'upload') return false
  return name.includes('\\') || (windows && name.includes(':'))
}

/** The local pane's starting folder: the system drive's root on Windows (it
 *  is not always C:), `/` elsewhere. The backend's answer is cached once
 *  known (`setLocalRoot`); until then the usual default. */
let localRoot: string | null = null

export function setLocalRoot(root: string | null | undefined): void {
  if (typeof root === 'string' && root !== '') localRoot = root
}

export function defaultLocalRoot(windows: boolean): string {
  return localRoot ?? (windows ? 'C:\\' : '/')
}
