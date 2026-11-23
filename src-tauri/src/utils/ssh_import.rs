//! Import hosts from an OpenSSH client config (`~/.ssh/config`) and from PuTTY
//! saved sessions (Windows registry).
//!
//! Both scanners produce the same [`ImportReport`]: a list of candidate hosts
//! plus the warnings and skipped items the preview dialog shows. Nothing here
//! writes anything: the frontend turns the checked rows into catalogue nodes
//! and saves them through the normal `hosts_save` path. No secret is read or
//! created: OpenSSH configs hold none, and PuTTY's saved sessions are read
//! value by value from an allowlist that holds none either.
//!
//! The OpenSSH side follows `ssh_config(5)` semantics where they matter for an
//! address book: case-insensitive keywords, `Key value` and `Key=value`,
//! quoting, `Include` (globs, relative to `~/.ssh`, 16 levels, cycles
//! detected), `Match` blocks skipped, and first-obtained-value-wins across
//! every block that applies to a name — including a `Host *` block further
//! down, which only fills in what nothing earlier set.

use serde::Serialize;
use std::collections::{BTreeMap, HashSet};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

/// One config file larger than this is refused: a real ssh config is a few KiB.
pub const MAX_FILE_BYTES: u64 = 1024 * 1024;
/// All files of one scan together (the Include tree).
pub const MAX_TOTAL_BYTES: u64 = 8 * 1024 * 1024;
/// Files read in one scan, so a wide Include glob cannot fan out unbounded.
pub const MAX_FILES: usize = 256;
/// Include nesting, as OpenSSH's READCONF_MAX_DEPTH.
pub const MAX_INCLUDE_DEPTH: usize = 16;
/// Candidate hosts in one report.
pub const MAX_HOSTS: usize = 2000;
/// Settings lines kept from one scan. Evaluation is aliases x directives, so
/// both are bounded; a real config has a few hundred lines.
pub const MAX_DIRECTIVES: usize = 20_000;
/// Entries of the "unsupported keys" / skipped lists kept for the summary.
const MAX_LIST: usize = 200;

/* ------------------------------------------------------------------ report */

/// Where a host's ProxyJump points.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum JumpRef {
    /// Another concrete alias of the same import, used as written.
    Alias { alias: String },
    /// An address. `user` is None when nothing (neither the hop nor the
    /// config) named one. `key_path` is the IdentityFile the config gives
    /// that hop name (as ssh would use it to log in to the jump host).
    Literal {
        host: String,
        port: u16,
        user: Option<String>,
        #[serde(rename = "keyPath")]
        key_path: Option<String>,
    },
}

/// One candidate host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScannedHost {
    /// The alias (ssh config) or decoded session name (PuTTY).
    pub name: String,
    pub hostname: String,
    pub port: u16,
    pub user: Option<String>,
    pub key_path: Option<String>,
    pub jump: Option<JumpRef>,
    /// Jump hosts ssh would really go through (0 for a direct route). Only
    /// a single hop maps onto Hawser; anything else sets `unsupported_route`.
    pub jump_hops: usize,
    /// Set when the configured route cannot be reproduced (more than one
    /// hop, or a hop that itself needs ProxyCommand). `jump` then holds the
    /// first hop only, and the preview leaves the host unchecked.
    pub unsupported_route: Option<String>,
    pub warnings: Vec<String>,
    /// `file:line` of the Host line, or `PuTTY session`.
    pub origin: String,
}

#[derive(Debug, Default, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportReport {
    /// `ssh-config` or `putty`.
    pub source: String,
    pub hosts: Vec<ScannedHost>,
    /// Problems not tied to one host (a file refused, a bad line).
    pub warnings: Vec<String>,
    /// Things deliberately not imported (Match blocks, wildcard patterns,
    /// non-SSH PuTTY sessions).
    pub skipped: Vec<String>,
    /// Keywords present in the config that the import does not map.
    pub unsupported_keys: Vec<String>,
    pub files_read: Vec<String>,
    /// The local account name, which OpenSSH uses when no User is set.
    pub local_user: String,
}

fn push_capped(list: &mut Vec<String>, item: String) {
    if list.len() < MAX_LIST {
        list.push(item);
    } else if list.len() == MAX_LIST {
        list.push("…more not shown".to_string());
    }
}

/* ------------------------------------------------------------ line parsing */

/// Split one config line into its lowercased keyword and arguments, or None
/// for a blank or comment line. `Key value`, `Key=value` and `Key = value`
/// are all accepted, as OpenSSH does.
pub fn split_line(raw: &str) -> Result<Option<(String, Vec<String>)>, String> {
    let line = raw.trim();
    if line.is_empty() || line.starts_with('#') {
        return Ok(None);
    }
    let end = line
        .find(|c: char| c.is_whitespace() || c == '=')
        .unwrap_or(line.len());
    let key = line[..end].to_ascii_lowercase();
    if key.is_empty() {
        return Err("line has no keyword".to_string());
    }
    let mut rest = line[end..].trim_start();
    if let Some(r) = rest.strip_prefix('=') {
        rest = r.trim_start();
    }
    Ok(Some((key, split_args(rest)?)))
}

/// OpenSSH's argv_split with comment termination: whitespace-separated words,
/// single or double quotes group a word (and are removed), a backslash escapes
/// a quote, a backslash or (outside quotes) a space, and a word starting with
/// an unquoted `#` ends the line.
pub fn split_args(s: &str) -> Result<Vec<String>, String> {
    let chars: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    loop {
        while i < chars.len() && chars[i].is_whitespace() {
            i += 1;
        }
        if i >= chars.len() || chars[i] == '#' {
            break;
        }
        let mut arg = String::new();
        let mut quote: Option<char> = None;
        while i < chars.len() {
            let c = chars[i];
            if quote.is_none() && c.is_whitespace() {
                break;
            }
            if c == '\\' && i + 1 < chars.len() {
                let n = chars[i + 1];
                if n == '\'' || n == '"' || n == '\\' || (quote.is_none() && n == ' ') {
                    arg.push(n);
                    i += 2;
                    continue;
                }
            }
            match quote {
                Some(q) if c == q => quote = None,
                Some(_) => arg.push(c),
                None if c == '\'' || c == '"' => quote = Some(c),
                None => arg.push(c),
            }
            i += 1;
        }
        if quote.is_some() {
            return Err("unterminated quote".to_string());
        }
        out.push(arg);
    }
    Ok(out)
}

/* ---------------------------------------------------------------- patterns */

/// `*` and `?` glob, ASCII case-insensitive when asked.
pub fn glob_match(pattern: &str, text: &str, fold: bool) -> bool {
    let norm = |s: &str| -> Vec<char> {
        if fold {
            s.chars().map(|c| c.to_ascii_lowercase()).collect()
        } else {
            s.chars().collect()
        }
    };
    let (p, t) = (norm(pattern), norm(text));
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ti));
            pi += 1;
        } else if let Some((sp, st)) = star {
            pi = sp + 1;
            ti = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// A `Host` line's pattern list against a name: no negated pattern may match,
/// and at least one positive pattern must.
pub fn host_patterns_match(patterns: &[String], name: &str) -> bool {
    let mut positive = false;
    for p in patterns {
        if let Some(neg) = p.strip_prefix('!') {
            if glob_match(neg, name, true) {
                return false;
            }
        } else if glob_match(p, name, true) {
            positive = true;
        }
    }
    positive
}

/// A pattern that names exactly one host: no wildcard, no negation.
pub fn is_concrete_alias(p: &str) -> bool {
    !p.is_empty() && !p.contains(['*', '?', '!'])
}

/// A hostname or user value fit for the catalogue: non-empty, bounded, no
/// whitespace or control characters.
fn plain_value(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && !s.chars().any(|c| c.is_whitespace() || c.is_control())
}

/* ----------------------------------------------------------------- reading */

#[derive(Debug, Clone)]
enum Cond {
    Always,
    Host(Vec<String>),
    /// Never evaluated: Match criteria depend on the connection.
    Match,
}

#[derive(Debug, Clone)]
struct Directive {
    cond: usize,
    key: String,
    args: Vec<String>,
    origin: String,
}

struct Reader {
    home: PathBuf,
    canon_home: Option<PathBuf>,
    stack: Vec<FileKey>,
    dir_entries_left: usize,
    files: usize,
    total: u64,
    conds: Vec<Cond>,
    directives: Vec<Directive>,
    aliases: Vec<(String, String)>,
    alias_seen: HashSet<String>,
    patterns_skipped: Vec<String>,
    match_blocks: usize,
    unsupported: BTreeMap<String, String>,
    report: ImportReport,
}

const MAPPED_KEYS: &[&str] = &["hostname", "user", "port", "identityfile", "proxyjump", "proxycommand"];

impl Reader {
    fn new(home: &Path) -> Self {
        Reader {
            home: home.to_path_buf(),
            canon_home: std::fs::canonicalize(home).ok(),
            stack: Vec::new(),
            dir_entries_left: MAX_DIR_ENTRIES,
            files: 0,
            total: 0,
            conds: vec![Cond::Always],
            directives: Vec::new(),
            aliases: Vec::new(),
            alias_seen: HashSet::new(),
            patterns_skipped: Vec::new(),
            match_blocks: 0,
            unsupported: BTreeMap::new(),
            report: ImportReport { source: "ssh-config".into(), ..Default::default() },
        }
    }

    fn warn(&mut self, w: String) {
        push_capped(&mut self.report.warnings, w);
    }

    /// Read the file the user chose (allowed anywhere; symlinks followed).
    /// Its errors are returned.
    fn read_top(&mut self, path: &Path) -> Result<(), String> {
        let shown = path.display().to_string();
        // No metadata() before the open: the opened handle is what is checked
        // (a FIFO cannot block the open, see open_top).
        let file = open_top(path).map_err(|e| format!("{shown}: {e}"))?;
        let key = match file_key_top(&file, path) {
            Ok(k) => k,
            Err(e) => return Err(format!("{shown}: {e}")),
        };
        self.read_opened(file, key, &shown, 0, 0).map_err(|e| format!("{shown}: {e}"))
    }

    /// Read one included file, already resolved by `include_paths` to a real
    /// path inside the canonical home with no symlink in it. It is opened
    /// without following links and must be the very file that was
    /// validated. Errors become warnings.
    #[allow(clippy::clone_on_copy)] // the key is a PathBuf off Unix
    fn read_included(&mut self, inc: &Resolved, cond: usize, depth: usize) {
        let shown = inc.path.display().to_string();
        if depth > MAX_INCLUDE_DEPTH {
            return self.warn(format!("{shown}: Include nested more than {MAX_INCLUDE_DEPTH} levels deep, not read"));
        }
        if self.files >= MAX_FILES {
            return self.warn(format!("{shown}: more than {MAX_FILES} config files, not read"));
        }
        let Some(home) = self.canon_home.clone() else {
            return self.warn(format!("{shown}: your home folder could not be resolved, Include not followed"));
        };
        let file = match open_included(inc, &home) {
            Ok(f) => f,
            Err(e) => return self.warn(format!("{shown}: {e}")),
        };
        if let Err(e) = self.read_opened(file, inc.key.clone(), &shown, cond, depth) {
            self.warn(format!("{shown}: {e}"));
        }
    }

    /// Read and parse an opened file. The handle's own metadata (fstat) is
    /// what decides regular-file and size, never a separate path lookup.
    fn read_opened(&mut self, file: std::fs::File, key: FileKey, shown: &str, cond: usize, depth: usize) -> Result<(), String> {
        let meta = file.metadata().map_err(|e| e.to_string())?;
        // Only regular files: a FIFO or a device (/dev/zero) would block or
        // never end.
        if !meta.is_file() {
            return Err("not a regular file, not read".to_string());
        }
        if meta.len() > MAX_FILE_BYTES {
            return Err(format!("larger than {} KiB, not read", MAX_FILE_BYTES / 1024));
        }
        if self.stack.contains(&key) {
            return Err("Include cycle, not read again".to_string());
        }
        if self.files >= MAX_FILES {
            return Err(format!("more than {MAX_FILES} config files, not read"));
        }
        let mut buf = Vec::new();
        file.take(MAX_FILE_BYTES + 1).read_to_end(&mut buf).map_err(|e| e.to_string())?;
        if buf.len() as u64 > MAX_FILE_BYTES {
            return Err(format!("larger than {} KiB, not read", MAX_FILE_BYTES / 1024));
        }
        if self.total + buf.len() as u64 > MAX_TOTAL_BYTES {
            return Err(format!("config files exceed {} MiB together, not read", MAX_TOTAL_BYTES / 1024 / 1024));
        }
        if buf.contains(&0) {
            return Err("looks like a binary file, not read".to_string());
        }
        self.files += 1;
        self.total += buf.len() as u64;
        let text = match String::from_utf8(buf) {
            Ok(t) => t,
            Err(e) => {
                self.warn(format!("{shown}: not valid UTF-8; unreadable characters replaced"));
                String::from_utf8_lossy(e.as_bytes()).into_owned()
            }
        };
        self.report.files_read.push(shown.to_string());
        self.stack.push(key);
        self.parse_text(&text, shown, cond, depth);
        self.stack.pop();
        Ok(())
    }

    fn push_cond(&mut self, c: Cond) -> usize {
        self.conds.push(c);
        self.conds.len() - 1
    }

    fn parse_text(&mut self, text: &str, label: &str, start: usize, depth: usize) {
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        let mut cond = start;
        for (i, raw) in text.lines().enumerate() {
            let origin = format!("{label}:{}", i + 1);
            let (key, args) = match split_line(raw) {
                Ok(Some(kv)) => kv,
                Ok(None) => continue,
                Err(e) => {
                    self.warn(format!("{origin}: {e}, line ignored"));
                    continue;
                }
            };
            match key.as_str() {
                "host" => {
                    if args.is_empty() {
                        self.warn(format!("{origin}: Host without a pattern"));
                    }
                    for a in &args {
                        if is_concrete_alias(a) {
                            let k = a.to_ascii_lowercase();
                            if self.alias_seen.insert(k) {
                                self.aliases.push((a.clone(), origin.clone()));
                            }
                        } else if self.patterns_skipped.len() < 50 && !self.patterns_skipped.contains(a) {
                            self.patterns_skipped.push(a.clone());
                        }
                    }
                    cond = self.push_cond(Cond::Host(args));
                }
                "match" => {
                    self.match_blocks += 1;
                    push_capped(&mut self.report.skipped, format!("Match block at {origin} (conditions are evaluated per connection)"));
                    cond = self.push_cond(Cond::Match);
                }
                "include" => {
                    if matches!(self.conds[cond], Cond::Match) {
                        push_capped(&mut self.report.skipped, format!("Include inside a Match block at {origin}, not followed"));
                        continue;
                    }
                    if args.is_empty() {
                        self.warn(format!("{origin}: Include without a file"));
                    }
                    for pat in args {
                        let paths = match self.include_paths(&pat) {
                            Ok(p) => p,
                            Err(why) => {
                                self.warn(format!("{origin}: Include {pat}: {why}, not followed"));
                                continue;
                            }
                        };
                        if paths.is_empty() {
                            push_capped(&mut self.report.skipped, format!("Include {pat} at {origin} matched no files"));
                        }
                        for p in &paths {
                            self.read_included(p, cond, depth + 1);
                        }
                    }
                    // `cond` is this file's own: an included file's Host lines
                    // end with it, as in OpenSSH.
                }
                _ => {
                    if !MAPPED_KEYS.contains(&key.as_str()) {
                        let written = raw.trim().split(|c: char| c.is_whitespace() || c == '=').next().unwrap_or("").to_string();
                        self.unsupported.entry(key.clone()).or_insert(written);
                    }
                    if self.directives.len() < MAX_DIRECTIVES {
                        self.directives.push(Directive { cond, key, args, origin });
                    } else if self.directives.len() == MAX_DIRECTIVES {
                        self.warn(format!("more than {MAX_DIRECTIVES} settings; the rest were ignored"));
                        self.directives.push(Directive { cond: 0, key: String::new(), args: Vec::new(), origin });
                    }
                }
            }
        }
    }

    /// The files one Include argument names: `~` expanded, relative paths
    /// resolved against `~/.ssh`, `*`/`?` globbed, sorted per directory (as
    /// glob(3)).
    ///
    /// Containment comes first and is lexical: the argument must name a
    /// place under the home folder (no network path, no other drive, no
    /// `..` above home) before anything on disk is touched. The glob is then
    /// walked one directory at a time from the canonical home; each
    /// component is looked at with symlink_metadata, and a symlink is
    /// followed only when its target (read, not followed) is itself inside
    /// home. Matches are capped while the directories are being read.
    fn include_paths(&mut self, pat: &str) -> Result<Vec<Resolved>, String> {
        let canon = self.canon_home.clone().ok_or("your home folder could not be resolved")?;
        let comps = include_components(pat, &self.home, &canon)?;
        let cap = MAX_FILES.saturating_sub(self.files);
        let mut w = Walker { home: &canon, entries_left: self.dir_entries_left, hops_left: MAX_SYMLINK_HOPS, notes: Vec::new() };
        let found = w.glob(&comps, cap);
        self.dir_entries_left = w.entries_left;
        let notes = std::mem::take(&mut w.notes);
        for n in notes {
            self.warn(format!("Include {pat}: {n}"));
        }
        Ok(found)
    }
}

/// How many symlinks one Include may pass through, as the kernel's limit.
const MAX_SYMLINK_HOPS: usize = 32;
/// Directory entries examined by all Include globs of one scan together, so
/// a glob over a huge directory stays bounded even when little matches.
pub const MAX_DIR_ENTRIES: usize = 20_000;

/// What identifies a file for Include cycle detection.
#[cfg(unix)]
type FileKey = (u64, u64);
#[cfg(not(unix))]
type FileKey = PathBuf;

/// An Include target after validation: its real path (inside the canonical
/// home, no symlink component) and the identity it had then.
#[derive(Debug, Clone)]
pub struct Resolved {
    pub path: PathBuf,
    key: FileKey,
}

/// One component of an Include path below the home folder.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Comp {
    Name(std::ffi::OsString),
    Parent,
}

/// Whether a path is a network or device path (`\\server\share`,
/// `//server/share`, `\\?\UNC\...`, `\\.\pipe\...`). Lexical only. A local
/// verbatim drive path (`\\?\C:\...`, what canonicalize returns on Windows)
/// is not.
fn is_network_path(s: &str) -> bool {
    let b = s.replace('/', "\\");
    let Some(rest) = b.strip_prefix("\\\\") else { return false };
    let r = rest.as_bytes();
    let verbatim_drive = cfg!(windows) && r.len() >= 4 && r[0] == b'?' && r[1] == b'\\' && r[2].is_ascii_alphabetic() && r[3] == b':';
    !verbatim_drive
}

/// Path components compare: ASCII case-folded on Windows (its paths are
/// case-insensitive), exact elsewhere.
fn same_component(a: Component<'_>, b: Component<'_>) -> bool {
    if cfg!(windows) {
        a.as_os_str().to_string_lossy().eq_ignore_ascii_case(&b.as_os_str().to_string_lossy())
    } else {
        a == b
    }
}

/// `full` below `base`, as Include components, or None when `full` is not
/// under `base` or (below it) holds anything but names, `.` and `..`.
fn below(full: &Path, base: &Path) -> Option<Vec<Comp>> {
    let mut f = full.components();
    for b in base.components() {
        if !same_component(f.next()?, b) {
            return None;
        }
    }
    let mut out = Vec::new();
    for c in f {
        match c {
            Component::Normal(n) => out.push(Comp::Name(n.to_os_string())),
            Component::CurDir => {}
            Component::ParentDir => out.push(Comp::Parent),
            Component::Prefix(_) | Component::RootDir => return None,
        }
    }
    Some(out)
}

/// The components of an Include argument below the home folder. Purely
/// lexical: no filesystem access. Err when the argument names a network
/// path, `~user`, or anything outside home.
fn include_components(pat: &str, home: &Path, canon_home: &Path) -> Result<Vec<Comp>, String> {
    if is_network_path(pat) {
        return Err("network paths are not followed".to_string());
    }
    let expanded = if pat == "~" {
        home.to_path_buf()
    } else if let Some(r) = pat.strip_prefix("~/").or_else(|| pat.strip_prefix("~\\")) {
        home.join(r)
    } else if pat.starts_with('~') {
        return Err("~user is not expanded".to_string());
    } else {
        PathBuf::from(pat)
    };
    // join() replaces the base when `expanded` has a root or a prefix (an
    // absolute path, or on Windows `\\x` / `D:x`): the result is checked as a
    // whole below.
    let full = if expanded.is_absolute() { expanded } else { home.join(".ssh").join(expanded) };
    if is_network_path(&full.to_string_lossy()) {
        return Err("network paths are not followed".to_string());
    }
    let comps = below(&full, canon_home)
        .or_else(|| below(&full, home))
        .ok_or("outside your home folder")?;
    // `..` may not climb above home (checked again on the real path while
    // walking, where symlink targets can add `..` too).
    let mut depth: isize = 0;
    for c in &comps {
        match c {
            Comp::Name(_) => depth += 1,
            Comp::Parent => {
                depth -= 1;
                if depth < 0 {
                    return Err("outside your home folder".to_string());
                }
            }
        }
    }
    if depth == 0 {
        return Err("names your home folder itself, not a file".to_string());
    }
    Ok(comps)
}

/// The Include glob walk. Every path it holds is real (no symlink in it)
/// and inside `home`.
struct Walker<'a> {
    home: &'a Path,
    entries_left: usize,
    hops_left: usize,
    notes: Vec<String>,
}

impl Walker<'_> {
    fn note(&mut self, n: String) {
        if self.notes.len() < 20 && !self.notes.contains(&n) {
            self.notes.push(n);
        }
    }

    /// `pos` with one `..` applied, or None (noted) when that leaves home.
    fn up(&mut self, pos: &Path) -> Option<PathBuf> {
        if pos == self.home || !pos.starts_with(self.home) {
            self.note("outside your home folder, not followed".to_string());
            return None;
        }
        pos.parent().map(Path::to_path_buf)
    }

    /// Step from the real directory `pos` into `name`, resolving a symlink
    /// there. Returns the real path, or None when there is nothing there or
    /// it leads out of home.
    fn step(&mut self, pos: &Path, name: &std::ffi::OsStr) -> Option<PathBuf> {
        let cand = pos.join(name);
        let meta = std::fs::symlink_metadata(&cand).ok()?;
        if !meta.file_type().is_symlink() {
            return Some(cand);
        }
        if self.hops_left == 0 {
            self.note("too many levels of symbolic links, not followed".to_string());
            return None;
        }
        self.hops_left -= 1;
        // The link's text is read, not followed: its target is checked
        // lexically before anything there is touched.
        let target = std::fs::read_link(&cand).ok()?;
        let ts = target.to_string_lossy();
        if is_network_path(&ts) {
            self.note(format!("{} points at a network path, not followed", cand.display()));
            return None;
        }
        let (start, comps) = if target.has_root() || target.components().any(|c| matches!(c, Component::Prefix(_))) {
            match below(&target, self.home) {
                Some(c) => (self.home.to_path_buf(), c),
                None => {
                    self.note(format!("{} points outside your home folder, not followed", cand.display()));
                    return None;
                }
            }
        } else {
            let mut c = Vec::new();
            for comp in target.components() {
                match comp {
                    Component::Normal(n) => c.push(Comp::Name(n.to_os_string())),
                    Component::ParentDir => c.push(Comp::Parent),
                    Component::CurDir => {}
                    Component::Prefix(_) | Component::RootDir => return None,
                }
            }
            (pos.to_path_buf(), c)
        };
        self.literal(start, &comps)
    }

    /// Resolve components taken literally (a symlink target: no globbing).
    fn literal(&mut self, mut pos: PathBuf, comps: &[Comp]) -> Option<PathBuf> {
        for c in comps {
            pos = match c {
                Comp::Parent => self.up(&pos)?,
                Comp::Name(n) => self.step(&pos, n)?,
            };
        }
        Some(pos)
    }

    /// Expand the Include components from home, with `*`/`?` in any name.
    /// At most `cap` results; the cap also bounds every intermediate level
    /// and is applied while each directory is read.
    fn glob(&mut self, comps: &[Comp], cap: usize) -> Vec<Resolved> {
        let mut current: Vec<PathBuf> = vec![self.home.to_path_buf()];
        let mut capped = false;
        for c in comps {
            let mut next = Vec::new();
            match c {
                Comp::Parent => {
                    for p in &current {
                        if let Some(u) = self.up(p) {
                            next.push(u);
                        }
                    }
                }
                Comp::Name(n) => {
                    let part = n.to_string_lossy().into_owned();
                    if !part.contains(['*', '?']) {
                        for p in &current {
                            if let Some(r) = self.step(p, n) {
                                next.push(r);
                            }
                        }
                    } else {
                        'dirs: for dir in &current {
                            if next.len() >= cap {
                                capped = true;
                                break;
                            }
                            let Ok(rd) = std::fs::read_dir(dir) else { continue };
                            let mut names: Vec<std::ffi::OsString> = Vec::new();
                            for e in rd {
                                if self.entries_left == 0 {
                                    self.note(format!("more than {MAX_DIR_ENTRIES} directory entries examined; the rest were not"));
                                    break;
                                }
                                self.entries_left -= 1;
                                let Ok(e) = e else { continue };
                                let fname = e.file_name();
                                let shown = fname.to_string_lossy();
                                if (!shown.starts_with('.') || part.starts_with('.')) && glob_match(&part, &shown, false) {
                                    if next.len() + names.len() >= cap {
                                        capped = true;
                                        break;
                                    }
                                    names.push(fname);
                                }
                            }
                            names.sort();
                            for name in names {
                                if let Some(r) = self.step(dir, &name) {
                                    next.push(r);
                                }
                                if next.len() >= cap {
                                    capped = true;
                                    break 'dirs;
                                }
                            }
                        }
                    }
                }
            }
            current = next;
            if current.is_empty() {
                break;
            }
        }
        if capped {
            self.note(format!("matched more than {cap} files; the rest were not read"));
        }
        let mut out = Vec::new();
        for p in current {
            // Final identity, taken without following a link (the path is
            // real, so this is the file itself).
            let Ok(m) = std::fs::symlink_metadata(&p) else { continue };
            if m.file_type().is_symlink() {
                continue;
            }
            #[cfg(unix)]
            let key = {
                use std::os::unix::fs::MetadataExt;
                (m.dev(), m.ino())
            };
            #[cfg(not(unix))]
            let key = p.clone();
            out.push(Resolved { path: p, key });
        }
        out
    }
}

/// Open the file the user chose. Symlinks are followed (it is their pick);
/// on Unix O_NONBLOCK keeps a FIFO from blocking the open (the handle is
/// then refused as not a regular file).
fn open_top(path: &Path) -> std::io::Result<std::fs::File> {
    let mut o = std::fs::OpenOptions::new();
    o.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY);
    }
    o.open(path)
}

fn file_key_top(file: &std::fs::File, path: &Path) -> std::io::Result<FileKey> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let _ = path;
        let m = file.metadata()?;
        Ok((m.dev(), m.ino()))
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        std::fs::canonicalize(path)
    }
}

/// Open a validated Include target without following any symlink, and
/// check (fstat) that the handle is the regular file that was validated.
fn open_included(inc: &Resolved, home: &Path) -> Result<std::fs::File, String> {
    let file = open_no_follow(&inc.path).map_err(|e| e.to_string())?;
    let meta = file.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file() {
        return Err("not a regular file, not read".to_string());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let _ = home;
        if (meta.dev(), meta.ino()) != inc.key {
            return Err("changed while it was being read, not read".to_string());
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err("is a link, not read".to_string());
        }
        match final_path(&file) {
            Some(p) if p.starts_with(home) || below(&p, home).is_some() => {}
            _ => return Err("outside your home folder, Include not followed".to_string()),
        }
    }
    #[cfg(not(any(unix, windows)))]
    let _ = home;
    Ok(file)
}

/// Unix: walk from `/` with openat, every directory O_DIRECTORY|O_NOFOLLOW
/// and the file O_NOFOLLOW|O_NONBLOCK, so no component can be a symlink,
/// even one swapped in after validation.
#[cfg(unix)]
fn open_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    use std::ffi::CString;
    use std::io::{Error, ErrorKind};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    let bad = || Error::new(ErrorKind::InvalidInput, "not an absolute plain path");
    let mut it = path.components();
    if it.next() != Some(Component::RootDir) {
        return Err(bad());
    }
    let mut names = Vec::new();
    for c in it {
        match c {
            Component::Normal(n) => names.push(CString::new(n.as_bytes()).map_err(|_| bad())?),
            _ => return Err(bad()),
        }
    }
    let (last, dirs) = names.split_last().ok_or_else(bad)?;
    let open_fd = |fd: libc::c_int| -> std::io::Result<OwnedFd> {
        if fd < 0 {
            Err(Error::last_os_error())
        } else {
            // SAFETY: a fresh descriptor from open/openat that nothing else owns.
            Ok(unsafe { OwnedFd::from_raw_fd(fd) })
        }
    };
    // SAFETY: a NUL-terminated literal path.
    let mut dir = open_fd(unsafe { libc::open(c"/".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) })?;
    for d in dirs {
        // SAFETY: `dir` is an open directory and `d` a NUL-terminated name.
        dir = open_fd(unsafe {
            libc::openat(dir.as_raw_fd(), d.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        })?;
    }
    // SAFETY: as above.
    let f = open_fd(unsafe {
        libc::openat(
            dir.as_raw_fd(),
            last.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC,
        )
    })?;
    Ok(std::fs::File::from(f))
}

/// Windows: open the reparse point itself rather than its target, so a
/// link swapped in at the last component is seen (and refused) instead of
/// followed; the handle's final path is checked against home as well.
#[cfg(windows)]
fn open_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    std::fs::OpenOptions::new().read(true).custom_flags(FILE_FLAG_OPEN_REPARSE_POINT).open(path)
}

#[cfg(not(any(unix, windows)))]
fn open_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}

/// The path an open handle really refers to (`\\?\C:\...`).
#[cfg(windows)]
fn final_path(file: &std::fs::File) -> Option<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleW;
    let mut buf = vec![0u16; 1024];
    // SAFETY: the handle is open for the call; buffer and length agree.
    let n = unsafe { GetFinalPathNameByHandleW(file.as_raw_handle() as _, buf.as_mut_ptr(), buf.len() as u32, 0) } as usize;
    if n == 0 || n >= buf.len() {
        return None;
    }
    Some(PathBuf::from(std::ffi::OsString::from_wide(&buf[..n])))
}

/* -------------------------------------------------------------- evaluation */

#[derive(Debug, Default, Clone)]
struct Effective {
    hostname: Option<String>,
    user: Option<String>,
    port: Option<(String, String)>,
    identity: Option<(String, String)>,
    proxy: Option<Proxy>,
}

#[derive(Debug, Clone)]
enum Proxy {
    Jump(String),
    Command,
    None,
}

fn effective(conds: &[Cond], directives: &[Directive], name: &str) -> Effective {
    let mut e = Effective::default();
    // Each block's patterns are matched once per name, not once per line.
    let mut memo: Vec<Option<bool>> = vec![None; conds.len()];
    for d in directives {
        let applies = *memo[d.cond].get_or_insert_with(|| match &conds[d.cond] {
            Cond::Always => true,
            Cond::Host(p) => host_patterns_match(p, name),
            Cond::Match => false,
        });
        if !applies {
            continue;
        }
        let first = d.args.first().cloned();
        match d.key.as_str() {
            "hostname" if e.hostname.is_none() => e.hostname = first,
            "user" if e.user.is_none() => e.user = first,
            "port" if e.port.is_none() => e.port = first.map(|p| (p, d.origin.clone())),
            "identityfile" if e.identity.is_none() => {
                if let Some(f) = first {
                    if !f.eq_ignore_ascii_case("none") {
                        e.identity = Some((f, d.origin.clone()));
                    }
                }
            }
            // ProxyJump and ProxyCommand: whichever is obtained first wins.
            "proxyjump" if e.proxy.is_none() => {
                e.proxy = Some(match first {
                    Some(v) if v.eq_ignore_ascii_case("none") => Proxy::None,
                    Some(v) => Proxy::Jump(v),
                    None => Proxy::None,
                })
            }
            "proxycommand" if e.proxy.is_none() => {
                e.proxy = Some(match first {
                    Some(v) if v.eq_ignore_ascii_case("none") && d.args.len() == 1 => Proxy::None,
                    _ => Proxy::Command,
                })
            }
            _ => {}
        }
    }
    e
}

/// Expand the `%` tokens of a HostName (`%h` the alias, `%%`). Unknown tokens
/// are left and reported.
fn expand_hostname(raw: &str, alias: &str, warnings: &mut Vec<String>) -> String {
    let mut out = String::new();
    let mut it = raw.chars().peekable();
    while let Some(c) = it.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('h') => out.push_str(alias),
            Some('%') => out.push('%'),
            Some(o) => {
                warnings.push(format!("HostName token %{o} is not expanded"));
                out.push('%');
                out.push(o);
            }
            None => out.push('%'),
        }
    }
    out
}

/// What an IdentityFile's `%` tokens may expand to.
pub struct TokenCtx<'a> {
    pub home: &'a Path,
    pub local_user: &'a str,
    pub hostname: &'a str,
    pub alias: &'a str,
    pub user: &'a str,
    pub port: u16,
}

/// Expand `~` and the simple `%` tokens (`%d` home, `%u` local user, `%h`
/// hostname, `%r` remote user, `%n` alias, `%p` port, `%%`). Anything else
/// (`%C`, `%i`, `%l`, `${ENV}`, `~otheruser`) is left as written and warned.
pub fn expand_identity(raw: &str, ctx: &TokenCtx<'_>) -> (String, Vec<String>) {
    let mut warnings = Vec::new();
    let home = ctx.home.to_string_lossy();
    // Join with the separator the home path itself uses.
    let sep = if home.contains('\\') && !home.contains('/') { '\\' } else { '/' };
    let mut s = if raw == "~" {
        home.to_string()
    } else if let Some(r) = raw.strip_prefix("~/").or_else(|| raw.strip_prefix("~\\")) {
        format!("{}{sep}{r}", home.trim_end_matches(['/', '\\']))
    } else {
        if raw.starts_with('~') {
            warnings.push(format!("key path {raw}: ~user is not expanded"));
        }
        raw.to_string()
    };
    if s.contains('%') {
        let mut out = String::new();
        let mut it = s.chars();
        let mut unknown = Vec::new();
        while let Some(c) = it.next() {
            if c != '%' {
                out.push(c);
                continue;
            }
            match it.next() {
                Some('d') => out.push_str(&home),
                Some('u') => out.push_str(ctx.local_user),
                Some('h') => out.push_str(ctx.hostname),
                Some('r') => out.push_str(ctx.user),
                Some('n') => out.push_str(ctx.alias),
                Some('p') => out.push_str(&ctx.port.to_string()),
                Some('%') => out.push('%'),
                Some(o) => {
                    unknown.push(format!("%{o}"));
                    out.push('%');
                    out.push(o);
                }
                None => out.push('%'),
            }
        }
        if !unknown.is_empty() {
            warnings.push(format!("key path {raw}: token {} is not expanded", unknown.join(", ")));
        }
        s = out;
    }
    if s.contains("${") {
        warnings.push(format!("key path {raw}: environment variables are not expanded"));
    }
    let p = Path::new(&s);
    if !(p.is_absolute() || s.starts_with('~') || s.starts_with('/') || s.starts_with('\\')) {
        warnings.push(format!("key path {raw} is relative; check it after importing"));
    }
    (s, warnings)
}

/// One ProxyJump hop: `[ssh://][user@]host[:port]`, with `[v6]:port`.
/// Returns (user, host, port) or None when unparseable.
pub fn parse_jump_hop(hop: &str) -> Option<(Option<String>, String, Option<u16>)> {
    let hop = hop.trim();
    let hop = hop.strip_prefix("ssh://").unwrap_or(hop).trim_end_matches('/');
    let (user, rest) = match hop.rsplit_once('@') {
        Some((u, r)) => (Some(u.to_string()), r),
        None => (None, hop),
    };
    let (host, port) = if let Some(r) = rest.strip_prefix('[') {
        let (h, after) = r.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(p) => Some(p.parse::<u16>().ok().filter(|p| *p > 0)?),
            None if after.is_empty() => None,
            None => return None,
        };
        (h.to_string(), port)
    } else if rest.matches(':').count() == 1 {
        let (h, p) = rest.split_once(':')?;
        (h.to_string(), Some(p.parse::<u16>().ok().filter(|p| *p > 0)?))
    } else {
        (rest.to_string(), None)
    };
    if !plain_value(&host, 255) || user.as_deref().is_some_and(|u| !plain_value(u, 255)) {
        return None;
    }
    Some((user, host, port))
}

fn parse_port(raw: &str) -> Option<u16> {
    raw.parse::<u16>().ok().filter(|p| *p > 0)
}

/// (hostname, user, port) a name resolves to under the config, with its
/// warnings.
fn resolve_base(conds: &[Cond], directives: &[Directive], name: &str, warnings: &mut Vec<String>) -> (String, Option<String>, u16, Effective) {
    let e = effective(conds, directives, name);
    let hostname = e
        .hostname
        .as_deref()
        .map(|h| expand_hostname(h, name, warnings))
        .unwrap_or_else(|| name.to_string());
    let port = match &e.port {
        Some((p, origin)) => parse_port(p).unwrap_or_else(|| {
            warnings.push(format!("{origin}: Port {p} is not a valid port; 22 used"));
            22
        }),
        None => 22,
    };
    let user = e.user.clone();
    (hostname, user, port, e)
}

/// The hops ssh goes through before it reaches jump host `name` (0 when
/// it is dialled directly), following that host's own ProxyJump. None when
/// it cannot be followed: a ProxyCommand, an unreadable hop or a loop.
fn hop_route(conds: &[Cond], directives: &[Directive], name: &str, depth: usize) -> Option<usize> {
    if depth >= 8 {
        return None;
    }
    match effective(conds, directives, name).proxy {
        None | Some(Proxy::None) => Some(0),
        Some(Proxy::Command) => None,
        Some(Proxy::Jump(spec)) => {
            let hops: Vec<&str> = spec.split(',').map(str::trim).filter(|h| !h.is_empty()).collect();
            let (_, first, _) = parse_jump_hop(hops.first()?)?;
            // ssh ignores a ProxyJump that names the host itself (typical
            // of a `Host *` ProxyJump that also matches the bastion).
            if hops.len() == 1 && first.eq_ignore_ascii_case(name) {
                return Some(0);
            }
            Some(hops.len() + hop_route(conds, directives, &first, depth + 1)?)
        }
    }
}

fn evaluate(r: &mut Reader, local_user: &str) {
    let aliases = std::mem::take(&mut r.aliases);
    let alias_set: HashSet<String> = aliases.iter().map(|(a, _)| a.to_ascii_lowercase()).collect();
    for (alias, origin) in aliases {
        if r.report.hosts.len() >= MAX_HOSTS {
            r.warn(format!("more than {MAX_HOSTS} hosts; the rest were not read"));
            break;
        }
        let mut warnings = Vec::new();
        let (hostname, user, port, e) = resolve_base(&r.conds, &r.directives, &alias, &mut warnings);
        if !plain_value(&hostname, 255) {
            push_capped(&mut r.report.skipped, format!("{alias} ({origin}): HostName \"{hostname}\" is not a usable address"));
            continue;
        }
        let user = match user {
            Some(u) if !plain_value(&u, 255) => {
                warnings.push(format!("User \"{u}\" is not usable; set the user after importing"));
                None
            }
            Some(u) if u.contains('%') || u.contains("${") => {
                warnings.push(format!("User {u} contains tokens that are not expanded"));
                Some(u)
            }
            other => other,
        };
        let key_path = e.identity.as_ref().map(|(raw, _)| {
            let ctx = TokenCtx {
                home: &r.home,
                local_user,
                hostname: &hostname,
                alias: &alias,
                user: user.as_deref().unwrap_or(local_user),
                port,
            };
            let (p, w) = expand_identity(raw, &ctx);
            warnings.extend(w);
            p
        });
        let mut jump_hops = 0usize;
        let mut unsupported_route = None;
        let jump = match &e.proxy {
            None | Some(Proxy::None) => None,
            Some(Proxy::Command) => {
                warnings.push("ProxyCommand is not supported and was not imported; the host may not be reachable directly".to_string());
                None
            }
            Some(Proxy::Jump(spec)) => {
                let hops: Vec<&str> = spec.split(',').map(str::trim).filter(|h| !h.is_empty()).collect();
                match hops.first().and_then(|h| parse_jump_hop(h)) {
                    None => {
                        warnings.push(format!("ProxyJump {spec} could not be read and was not imported"));
                        None
                    }
                    Some((_, hh, _)) if hops.len() == 1 && hh.eq_ignore_ascii_case(&alias) => {
                        warnings.push("ProxyJump points at the host itself; ignored".to_string());
                        None
                    }
                    Some((hu, hh, hp)) => {
                        // What ssh really goes through: every listed hop, plus
                        // whatever the first hop itself needs to be reached
                        // (its own ProxyJump, as ssh evaluates it for that hop).
                        let behind = hop_route(&r.conds, &r.directives, &hh, 0);
                        let total = behind.map(|b| hops.len() + b);
                        jump_hops = total.unwrap_or(hops.len() + 1);
                        if total != Some(1) {
                            let why = match total {
                                Some(n) => format!("route not supported ({n} hops: {spec}{}); Hawser uses one jump host", if n > hops.len() { format!(", and {hh} has its own ProxyJump") } else { String::new() }),
                                None => format!("route not supported (jump host {hh} needs ProxyCommand or a ProxyJump loop to be reached)"),
                            };
                            warnings.push(why.clone());
                            unsupported_route = Some(why);
                        }
                        if hu.is_none() && hp.is_none() && alias_set.contains(&hh.to_ascii_lowercase()) {
                            Some(JumpRef::Alias { alias: hh })
                        } else {
                            // Not a plain alias: resolve the hop name through the
                            // config (as ssh does for each hop), then apply the
                            // hop's own user/port. Its IdentityFile comes along,
                            // so the jump host logs in as ssh would.
                            let mut jw = Vec::new();
                            let (jh, ju, jp, je) = resolve_base(&r.conds, &r.directives, &hh, &mut jw);
                            let host = if plain_value(&jh, 255) { jh } else { hh.clone() };
                            let port = hp.unwrap_or(jp);
                            let user = hu.or(ju).filter(|u| plain_value(u, 255));
                            let key_path = je.identity.as_ref().map(|(raw, _)| {
                                let ctx = TokenCtx {
                                    home: &r.home,
                                    local_user,
                                    hostname: &host,
                                    alias: &hh,
                                    user: user.as_deref().unwrap_or(local_user),
                                    port,
                                };
                                let (p, w) = expand_identity(raw, &ctx);
                                jw.extend(w);
                                p
                            });
                            warnings.extend(jw.into_iter().map(|w| format!("jump host {hh}: {w}")));
                            Some(JumpRef::Literal { host, port, user, key_path })
                        }
                    }
                }
            }
        };
        r.report.hosts.push(ScannedHost {
            name: alias,
            hostname,
            port,
            user,
            key_path,
            jump,
            jump_hops,
            unsupported_route,
            warnings,
            origin,
        });
    }
}

fn finish(mut r: Reader, local_user: &str) -> ImportReport {
    evaluate(&mut r, local_user);
    if !r.patterns_skipped.is_empty() {
        let list = r.patterns_skipped.join(", ");
        push_capped(&mut r.report.skipped, format!("Wildcard or negated Host patterns are defaults, not hosts: {list}"));
    }
    if r.match_blocks > 0 {
        r.report.skipped.insert(0, format!("{} Match block(s) skipped", r.match_blocks));
    }
    r.report.unsupported_keys = r.unsupported.into_values().take(MAX_LIST).collect();
    r.report.local_user = local_user.to_string();
    r.report
}

/// Scan an OpenSSH client config file and everything it includes.
pub fn scan_ssh_config(path: &Path, home: &Path, local_user: &str) -> Result<ImportReport, String> {
    let mut r = Reader::new(home);
    r.read_top(path)?;
    Ok(finish(r, local_user))
}

/// Parse config text directly (Include still resolves against `home`).
#[cfg(test)]
pub fn parse_ssh_config_str(text: &str, label: &str, home: &Path, local_user: &str) -> ImportReport {
    let mut r = Reader::new(home);
    r.parse_text(text, label, 0, 0);
    finish(r, local_user)
}

/// `~/.ssh/config`.
pub fn default_ssh_config_path(home: &Path) -> PathBuf {
    home.join(".ssh").join("config")
}

/// The local account name, as OpenSSH defaults User to it.
pub fn local_user_name() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .ok()
        .filter(|u| plain_value(u, 255))
        .unwrap_or_default()
}

/* ------------------------------------------------------------------- PuTTY */

/// The values of one PuTTY saved session that the import reads. Nothing else
/// is read from the registry (PuTTY stores no password, but the allowlist
/// keeps that true whatever a future version adds).
#[derive(Debug, Default, Clone)]
pub struct PuttySession {
    /// The registry key name, still escaped.
    pub raw_name: String,
    pub host_name: Option<String>,
    pub user_name: Option<String>,
    pub port_number: Option<u32>,
    pub protocol: Option<String>,
    pub public_key_file: Option<String>,
    pub proxy_method: Option<u32>,
    pub proxy_host: Option<String>,
}

/// Undo PuTTY's session-name escaping (`%XX` for space, `%`, `*`, `?`, `\`,
/// controls and non-ASCII). The bytes are UTF-8 when they decode as such,
/// else taken as Latin-1.
pub fn decode_putty_name(raw: &str) -> String {
    let b = raw.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if let (Some(h), Some(l)) = (b.get(i + 1).and_then(|c| hex(*c)), b.get(i + 2).and_then(|c| hex(*c))) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    match String::from_utf8(out) {
        Ok(s) => s,
        Err(e) => e.into_bytes().iter().map(|&c| c as char).collect(),
    }
}

const PUTTY_PROXY_TYPES: &[&str] = &["none", "SOCKS 4", "SOCKS 5", "HTTP", "Telnet", "local command", "SSH"];

/// Map one session to a candidate host, or Err(reason) to skip it.
/// `Ok(None)` is a session that is silently not a host (Default Settings
/// without a HostName).
pub fn map_putty_session(s: &PuttySession) -> Result<Option<ScannedHost>, String> {
    let name = decode_putty_name(&s.raw_name);
    let host_raw = s.host_name.as_deref().map(str::trim).unwrap_or("");
    if name == "Default Settings" && host_raw.is_empty() {
        return Ok(None);
    }
    let protocol = s.protocol.as_deref().unwrap_or("ssh").trim().to_ascii_lowercase();
    if protocol != "ssh" {
        return Err(format!("{name}: {protocol} session, only SSH is imported"));
    }
    if host_raw.is_empty() {
        return Err(format!("{name}: no host name"));
    }
    let mut warnings = Vec::new();
    // "user@host" in HostName wins over UserName, as PuTTY does.
    let (user_in_host, host) = match host_raw.rsplit_once('@') {
        Some((u, h)) => (Some(u.to_string()), h.to_string()),
        None => (None, host_raw.to_string()),
    };
    if !plain_value(&host, 255) {
        return Err(format!("{name}: host name \"{host_raw}\" is not usable"));
    }
    let user = user_in_host
        .or_else(|| s.user_name.clone())
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty());
    let user = match user {
        Some(u) if !plain_value(&u, 255) => {
            warnings.push(format!("user name \"{u}\" is not usable; set it after importing"));
            None
        }
        other => other,
    };
    let port = match s.port_number {
        None => 22,
        Some(p) if (1..=65535).contains(&p) => p as u16,
        Some(p) => {
            warnings.push(format!("port {p} is not valid; 22 used"));
            22
        }
    };
    // Hawser's key loader (russh / ssh-key with "ppk") reads PuTTY .ppk v2
    // and v3 files, encrypted or not, so the path is kept as is.
    let key_path = s
        .public_key_file
        .as_deref()
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .map(str::to_string);
    if let Some(m) = s.proxy_method.filter(|m| *m != 0) {
        let kind = PUTTY_PROXY_TYPES.get(m as usize).copied().unwrap_or("unknown");
        let via = s.proxy_host.as_deref().map(str::trim).filter(|h| !h.is_empty()).map(|h| format!(" via {h}")).unwrap_or_default();
        warnings.push(format!("uses a PuTTY {kind} proxy{via}, which is not imported; the host may not be reachable directly"));
    }
    Ok(Some(ScannedHost {
        name,
        hostname: host,
        port,
        user,
        key_path,
        jump: None,
        jump_hops: 0,
        unsupported_route: None,
        warnings,
        origin: "PuTTY session".to_string(),
    }))
}

/// Build the report for a list of sessions.
pub fn putty_report(sessions: &[PuttySession], local_user: &str) -> ImportReport {
    let mut report = ImportReport { source: "putty".into(), local_user: local_user.to_string(), ..Default::default() };
    for s in sessions {
        if report.hosts.len() >= MAX_HOSTS {
            push_capped(&mut report.warnings, format!("more than {MAX_HOSTS} sessions; the rest were not read"));
            break;
        }
        match map_putty_session(s) {
            Ok(Some(h)) => report.hosts.push(h),
            Ok(None) => {}
            Err(why) => push_capped(&mut report.skipped, why),
        }
    }
    report
}

/// Read PuTTY's saved sessions from HKCU.
#[cfg(windows)]
pub fn read_putty_sessions() -> Result<Vec<PuttySession>, String> {
    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_CURRENT_USER, KEY_READ, REG_DWORD,
        REG_EXPAND_SZ, REG_SZ,
    };

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    struct Key(HKEY);
    impl Drop for Key {
        fn drop(&mut self) {
            // SAFETY: the handle came from a successful RegOpenKeyExW.
            unsafe { RegCloseKey(self.0) };
        }
    }

    fn open(parent: HKEY, sub: &str) -> Result<Option<Key>, u32> {
        let name = wide(sub);
        let mut h: HKEY = std::ptr::null_mut();
        // SAFETY: `name` is NUL-terminated and outlives the call; `h` is a
        // valid out pointer.
        let rc = unsafe { RegOpenKeyExW(parent, name.as_ptr(), 0, KEY_READ, &mut h) };
        match rc {
            ERROR_SUCCESS => Ok(Some(Key(h))),
            ERROR_FILE_NOT_FOUND => Ok(None),
            e => Err(e),
        }
    }

    /// A REG_SZ / REG_EXPAND_SZ value, capped at 4 KiB, or None.
    fn string_value(k: &Key, name: &str) -> Option<String> {
        let n = wide(name);
        let mut ty = 0u32;
        let mut buf = vec![0u16; 2048];
        let mut len = (buf.len() * 2) as u32;
        // SAFETY: buffer and length describe the same allocation; all
        // pointers are valid for the call.
        let rc = unsafe {
            RegQueryValueExW(k.0, n.as_ptr(), std::ptr::null(), &mut ty, buf.as_mut_ptr() as *mut u8, &mut len)
        };
        if rc != ERROR_SUCCESS || (ty != REG_SZ && ty != REG_EXPAND_SZ) {
            return None;
        }
        let units = ((len as usize) / 2).min(buf.len());
        let s = &buf[..units];
        let s = match s.iter().position(|&c| c == 0) {
            Some(z) => &s[..z],
            None => s,
        };
        Some(String::from_utf16_lossy(s))
    }

    fn dword_value(k: &Key, name: &str) -> Option<u32> {
        let n = wide(name);
        let mut ty = 0u32;
        let mut v = 0u32;
        let mut len = 4u32;
        // SAFETY: `v` is 4 bytes, as `len` says.
        let rc = unsafe {
            RegQueryValueExW(k.0, n.as_ptr(), std::ptr::null(), &mut ty, &mut v as *mut u32 as *mut u8, &mut len)
        };
        (rc == ERROR_SUCCESS && ty == REG_DWORD && len == 4).then_some(v)
    }

    let root = match open(HKEY_CURRENT_USER, "Software\\SimonTatham\\PuTTY\\Sessions") {
        Ok(Some(k)) => k,
        Ok(None) => return Ok(Vec::new()),
        Err(e) => return Err(format!("could not open the PuTTY sessions key (error {e})")),
    };
    let mut out = Vec::new();
    let mut index = 0u32;
    while (index as usize) < MAX_HOSTS {
        let mut name = vec![0u16; 256];
        let mut len = name.len() as u32;
        // SAFETY: `name`/`len` describe one buffer; optional outputs are null.
        let rc = unsafe {
            RegEnumKeyExW(
                root.0,
                index,
                name.as_mut_ptr(),
                &mut len,
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        index += 1;
        if rc == ERROR_NO_MORE_ITEMS {
            break;
        }
        if rc != ERROR_SUCCESS {
            // A name longer than 255 (not one PuTTY writes) or a transient
            // error: skip that entry.
            continue;
        }
        let raw_name = String::from_utf16_lossy(&name[..(len as usize).min(name.len())]);
        let Ok(Some(k)) = open(root.0, &raw_name) else { continue };
        out.push(PuttySession {
            raw_name,
            host_name: string_value(&k, "HostName"),
            user_name: string_value(&k, "UserName"),
            port_number: dword_value(&k, "PortNumber"),
            protocol: string_value(&k, "Protocol"),
            public_key_file: string_value(&k, "PublicKeyFile"),
            proxy_method: dword_value(&k, "ProxyMethod"),
            proxy_host: string_value(&k, "ProxyHost"),
        });
    }
    Ok(out)
}

#[cfg(not(windows))]
pub fn read_putty_sessions() -> Result<Vec<PuttySession>, String> {
    Err("not available on this platform".to_string())
}

/* ------------------------------------------------------------------- tests */

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn home() -> PathBuf {
        PathBuf::from("/home/alice")
    }

    fn parse(text: &str) -> ImportReport {
        parse_ssh_config_str(text, "config", &home(), "alice")
    }

    fn host<'a>(r: &'a ImportReport, name: &str) -> &'a ScannedHost {
        r.hosts.iter().find(|h| h.name == name).unwrap_or_else(|| panic!("no host {name}: {:?}", r.hosts))
    }

    /// A fresh directory under the system temp dir, removed on drop.
    struct TempHome(PathBuf);
    impl TempHome {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "hawser-sshimp-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
            ));
            fs::create_dir_all(p.join(".ssh")).unwrap();
            TempHome(fs::canonicalize(p).unwrap())
        }
        fn write(&self, rel: &str, text: &str) -> PathBuf {
            let p = self.0.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, text).unwrap();
            p
        }
    }
    impl Drop for TempHome {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn equals_syntax_quotes_and_comments() {
        let r = parse(
            "# comment\n\n  HOST=web\n\tHostName = \"web.example.com\"\n  user=\"deploy user\"\nPort=2222 # trailing\n",
        );
        let h = host(&r, "web");
        assert_eq!(h.hostname, "web.example.com");
        // A user with a space is not usable as a login name.
        assert_eq!(h.user, None);
        assert!(h.warnings.iter().any(|w| w.contains("not usable")));
        assert_eq!(h.port, 2222);
        assert_eq!(split_args(r#"a "b c" 'd e' f\ g # gone"#).unwrap(), vec!["a", "b c", "d e", "f g"]);
        assert_eq!(split_line("IdentityFile=\"~/my keys/id\"").unwrap(), Some(("identityfile".into(), vec!["~/my keys/id".into()])));
        assert!(split_line("User \"unterminated").is_err());
        let r = parse("Host a\n  User \"oops\nHost b\n");
        assert!(r.warnings.iter().any(|w| w.contains("config:2") && w.contains("unterminated")));
        assert_eq!(r.hosts.len(), 2);
    }

    #[test]
    fn keywords_case_insensitive_and_defaults() {
        let r = parse("hOsT box\n  hOsTnAmE 10.0.0.5\n  USER root\n");
        let h = host(&r, "box");
        assert_eq!((h.hostname.as_str(), h.user.as_deref(), h.port), ("10.0.0.5", Some("root"), 22));
        let r = parse("Host plain\n");
        let h = host(&r, "plain");
        assert_eq!((h.hostname.as_str(), h.user.as_deref(), h.port), ("plain", None, 22));
        assert_eq!(r.local_user, "alice");
    }

    #[test]
    fn host_star_inherits_only_unset_fields_first_value_wins() {
        let r = parse(
            "Host web\n  User webuser\n  HostName web.internal\n\
             Host *.corp web\n  User corpuser\n  Port 2200\n\
             Host *\n  User fallback\n  Port 22\n  IdentityFile ~/.ssh/id_default\n\
             Host db\n  User dbuser\n",
        );
        let w = host(&r, "web");
        // Its own block came first: User stays; Port from the *.corp block
        // (before Host *); IdentityFile from Host *.
        assert_eq!(w.user.as_deref(), Some("webuser"));
        assert_eq!(w.port, 2200);
        assert_eq!(w.key_path.as_deref(), Some("/home/alice/.ssh/id_default"));
        // db's own block is AFTER Host *, so Host * wins (first obtained).
        let d = host(&r, "db");
        assert_eq!(d.user.as_deref(), Some("fallback"));
        assert_eq!(d.port, 22);
        // Settings before any Host line apply to everyone, first.
        let r = parse("User global\nHost a\n  User mine\n");
        assert_eq!(host(&r, "a").user.as_deref(), Some("global"));
    }

    #[test]
    fn multiple_aliases_and_patterns() {
        let r = parse("Host one two *.wild !nope three?\n  HostName %h.example.com\nHost two\n  Port 99\n");
        let names: Vec<&str> = r.hosts.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(names, vec!["one", "two"]);
        assert_eq!(host(&r, "one").hostname, "one.example.com");
        assert_eq!(host(&r, "two").hostname, "two.example.com");
        assert_eq!(host(&r, "two").port, 99);
        assert!(r.skipped.iter().any(|s| s.contains("*.wild") && s.contains("!nope") && s.contains("three?")));
        // Negation excludes a name from a block that would otherwise match.
        let r = parse("Host a b\nHost * !b\n  User star\n");
        assert_eq!(host(&r, "a").user.as_deref(), Some("star"));
        assert_eq!(host(&r, "b").user, None);
    }

    #[test]
    fn identity_file_first_one_and_tokens() {
        let r = parse(
            "Host srv\n  HostName srv.example.com\n  User bob\n  Port 2022\n  IdentityFile ~/.ssh/%h_%r_%u_%p_%n\n  IdentityFile ~/.ssh/second\n",
        );
        assert_eq!(
            host(&r, "srv").key_path.as_deref(),
            Some("/home/alice/.ssh/srv.example.com_bob_alice_2022_srv")
        );
        let r = parse("Host x\n  IdentityFile %d/.ssh/id_%C\n");
        let h = host(&r, "x");
        assert_eq!(h.key_path.as_deref(), Some("/home/alice/.ssh/id_%C"));
        assert!(h.warnings.iter().any(|w| w.contains("%C")));
        let r = parse("Host y\n  IdentityFile none\nHost *\n  IdentityFile ~/.ssh/real\n");
        assert_eq!(host(&r, "y").key_path.as_deref(), Some("/home/alice/.ssh/real"));
        let r = parse("Host z\n  IdentityFile keys/id\n");
        assert!(host(&r, "z").warnings.iter().any(|w| w.contains("relative")));
        let r = parse("Host q\n  IdentityFile ${HOME}/id\n");
        assert!(host(&r, "q").warnings.iter().any(|w| w.contains("environment")));
    }

    #[test]
    fn proxyjump_forms() {
        let r = parse(
            "Host bastion\n  HostName bastion.example.com\n  User jumper\n\
             Host inner\n  ProxyJump bastion\n\
             Host literal\n  ProxyJump ops@gw.example.com:2222\n\
             Host v6\n  ProxyJump [2001:db8::1]:2200\n\
             Host url\n  ProxyJump ssh://u@gw2:23\n\
             Host multi\n  ProxyJump bastion,second.example.com\n\
             Host aliasuser\n  ProxyJump root@bastion\n\
             Host corpjump\n  ProxyJump edge.corp\n\
             Host *.corp\n  User corpuser\n  Port 2201\n\
             Host selfie\n  ProxyJump selfie\n\
             Host nojump\n  ProxyJump none\nHost *\n  ProxyJump bastion\n",
        );
        assert_eq!(host(&r, "inner").jump, Some(JumpRef::Alias { alias: "bastion".into() }));
        assert_eq!(
            host(&r, "literal").jump,
            Some(JumpRef::Literal { host: "gw.example.com".into(), port: 2222, user: Some("ops".into()), key_path: None })
        );
        assert_eq!(host(&r, "v6").jump, Some(JumpRef::Literal { host: "2001:db8::1".into(), port: 2200, user: None, key_path: None }));
        assert_eq!(host(&r, "url").jump, Some(JumpRef::Literal { host: "gw2".into(), port: 23, user: Some("u".into()), key_path: None }));
        let m = host(&r, "multi");
        assert_eq!(m.jump, Some(JumpRef::Alias { alias: "bastion".into() }));
        assert!(m.warnings.iter().any(|w| w.contains("2 hops")));
        assert_eq!(m.jump_hops, 2);
        assert!(m.unsupported_route.as_deref().is_some_and(|w| w.contains("route not supported (2 hops")));
        // A single hop whose own config adds nothing is supported.
        let i = host(&r, "inner");
        assert_eq!((i.jump_hops, i.unsupported_route.as_deref()), (1, None));
        // An alias with a user override resolves through the config.
        assert_eq!(
            host(&r, "aliasuser").jump,
            Some(JumpRef::Literal { host: "bastion.example.com".into(), port: 22, user: Some("root".into()), key_path: None })
        );
        // A non-alias hop name still picks up matching pattern blocks.
        assert_eq!(
            host(&r, "corpjump").jump,
            Some(JumpRef::Literal { host: "edge.corp".into(), port: 2201, user: Some("corpuser".into()), key_path: None })
        );
        assert_eq!(host(&r, "selfie").jump, None);
        // `none` first wins over the later Host * ProxyJump.
        assert_eq!(host(&r, "nojump").jump, None);
        // bastion itself inherits the Host * ProxyJump to itself: ignored.
        assert_eq!(host(&r, "bastion").jump, None);
        assert_eq!(parse_jump_hop("bad host"), None);
        assert_eq!(parse_jump_hop("h:0"), None);
        assert_eq!(parse_jump_hop("h:99999"), None);
    }

    #[test]
    fn proxycommand_skipped_with_warning_and_first_wins() {
        let r = parse("Host pc\n  ProxyCommand ssh -W %h:%p gw\n  ProxyJump gw\nHost gw\n");
        let h = host(&r, "pc");
        assert_eq!(h.jump, None);
        assert!(h.warnings.iter().any(|w| w.contains("ProxyCommand")));
        let r = parse("Host pj\n  ProxyJump gw\n  ProxyCommand nc %h %p\nHost gw\n");
        assert_eq!(host(&r, "pj").jump, Some(JumpRef::Alias { alias: "gw".into() }));
        assert!(host(&r, "pj").warnings.is_empty());
    }

    #[test]
    fn match_blocks_skipped_and_reported() {
        let r = parse(
            "Host a\n  User early\nMatch host a exec \"true\"\n  User frommatch\n  Port 1\n  Include evil\nHost b\n  Port 2\n",
        );
        assert_eq!(host(&r, "a").user.as_deref(), Some("early"));
        assert_eq!(host(&r, "a").port, 22);
        assert_eq!(host(&r, "b").port, 2);
        assert!(r.skipped[0].contains("1 Match block"));
        assert!(r.skipped.iter().any(|s| s.contains("Match block at config:3")));
        assert!(r.skipped.iter().any(|s| s.contains("Include inside a Match")));
    }

    #[test]
    fn unsupported_keys_collected() {
        let r = parse("ForwardAgent yes\nHost a\n  ServerAliveInterval 30\n  forwardagent no\n  HostName a.example\n");
        assert_eq!(r.unsupported_keys, vec!["ForwardAgent".to_string(), "ServerAliveInterval".to_string()]);
    }

    #[test]
    fn bad_values() {
        let r = parse("Host p\n  Port http\nHost h\n  HostName \"bad host\"\n");
        let p = host(&r, "p");
        assert_eq!(p.port, 22);
        assert!(p.warnings.iter().any(|w| w.contains("not a valid port")));
        assert!(r.hosts.iter().all(|h| h.name != "h"));
        assert!(r.skipped.iter().any(|s| s.starts_with("h (")));
    }

    #[test]
    fn include_globs_relative_and_order() {
        let t = TempHome::new("glob");
        t.write(".ssh/config.d/20-b.conf", "Host bee\n  User b\n");
        t.write(".ssh/config.d/10-a.conf", "Host ay\n  User a\n");
        t.write(".ssh/config.d/.hidden.conf", "Host hidden\n");
        t.write(".ssh/extra", "Host extra\n  Port 2022\n");
        t.write(".ssh/nested/one", "Include ~/.ssh/nested/two\nHost one\n");
        t.write(".ssh/nested/two", "Host two\n");
        let cfg = t.write(
            ".ssh/config",
            "Include config.d/*.conf extra\nInclude ~/.ssh/nested/one\nInclude missing-*\nHost main\n  User m\n",
        );
        let r = scan_ssh_config(&cfg, &t.0, "alice").unwrap();
        let names: Vec<&str> = r.hosts.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(names, vec!["ay", "bee", "extra", "two", "one", "main"]);
        assert_eq!(host(&r, "extra").port, 2022);
        assert_eq!(r.files_read.len(), 6);
        assert!(r.skipped.iter().any(|s| s.contains("missing-*") && s.contains("no files")));
    }

    #[test]
    fn include_inside_host_block_is_conditional() {
        let t = TempHome::new("cond");
        t.write(".ssh/web.inc", "User webonly\n");
        let cfg = t.write(".ssh/config", "Host web\n  Include web.inc\nHost other\nHost *\n  User star\n");
        let r = scan_ssh_config(&cfg, &t.0, "alice").unwrap();
        assert_eq!(host(&r, "web").user.as_deref(), Some("webonly"));
        assert_eq!(host(&r, "other").user.as_deref(), Some("star"));
    }

    #[test]
    fn include_cycles_and_depth() {
        let t = TempHome::new("cycle");
        t.write(".ssh/a", "Host a\nInclude b\n");
        t.write(".ssh/b", "Host b\nInclude a\n");
        let cfg = t.write(".ssh/config", "Include a\nInclude config\n");
        let r = scan_ssh_config(&cfg, &t.0, "alice").unwrap();
        let names: Vec<&str> = r.hosts.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(names, vec!["a", "b"]);
        assert!(r.warnings.iter().filter(|w| w.contains("cycle")).count() >= 2);

        // A chain deeper than 16 stops at the limit with a warning.
        let t = TempHome::new("deep");
        for i in 0..20 {
            t.write(&format!(".ssh/d{i}"), &format!("Host h{i}\nInclude d{}\n", i + 1));
        }
        let cfg = t.write(".ssh/config", "Include d0\n");
        let r = scan_ssh_config(&cfg, &t.0, "alice").unwrap();
        assert_eq!(r.hosts.len(), MAX_INCLUDE_DEPTH);
        assert!(r.warnings.iter().any(|w| w.contains("16 levels")));
    }

    #[test]
    fn include_outside_home_refused() {
        let t = TempHome::new("out");
        let outside = TempHome::new("outside-target");
        let p = outside.write("evil.conf", "Host evil\n");
        // Backslashes (Windows paths) are escapes in config syntax.
        let written = p.display().to_string().replace('\\', "\\\\");
        let cfg = t.write(".ssh/config", &format!("Include {written}\nHost ok\n"));
        let r = scan_ssh_config(&cfg, &t.0, "alice").unwrap();
        assert_eq!(r.hosts.len(), 1);
        assert!(r.warnings.iter().any(|w| w.contains("outside your home")));
        #[cfg(unix)]
        {
            // A symlink inside home pointing outside is refused too.
            std::os::unix::fs::symlink(&p, t.0.join(".ssh/link.conf")).unwrap();
            let cfg = t.write(".ssh/config", "Include link.conf\n");
            let r = scan_ssh_config(&cfg, &t.0, "alice").unwrap();
            assert!(r.hosts.is_empty());
            assert!(r.warnings.iter().any(|w| w.contains("outside your home")));
        }
    }

    #[test]
    fn size_cap_binary_and_non_files() {
        let t = TempHome::new("size");
        let big = "#".repeat(MAX_FILE_BYTES as usize + 10);
        let cfg = t.write(".ssh/config", &big);
        let err = scan_ssh_config(&cfg, &t.0, "alice").unwrap_err();
        assert!(err.contains("larger than"));
        t.write(".ssh/big.inc", &big);
        let cfg = t.write(".ssh/config", "Include big.inc\nHost fine\n");
        let r = scan_ssh_config(&cfg, &t.0, "alice").unwrap();
        assert_eq!(r.hosts.len(), 1);
        assert!(r.warnings.iter().any(|w| w.contains("larger than")));
        let bin = t.0.join(".ssh/bin");
        fs::write(&bin, b"Host x\n\0\x01\x02").unwrap();
        assert!(scan_ssh_config(&bin, &t.0, "alice").unwrap_err().contains("binary"));
        let lossy = t.0.join(".ssh/lossy");
        fs::write(&lossy, b"Host caf\xe9\nHost good\n").unwrap();
        let r = scan_ssh_config(&lossy, &t.0, "alice").unwrap();
        assert!(r.warnings.iter().any(|w| w.contains("UTF-8")));
        assert!(r.hosts.iter().any(|h| h.name == "good"));
        assert!(scan_ssh_config(&t.0.join(".ssh"), &t.0, "alice").unwrap_err().contains("not a regular file"));
        assert!(scan_ssh_config(&t.0.join("nope"), &t.0, "alice").is_err());
    }

    #[test]
    fn huge_config_is_bounded() {
        let mut text = String::new();
        for i in 0..3000 {
            text.push_str(&format!("Host h{i}\n  HostName 10.0.{}.{}\n  User u{i}\n", i / 250, i % 250));
        }
        text.push_str("Host *\n  Port 2222\n");
        let started = std::time::Instant::now();
        let r = parse(&text);
        assert_eq!(r.hosts.len(), MAX_HOSTS);
        assert!(r.warnings.iter().any(|w| w.contains("more than")));
        assert_eq!(host(&r, "h1999").port, 2222);
        assert!(started.elapsed() < std::time::Duration::from_secs(20));
    }

    #[test]
    fn real_world_fixture() {
        let r = parse(
            r#"# ~/.ssh/config — managed by hand
Include ~/.ssh/does-not-exist/*

Host github.com
    HostName github.com
    User git
    IdentityFile ~/.ssh/id_ed25519_github
    IdentitiesOnly yes

Host bastion bastion.prod
    HostName 203.0.113.10
    User ec2-user
    Port 22
    IdentityFile ~/.ssh/prod.pem
    ForwardAgent yes

Host app-1 app-2
    HostName %h.prod.internal
    ProxyJump bastion
    User deploy

Host db-primary
    HostName 10.20.0.5
    ProxyJump ops@bastion.example.org:2222,inner-hop
    LocalForward 5432 localhost:5432

Host legacy-switch
    HostName 192.0.2.50
    KexAlgorithms +diffie-hellman-group1-sha1
    ProxyCommand ssh -W %h:%p bastion

Match host *.prod.internal exec "test -f ~/.vpn"
    User vpnuser

Host 10.*
    StrictHostKeyChecking no

Host *
    ServerAliveInterval 60
    AddKeysToAgent yes
    UseKeychain yes
    IdentityFile ~/.ssh/id_ed25519
    User me
"#,
        );
        let names: Vec<&str> = r.hosts.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(names, vec!["github.com", "bastion", "bastion.prod", "app-1", "app-2", "db-primary", "legacy-switch"]);
        let g = host(&r, "github.com");
        assert_eq!((g.user.as_deref(), g.key_path.as_deref()), (Some("git"), Some("/home/alice/.ssh/id_ed25519_github")));
        let a = host(&r, "app-2");
        assert_eq!(a.hostname, "app-2.prod.internal");
        assert_eq!(a.user.as_deref(), Some("deploy"));
        assert_eq!(a.jump, Some(JumpRef::Alias { alias: "bastion".into() }));
        assert_eq!(a.key_path.as_deref(), Some("/home/alice/.ssh/id_ed25519"));
        let d = host(&r, "db-primary");
        assert_eq!(d.user.as_deref(), Some("me"));
        assert_eq!(
            d.jump,
            Some(JumpRef::Literal {
                host: "bastion.example.org".into(),
                port: 2222,
                user: Some("ops".into()),
                key_path: Some("/home/alice/.ssh/id_ed25519".into()),
            })
        );
        assert!(d.warnings.iter().any(|w| w.contains("2 hops")));
        assert_eq!(d.jump_hops, 2);
        assert!(d.unsupported_route.is_some());
        assert_eq!(host(&r, "app-1").unsupported_route, None);
        let l = host(&r, "legacy-switch");
        assert!(l.warnings.iter().any(|w| w.contains("ProxyCommand")));
        assert!(r.skipped.iter().any(|s| s.contains("Match block")));
        assert!(r.skipped.iter().any(|s| s.contains("10.*")));
        for k in ["IdentitiesOnly", "ForwardAgent", "LocalForward", "KexAlgorithms", "StrictHostKeyChecking", "ServerAliveInterval", "UseKeychain"] {
            assert!(r.unsupported_keys.iter().any(|u| u == k), "{k} missing from {:?}", r.unsupported_keys);
        }
    }

    #[test]
    fn glob_matching() {
        assert!(glob_match("*.corp", "a.b.corp", true));
        assert!(glob_match("WEB?", "web1", true));
        assert!(!glob_match("WEB?", "web1", false));
        assert!(!glob_match("web?", "web12", true));
        assert!(glob_match("*a*b*", "xxaxxbxx", false));
        assert!(glob_match("*", "", false));
        assert!(!glob_match("a*c", "abd", false));
    }

    #[test]
    fn putty_names_decode() {
        assert_eq!(decode_putty_name("My%20Server"), "My Server");
        assert_eq!(decode_putty_name("100%25%20done"), "100% done");
        assert_eq!(decode_putty_name("a%2Ab%3Fc%5Cd"), "a*b?c\\d");
        assert_eq!(decode_putty_name("%2Edot"), ".dot");
        assert_eq!(decode_putty_name("caf%C3%A9"), "café");
        // Not UTF-8: taken as Latin-1.
        assert_eq!(decode_putty_name("caf%E9"), "café");
        // Malformed escapes are kept literally.
        assert_eq!(decode_putty_name("50%"), "50%");
        assert_eq!(decode_putty_name("x%zz"), "x%zz");
        assert_eq!(decode_putty_name("x%4"), "x%4");
    }

    fn sess(name: &str) -> PuttySession {
        PuttySession { raw_name: name.into(), host_name: Some("10.0.0.1".into()), ..Default::default() }
    }

    #[test]
    fn putty_mapping() {
        let mut s = sess("Core%20Switch");
        s.host_name = Some("admin@core.example.net".into());
        s.user_name = Some("ignored".into());
        s.port_number = Some(2222);
        s.protocol = Some("ssh".into());
        s.public_key_file = Some("C:\\Users\\a\\keys\\core.ppk".into());
        let h = map_putty_session(&s).unwrap().unwrap();
        assert_eq!(h.name, "Core Switch");
        assert_eq!(h.hostname, "core.example.net");
        assert_eq!(h.user.as_deref(), Some("admin"));
        assert_eq!(h.port, 2222);
        assert_eq!(h.key_path.as_deref(), Some("C:\\Users\\a\\keys\\core.ppk"));
        assert!(h.warnings.is_empty());

        let mut s = sess("u");
        s.user_name = Some("bob".into());
        s.port_number = Some(0);
        s.proxy_method = Some(2);
        s.proxy_host = Some("socks.local".into());
        let h = map_putty_session(&s).unwrap().unwrap();
        assert_eq!((h.user.as_deref(), h.port), (Some("bob"), 22));
        assert!(h.warnings.iter().any(|w| w.contains("port 0")));
        assert!(h.warnings.iter().any(|w| w.contains("SOCKS 5") && w.contains("socks.local")));

        let mut t = sess("tel");
        t.protocol = Some("telnet".into());
        assert!(map_putty_session(&t).unwrap_err().contains("telnet"));
        let mut d = sess("Default%20Settings");
        d.host_name = None;
        assert_eq!(map_putty_session(&d).unwrap(), None);
        d.host_name = Some("".into());
        assert_eq!(map_putty_session(&d).unwrap(), None);
        let d = sess("Default%20Settings");
        assert_eq!(map_putty_session(&d).unwrap().unwrap().name, "Default Settings");
        let mut e = sess("empty");
        e.host_name = Some("  ".into());
        assert!(map_putty_session(&e).is_err());

        let rep = putty_report(&[sess("a"), t, sess("b")], "alice");
        assert_eq!(rep.source, "putty");
        assert_eq!(rep.hosts.len(), 2);
        assert_eq!(rep.skipped.len(), 1);
    }

    #[cfg(not(windows))]
    #[test]
    fn putty_unavailable_off_windows() {
        assert_eq!(read_putty_sessions().unwrap_err(), "not available on this platform");
    }

    #[test]
    fn report_serializes_camel_case() {
        let r = parse("Host a\n  ProxyJump u@b:2\n");
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["hosts"][0]["jump"], serde_json::json!({ "kind": "literal", "host": "b", "port": 2, "user": "u", "keyPath": null }));
        assert_eq!(v["hosts"][0]["jumpHops"], 1);
        assert!(v["hosts"][0]["unsupportedRoute"].is_null());
        assert!(v.get("unsupportedKeys").is_some() && v.get("localUser").is_some() && v.get("filesRead").is_some());
        assert!(v["hosts"][0].get("keyPath").is_some());
    }

    /* ---------------------------------------- Include containment (P2) */

    #[test]
    fn include_paths_validated_lexically_before_any_access() {
        // Nothing under these paths exists: every verdict is lexical.
        let home = Path::new("/nonexistent-hawser/alice");
        let ok = |p: &str| include_components(p, home, home);
        for bad in [
            "//server/share/cfg",
            "\\\\server\\share\\cfg",
            "\\\\?\\UNC\\server\\share\\cfg",
            "\\\\.\\pipe\\x",
            "/etc/ssh/ssh_config",
            "/nonexistent-hawser/bob/.ssh/config",
            "~/../bob/.ssh/config",
            "../../etc/passwd",
            "~bob/.ssh/config",
            "~",
            "..",
        ] {
            assert!(ok(bad).is_err(), "{bad} should be refused");
        }
        assert!(ok("//server/x").unwrap_err().contains("network"));
        assert!(ok("/etc/ssh/ssh_config").unwrap_err().contains("outside your home"));
        assert_eq!(
            ok("config.d/*.conf").unwrap(),
            vec![Comp::Name(".ssh".into()), Comp::Name("config.d".into()), Comp::Name("*.conf".into())]
        );
        assert_eq!(ok("~/x").unwrap(), vec![Comp::Name("x".into())]);
        assert_eq!(ok("/nonexistent-hawser/alice/.ssh/x").unwrap().len(), 2);
        // `..` that stays inside home is fine: ~/.ssh/../shared = ~/shared.
        assert!(ok("../shared").is_ok());
        assert!(is_network_path("//a/b") && is_network_path("\\\\a\\b") && !is_network_path("/a//b"));
    }

    #[test]
    fn include_network_and_outside_paths_warned_not_read() {
        let t = TempHome::new("net");
        let cfg = t.write(
            ".ssh/config",
            "Include //fileserver/share/ssh.conf\nInclude \\\\\\\\fileserver\\\\share\\\\x.conf\nInclude /etc/ssh/ssh_config\nHost ok\n",
        );
        let r = scan_ssh_config(&cfg, &t.0, "alice").unwrap();
        assert_eq!(r.hosts.len(), 1);
        assert_eq!(r.files_read.len(), 1);
        assert_eq!(r.warnings.iter().filter(|w| w.contains("network paths are not followed")).count(), 2, "{:?}", r.warnings);
        assert!(r.warnings.iter().any(|w| w.contains("/etc/ssh/ssh_config") && w.contains("outside your home")));
    }

    #[cfg(unix)]
    #[test]
    fn include_glob_walk_checks_every_component() {
        use std::os::unix::fs::symlink;
        let t = TempHome::new("walk");
        let outside = TempHome::new("walk-outside");
        outside.write("d/evil.conf", "Host evil\n");
        // A glob directory that is a symlink out of home: refused, its
        // target directory never listed for matches.
        symlink(outside.0.join("d"), t.0.join(".ssh/conf.d")).unwrap();
        // A symlink chain that stays inside home is followed.
        t.write("shared/real.conf", "Host shared\n");
        symlink("../shared/real.conf", t.0.join(".ssh/rel.conf")).unwrap();
        symlink(t.0.join(".ssh/rel.conf"), t.0.join(".ssh/abs.conf")).unwrap();
        // A link inside a glob match that points out is refused per file.
        t.write(".ssh/inc/a.conf", "Host a\n");
        symlink(outside.0.join("d/evil.conf"), t.0.join(".ssh/inc/b.conf")).unwrap();
        let cfg = t.write(".ssh/config", "Include conf.d/*\nInclude rel.conf abs.conf\nInclude inc/*.conf\nHost main\n");
        let r = scan_ssh_config(&cfg, &t.0, "alice").unwrap();
        let names: Vec<&str> = r.hosts.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(names, vec!["shared", "a", "main"], "{:?}", r.warnings);
        assert!(r.warnings.iter().any(|w| w.contains("conf.d") && w.contains("outside your home")));
        assert!(r.warnings.iter().any(|w| w.contains("b.conf") && w.contains("outside your home")));
        // The real path is what was read (no symlink in it).
        assert!(r.files_read.iter().all(|f| !f.contains("rel.conf") && !f.contains("abs.conf")));
        assert_eq!(r.files_read.iter().filter(|f| f.ends_with("shared/real.conf")).count(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn include_symlink_loop_is_bounded() {
        use std::os::unix::fs::symlink;
        let t = TempHome::new("loop");
        symlink("b", t.0.join(".ssh/a")).unwrap();
        symlink("a", t.0.join(".ssh/b")).unwrap();
        let cfg = t.write(".ssh/config", "Include a\nHost ok\n");
        let r = scan_ssh_config(&cfg, &t.0, "alice").unwrap();
        assert_eq!(r.hosts.len(), 1);
        assert!(r.warnings.iter().any(|w| w.contains("too many levels")));
    }

    #[test]
    fn include_glob_cap_applies_while_enumerating() {
        let t = TempHome::new("cap");
        for i in 0..50 {
            t.write(&format!(".ssh/many/f{i:02}"), "");
        }
        let home = t.0.clone();
        let comps = include_components("many/*", &home, &home).unwrap();
        let mut w = Walker { home: &home, entries_left: 1000, hops_left: MAX_SYMLINK_HOPS, notes: Vec::new() };
        let got = w.glob(&comps, 5);
        assert_eq!(got.len(), 5);
        // Stopped at the first match over the cap: 6 entries examined, not 50.
        assert_eq!(1000 - w.entries_left, 6);
        assert!(w.notes.iter().any(|n| n.contains("more than 5")));
        // The per-scan entry budget stops a huge directory too.
        let mut w = Walker { home: &home, entries_left: 10, hops_left: MAX_SYMLINK_HOPS, notes: Vec::new() };
        let got = w.glob(&comps, 1000);
        assert_eq!(got.len(), 10);
        assert_eq!(w.entries_left, 0);
        assert!(w.notes.iter().any(|n| n.contains("directory entries")));

        // End to end: at most MAX_FILES files per scan.
        for i in 0..(MAX_FILES + 20) {
            t.write(&format!(".ssh/wide/f{i:03}"), "");
        }
        let cfg = t.write(".ssh/config", "Include wide/*\n");
        let r = scan_ssh_config(&cfg, &t.0, "alice").unwrap();
        assert_eq!(r.files_read.len(), MAX_FILES);
        assert!(r.warnings.iter().any(|w| w.contains("matched more than")));
    }

    #[cfg(unix)]
    #[test]
    fn included_file_opened_without_following_and_checked_by_fstat() {
        use std::os::unix::fs::symlink;
        let t = TempHome::new("nofollow");
        let real = t.write(".ssh/real.conf", "Host real\n");
        let other = t.write(".ssh/other.conf", "Host other\n");
        let resolve = |p: &Path| {
            use std::os::unix::fs::MetadataExt;
            let m = fs::symlink_metadata(p).unwrap();
            Resolved { path: p.to_path_buf(), key: (m.dev(), m.ino()) }
        };
        let inc = resolve(&real);
        assert!(open_included(&inc, &t.0).is_ok());
        // Swapped for a symlink after validation: O_NOFOLLOW refuses it.
        fs::remove_file(&real).unwrap();
        symlink(&other, &real).unwrap();
        assert!(open_included(&inc, &t.0).is_err());
        // Swapped for another regular file: fstat identity differs.
        fs::remove_file(&real).unwrap();
        fs::copy(&other, &real).unwrap();
        assert!(open_included(&inc, &t.0).unwrap_err().contains("changed"));
        // A directory on the way swapped for a symlink: refused too.
        let sub = t.write(".ssh/sub/x.conf", "Host x\n");
        let inc = resolve(&sub);
        fs::rename(t.0.join(".ssh/sub"), t.0.join(".ssh/sub-moved")).unwrap();
        symlink(t.0.join(".ssh/sub-moved"), t.0.join(".ssh/sub")).unwrap();
        assert!(open_no_follow(&sub).is_err());
        assert!(open_included(&inc, &t.0).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn included_fifo_does_not_block() {
        let t = TempHome::new("fifo");
        let fifo = t.0.join(".ssh/pipe");
        let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let cfg = t.write(".ssh/config", "Include pipe\nHost ok\n");
        let r = scan_ssh_config(&cfg, &t.0, "alice").unwrap();
        assert_eq!(r.hosts.len(), 1);
        assert!(r.warnings.iter().any(|w| w.contains("not a regular file")));
        // The chosen file being a FIFO does not block either.
        assert!(scan_ssh_config(&fifo, &t.0, "alice").unwrap_err().contains("not a regular file"));
    }

    /* --------------------------------------------- routes kept honest (P2) */

    #[test]
    fn multi_hop_route_marked_unsupported() {
        let r = parse(
            "Host edge\n  HostName edge.example\n\
             Host inner\n  HostName inner.example\n  ProxyJump edge\n\
             Host twohop\n  ProxyJump edge,inner.example\n\
             Host nested\n  ProxyJump inner\n\
             Host viacmd\n  ProxyJump cmdhop\n\
             Host cmdhop\n  ProxyCommand nc %h %p\n\
             Host loopa\n  ProxyJump loopb\nHost loopb\n  ProxyJump loopa\n",
        );
        let t = host(&r, "twohop");
        assert_eq!(t.jump, Some(JumpRef::Alias { alias: "edge".into() }));
        assert_eq!(t.jump_hops, 2);
        assert!(t.unsupported_route.as_deref().unwrap().contains("2 hops"));
        // One hop written, but that hop has its own ProxyJump: two in total.
        let n = host(&r, "nested");
        assert_eq!(n.jump, Some(JumpRef::Alias { alias: "inner".into() }));
        assert_eq!(n.jump_hops, 2);
        assert!(n.unsupported_route.as_deref().unwrap().contains("inner has its own ProxyJump"));
        // A hop reached through ProxyCommand, or a loop, cannot be followed.
        assert!(host(&r, "viacmd").unsupported_route.as_deref().unwrap().contains("ProxyCommand"));
        assert!(host(&r, "loopa").unsupported_route.is_some());
        assert_eq!(host(&r, "inner").unsupported_route, None);
        assert_eq!(host(&r, "edge").jump_hops, 0);
    }

    #[test]
    fn literal_hop_through_alias_keeps_its_identity_hostname_and_port() {
        let r = parse(
            "Host bastion\n  HostName bastion.example.com\n  Port 2200\n  User jumper\n  IdentityFile ~/.ssh/bastion_%r\n\
             Host app\n  ProxyJump ops@bastion\n\
             Host app2\n  ProxyJump bastion:2222\n\
             Host *\n  IdentityFile ~/.ssh/id_default\n",
        );
        assert_eq!(
            host(&r, "app").jump,
            Some(JumpRef::Literal {
                host: "bastion.example.com".into(),
                port: 2200,
                user: Some("ops".into()),
                // %r is the hop's user, as ssh expands it for that hop.
                key_path: Some("/home/alice/.ssh/bastion_ops".into()),
            })
        );
        assert_eq!(
            host(&r, "app2").jump,
            Some(JumpRef::Literal {
                host: "bastion.example.com".into(),
                port: 2222,
                user: Some("jumper".into()),
                key_path: Some("/home/alice/.ssh/bastion_jumper".into()),
            })
        );
        // A literal address with no IdentityFile anywhere stays keyless.
        let r = parse("Host app\n  ProxyJump gw.example\n");
        assert_eq!(
            host(&r, "app").jump,
            Some(JumpRef::Literal { host: "gw.example".into(), port: 22, user: None, key_path: None })
        );
    }

}
