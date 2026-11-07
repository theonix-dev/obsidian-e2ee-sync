/**
 * IMP-5 — user-defined ignore patterns (`.syncignore` + settings textarea).
 *
 * A tiny gitignore-flavoured glob matcher with no dependencies:
 *   - one pattern per line; blank lines and `#` comments are skipped;
 *   - `**` crosses directory separators, `*` and `?` stay within one segment;
 *   - a pattern containing `/` is anchored to the vault root (a leading `/`
 *     is optional); a pattern without `/` matches a path segment at ANY depth
 *     (so `private` ignores `private/x.md` and `notes/private/y.md`);
 *   - a trailing `/` marks a directory: everything under a matching folder is
 *     ignored;
 *   - matching is case-sensitive; there is no negation (`!`) — keep the list
 *     additive so "what will sync" stays obvious.
 *
 * Ignoring never deletes: the engine simply stops planning ops for ignored
 * paths; server entries for newly-ignored paths are left untouched and the
 * journal flags them (SyncRecord.ignored).
 */

export interface IgnoreMatcher {
  /** True when this vault-relative file path must never sync. */
  isIgnored(path: string): boolean;
  /** The accepted patterns, for diagnostics. */
  readonly patterns: readonly string[];
}

interface CompiledPattern {
  source: string;
  regex: RegExp;
  /** Match against every path segment instead of the whole path. */
  segmentMatch: boolean;
  /** Match against ancestor directories only (trailing-`/` patterns). */
  dirOnly: boolean;
}

function escapeRegex(ch: string): string {
  return /[a-zA-Z0-9_-]/.test(ch) ? ch : `\\${ch}`;
}

/** Translate one glob line into a regex source. */
function globToRegexSource(glob: string): string {
  let out = '';
  let i = 0;
  while (i < glob.length) {
    // '**/' spans directories and can also match zero of them (gitignore
    // semantics): a leading '**/' is optional, a middle '/**/' collapses.
    if (glob.startsWith('**/', i)) {
      out += '(?:.*/)?';
      i += 3;
      continue;
    }
    if (glob.startsWith('/**/', i)) {
      out += '(?:/.*)?/';
      i += 4;
      continue;
    }
    if (glob[i] === '*' && glob[i + 1] === '*') {
      out += '.*';
      i += 2;
      continue;
    }
    const ch = glob[i];
    if (ch === '*') out += '[^/]*';
    else if (ch === '?') out += '[^/]';
    else out += escapeRegex(ch);
    i++;
  }
  return out;
}

function compileLine(raw: string): CompiledPattern | null {
  let pattern = raw.trim();
  if (pattern === '' || pattern.startsWith('#')) return null;
  const dirOnly = pattern.endsWith('/');
  if (dirOnly) pattern = pattern.slice(0, -1);
  if (pattern === '') return null;
  // Any inner (or leading) slash anchors the pattern to the vault root.
  const anchored = pattern.includes('/');
  pattern = pattern.replace(/^\/+/, '');
  if (pattern === '') return null;

  const source = globToRegexSource(pattern);
  const flags = '';
  if (anchored) {
    return {
      source: pattern,
      regex: new RegExp(`^${source}$`, flags),
      segmentMatch: false,
      dirOnly,
    };
  }
  // Unanchored: the pattern must equal ONE path segment (file name or folder
  // name at any depth). A trailing-slash pattern only matches directories.
  return {
    source: pattern,
    regex: new RegExp(`^${source}$`, flags),
    segmentMatch: true,
    dirOnly,
  };
}

/** Compile the newline-separated pattern list into a matcher. */
export function compileIgnorePatterns(text: string | null | undefined): IgnoreMatcher {
  const lines = (text ?? '').split(/\r?\n/);
  const compiled: CompiledPattern[] = [];
  const accepted: string[] = [];
  for (const line of lines) {
    const c = compileLine(line);
    if (c) {
      compiled.push(c);
      accepted.push(c.source + (c.dirOnly ? '/' : ''));
    }
  }

  const segmentsOf = (path: string): string[] => path.split('/').filter((s) => s !== '');
  /** Ancestor directory paths of 'a/b/c.md' -> ['a', 'a/b']. */
  const ancestorsOf = (path: string): string[] => {
    const segs = segmentsOf(path);
    const out: string[] = [];
    for (let i = 1; i < segs.length; i++) out.push(segs.slice(0, i).join('/'));
    return out;
  };

  return {
    patterns: accepted,
    isIgnored(path: string): boolean {
      if (compiled.length === 0) return false;
      const clean = path.replace(/^\/+/, '');
      if (clean === '') return false;
      const segs = segmentsOf(clean);
      const ancestors = ancestorsOf(clean);
      for (const c of compiled) {
        if (c.segmentMatch) {
          // Unanchored: test every path segment at any depth. Directory-only
          // patterns skip the file's own name — they match folders, whose
          // contents are then ignored through those segments.
          const segCount = c.dirOnly ? segs.length - 1 : segs.length;
          for (let i = 0; i < segCount; i++) {
            if (c.regex.test(segs[i])) return true;
          }
          continue;
        }
        // Anchored: the pattern addresses the whole path (file patterns) or
        // one of the ancestor directories (directory patterns).
        if (!c.dirOnly && c.regex.test(clean)) return true;
        for (const dir of ancestors) {
          if (c.regex.test(dir)) return true;
        }
      }
      return false;
    },
  };
}

/** Merge several sources (e.g. the settings textarea + `.syncignore`). */
export function ignoreMatcherFromSources(
  ...sources: Array<string | null | undefined>
): IgnoreMatcher {
  return compileIgnorePatterns(sources.filter((s) => s && s.trim() !== '').join('\n'));
}
