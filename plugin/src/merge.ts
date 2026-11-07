/**
 * IMP-1 — dependency-free three-way line merge for Markdown.
 *
 * diff3 semantics over LINES (never bytes): base = the last synced copy held
 * in the journal, ours = the local file, theirs = the decrypted remote file.
 * Non-overlapping hunks merge cleanly; any overlap between the two sides'
 * edits is a conflict and the caller falls back to keep-both. The merge never
 * invents conflict markers inside the text — a conflicted merge IS a failed
 * merge here, because the result would be pushed to other devices as if
 * resolved.
 *
 * Bounded by design (mobile): Myers O(ND) diff with a hard D cap and a
 * plaintext size cap. Inputs past either bound (or binary-looking content)
 * are reported as conflicts — the safe fallback is always keep-both.
 *
 * Line-ending policy: content is compared WITHOUT line terminators; the
 * output is joined with the dominant EOL of the three inputs (so a CRLF file
 * stays CRLF and never mixes endings) and the trailing-newline state is
 * inherited from whichever side supplied the final region.
 */

/**
 * Largest plaintext auto-merge will touch. Larger notes keep both versions —
 * keeping the bound makes the diff work O(lines × D-cap) predictable on
 * low-memory mobile devices.
 */
export const MERGE_MAX_BYTES = 512 * 1024;
/** Myers D cap: beyond this many edits the sides are "too divergent" to trust.
 *  The backtrack trace needs ~(D+1)² ints — 2048 keeps the worst case ~17 MB. */
const MAX_DIFF_D = 2048;

export type MergeResult =
  | { kind: 'merged'; text: string }
  | { kind: 'conflict'; reason: string };

interface SplitText {
  lines: string[];
  /** True when the text ended with a line terminator. */
  trailingNewline: boolean;
  /** Dominant terminator; null when the text carries no EOL information. */
  eol: '\r\n' | '\n' | null;
}

/** Split into content lines, counting EOL styles for the dominant-EOL rule. */
function splitLines(text: string): SplitText {
  const lines: string[] = [];
  const parts = text.split('\n');
  let trailingNewline = false;
  if (parts.length > 0 && parts[parts.length - 1] === '') {
    trailingNewline = true; // text ended with '\n'
    parts.pop();
  }
  let crlf = 0;
  let lf = 0;
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i];
    const hadEol = i < parts.length - 1 || trailingNewline;
    if (part.endsWith('\r')) {
      if (hadEol) crlf++;
      lines.push(part.slice(0, -1));
    } else {
      if (hadEol) lf++;
      lines.push(part);
    }
  }
  const eol: '\r\n' | '\n' | null =
    crlf + lf === 0 ? null : crlf > lf ? '\r\n' : '\n';
  return { lines, trailingNewline, eol };
}

/**
 * Myers O(ND) diff reduced to a match map: `m[a] = b` for paired lines,
 * -1 when the line of `a` has no partner. Returns null when the edit
 * distance exceeds `maxD` (too divergent — caller falls back to keep-both).
 */
function matchMap(a: string[], b: string[], maxD: number): Int32Array | null {
  const n = a.length;
  const m = b.length;
  const out = new Int32Array(n).fill(-1);
  if (n === 0 && m === 0) return out;
  if (n === 0 || m === 0) return out; // everything inserted/deleted — still a valid script

  const dCap = Math.min(maxD, n + m);
  // V is indexed k + offset (k in -d..d). The trace keeps a per-round WINDOW
  // (|k| ≤ d) snapshot — backtracking only ever reads inside it — which caps
  // trace memory at ~(D+1)² ints instead of D × (2·dCap+1).
  const offset = dCap;
  const v = new Int32Array(2 * dCap + 1);
  const trace: Int32Array[] = [];

  let foundD = -1;
  for (let d = 0; d <= dCap; d++) {
    trace.push(v.slice(offset - d, offset + d + 1));
    for (let k = -d; k <= d; k += 2) {
      let x: number;
      if (k === -d || (k !== d && v[offset + k - 1] < v[offset + k + 1])) {
        x = v[offset + k + 1]; // down move (insertion from b)
      } else {
        x = v[offset + k - 1] + 1; // right move (deletion from a)
      }
      let y = x - k;
      while (x < n && y < m && a[x] === b[y]) {
        x++;
        y++;
      }
      v[offset + k] = x;
      if (x >= n && y >= m) {
        foundD = d;
        break;
      }
    }
    if (foundD >= 0) break;
  }
  if (foundD < 0) return null; // too divergent

  // Backtrack the greedy path into (reversed) match pairs. trace[d] is the
  // window centered on k = 0 with width 2d+1, so vt[k + d] reads k.
  const pairs: number[] = [];
  let x = n;
  let y = m;
  for (let d = foundD; d >= 0; d--) {
    if (d === 0) {
      // Round 0 is a pure diagonal walk from the origin — record its matches.
      while (x > 0 && y > 0) {
        pairs.push(x - 1, y - 1);
        x--;
        y--;
      }
      break;
    }
    const vt = trace[d];
    const k = x - y;
    const goDown = k === -d || (k !== d && vt[k - 1 + d] < vt[k + 1 + d]);
    const prevK = goDown ? k + 1 : k - 1;
    const prevX = vt[prevK + d];
    const prevY = prevX - prevK;
    while (x > prevX && y > prevY) {
      pairs.push(x - 1, y - 1);
      x--;
      y--;
    }
    x = prevX;
    y = prevY;
  }
  for (let i = 0; i < pairs.length; i += 2) {
    out[pairs[i]] = pairs[i + 1];
  }
  return out;
}

function listEquals(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/** One edit hunk of a two-way diff: replaces base[start..end) — an EMPTY base
 *  range (start === end) is a pure insertion — with side[start..end). */
interface Hunk {
  baseStart: number;
  baseEnd: number;
  sideStart: number;
  sideEnd: number;
}

/**
 * Edit hunks of the diff base→side encoded by `matches` (m[i] = partner index
 * or -1). Replacement runs cover unmatched base lines; insertion hunks cover
 * gaps between consecutive matches (incl. a leading/trailing one). Hunks of
 * one side are disjoint and sorted.
 */
function sideHunks(matches: Int32Array, side: string[]): Hunk[] {
  const hunks: Hunk[] = [];
  const n = matches.length;
  if (n === 0) {
    if (side.length > 0) {
      hunks.push({ baseStart: 0, baseEnd: 0, sideStart: 0, sideEnd: side.length });
    }
    return hunks;
  }
  // Insertions in gaps between consecutive matched lines. A gap before the
  // FIRST matched line is not an insertion when base lines 0..i-1 are
  // unmatched — the leading run's replacement already spans those side lines.
  let prevMatch = -1;
  for (let i = 0; i < n; i++) {
    const m = matches[i];
    if (m === -1) continue;
    if (i === 0) {
      if (m > 0) {
        hunks.push({ baseStart: 0, baseEnd: 0, sideStart: 0, sideEnd: m });
      }
    } else if (prevMatch >= 0 && m - prevMatch > 1) {
      hunks.push({ baseStart: i, baseEnd: i, sideStart: prevMatch + 1, sideEnd: m });
    }
    prevMatch = m;
  }
  // Trailing insertion — only when the last base line is matched (otherwise
  // the trailing run below already carries the extra side lines).
  if (matches[n - 1] !== -1 && prevMatch < side.length - 1) {
    hunks.push({ baseStart: n, baseEnd: n, sideStart: prevMatch + 1, sideEnd: side.length });
  }
  // Replacement / deletion runs of unmatched base lines.
  let i = 0;
  while (i < n) {
    if (matches[i] !== -1) {
      i++;
      continue;
    }
    let j = i;
    while (j < n && matches[j] === -1) j++;
    hunks.push({
      baseStart: i,
      baseEnd: j,
      sideStart: i === 0 ? 0 : matches[i - 1] + 1,
      sideEnd: j === n ? side.length : matches[j],
    });
    i = j;
  }
  return hunks.sort((a, b) => a.baseStart - b.baseStart || a.baseEnd - b.baseEnd);
}

/**
 * Do two hunks interact (belong to one diff3 region)? Non-empty ranges group
 * only on strict overlap — two edits of ADJACENT lines stay independent.
 * An empty range (insertion) at p groups with anything spanning p, edges
 * included — ordering next to another edit is ambiguous, so that is treated
 * as a conflict (conservative).
 */
function hunksInteract(a: Hunk, b: Hunk): boolean {
  const aEmpty = a.baseStart === a.baseEnd;
  const bEmpty = b.baseStart === b.baseEnd;
  if (aEmpty && bEmpty) return a.baseStart === b.baseStart;
  if (aEmpty) return b.baseStart <= a.baseStart && a.baseStart <= b.baseEnd;
  if (bEmpty) return a.baseStart <= b.baseStart && b.baseStart <= a.baseEnd;
  return a.baseStart < b.baseEnd && b.baseStart < a.baseEnd;
}

/** Reconstruct one side's content for the region [lo, hi) from its hunks. */
function sideContent(
  base: string[],
  side: string[],
  hunks: Hunk[],
  lo: number,
  hi: number,
): string[] {
  const out: string[] = [];
  let cursor = lo;
  for (const h of hunks) {
    if (h.baseStart > cursor) for (let k = cursor; k < h.baseStart; k++) out.push(base[k]);
    for (let k = h.sideStart; k < h.sideEnd; k++) out.push(side[k]);
    if (h.baseEnd > cursor) cursor = h.baseEnd;
  }
  for (let k = cursor; k < hi; k++) out.push(base[k]);
  return out;
}

/**
 * Three-way merge of line arrays. Returns the merged lines plus which side
 * supplied the final region (drives the trailing-newline rule), or null on
 * any overlapping edit.
 */
function mergeLines(
  base: string[],
  ours: string[],
  theirs: string[],
  mo: Int32Array,
  mt: Int32Array,
): { lines: string[]; tailSource: 'base' | 'ours' | 'theirs' } | null {
  const out: string[] = [];
  let tailSource: 'base' | 'ours' | 'theirs' = 'base';

  const emit = (lines: string[], source: 'base' | 'ours' | 'theirs'): void => {
    if (lines.length === 0) return; // empty regions never own the tail
    for (const l of lines) out.push(l);
    tailSource = source;
  };

  const oursHunks = sideHunks(mo, ours);
  const theirsHunks = sideHunks(mt, theirs);
  const all: Array<Hunk & { o: boolean }> = [
    ...oursHunks.map((h) => ({ ...h, o: true })),
    ...theirsHunks.map((h) => ({ ...h, o: false })),
  ].sort((a, b) => a.baseStart - b.baseStart || a.baseEnd - b.baseEnd);

  // Group interacting hunks into diff3 regions (connected components);
  // base lines between regions are stable and emitted verbatim.
  let prevHi = 0;
  let lo = 0;
  let hi = 0;
  let group: Array<Hunk & { o: boolean }> = [];

  const flushRegion = (): boolean => {
    if (group.length === 0) return true;
    const oGroup = group.filter((h) => h.o);
    const tGroup = group.filter((h) => !h.o);
    const bChunk = base.slice(lo, hi);
    const oChunk = sideContent(base, ours, oGroup, lo, hi);
    const tChunk = sideContent(base, theirs, tGroup, lo, hi);
    const oChanged = !listEquals(oChunk, bChunk);
    const tChanged = !listEquals(tChunk, bChunk);
    group = [];
    if (!oChanged && !tChanged) emit(bChunk, 'base');
    else if (!oChanged) emit(tChunk, 'theirs');
    else if (!tChanged) emit(oChunk, 'ours');
    else if (listEquals(oChunk, tChunk)) emit(oChunk, 'ours'); // identical edits
    else return false; // overlapping edits — keep-both fallback
    return true;
  };
  /** Close the current region, then emit the stable base gap before `next`. */
  const advance = (next: number): boolean => {
    if (group.length > 0) {
      if (!flushRegion()) return false;
      prevHi = hi; // the region's base span was consumed by flushRegion
    }
    if (next > prevHi) emit(base.slice(prevHi, next), 'base');
    prevHi = next;
    return true;
  };

  for (const h of all) {
    let touch = false;
    if (group.length > 0) {
      for (const r of group) {
        if (hunksInteract(h, r)) {
          touch = true;
          break;
        }
      }
    }
    if (touch) {
      lo = Math.min(lo, h.baseStart);
      hi = Math.max(hi, h.baseEnd);
      group.push(h);
      continue;
    }
    // Also runs for the first hunk — emits the stable base lines before it.
    if (!advance(h.baseStart)) return null;
    lo = h.baseStart;
    hi = h.baseEnd;
    group.push(h);
  }
  if (!advance(base.length)) return null;
  return { lines: out, tailSource };
}

/**
 * Merge `ours` and `theirs` against their common ancestor `base`.
 * Any overlap (or an oversized/too-divergent input) yields
 * `{ kind: 'conflict' }` — the caller keeps both versions.
 */
export function merge3(
  base: string,
  ours: string,
  theirs: string,
  opts: { maxBytes?: number } = {},
): MergeResult {
  const maxBytes = opts.maxBytes ?? MERGE_MAX_BYTES;
  if (base.length > maxBytes || ours.length > maxBytes || theirs.length > maxBytes) {
    return { kind: 'conflict', reason: 'note is too large for auto-merge' };
  }
  // Fast paths: the trivial agreements need no diff at all.
  if (ours === theirs) return { kind: 'merged', text: ours };
  if (base === ours) return { kind: 'merged', text: theirs };
  if (base === theirs) return { kind: 'merged', text: ours };

  const b = splitLines(base);
  const o = splitLines(ours);
  const t = splitLines(theirs);

  const mo = matchMap(b.lines, o.lines, MAX_DIFF_D);
  const mt = matchMap(b.lines, t.lines, MAX_DIFF_D);
  if (!mo || !mt) {
    return { kind: 'conflict', reason: 'versions are too divergent to auto-merge' };
  }
  const merged = mergeLines(b.lines, o.lines, t.lines, mo, mt);
  if (!merged) {
    return { kind: 'conflict', reason: 'both sides edited the same region' };
  }
  // Dominant EOL: prefer ours' (the local file keeps its endings), fall back
  // to theirs, then base — a file with no EOL information defaults to '\n'.
  const dominant: '\r\n' | '\n' = o.eol ?? t.eol ?? b.eol ?? '\n';
  // Trailing newline follows the side that owns the final region.
  const trailing =
    merged.tailSource === 'ours' ? o.trailingNewline
      : merged.tailSource === 'theirs' ? t.trailingNewline
        : b.trailingNewline;
  const text = merged.lines.length === 0
    ? ''
    : merged.lines.join(dominant) + (trailing ? dominant : '');
  return { kind: 'merged', text };
}

