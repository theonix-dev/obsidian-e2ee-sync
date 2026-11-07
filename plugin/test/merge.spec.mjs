/**
 * IMP-1 — spec corpus for the pure three-way Markdown merge (src/merge.ts).
 *
 * Covers the roadmap verification line — insertions/deletions/edits in
 * different regions merge cleanly, same-line edits conflict — plus identical
 * edits, EOF appends, empty base, CRLF/trailing-newline preservation, size
 * and divergence caps.
 */

import { finish, loadModule, ok, equal } from './harness.mjs';

async function run() {
  const { merge3 } = await loadModule('src/merge.ts');

  /** Shorthand: expect a clean merge equal to `want`. */
  function merged(base, ours, theirs, want, label) {
    const r = merge3(base, ours, theirs);
    ok(
      r.kind === 'merged' && r.text === want,
      label,
      `got kind=${r.kind} text=${JSON.stringify(r.kind === 'merged' ? r.text : r.reason)}`,
    );
  }

  /** Shorthand: expect a conflict with an optional reason hint. */
  function conflict(base, ours, theirs, label) {
    const r = merge3(base, ours, theirs);
    ok(r.kind === 'conflict', label, `got ${JSON.stringify(r)}`);
  }

  console.log('[1] non-overlapping edits merge cleanly');
  merged(
    'one\ntwo\nthree\n',
    'ONE\ntwo\nthree\n',            // ours edits line 1
    'one\ntwo\nTHREE\n',            // theirs edits line 3
    'ONE\ntwo\nTHREE\n',
    'edits in different regions',
  );
  merged(
    'a\nb\nc\nd\ne\n',
    'a\nINSERTED\nb\nc\nd\ne\n',    // ours inserts after a
    'a\nb\nc\nd\ne\nEXTRA\n',       // theirs appends
    'a\nINSERTED\nb\nc\nd\ne\nEXTRA\n',
    'insertions in different regions',
  );
  merged(
    'keep\ndelete-me\nkeep2\ndelete-too\n',
    'keep\nkeep2\ndelete-too\n',    // ours deletes the first target
    'keep\ndelete-me\nkeep2\n',     // theirs deletes the second
    'keep\nkeep2\n',
    'deletions in different regions',
  );
  merged(
    'header\n\nbody\n',
    'header\n\nedited body\n',
    'header edited\n\nbody\n',
    'header edited\n\nedited body\n',
    'blank-line-separated regions stay independent',
  );

  console.log('[2] overlaps conflict');
  conflict('a\nb\nc\n', 'a\nX\nc\n', 'a\nY\nc\n', 'same line edited differently');
  conflict('a\nb\nc\n', 'a\n', 'a\nb2\nc\n', 'delete vs edit of the same line');
  conflict('end\n', 'end\nours-tail\n', 'end\ntheirs-tail\n', 'different appends at EOF');
  conflict('a\nb\nc\n', 'X\n', 'Y\n', 'wholesale rewrites conflict');

  console.log('[3] agreements');
  merged('a\nb\n', 'a\nb\nEXTRA\n', 'a\nb\nEXTRA\n', 'a\nb\nEXTRA\n', 'identical edits take one copy');
  merged('a\nb\n', 'a\nb\n', 'a\nb\nTHEIRS\n', 'a\nb\nTHEIRS\n', 'untouched ours takes theirs');
  merged('a\nb\n', 'A\nb\n', 'a\nb\n', 'A\nb\n', 'untouched theirs takes ours');

  console.log('[4] insertions between stable lines are never lost');
  merged(
    'A\nB\nC\n',
    'A\nB\nC\n',                    // ours untouched
    'A\nX\nB\nC\n',                 // theirs inserts between A and B
    'A\nX\nB\nC\n',
    'insertion between stable lines survives',
  );
  merged(
    'A\nB\n',
    'A\nB\n',                       // ours untouched
    'X\nA\nB\n',                    // theirs prepends
    'X\nA\nB\n',
    'prepend survives',
  );
  conflict(
    'one\nY\nthree\n',
    'one\nY1\nthree\n',             // ours edits the middle line
    'one\nY\nY2\nthree\n',          // theirs inserts right after it — ordering ambiguous
    'edit adjacent to another side\u2019s insertion conflicts (conservative)',
  );
  conflict(
    'one\nY\nthree\n',
    'one\nY1\nthree\n',
    'one\nY2\nthree\nY3\n',
    'conflicting edit + insertion elsewhere still conflicts',
  );
  conflict(
    'A\nB\nC\nD\n',
    'A\nB1\nC\nD\n',
    'A\nB\nB2\nC\nD\n',
    'our edit of B + their duplicate-insertion of B',
  );

  console.log('[5] empty base and empty sides');
  merged('', 'line1\nline2\n', 'line1\nline2\n', 'line1\nline2\n', 'both start from empty, identical content');
  conflict('', 'mine\n', 'theirs\n', 'both start from empty, different content');
  conflict('a\nb\n', '', 'a\nb\nc\n', 'ours emptied the file, theirs appended — ordering ambiguous');
  conflict('a\nb\n', 'A\n', '', 'ours edited, theirs emptied the file');

  console.log('[6] line endings');
  merged('a\r\nb\r\n', 'A\r\nb\r\n', 'a\r\nB\r\n', 'A\r\nB\r\n', 'CRLF file stays CRLF');
  merged('a\nb\n', 'A\nb\n', 'a\nB\r\n', 'A\nB\n', 'mixed endings normalize to the local (LF) style');
  merged('a\r\nb\r\n', 'A\r\nb\r\n', 'a\nB\n', 'A\r\nB\r\n', 'local CRLF wins over remote LF');
  merged('a\nb', 'A\nb', 'a\nB', 'A\nB', 'missing trailing newline preserved');
  merged('a\nb\n', 'A\nb\n', 'a\nB\n', 'A\nB\n', 'trailing newline preserved');
  merged('a\nb\n', 'A\nb', 'a\nB\n', 'A\nB\n', 'trailing-newline state follows the tail owner (theirs again)');
  merged('a\nb\n', 'a\nb\n', 'A\nB', 'A\nB', 'trailing-newline state follows the tail owner (theirs)');

  console.log('[7] guards');
  conflict('x\n', 'y\n', 'z\n', 'oversized input conflicts (maxBytes: 0)');
  {
    const big = 'x'.repeat(513 * 1024);
    const r = merge3(big, big + 'a\n', big + 'b\n');
    ok(r.kind === 'conflict', 'over MERGE_MAX_BYTES inputs fall back to keep-both');
  }
  {
    // Divergence cap: two sides rewriting a large base in disjoint chunks.
    const n = 6000;
    const base = Array.from({ length: n }, (_, i) => `line ${i} base`).join('\n');
    const ours = Array.from({ length: n }, (_, i) => `line ${i} ours`).join('\n');
    const theirs = Array.from({ length: n }, (_, i) => `line ${i} theirs`).join('\n');
    const r = merge3(base, ours, theirs);
    ok(r.kind === 'conflict', 'too-divergent inputs fall back to keep-both (D cap)', JSON.stringify(r.reason));
  }
  {
    // Sanity: the same corpus at moderate size still merges.
    const n = 600;
    const base = Array.from({ length: n }, (_, i) => `line ${i}`).join('\n') + '\n';
    const ours = base.replace('line 10', 'line 10 (ours)');
    const theirs = base.replace('line 500', 'line 500 (theirs)');
    const r = merge3(base, ours, theirs);
    ok(
      r.kind === 'merged' && r.text.includes('line 10 (ours)') && r.text.includes('line 500 (theirs)'),
      '600-line corpus merges both single-line edits',
    );
  }
  {
    // Unicode content survives byte-for-byte.
    const base = 'α热线\n🔥 emoji\nutf-8 ✓\n';
    const r = merge3(base, base.replace('α热线', 'α热线 edited'), base.replace('utf-8 ✓', 'utf-8 ✓ ok'));
    equal(r.kind, 'merged', 'unicode corpus merges');
    ok(
      r.kind === 'merged' && r.text === 'α热线 edited\n🔥 emoji\nutf-8 ✓ ok\n',
      'unicode content preserved exactly',
    );
  }

  finish('merge.spec');
}

run().catch((err) => {
  console.error('spec crashed:', err);
  process.exit(1);
});
