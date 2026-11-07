/**
 * IMP-5 — spec for the tiny glob ignore matcher (src/ignore.ts).
 */

import { finish, loadModule, ok } from './harness.mjs';

async function run() {
  const { compileIgnorePatterns, ignoreMatcherFromSources } = await loadModule('src/ignore.ts');

  /** Assert ignore decisions for one pattern list. */
  function check(source, cases, label) {
    const m = compileIgnorePatterns(source);
    for (const [path, want] of cases) {
      const got = m.isIgnored(path);
      ok(got === want, `${label}: "${path}" -> ${want ? 'ignored' : 'synced'}`, `got ${got}`);
    }
  }

  console.log('[1] plain names match any depth');
  check('private\n', [
    ['private/x.md', true],
    ['notes/private/y.md', true],
    ['private', true],
    ['x.md', false],
    ['notprivate/x.md', false],
  ], 'plain name');

  console.log('[2] star and question mark stay within one segment');
  check('*.bak\n', [
    ['notes/old.bak', true],
    ['old.bak', true],
    ['notes/sub/old.bak', true],
    ['old.backup', false],
  ], '*.bak');
  check('temp?.md\n', [
    ['tempA.md', true],
    ['tempAB.md', false],
  ], 'temp?');

  console.log('[3] anchored patterns (contain a slash)');
  check('docs/draft.md\n', [
    ['docs/draft.md', true],
    ['notes/docs/draft.md', false],
  ], 'anchored exact');
  check('/notes/*.md\n', [
    ['notes/a.md', true],
    ['notes/sub/b.md', false],
    ['other/notes/a.md', false],
  ], 'leading slash is optional anchoring');
  check('build\n', [
    ['build/output.bin', true],
    ['src/build/output.bin', true],
  ], 'folder name via ancestor match');

  console.log('[4] double-star');
  check('**/secret.md\n', [
    ['secret.md', true],
    ['a/b/secret.md', true],
  ], 'leading **/');
  check('media/**/*.tmp\n', [
    ['media/x.tmp', true],
    ['media/a/b/x.tmp', true],
    ['other/x.tmp', false],
  ], 'middle **/');
  check('vault/**/*.md\n', [
    ['vault/deep/note.md', true],
    ['other/note.md', false],
  ], 'trailing ** span');

  console.log('[5] directory-only patterns (trailing slash)');
  check('logs/\n', [
    ['logs/x.txt', true],
    ['logs', false], // dirOnly never matches a FILE of the same name
    ['logsy.txt', false],
  ], 'dirOnly');
  check('notes/tmp/\n', [
    ['notes/tmp/a.md', true],
    ['tmp/b.md', false],
  ], 'anchored dirOnly');

  console.log('[6] comments, blanks, whitespace');
  const m = compileIgnorePatterns('# comment line\n\n  private  \n   # indented comment\n*.log\n');
  ok(m.patterns.join('|') === 'private|*.log', 'comments and blanks skipped, entries trimmed',
    JSON.stringify(m.patterns));

  console.log('[7] merging sources');
  const merged = ignoreMatcherFromSources('*.bak\n', null, 'private/\n', '');
  ok(merged.isIgnored('x.bak') && merged.isIgnored('private/a.md'), 'sources merge');
  ok(!merged.isIgnored('x.md'), 'non-matching path still syncs');
  const empty = ignoreMatcherFromSources('', null, undefined);
  ok(!empty.isIgnored('anything/at/all.md'), 'empty sources ignore nothing');

  console.log('[8] hostile inputs stay inert');
  const evil = compileIgnorePatterns('*(\n[unclosed\na(b\nc\\d\n');
  ok(typeof evil.isIgnored('a(b') === 'boolean', 'regex metacharacters are escaped, never thrown');
  ok(!evil.isIgnored('../../etc/passwd'), 'traversal path simply does not match');

  finish('ignore.spec');
}

run().catch((err) => {
  console.error('spec crashed:', err);
  process.exit(1);
});
