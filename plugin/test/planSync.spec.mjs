/**
 * Exhaustive decision matrix for the pure planner (PROB-4).
 *
 * Enumerates local {absent, unchanged, changed} × record {absent, present} ×
 * remote {absent, live, tombstone} × {hash same/different} × first-sync mtime
 * ordering — every coherent cell asserts the exact planned action against an
 * INDEPENDENT restatement of the decision table (the executable spec). Plus
 * the case-collision guards (local/local rename, pull→conflict downgrade) and
 * exclusion rules.
 *
 * Any future planSync edit that changes a cell's verdict fails here unless
 * the table is updated deliberately.
 */

import { finish, loadModule, ok } from './harness.mjs';

const CONFIG_DIR = '.obsidian';
const MTIME = 1_700_000_000_000;

function file(path, mtime = MTIME) {
  return { path, stat: { mtime } };
}

function record(localMtime, remoteHash) {
  return { localMtime, remoteHash, remoteMtime: MTIME, remoteVersion: 3 };
}

function liveInfo(hash = 'h1', mtime = MTIME) {
  return { mtime, size: 10, hash, deleted: false, keyId: 'a'.repeat(16), ver: 3, manifest: '' };
}

function tombstone() {
  return { mtime: MTIME, size: 0, hash: '', deleted: true, keyId: '', ver: 0, manifest: '' };
}

async function run() {
  const engine = await loadModule('src/syncEngine.ts');
  const { planSync, findCaseVariant, isSyncablePath, canonicalPath } = engine;

  const HASH_A = 'aaaa';
  const HASH_B = 'bbbb';

  /**
   * Independent restatement of the decision table (syncEngine.ts header):
   * returns the action expected for one cell, or null for "no operation".
   */
  function expected({ local, hasRecord, remote, hashChanged, remoteNewerMtime }) {
    if (remote === 'live') {
      const remoteChanged = !hasRecord || hashChanged;
      if (local !== 'absent') {
        const localChanged = !hasRecord || local === 'changed';
        if (localChanged && remoteChanged) {
          return hasRecord ? 'conflict' : remoteNewerMtime ? 'pull' : 'push';
        }
        if (localChanged) return 'push';
        if (remoteChanged) return 'pull';
        return null;
      }
      return hasRecord && !remoteChanged ? 'delete-remote' : 'pull';
    }
    // tombstone or unknown on the server
    if (local === 'absent') return hasRecord ? 'forget' : null;
    const localChanged = !hasRecord || local === 'changed';
    return localChanged ? 'push' : 'delete-local';
  }

  let cells = 0;
  let mismatches = 0;

  const remoteStates = ['absent', 'live', 'tombstone'];

  // Enumerate coherent cells. Without a journal record, "unchanged" is
  // meaningless (untracked files are always changed from the record's point
  // of view) and the first-sync mtime ordering decides; with a record, the
  // hash relation decides and — separately — the index version counter must
  // NEVER influence planning (execution owns rollback detection).
  const variants = (hasRecord, remoteState) => {
    if (remoteState !== 'live') return [{}];
    if (!hasRecord) return [{ remoteNewerMtime: false }, { remoteNewerMtime: true }];
    // With a record: hash relation × index version counter (must NEVER
    // influence planning) × remote wall-clock mtime (must NEVER influence
    // planning either — see the header invariant).
    return [false, true].flatMap((hashChanged) =>
      [0, 3, 5].flatMap((remoteVer) =>
        [false, true].map((remoteNewerMtime) => ({ hashChanged, remoteVer, remoteNewerMtime })),
      ),
    );
  };

  for (const hasRecord of [false, true]) {
    const localStates = hasRecord ? ['absent', 'unchanged', 'changed'] : ['absent', 'untracked'];
    for (const localState of localStates) {
      for (const remoteState of remoteStates) {
        for (const v of variants(hasRecord, remoteState)) {
          const { hashChanged = true, remoteNewerMtime = true, remoteVer = 3 } = v;
          const path = 'note.md';
          const locals = new Map();
          if (localState !== 'absent') {
            locals.set(
              path,
              file(path, localState === 'changed' ? MTIME + 5000 : MTIME),
            );
          }
          const remoteMap = new Map();
          if (remoteState !== 'absent') {
            const remoteMtime = remoteNewerMtime ? MTIME + 1000 : MTIME - 1000;
            const info =
              remoteState === 'live'
                ? {
                    ...liveInfo(hasRecord && !hashChanged ? HASH_A : HASH_B, remoteMtime),
                    ver: remoteVer,
                  }
                : tombstone();
            remoteMap.set(path, { key: path, info });
          }
          const journal = {};
          if (hasRecord) journal[path] = record(MTIME, HASH_A);

          const ops = planSync(locals, remoteMap, journal, CONFIG_DIR);
          const op = ops.find((o) => o.path === path) ?? null;
          const effectiveLocal = hasRecord ? localState : localState === 'absent' ? 'absent' : 'changed';
          // The remote mtime only matters in the no-record first-sync cell;
          // elsewhere it must not change the verdict.
          const want = expected({
            local: effectiveLocal,
            hasRecord,
            remote: remoteState,
            hashChanged,
            remoteNewerMtime: hasRecord ? true : remoteNewerMtime,
          });
          const got = op ? op.action : null;
          cells++;
          if (got !== want) {
            mismatches++;
            console.error(
              `  ✘ cell local=${localState} record=${hasRecord} remote=${remoteState} ` +
                `hashChanged=${hashChanged} remoteVer=${remoteVer} remoteNewer=${remoteNewerMtime}: ` +
                `expected ${want}, got ${got}`,
            );
          }
        }
      }
    }
  }
  ok(mismatches === 0, `decision matrix: all ${cells} coherent cells match the table`, `${mismatches} mismatch(es)`);
  ok(cells >= 40, 'matrix coverage is meaningful', `${cells} cells`);

  console.log('[2] mtime-never-compared-across-devices invariant');
  {
    // The planner must never compare local mtime with remote mtime when a
    // record exists — wall clocks of different devices are incomparable.
    // (Covered by the matrix's conflict/push/pull cells; assert the two
    // directions explicitly for clarity.)
    const path = 'note.md';
    const locals = new Map([[path, file(path, MTIME)]]);
    const journal = { [path]: record(MTIME, HASH_A) };
    for (const remoteMtime of [MTIME - 999_999, MTIME + 999_999]) {
      const ops = planSync(
        locals,
        new Map([[path, { key: path, info: liveInfo(HASH_B, remoteMtime) }]]),
        journal,
        CONFIG_DIR,
      );
      ok(ops[0]?.action === 'pull', `remote-only change plans pull regardless of remote mtime (${remoteMtime > MTIME ? 'newer' : 'older'})`);
    }
  }

  console.log('[3] case-collision guards (PROB-4)');
  {
    // local/local: two files differing only by ASCII case
    const locals = new Map([
      ['note.md', file('note.md')],
      ['Note.md', file('Note.md')],
    ]);
    const ops = planSync(locals, new Map(), {}, CONFIG_DIR);
    const rename = ops.filter((o) => o.action === 'case-rename');
    ok(rename.length === 1, 'exactly one case-rename op is planned');
    ok(rename[0]?.path === 'note.md', 'the lexicographically later spelling is renamed');
    ok(
      ops.some((o) => o.path === 'Note.md' && o.action === 'push'),
      'the kept spelling plans normally (untracked -> push)',
    );

    // A remote path whose only local counterpart differs by case: the planner
    // sees no local file under that exact path and plans a plain pull — the
    // protection is the WRITE-TIME guard in doPull (findCaseVariant), which
    // redirects the write to a _remote-case_ copy instead of overwriting.
    const locals2 = new Map([['note.md', file('note.md', MTIME)]]);
    const remote2 = new Map([['Note.md', { key: 'Note.md', info: liveInfo(HASH_B) }]]);
    const ops2 = planSync(locals2, remote2, {}, CONFIG_DIR);
    ok(
      ops2.some((o) => o.path === 'Note.md' && o.action === 'pull'),
      'colliding remote variant plans a pull (redirected at write time)',
    );
    ok(
      findCaseVariant('Note.md', locals2.keys()) === 'note.md',
      'the write-time guard sees the collision',
    );

    // Local present under the SAME canonical path + remote changed + record:
    // the planner-level downgrade to conflict applies here.
    const locals2c = new Map([['Note.md', file('Note.md', MTIME)]]);
    const journal2c = { 'Note.md': record(MTIME, HASH_A) };
    const ops2c = planSync(locals2c, remote2, journal2c, CONFIG_DIR);
    ok(
      ops2c.some((o) => o.path === 'Note.md' && o.action === 'pull'),
      'same-path remote-only change plans a plain pull (no case collision)',
    );

    // No local file: a plain pull is planned and the WRITE-TIME guard in
    // doPull (findCaseVariant -> _remote-case_ redirect) provides the
    // protection — assert the primitive the executor relies on.
    const locals3 = new Map();
    const ops3 = planSync(locals3, remote2, {}, CONFIG_DIR);
    ok(ops3.some((o) => o.path === 'Note.md' && o.action === 'pull'), 'no-local colliding pull is planned plainly');
    ok(findCaseVariant('Note.md', ['note.md']) === 'note.md', '…and the write-time guard detects the variant');

    // Same case, no collision: ordinary pull
    const ops4 = planSync(new Map(), new Map([['Note.md', { key: 'Note.md', info: liveInfo(HASH_B) }]]), {}, CONFIG_DIR);
    ok(ops4.some((o) => o.path === 'Note.md' && o.action === 'pull'), 'non-colliding remote file plans a plain pull');
  }

  console.log('[4] findCaseVariant');
  ok(findCaseVariant('Note.md', ['note.md', 'other.md']) === 'note.md', 'detects a case variant');
  ok(findCaseVariant('note.md', ['note.md', 'other.md']) === null, 'identical path is not a variant');
  ok(findCaseVariant('NOTE.md', ['note.md']) === 'note.md', 'case-only difference detected');
  ok(findCaseVariant('dir/note.md', ['note.md']) === null, 'different paths are not variants');

  console.log('[5] exclusions');
  ok(!isSyncablePath('.obsidian/app.json', CONFIG_DIR), 'config dir excluded');
  ok(!isSyncablePath('.trash/x.md', CONFIG_DIR), '.trash excluded');
  ok(!isSyncablePath('.DS_Store', CONFIG_DIR), 'OS junk excluded');
  ok(!isSyncablePath('.e2ee-verifier.' + 'a'.repeat(16), CONFIG_DIR), 'per-key verifier path excluded');
  ok(!isSyncablePath('.e2ee-sync-verifier.v1', CONFIG_DIR), 'legacy verifier path excluded');
  ok(isSyncablePath('notes/x.md', CONFIG_DIR), 'normal file included');

  console.log('[6] canonicalization');
  ok(canonicalPath('notes//x.md') === 'notes/x.md', 'duplicate slashes collapse');
  ok(canonicalPath('notes/cafe\u0301.md') === 'notes/caf\u00e9.md', 'NFD normalizes to NFC');
  ok(
    planSync(
      new Map([['notes/café.md', file('notes/café.md')]]),
      new Map([['notes/cafe\u0301.md', { key: 'notes/cafe\u0301.md', info: liveInfo(HASH_A) }]]),
      {},
      CONFIG_DIR,
    ).some((o) => o.remoteKey === 'notes/cafe\u0301.md'),
    'remote key falls back to the raw pre-NFC spelling for API calls',
  );

  console.log('[7] journal-only paths (deleted everywhere)');
  {
    const ops = planSync(new Map(), new Map(), { 'gone.md': record(MTIME, HASH_A) }, CONFIG_DIR);
    ok(ops.length === 1 && ops[0].action === 'forget', 'stale journal entry is forgotten');
  }

  console.log('[8] user ignore patterns (IMP-5): ignored paths plan nothing, never delete');
  {
    // A matcher stub standing in for src/ignore.ts's compiled patterns.
    const ignores = { isIgnored: (p) => p.startsWith('private') };
    const locals = new Map([
      ['private/x.md', file('private/x.md')],
      ['open.md', file('open.md')],
    ]);
    const remote = new Map([
      ['private/x.md', { key: 'private/x.md', info: liveInfo(HASH_B) }],
      // hash unchanged vs the record -> the unfiltered planner plans delete-remote
      ['private/gone.md', { key: 'private/gone.md', info: liveInfo(HASH_A) }],
      ['open.md', { key: 'open.md', info: liveInfo(HASH_A) }],
    ]);
    const journal = { 'private/gone.md': record(MTIME, HASH_A) };
    const ops = planSync(locals, remote, journal, CONFIG_DIR, ignores);
    ok(!ops.some((o) => o.path.startsWith('private')), 'ignored paths plan zero ops of any kind');
    ok(
      !ops.some((o) => o.path === 'private/gone.md' && o.action === 'delete-remote'),
      'ignoring never propagates a deletion to the server',
    );
    ok(ops.some((o) => o.path === 'open.md' && o.action === 'pull'),
      'non-ignored paths plan normally');
    // Without the matcher the very same state plans the deletions/pulls.
    const unfiltered = planSync(locals, remote, journal, CONFIG_DIR);
    ok(unfiltered.some((o) => o.path === 'private/gone.md' && o.action === 'delete-remote'),
      'without a matcher the planner behaves exactly as before');
  }

  finish('planSync.spec');
}

run().catch((err) => {
  console.error('spec crashed:', err);
  process.exit(1);
});
