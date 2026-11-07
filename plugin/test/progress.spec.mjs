/**
 * IMP-3 — spec for the pure progress formatter (src/util.ts).
 */

import { finish, loadModule, equal } from './harness.mjs';

async function run() {
  const { formatProgress } = await loadModule('src/util.ts');

  equal(
    formatProgress({ done: 12, total: 87, phase: 'push', currentPath: 'notes/x.md' }),
    '12/87 — uploading notes/x.md',
    'plain upload progress',
  );
  equal(
    formatProgress({ done: 3, total: 40, phase: 'pull', currentPath: 'media/video.bin' }),
    '3/40 — downloading media/video.bin',
    'download phase verb',
  );
  equal(
    formatProgress({ done: 1, total: 5, phase: 'conflict', currentPath: 'note.md' }),
    '1/5 — resolving note.md',
    'conflict phase verb',
  );
  equal(
    formatProgress({ done: 4, total: 9, phase: 'delete', currentPath: 'old.md' }),
    '4/9 — deleting old.md',
    'delete phase verb',
  );
  equal(
    formatProgress({ done: 0, total: 2, phase: 'unknown-phase', currentPath: 'x.md' }),
    '0/2 — syncing x.md',
    'unknown phases fall back to "syncing"',
  );
  equal(
    formatProgress({ done: 5, total: 6, phase: 'push', currentPath: 'media/big.bin', chunk: { index: 1, count: 3 } }),
    '5/6 — uploading media/big.bin (33%)',
    'chunked upload shows per-file percentage',
  );
  equal(
    formatProgress({ done: 5, total: 6, phase: 'push', currentPath: 'media/big.bin', chunk: { index: 3, count: 3 } }),
    '5/6 — uploading media/big.bin (100%)',
    'last chunk reads 100%',
  );
  equal(
    formatProgress({ done: 5, total: 6, phase: 'push', currentPath: 'media/big.bin', chunk: { index: 9, count: 3 } }),
    '5/6 — uploading media/big.bin (100%)',
    'out-of-range chunk indices clamp to 100%',
  );
  equal(
    formatProgress({ done: 5, total: 6, phase: 'push', currentPath: 'media/small.bin', chunk: { index: 1, count: 1 } }),
    '5/6 — uploading media/small.bin',
    'single-chunk transfers hide the percentage',
  );

  finish('progress.spec');
}

run().catch((err) => {
  console.error('spec crashed:', err);
  process.exit(1);
});
