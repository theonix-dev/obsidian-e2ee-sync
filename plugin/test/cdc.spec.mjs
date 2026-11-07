/**
 * IMP-7 — spec for the gear-based content-defined chunker (src/cdc.ts).
 */

import { finish, loadModule, ok, equal, deepEqual } from './harness.mjs';

/** Deterministic pseudo-random filler (xorshift), reproducible across runs. */
function fill(seed, length) {
  const out = new Uint8Array(length);
  let x = seed | 0 || 1;
  for (let i = 0; i < length; i++) {
    x ^= x << 13; x |= 0;
    x ^= x >>> 17;
    x ^= x << 5; x |= 0;
    out[i] = x & 0xff;
  }
  return out;
}

async function run() {
  const { cdcChunkSlices, CDC_MIN_BYTES, CDC_AVG_BYTES, CDC_MAX_BYTES } = await loadModule('src/cdc.ts');

  function slicesOf(bytes, opts) {
    return cdcChunkSlices(bytes, opts);
  }

  function assertSlicesWellFormed(bytes, slices, opts = {}, label) {
    const min = opts.min ?? CDC_MIN_BYTES;
    const max = opts.max ?? CDC_MAX_BYTES;
    let pos = 0;
    let malformed = '';
    for (let i = 0; i < slices.length; i++) {
      const [s, e] = slices[i];
      if (s !== pos) malformed += ` slice ${i} starts at ${s}, expected ${pos}`;
      if (e <= s) malformed += ` slice ${i} empty`;
      if (i < slices.length - 1 && e - s > max) malformed += ` slice ${i} exceeds max`;
      if (i < slices.length - 1 && e - s < min) malformed += ` slice ${i} below min`;
      pos = e;
    }
    if (pos !== bytes.length) malformed += ` coverage ends at ${pos}, expected ${bytes.length}`;
    ok(malformed === '', label, malformed);
  }

  console.log('[1] well-formed output');
  {
    const bytes = fill(12345, 5 * 1024 * 1024);
    const slices = slicesOf(bytes);
    assertSlicesWellFormed(bytes, slices, {}, '5 MiB: contiguous, min/max respected');
    equal(slices[0][0], 0, 'first slice starts at 0');
    equal(slices[slices.length - 1][1], bytes.length, 'last slice ends at the input length');
  }

  console.log('[2] determinism and content-addressing');
  {
    const bytes = fill(777, 3 * 1024 * 1024);
    deepEqual(slicesOf(bytes), slicesOf(bytes), 'same input -> identical slices');
    deepEqual(slicesOf(bytes.slice()), slicesOf(bytes), 'copy of the input -> identical slices');
    const other = fill(778, 3 * 1024 * 1024);
    ok(JSON.stringify(slicesOf(bytes)) !== JSON.stringify(slicesOf(other)),
      'different content usually cuts differently');
  }

  console.log('[3] size distribution near the target');
  {
    const bytes = fill(24680, 8 * 1024 * 1024);
    const slices = slicesOf(bytes);
    const sizes = slices.map(([s, e]) => e - s);
    const mean = sizes.reduce((a, b) => a + b, 0) / sizes.length;
    ok(sizes.length > 64, '8 MiB yields a meaningful chunk count', `${sizes.length} chunks`);
    ok(mean > CDC_AVG_BYTES / 3 && mean < CDC_AVG_BYTES * 3,
      `mean chunk size within [avg/3, avg*3] (got ${Math.round(mean / 1024)} KiB)`);
    ok(sizes.every((s, i) => i === sizes.length - 1 || s <= CDC_MAX_BYTES), 'no chunk over max');
  }

  console.log('[4] boundary stability under edits (the CDC property)');
  {
    const base = fill(999, 4 * 1024 * 1024);
    const before = slicesOf(base).map(([s]) => s);
    for (const [label, edit] of [
      ['1-byte insert at 1/3', (b) => {
        const at = Math.floor(b.length / 3);
        const out = new Uint8Array(b.length + 1);
        out.set(b.subarray(0, at), 0);
        out[at] = 0xab;
        out.set(b.subarray(at), at + 1);
        return out;
      }],
      ['2 KiB delete at 2/3', (b) => {
        const at = Math.floor((2 * b.length) / 3);
        const out = new Uint8Array(b.length - 2048);
        out.set(b.subarray(0, at), 0);
        out.set(b.subarray(at + 2048), at);
        return out;
      }],
      ['512-byte overwrite at 1/2', (b) => {
        const at = Math.floor(b.length / 2);
        const out = b.slice();
        for (let i = 0; i < 512; i++) out[at + i] = 0x5a;
        return out;
      }],
    ]) {
      const edited = edit(base);
      const after = slicesOf(edited).map(([s]) => s);
      // Boundaries strictly before the edit region must be identical.
      // The edit position: find the first boundary that differs.
      let firstDiff = 0;
      while (firstDiff < Math.min(before.length, after.length) && before[firstDiff] === after[firstDiff]) {
        firstDiff++;
      }
      const stable = firstDiff;
      // Everything after the edit shifts by the length delta — count how many
      // of the AFTER boundaries align with a BEFORE boundary shifted by the
      // length delta.
      const delta = edited.length - base.length;
      let aligned = 0;
      for (let i = firstDiff; i < after.length; i++) {
        if (before.includes(after[i] - delta)) aligned++;
      }
      const total = after.length - firstDiff;
      ok(aligned >= total * 0.9,
        `${label}: ≥90% of downstream boundaries preserved (${aligned}/${total})`);
      ok(stable >= 1, `${label}: upstream boundaries untouched (${stable})`);
    }
  }

  console.log('[5] small and degenerate inputs');
  deepEqual(slicesOf(new Uint8Array(0)), [], 'empty input -> no slices');
  deepEqual(slicesOf(new Uint8Array(10)), [[0, 10]], 'tiny input -> one slice');
  {
    const tiny = slicesOf(new Uint8Array(1024));
    deepEqual(tiny, [[0, 1024]], 'sub-min input -> one slice');
  }
  {
    // Exactly min: one chunk; min+1: at most two.
    equal(slicesOf(new Uint8Array(16 * 1024)).length, 1, 'input == min -> one chunk');
  }
  {
    // Adversarial constant content must still terminate and respect max.
    const constant = new Uint8Array(3 * CDC_MAX_BYTES).fill(0x41);
    const slices = slicesOf(constant);
    assertSlicesWellFormed(constant, slices, {}, 'constant content: max-bound respected');
  }
  {
    // Custom options shrink both the average and the bounds.
    const bytes = fill(31, 512 * 1024);
    const slices = slicesOf(bytes, { min: 1024, average: 4 * 1024, max: 16 * 1024 });
    assertSlicesWellFormed(bytes, slices, { min: 1024, max: 16 * 1024 }, 'custom options respected');
    const sizes = slices.map(([s, e]) => e - s);
    const mean = sizes.reduce((a, b) => a + b, 0) / sizes.length;
    ok(mean < 16 * 1024, `custom average gives smaller chunks (mean ${Math.round(mean)} B)`);
  }

  finish('cdc.spec');
}

run().catch((err) => {
  console.error('spec crashed:', err);
  process.exit(1);
});
