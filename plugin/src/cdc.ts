/**
 * IMP-7 — content-defined chunking (CDC) with a gear rolling hash.
 *
 * Replaces the fixed 8 MiB cut of the chunked transport with content-defined
 * boundaries: the rolling hash over a 32-byte window (implicit in the 32-bit
 * gear shift) picks cut points from the PLAINTEXT, so inserting or deleting
 * bytes only shifts the boundaries near the edit — every other chunk keeps
 * byte-identical content across versions of the file.
 *
 * Why that matters: the per-file manifest the staging protocol authenticates
 * is a hash over the PLAINTEXT chunk hashes, so unchanged regions produce the
 * same manifest contributions after an edit. The journal stores
 * `baseChunkHashes` (the previous upload's plaintext chunk hashes) — the delta
 * planning primitive. (See the ROADMAP note: re-uploading only changed chunks
 * requires a future server-side reuse protocol; today every chunk is
 * re-encrypted with a fresh IV, so the win is boundary stability, retry
 * granularity at ~64 KiB and low per-chunk memory.)
 *
 * Determinism: the gear table is generated from a fixed seed at module load —
 * every device, every session produces identical boundaries for identical
 * content. No randomness, no platform variance.
 */

/** Hard bounds around the average target size. */
export const CDC_MIN_BYTES = 16 * 1024;
export const CDC_AVG_BYTES = 64 * 1024;
export const CDC_MAX_BYTES = 1024 * 1024;

/** Gear table: deterministic pseudorandom bytes seeded once (LCG, Knuth). */
const GEAR = new Int32Array(256);
(function initGear(): void {
  let x = 0x9e3779b9 | 0;
  for (let i = 0; i < 256; i++) {
    x = (Math.imul(x, 1664525) + 1013904223) | 0;
    GEAR[i] = x;
  }
})();

export interface CdcOptions {
  min?: number;
  average?: number;
  max?: number;
}

/**
 * Cut `bytes` into [start, end) slices with content-defined boundaries.
 * Guaranteed: slices are contiguous, cover the whole input, every chunk is
 * ≥ min except the trailing remainder, and no chunk exceeds max.
 */
export function cdcChunkSlices(bytes: Uint8Array, opts: CdcOptions = {}): Array<[number, number]> {
  const min = Math.max(1, opts.min ?? CDC_MIN_BYTES);
  const average = opts.average ?? CDC_AVG_BYTES;
  const max = Math.max(min, opts.max ?? CDC_MAX_BYTES);
  // Boundary mask: a boundary where the low log2(average) hash bits are zero
  // gives the geometric size distribution around the target.
  let mask = 0;
  for (let v = average; v > 1; v >>= 1) mask = (mask << 1) | 1;

  const slices: Array<[number, number]> = [];
  const n = bytes.length;
  let start = 0;
  while (start < n) {
    let end = Math.min(start + max, n);
    if (end - start > min) {
      let h = 0;
      for (let i = start + min; i < end; i++) {
        h = (Math.imul(h, 2) + GEAR[bytes[i]]) | 0;
        if ((h & mask) === 0) {
          end = i + 1;
          break;
        }
      }
    }
    slices.push([start, end]);
    start = end;
  }
  return slices;
}
