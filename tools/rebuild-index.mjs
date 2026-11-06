#!/usr/bin/env node
/**
 * Rebuild server/data/index.json from the blobs under data/files/ (PROB-9).
 *
 * If index.json is lost or corrupted while the blobs survive, this tool
 * reconstructs a consistent index: sha256 + size per blob, the file-system
 * mtime, ver 0 and keyId '' (counters and key ids are client-authenticated
 * metadata the server cannot recover from ciphertext — clients re-assert
 * them on the next push). Tombstone history cannot be recovered; orphaned
 * index entries (no blob on disk) are reported and dropped.
 *
 * Usage:
 *   node tools/rebuild-index.mjs [DATA_DIR]        default: server/data
 *   node tools/rebuild-index.mjs --dry-run [DIR]   report only, write nothing
 *
 * Run with the server STOPPED.
 */

'use strict';

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const dryRun = args.includes('--dry-run');
const dataDir = path.resolve(
  args.filter((a) => a !== '--dry-run')[0] || path.join(__dirname, '..', 'server', 'data'),
);
const filesDir = path.join(dataDir, 'files');
const indexPath = path.join(dataDir, 'index.json');

function fail(message) {
  console.error(`[fatal] ${message}`);
  process.exit(1);
}

if (!fs.existsSync(filesDir)) {
  fail(`${filesDir} does not exist — nothing to rebuild from.`);
}

// ---------------------------------------------------------------- helpers --

/** Reject anything the server's own sanitizer would reject (mirror of
 *  server.js sanitizePath): keeps the rebuilt index loadable. */
function isAcceptableRelativePath(rel) {
  if (rel.length === 0 || rel.length > 4096) return false;
  if (rel.includes('\\') || rel.includes('\0')) return false;
  const segments = rel.split('/');
  for (const segment of segments) {
    if (segment === '' || segment === '.' || segment === '..') return false;
    if (segment.length > 255) return false;
    if (/[<>:"|?*\u0000-\u001f]/.test(segment)) return false;
  }
  return true;
}

function sha256File(filePath) {
  return new Promise((resolve, reject) => {
    const hasher = crypto.createHash('sha256');
    const rs = fs.createReadStream(filePath);
    rs.on('data', (c) => hasher.update(c));
    rs.on('error', reject);
    rs.on('end', () => resolve(hasher.digest('hex')));
  });
}

async function walk(dir, base, out) {
  let entries;
  try {
    entries = await fs.promises.readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      await walk(full, base, out);
    } else if (entry.isFile()) {
      out.push(path.relative(base, full).split(path.sep).join('/'));
    }
  }
}

// ------------------------------------------------------------------ main ---

async function main() {
  const blobs = [];
  await walk(filesDir, filesDir, blobs);

  let previous = {};
  try {
    previous = JSON.parse(await fs.promises.readFile(indexPath, 'utf8'));
  } catch {
    console.log('[info] no readable index.json — starting from a clean slate');
  }

  const rebuilt = {};
  const skipped = [];
  for (const rel of blobs.sort()) {
    if (!isAcceptableRelativePath(rel)) {
      skipped.push(rel);
      continue;
    }
    const full = path.join(filesDir, rel);
    const stat = await fs.promises.stat(full);
    const hash = await sha256File(full);
    // NFC — the server canonicalizes stored paths the same way.
    rebuilt[rel.normalize('NFC')] = {
      mtime: Math.floor(stat.mtimeMs),
      size: stat.size,
      hash,
      deleted: false,
      keyId: '',
      ver: 0,
      manifest: '',
    };
  }

  const orphans = Object.entries(previous)
    .filter(([p, e]) => e && !e.deleted && !(p in rebuilt))
    .map(([p]) => p);

  console.log(`data dir   : ${dataDir}`);
  console.log(`blobs found: ${Object.keys(rebuilt).length}`);
  console.log(`skipped    : ${skipped.length}${skipped.length ? ` (${skipped.slice(0, 5).join(', ')}…)` : ''}`);
  console.log(`orphans    : ${orphans.length}${orphans.length ? ` (index entries with no blob: ${orphans.slice(0, 5).join(', ')}${orphans.length > 5 ? '…' : ''})` : ''}`);
  if (dryRun) {
    console.log('[dry-run] index.json was NOT modified.');
    return;
  }

  const tmp = `${indexPath}.rebuild-${process.pid}.tmp`;
  await fs.promises.writeFile(tmp, JSON.stringify(rebuilt, null, 2), { mode: 0o600 });
  await fs.promises.rename(tmp, indexPath);
  console.log(`[ok] wrote ${indexPath} (${Object.keys(rebuilt).length} entries).`);
  console.log('[note] version counters reset to 0 and key ids to "" — clients re-assert');
  console.log('       them on their next authenticated push; tombstone history is gone.');
}

main().catch((err) => fail(err.stack || err.message));
