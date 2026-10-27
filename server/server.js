#!/usr/bin/env node
/**
 * Obsidian E2EE Sync — "dumb storage" server.
 *
 * Zero npm dependencies: Node.js built-ins only (Node >= 18).
 *
 * The server stores opaque encrypted blobs and knows NOTHING about keys or
 * plaintext. It exposes:
 *
 *   GET    /api/meta                  -> { vaultId }            (stable KDF salt source)
 *   GET    /api/index                 -> full index incl. tombstones
 *   POST   /api/upload                -> binary body + X-File-Path / X-Client-Mtime /
 *                                        X-Cipher-Hash headers; atomic tmp+rename write
 *   GET    /api/download?path=<enc>   -> streams the encrypted blob
 *   DELETE /api/delete?path=<enc>     -> removes the blob, keeps a tombstone in the index
 *   GET    /api/health                -> unauthenticated liveness probe
 *
 * All /api/* routes except /health require `Authorization: Bearer <AUTH_TOKEN>`
 * and are compared in constant time.
 *
 * Configuration (environment variables):
 *   AUTH_TOKEN          required, >= 16 chars   bearer token clients must present
 *   PORT                default 8080
 *   HOST                default 127.0.0.1 (put nginx/TLS in front for remote access)
 *   DATA_DIR            default ./data
 *   MAX_BODY_BYTES      default 256 MiB
 *   TOMBSTONE_TTL_DAYS  default 0 (keep tombstones forever; see README before enabling GC)
 */

'use strict';

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');

// ---------------------------------------------------------------- config ----

const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || '127.0.0.1';
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
const AUTH_TOKEN = process.env.AUTH_TOKEN || '';
const MAX_BODY_BYTES = Number(process.env.MAX_BODY_BYTES || 256 * 1024 * 1024);
const TOMBSTONE_TTL_DAYS = Number(process.env.TOMBSTONE_TTL_DAYS || 0);

if (!AUTH_TOKEN || AUTH_TOKEN.length < 16) {
  console.error(
    '[fatal] AUTH_TOKEN is missing or shorter than 16 characters.\n' +
      '        Generate one with:  openssl rand -hex 32\n' +
      '        Then start with:    AUTH_TOKEN=<token> node server.js',
  );
  process.exit(1);
}

const FILES_DIR = path.join(DATA_DIR, 'files');
const META_PATH = path.join(DATA_DIR, 'meta.json');
const INDEX_PATH = path.join(DATA_DIR, 'index.json');

// ------------------------------------------------------------------ auth ----

const TOKEN_DIGEST = crypto.createHash('sha256').update(AUTH_TOKEN, 'utf8').digest();

function isAuthorized(req) {
  const header = req.headers['authorization'] || '';
  const match = /^Bearer\s+(.+)$/.exec(header);
  if (!match) return false;
  // Hash both sides first: timingSafeEqual requires equal lengths and hashing
  // avoids leaking the token length.
  const digest = crypto.createHash('sha256').update(match[1], 'utf8').digest();
  return digest.length === TOKEN_DIGEST.length && crypto.timingSafeEqual(digest, TOKEN_DIGEST);
}

// ---------------------------------------------------------------- helpers ---

class HttpError extends Error {
  constructor(statusCode, message) {
    super(message);
    this.statusCode = statusCode;
  }
}

function sendJson(res, statusCode, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

/**
 * Normalize a client-supplied vault path to a safe relative path.
 * Returns null for anything suspicious (traversal, absolute paths, control
 * characters, Windows-reserved characters, over-long segments).
 */
function sanitizePath(raw) {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > 4096) return null;
  if (raw.includes('\\') || raw.includes('\0')) return null;
  const segments = raw.split('/').filter((s) => s.length > 0);
  if (segments.length === 0) return null;
  for (const segment of segments) {
    if (segment === '.' || segment === '..') return null;
    if (segment.length > 255) return null;
    if (/[<>:"|?*\u0000-\u001f]/.test(segment)) return null;
  }
  return segments.join('/');
}

/** Decode a URL-encoded path coming from a header or query parameter. */
function decodePathValue(value) {
  if (value === undefined || value === null) return undefined;
  try {
    return decodeURIComponent(String(value));
  } catch {
    throw new HttpError(400, 'Path header/query is not validly URL-encoded.');
  }
}

// ------------------------------------------------------------------ state ---

/** @type {{ vaultId: string } | null} */
let meta = null;
/** @type {Map<string, {mtime:number,size:number,hash:string,deleted:boolean}>} */
const index = new Map();

async function writeJsonAtomic(filePath, data) {
  const tmp = `${filePath}.${process.pid}.${Date.now()}.${crypto.randomBytes(4).toString('hex')}.tmp`;
  await fsp.writeFile(tmp, JSON.stringify(data), { mode: 0o600 });
  await fsp.rename(tmp, filePath); // atomic on POSIX
}

// Serialized persistence so concurrent requests cannot interleave partial files.
let persistChain = Promise.resolve();
function persistJson(filePath, data) {
  persistChain = persistChain
    .then(() => writeJsonAtomic(filePath, data))
    .catch((err) => console.error(`[warn] failed to persist ${path.basename(filePath)}: ${err.message}`));
  return persistChain;
}
const persistMeta = () => persistJson(META_PATH, meta);
const persistIndex = () => persistJson(INDEX_PATH, Object.fromEntries(index));

async function loadState() {
  await fsp.mkdir(FILES_DIR, { recursive: true, mode: 0o700 });

  try {
    meta = JSON.parse(await fsp.readFile(META_PATH, 'utf8'));
  } catch {
    meta = { vaultId: crypto.randomBytes(16).toString('hex') };
    await writeJsonAtomic(META_PATH, meta);
  }
  if (!meta || typeof meta.vaultId !== 'string' || meta.vaultId.length < 8) {
    throw new Error(`${META_PATH} exists but has no valid vaultId — refusing to overwrite it.`);
  }

  try {
    const raw = JSON.parse(await fsp.readFile(INDEX_PATH, 'utf8'));
    for (const [filePath, entry] of Object.entries(raw || {})) {
      if (typeof filePath === 'string' && entry && typeof entry === 'object') {
        index.set(filePath, {
          mtime: Number(entry.mtime) || 0,
          size: Number(entry.size) || 0,
          hash: String(entry.hash || ''),
          deleted: Boolean(entry.deleted),
        });
      }
    }
  } catch {
    // No index yet — start empty. Existing files on disk are not resurrected;
    // clients will re-upload whatever they still have.
  }
}

// ------------------------------------------------------------ body stream ---

/**
 * Stream the request body into a temp file while hashing it. Enforces the size
 * cap so a rogue client cannot fill the disk with a single request.
 */
function streamBodyToFile(req, tmpPath, maxBytes) {
  return new Promise((resolve, reject) => {
    const ws = fs.createWriteStream(tmpPath, { mode: 0o600 });
    const hasher = crypto.createHash('sha256');
    let size = 0;
    let settled = false;

    const fail = (err) => {
      if (settled) return;
      settled = true;
      req.destroy();
      ws.destroy();
      fsp.unlink(tmpPath).catch(() => {});
      reject(err);
    };

    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > maxBytes) {
        fail(new HttpError(413, `Body exceeds the ${maxBytes}-byte limit.`));
        return;
      }
      hasher.update(chunk);
      if (!ws.write(chunk)) req.pause();
    });
    ws.on('drain', () => req.resume());
    req.on('end', () => {
      ws.end(() => {
        if (settled) return;
        settled = true;
        resolve({ size, hash: hasher.digest('hex') });
      });
    });
    req.on('error', fail);
    ws.on('error', fail);
  });
}

// ---------------------------------------------------------------- routes ----

async function handleUpload(req, res, url) {
  const rawPath =
    req.headers['x-file-path'] !== undefined
      ? decodePathValue(req.headers['x-file-path'])
      : url.searchParams.get('path');

  if (rawPath === undefined) throw new HttpError(400, 'Missing path (X-File-Path header or ?path=).');
  const clientPath = sanitizePath(rawPath);
  if (!clientPath) throw new HttpError(400, 'Invalid file path.');

  const rawMtime = req.headers['x-client-mtime'] ?? url.searchParams.get('mtime') ?? Date.now();
  const clientMtime = Math.floor(Number(rawMtime));
  const expectedHash = String(req.headers['x-cipher-hash'] ?? url.searchParams.get('hash') ?? '').toLowerCase();

  const target = path.join(FILES_DIR, ...clientPath.split('/'));
  const tmp = path.join(DATA_DIR, `upload-${process.pid}-${crypto.randomBytes(6).toString('hex')}.tmp`);

  const { size, hash } = await streamBodyToFile(req, tmp, MAX_BODY_BYTES);
  if (expectedHash && expectedHash !== hash) {
    await fsp.unlink(tmp).catch(() => {});
    throw new HttpError(400, 'Cipher hash mismatch — upload corrupted in transit?');
  }

  await fsp.mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
  await fsp.rename(tmp, target); // atomic publish

  const entry = {
    mtime: Number.isFinite(clientMtime) && clientMtime > 0 ? clientMtime : Date.now(),
    size,
    hash,
    deleted: false, // uploading clears any tombstone
  };
  index.set(clientPath, entry);
  persistIndex();
  sendJson(res, 200, { path: clientPath, ...entry });
}

async function handleDownload(req, res, url) {
  const rawPath = url.searchParams.get('path');
  if (rawPath === null) throw new HttpError(400, 'Missing ?path= parameter.');
  const clientPath = sanitizePath(rawPath);
  if (!clientPath) throw new HttpError(400, 'Invalid file path.');

  const entry = index.get(clientPath);
  if (!entry || entry.deleted) throw new HttpError(404, 'File not found.');

  const target = path.join(FILES_DIR, ...clientPath.split('/'));
  let stat;
  try {
    stat = await fsp.stat(target);
  } catch {
    throw new HttpError(404, 'File not found.');
  }

  res.writeHead(200, {
    'Content-Type': 'application/octet-stream',
    'Content-Length': stat.size,
    'X-File-Mtime': String(entry.mtime),
    'Cache-Control': 'no-store',
  });
  const stream = fs.createReadStream(target);
  stream.on('error', () => res.destroy());
  stream.pipe(res);
}

async function handleDelete(req, res, url) {
  const rawPath = url.searchParams.get('path');
  if (rawPath === null) throw new HttpError(400, 'Missing ?path= parameter.');
  const clientPath = sanitizePath(rawPath);
  if (!clientPath) throw new HttpError(400, 'Invalid file path.');

  const entry = index.get(clientPath);
  if (!entry) throw new HttpError(404, 'Unknown path.');

  if (!entry.deleted) {
    const target = path.join(FILES_DIR, ...clientPath.split('/'));
    try {
      await fsp.unlink(target);
    } catch (err) {
      if (err.code !== 'ENOENT') throw err;
    }
    // Tombstone: keep the path in the index so every other device learns about
    // the deletion; mtime becomes the deletion time.
    const tombstone = { mtime: Date.now(), size: 0, hash: '', deleted: true };
    index.set(clientPath, tombstone);
    persistIndex();
    sendJson(res, 200, { path: clientPath, ...tombstone });
    return;
  }

  // Already tombstoned — idempotent.
  sendJson(res, 200, { path: clientPath, ...entry });
}

function gcTombstones() {
  if (!(TOMBSTONE_TTL_DAYS > 0)) return;
  const cutoff = Date.now() - TOMBSTONE_TTL_DAYS * 86400_000;
  let removed = 0;
  for (const [filePath, entry] of index) {
    if (entry.deleted && entry.mtime < cutoff) {
      index.delete(filePath);
      removed++;
    }
  }
  if (removed > 0) {
    persistIndex();
    console.log(`[gc] removed ${removed} expired tombstone(s)`);
  }
}

// ------------------------------------------------------------------ server --

const server = http.createServer((req, res) => {
  (async () => {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const route = `${req.method} ${url.pathname}`;

    // Liveness probe (no auth) — useful for load balancers and monitoring.
    if (route === 'GET /api/health') {
      return sendJson(res, 200, { ok: true });
    }

    if (!isAuthorized(req)) {
      return sendJson(res, 401, { error: 'Unauthorized' });
    }

    switch (route) {
      case 'GET /api/meta':
        return sendJson(res, 200, { vaultId: meta.vaultId });
      case 'GET /api/index':
        return sendJson(res, 200, { files: Object.fromEntries(index) });
      case 'POST /api/upload':
        return await handleUpload(req, res, url);
      case 'GET /api/download':
        return await handleDownload(req, res, url);
      case 'DELETE /api/delete':
        return await handleDelete(req, res, url);
      default:
        return sendJson(res, 404, { error: 'Not found' });
    }
  })().catch((err) => {
    const status = err instanceof HttpError ? err.statusCode : 500;
    if (status >= 500) console.error(`[error] ${req.method} ${req.url}:`, err.stack || err.message);
    if (!res.headersSent) sendJson(res, status, { error: err.message || 'Internal error' });
    else res.destroy();
  });
});

server.headersTimeout = 60_000;
server.requestTimeout = 0; // long uploads: governed by MAX_BODY_BYTES, not a timer

// ------------------------------------------------------------------ main ----

async function main() {
  await loadState();
  if (TOMBSTONE_TTL_DAYS > 0) {
    gcTombstones();
    setInterval(gcTombstones, 24 * 3600 * 1000).unref();
  }
  server.listen(PORT, HOST, () => {
    console.log(`[obsidian-e2ee-sync] listening on http://${HOST}:${PORT}`);
    console.log(`[obsidian-e2ee-sync] data dir: ${DATA_DIR} (${index.size} index entries, vaultId ${meta.vaultId.slice(0, 8)}…)`);
    console.log('[obsidian-e2ee-sync] put nginx + HTTPS in front before exposing this to the internet');
  });
}

main().catch((err) => {
  console.error('[fatal] failed to start:', err);
  process.exit(1);
});
