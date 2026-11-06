#!/usr/bin/env node
/**
 * Obsidian E2EE Sync — storage server.
 *
 * Zero npm dependencies: Node.js built-ins only (Node >= 18).
 *
 * The server operates as an untrusted ciphertext store: it persists opaque
 * encrypted blobs and maintains a per-path index, and receives neither
 * encryption keys nor plaintext. It exposes:
 *
 *   GET    /api/meta                  -> { vaultId }            (stable KDF salt source)
 *   GET    /api/index                 -> full index incl. tombstones (ETag / 304)
 *   POST   /api/upload                -> binary body + X-File-Path / X-Client-Mtime /
 *                                        X-Cipher-Hash [/ X-Key-Id / X-File-Version]
 *                                        headers; atomic tmp+rename write
 *   POST   /api/upload/begin          -> JSON {path,totalBytes,chunkCount,fileManifest}
 *                                        opens a resumable staging upload
 *   PUT    /api/upload/chunk?uploadId=&n= -> one ciphertext chunk (X-Chunk-Hash
 *                                        verified), stored as a staging part
 *   GET    /api/upload/status?uploadId=   -> accepted chunk numbers (resume)
 *   POST   /api/upload/commit?uploadId=   -> assemble parts under the path lock,
 *                                        hash the blob, index it, drop staging
 *   GET    /api/download?path=<enc>   -> streams the encrypted blob
 *   DELETE /api/delete?path=<enc>     -> removes the blob, keeps a tombstone in the index
 *   GET    /api/health                -> unauthenticated liveness probe
 *
 * All /api/* routes except /health require `Authorization: Bearer <token>` and
 * are compared in constant time against every configured token. X-Key-Id /
 * X-File-Version are opaque client metadata echoed into the index (packet v3:
 * they let clients detect key rotations and rollbacks; the server cannot
 * forge them usefully because they are authenticated inside each packet's
 * AES-GCM AAD on the client). Path mutations (upload/delete) are serialized
 * per path so the on-disk blob and the index can never disagree, and every
 * stored path is canonicalized to Unicode NFC (clients on iOS/macOS produce
 * NFD filenames; without a single canonical form the same logical file would
 * fork into two independent entries).
 *
 * Configuration (environment variables):
 *   AUTH_TOKEN           required, >= 16 chars   bearer token clients must present
 *   AUTH_TOKENS          optional, comma-separated additional tokens (PROB-5:
 *                        issue one per device; drop a lost device's token
 *                        without re-provisioning the fleet)
 *   PORT                 default 8080
 *   HOST                 default 127.0.0.1 (put nginx/TLS in front for remote access)
 *   DATA_DIR             default ./data
 *   MAX_BODY_BYTES       default 256 MiB — per-request (per-chunk) cap
 *   MAX_FILE_BYTES       default 2 GiB — cap for assembled chunked uploads
 *   TOMBSTONE_TTL_DAYS   default 0 (keep tombstones forever; see README before enabling GC)
 *   STAGING_TTL_HOURS    default 24 — sweep abandoned staging uploads older than this
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
const MAX_FILE_BYTES = Number(process.env.MAX_FILE_BYTES || 2 * 1024 * 1024 * 1024);
const TOMBSTONE_TTL_DAYS = Number(process.env.TOMBSTONE_TTL_DAYS || 0);
const STAGING_TTL_HOURS = Number(process.env.STAGING_TTL_HOURS || 24);
/** Farthest future a client-supplied mtime may claim (guards the clients'
 * first-sync "newest mtime wins" heuristic against skewed device clocks). */
const MAX_MTIME_SKEW_MS = 24 * 3600 * 1000;
const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER;

const AUTH_TOKEN_LIST = [
  ...AUTH_TOKEN.split(',').map((t) => t.trim()).filter(Boolean),
  ...(process.env.AUTH_TOKENS || '').split(',').map((t) => t.trim()).filter(Boolean),
];
if (AUTH_TOKEN_LIST.length === 0 || AUTH_TOKEN_LIST.some((t) => t.length < 16)) {
  console.error(
    '[fatal] No AUTH_TOKEN (or all tokens are shorter than 16 characters).\n' +
      '        Generate one with:  openssl rand -hex 32\n' +
      '        Then start with:    AUTH_TOKEN=<token> node server.js',
  );
  process.exit(1);
}

const FILES_DIR = path.join(DATA_DIR, 'files');
const STAGING_DIR = path.join(DATA_DIR, 'staging');
const META_PATH = path.join(DATA_DIR, 'meta.json');
const INDEX_PATH = path.join(DATA_DIR, 'index.json');

// ------------------------------------------------------------------ auth ----

const TOKEN_DIGESTS = AUTH_TOKEN_LIST.map((t) =>
  crypto.createHash('sha256').update(t, 'utf8').digest(),
);

function isAuthorized(req) {
  const header = req.headers['authorization'] || '';
  const match = /^Bearer\s+(.+)$/.exec(header);
  if (!match) return false;
  // Hash both sides first: timingSafeEqual requires equal lengths and hashing
  // avoids leaking the token length. Compare against every configured token
  // so per-device tokens (PROB-5) all authorize.
  const digest = crypto.createHash('sha256').update(match[1], 'utf8').digest();
  return TOKEN_DIGESTS.some(
    (known) => digest.length === known.length && crypto.timingSafeEqual(digest, known),
  );
}

/** Throttle repeated auth failures per source address (memory-bounded). */
const authFailures = new Map(); // ip -> { count, resetAt }
function isAuthThrottled(ip) {
  const now = Date.now();
  let entry = authFailures.get(ip);
  if (!entry || now > entry.resetAt) {
    if (authFailures.size > 10_000) authFailures.clear();
    entry = { count: 0, resetAt: now + 60_000 };
    authFailures.set(ip, entry);
  }
  return ++entry.count > 20;
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
 * Normalize a client-supplied vault path to a safe, canonical relative path.
 * Returns null for anything suspicious (absolute paths, traversal, control
 * characters, Windows-reserved characters, over-long segments). The result is
 * Unicode-NFC normalized so that NFD (iOS/macOS) and NFC (Windows/Linux)
 * spellings of the same filename share one storage entry.
 */
function sanitizePath(raw) {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > 4096) return null;
  if (raw.startsWith('/')) return null; // absolute — reject, never re-anchor
  if (raw.includes('\\') || raw.includes('\0')) return null;
  const segments = raw.split('/').filter((s) => s.length > 0);
  if (segments.length === 0) return null;
  for (const segment of segments) {
    if (segment === '.' || segment === '..') return null;
    if (segment.length > 255) return null;
    if (/[<>:"|?*\u0000-\u001f]/.test(segment)) return null;
  }
  return segments.join('/').normalize('NFC');
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
/**
 * @type {Map<string, {mtime:number,size:number,hash:string,deleted:boolean,
 *                     keyId:string,ver:number,manifest:string}>}
 */
const index = new Map();

/**
 * Resumable chunked uploads (PROB-3). One directory per upload under
 * DATA_DIR/staging/<uploadId>/ holding meta.json plus <n>.part files; the
 * in-memory map mirrors the on-disk state and is rebuilt on startup.
 * @type {Map<string, {path:string,totalBytes:number,chunkCount:number,
 *                     fileManifest:string,createdAt:number}>}
 */
const staging = new Map();

function stagingDir(uploadId) {
  // uploadId is always server-generated hex — reject anything else outright.
  if (!/^[0-9a-f]{32}$/.test(uploadId)) throw new HttpError(400, 'Malformed uploadId.');
  return path.join(STAGING_DIR, uploadId);
}

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

/**
 * Per-path mutation lock: the sequence [rename/unlink on disk] + [index.set]
 * must be atomic with respect to other requests for the same path, otherwise
 * two racing uploads can leave the disk holding one client's bytes while the
 * index describes the other's hash.
 */
const pathLocks = new Map();
function withPathLock(key, fn) {
  const prev = pathLocks.get(key) ?? Promise.resolve();
  const next = prev.then(fn);
  const guarded = next.catch(() => {});
  pathLocks.set(key, guarded);
  guarded.then(() => {
    if (pathLocks.get(key) === guarded) pathLocks.delete(key);
  });
  return next;
}

/** Remove upload/persist temp files left behind by crashed requests, and
 *  staging uploads abandoned for longer than STAGING_TTL_HOURS. */
async function cleanupTmpFiles() {
  let names;
  try {
    names = await fsp.readdir(DATA_DIR);
  } catch {
    return;
  }
  await Promise.all(
    names
      .filter((n) => n.endsWith('.tmp'))
      .map((n) => fsp.unlink(path.join(DATA_DIR, n)).catch(() => {})),
  );

  // Staging sweep (PROB-3): abandoned chunked uploads must not squat on disk.
  let stagingIds;
  try {
    stagingIds = await fsp.readdir(STAGING_DIR);
  } catch {
    stagingIds = [];
  }
  const cutoff = Date.now() - STAGING_TTL_HOURS * 3600_000;
  for (const id of stagingIds) {
    const dir = path.join(STAGING_DIR, id);
    try {
      const metaPath = path.join(dir, 'meta.json');
      const stat = await fsp.stat(metaPath).catch(() => null);
      const stale = stat ? stat.mtimeMs < cutoff : true;
      if (stale) {
        await fsp.rm(dir, { recursive: true, force: true });
        staging.delete(id);
      }
    } catch {
      /* best effort */
    }
  }
}

async function loadState() {
  await fsp.mkdir(FILES_DIR, { recursive: true, mode: 0o700 });
  await fsp.mkdir(STAGING_DIR, { recursive: true, mode: 0o700 });

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
        index.set(filePath.normalize('NFC'), {
          mtime: Number(entry.mtime) || 0,
          size: Number(entry.size) || 0,
          hash: String(entry.hash || ''),
          deleted: Boolean(entry.deleted),
          keyId: typeof entry.keyId === 'string' && /^[0-9a-f]{16}$/.test(entry.keyId) ? entry.keyId : '',
          ver:
            Number.isFinite(Number(entry.ver)) && Number(entry.ver) >= 0 && Number(entry.ver) <= MAX_SAFE_INTEGER
              ? Math.floor(Number(entry.ver))
              : 0,
          manifest: typeof entry.manifest === 'string' && /^[0-9a-f]{64}$/.test(entry.manifest) ? entry.manifest : '',
        });
      }
    }
  } catch {
    // No index yet — start empty. Existing files on disk are not resurrected;
    // clients will re-upload whatever they still have.
  }

  // Re-attach staging uploads that survived a restart.
  try {
    for (const id of await fsp.readdir(STAGING_DIR)) {
      try {
        const m = JSON.parse(await fsp.readFile(path.join(STAGING_DIR, id, 'meta.json'), 'utf8'));
        if (m && typeof m.path === 'string') {
          staging.set(id, {
            path: m.path,
            totalBytes: Number(m.totalBytes) || 0,
            chunkCount: Number(m.chunkCount) || 0,
            fileManifest: String(m.fileManifest || ''),
            createdAt: Number(m.createdAt) || Date.now(),
          });
        }
      } catch {
        await fsp.rm(path.join(STAGING_DIR, id), { recursive: true, force: true }).catch(() => {});
      }
    }
  } catch {
    /* no staging dir */
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

/** Parse the optional packet-v3 echo headers: X-Key-Id (16 hex) and
 *  X-File-Version (non-negative integer). Both default to ''/0. */
function parseKeyHeaders(req) {
  const keyId = String(req.headers['x-key-id'] ?? '').toLowerCase();
  if (keyId !== '' && !/^[0-9a-f]{16}$/.test(keyId)) {
    throw new HttpError(400, 'X-Key-Id must be 16 lowercase hex characters.');
  }
  const rawVer = req.headers['x-file-version'];
  let ver = 0;
  if (rawVer !== undefined && rawVer !== '') {
    const n = Number(rawVer);
    if (!/^\d+$/.test(String(rawVer)) || !Number.isFinite(n) || n < 0 || n > MAX_SAFE_INTEGER) {
      throw new HttpError(400, 'X-File-Version must be a non-negative integer.');
    }
    ver = Math.floor(n);
  }
  return { keyId, ver };
}

function clampClientMtime(raw) {
  const clientMtime = Math.floor(Number(raw));
  return Number.isFinite(clientMtime) && clientMtime > 0
    ? Math.min(clientMtime, Date.now() + MAX_MTIME_SKEW_MS)
    : Date.now();
}

async function readJsonBody(req, maxBytes = 1024 * 1024) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maxBytes) throw new HttpError(413, 'JSON body too large.');
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new HttpError(400, 'Malformed JSON body.');
  }
}

async function handleUpload(req, res, url) {
  const rawPath =
    req.headers['x-file-path'] !== undefined
      ? decodePathValue(req.headers['x-file-path'])
      : url.searchParams.get('path');

  if (rawPath === undefined) throw new HttpError(400, 'Missing path (X-File-Path header or ?path=).');
  const clientPath = sanitizePath(rawPath);
  if (!clientPath) throw new HttpError(400, 'Invalid file path.');

  const rawMtime = req.headers['x-client-mtime'] ?? url.searchParams.get('mtime') ?? Date.now();
  const expectedHash = String(req.headers['x-cipher-hash'] ?? url.searchParams.get('hash') ?? '').toLowerCase();
  const { keyId, ver } = parseKeyHeaders(req);

  const target = path.join(FILES_DIR, ...clientPath.split('/'));
  const tmp = path.join(DATA_DIR, `upload-${process.pid}-${crypto.randomBytes(6).toString('hex')}.tmp`);

  const { size, hash } = await streamBodyToFile(req, tmp, MAX_BODY_BYTES);
  if (expectedHash && expectedHash !== hash) {
    await fsp.unlink(tmp).catch(() => {});
    throw new HttpError(400, 'Cipher hash mismatch — upload corrupted in transit?');
  }

  const entry = {
    mtime: clampClientMtime(rawMtime),
    size,
    hash,
    deleted: false, // uploading clears any tombstone
    keyId,
    ver,
    manifest: '',
  };
  await withPathLock(clientPath, async () => {
    await fsp.mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
    await fsp.rename(tmp, target); // atomic publish
    index.set(clientPath, entry);
    persistIndex();
  });
  sendJson(res, 200, { path: clientPath, ...entry });
}

// ------------------------------------------------- chunked transport (v3) --

async function handleUploadBegin(req, res) {
  const body = await readJsonBody(req);
  if (!body || typeof body !== 'object') throw new HttpError(400, 'Body must be a JSON object.');
  const clientPath = sanitizePath(body.path);
  if (!clientPath) throw new HttpError(400, 'Invalid file path.');
  const totalBytes = Number(body.totalBytes);
  const chunkCount = Number(body.chunkCount);
  const fileManifest = String(body.fileManifest ?? '');
  if (!Number.isFinite(totalBytes) || totalBytes < 1 || totalBytes > MAX_FILE_BYTES) {
    throw new HttpError(400, `totalBytes must be 1..${MAX_FILE_BYTES}.`);
  }
  if (!Number.isInteger(chunkCount) || chunkCount < 1 || chunkCount > 100_000) {
    throw new HttpError(400, 'chunkCount must be an integer in 1..100000.');
  }
  if (!/^[0-9a-f]{64}$/.test(fileManifest)) {
    throw new HttpError(400, 'fileManifest must be 64 hex characters.');
  }

  const uploadId = crypto.randomBytes(16).toString('hex');
  const dir = stagingDir(uploadId);
  await fsp.mkdir(dir, { mode: 0o700, recursive: true });
  const record = {
    path: clientPath,
    totalBytes: Math.floor(totalBytes),
    chunkCount,
    fileManifest,
    createdAt: Date.now(),
  };
  await writeJsonAtomic(path.join(dir, 'meta.json'), record);
  staging.set(uploadId, record);
  sendJson(res, 200, { uploadId });
}

async function handleUploadChunk(req, res, url) {
  const uploadId = url.searchParams.get('uploadId') ?? '';
  const dir = stagingDir(uploadId);
  const record = staging.get(uploadId);
  if (!record) throw new HttpError(404, 'Unknown or expired uploadId.');
  const n = Number(url.searchParams.get('n'));
  if (!Number.isInteger(n) || n < 0 || n >= record.chunkCount) {
    throw new HttpError(400, `n must be an integer in 0..${record.chunkCount - 1}.`);
  }
  const expectedHash = String(req.headers['x-chunk-hash'] ?? '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(expectedHash)) {
    throw new HttpError(400, 'X-Chunk-Hash must be 64 hex characters.');
  }

  const tmp = path.join(dir, `${n}.${crypto.randomBytes(4).toString('hex')}.tmp`);
  const { hash } = await streamBodyToFile(req, tmp, MAX_BODY_BYTES);
  if (hash !== expectedHash) {
    await fsp.unlink(tmp).catch(() => {});
    throw new HttpError(400, 'Chunk hash mismatch — upload corrupted in transit?');
  }
  await fsp.rename(tmp, path.join(dir, `${n}.part`)); // idempotent re-PUT

  sendJson(res, 200, { accepted: acceptedChunksSync(dir, record.chunkCount) });
}

/** Synchronous listing of part files present on disk (source of truth). */
function acceptedChunksSync(dir, chunkCount) {
  let names;
  try {
    names = fs.readdirSync(dir);
  } catch {
    return [];
  }
  const accepted = [];
  for (const name of names) {
    const m = /^(\d+)\.part$/.exec(name);
    if (m) {
      const n = Number(m[1]);
      if (n >= 0 && n < chunkCount) accepted.push(n);
    }
  }
  return accepted.sort((a, b) => a - b);
}

async function handleUploadStatus(req, res, url) {
  const uploadId = url.searchParams.get('uploadId') ?? '';
  const dir = stagingDir(uploadId);
  const record = staging.get(uploadId);
  if (!record) throw new HttpError(404, 'Unknown or expired uploadId.');
  sendJson(res, 200, { accepted: acceptedChunksSync(dir, record.chunkCount), chunkCount: record.chunkCount });
}

async function handleUploadCommit(req, res, url) {
  const uploadId = url.searchParams.get('uploadId') ?? '';
  const dir = stagingDir(uploadId);
  const record = staging.get(uploadId);
  if (!record) throw new HttpError(404, 'Unknown or expired uploadId.');

  const accepted = acceptedChunksSync(dir, record.chunkCount);
  if (accepted.length !== record.chunkCount) {
    const missing = [];
    for (let i = 0; i < record.chunkCount; i++) {
      if (!accepted.includes(i)) missing.push(i);
    }
    throw new HttpError(400, `Upload incomplete — missing chunk(s): ${missing.slice(0, 8).join(', ')}${missing.length > 8 ? '…' : ''}.`);
  }

  const rawMtime = req.headers['x-client-mtime'] ?? Date.now();
  const { keyId, ver } = parseKeyHeaders(req);
  const target = path.join(FILES_DIR, ...record.path.split('/'));
  const tmp = path.join(DATA_DIR, `commit-${process.pid}-${crypto.randomBytes(6).toString('hex')}.tmp`);

  let totalSize = 0;
  let blobHash = '';
  await withPathLock(record.path, async () => {
    // Concatenate parts into one blob under the path lock, hashing on the way.
    const hasher = crypto.createHash('sha256');
    const out = fs.createWriteStream(tmp, { mode: 0o600 });
    try {
      for (let i = 0; i < record.chunkCount; i++) {
        await new Promise((resolve, reject) => {
          const rs = fs.createReadStream(path.join(dir, `${i}.part`));
          rs.on('data', (c) => hasher.update(c));
          rs.on('error', reject);
          rs.on('end', resolve);
          rs.pipe(out, { end: false });
        });
      }
      await new Promise((resolve, reject) => {
        out.on('error', reject);
        out.end(resolve);
      });
    } catch (err) {
      out.destroy();
      await fsp.unlink(tmp).catch(() => {});
      throw err;
    }
    totalSize = await (await fsp.stat(tmp)).size;
    blobHash = hasher.digest('hex');
    if (totalSize > record.totalBytes || totalSize > MAX_FILE_BYTES) {
      await fsp.unlink(tmp).catch(() => {});
      throw new HttpError(400, 'Assembled blob exceeds the declared or configured size cap.');
    }
    await fsp.mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
    await fsp.rename(tmp, target); // atomic publish
    index.set(record.path, {
      mtime: clampClientMtime(rawMtime),
      size: totalSize,
      hash: blobHash,
      deleted: false,
      keyId,
      ver,
      manifest: record.fileManifest,
    });
    persistIndex();
  });

  await fsp.rm(dir, { recursive: true, force: true });
  staging.delete(uploadId);
  const entry = index.get(record.path);
  sendJson(res, 200, { path: record.path, ...entry });
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
    // lstat, not stat: a symlink planted inside the files dir must never be
    // followed out of the storage jail.
    stat = await fsp.lstat(target);
  } catch {
    throw new HttpError(404, 'File not found.');
  }
  if (!stat.isFile()) throw new HttpError(404, 'File not found.');

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
    // Tombstone: keep the path in the index so every other device learns about
    // the deletion; mtime becomes the deletion time. Version counters and key
    // ids reset — a re-upload after a deletion starts a fresh history.
    const tombstone = { mtime: Date.now(), size: 0, hash: '', deleted: true, keyId: '', ver: 0, manifest: '' };
    await withPathLock(clientPath, async () => {
      try {
        await fsp.unlink(target);
      } catch (err) {
        if (err.code !== 'ENOENT') throw err;
      }
      index.set(clientPath, tombstone);
      persistIndex();
    });
    sendJson(res, 200, { path: clientPath, ...tombstone });
    return;
  }

  // Already tombstoned — idempotent.
  sendJson(res, 200, { path: clientPath, ...entry });
}

/**
 * GET /api/index with entity-tag conditioning (PROB-6): the ETag is the
 * SHA-256 of the response body, so an unchanged index costs the client one
 * 304 instead of a full re-download and replan on every idle cycle.
 */
function handleIndex(req, res) {
  const body = JSON.stringify({ files: Object.fromEntries(index) });
  const etag = `"${crypto.createHash('sha256').update(body, 'utf8').digest('hex')}"`;
  const inm = String(req.headers['if-none-match'] ?? '');
  if (inm === etag || inm === '*' || inm.replace(/^W\//, '') === etag) {
    res.writeHead(304, { ETag: etag, 'Cache-Control': 'no-store' });
    res.end();
    return;
  }
  res.writeHead(200, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    ETag: etag,
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

function gcTombstones() {  if (!(TOMBSTONE_TTL_DAYS > 0)) return;
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
      if (isAuthThrottled(req.socket.remoteAddress || 'unknown')) {
        return sendJson(res, 429, { error: 'Too many failed attempts — slow down.' });
      }
      return sendJson(res, 401, { error: 'Unauthorized' });
    }

    switch (route) {
      case 'GET /api/meta':
        return sendJson(res, 200, { vaultId: meta.vaultId });
      case 'GET /api/index':
        return handleIndex(req, res);
      case 'POST /api/upload':
        return await handleUpload(req, res, url);
      case 'POST /api/upload/begin':
        return await handleUploadBegin(req, res);
      case 'PUT /api/upload/chunk':
        return await handleUploadChunk(req, res, url);
      case 'GET /api/upload/status':
        return await handleUploadStatus(req, res, url);
      case 'POST /api/upload/commit':
        return await handleUploadCommit(req, res, url);
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

server.headersTimeout = 70_000;
server.keepAliveTimeout = 65_000;
// Bound the total lifetime of a request: 30 min is ample for a 256 MiB body on
// a slow uplink (~150 KB/s) while preventing indefinite socket squatting.
server.requestTimeout = 30 * 60_000;

// ------------------------------------------------------------------ main ----

async function main() {
  await cleanupTmpFiles();
  await loadState();
  if (TOMBSTONE_TTL_DAYS > 0) {
    gcTombstones();
    setInterval(gcTombstones, 24 * 3600 * 1000).unref();
  }
  server.listen(PORT, HOST, () => {
    console.log(`[obsidian-e2ee-sync] listening on http://${HOST}:${PORT}`);
    console.log(`[obsidian-e2ee-sync] data dir: ${DATA_DIR} (${index.size} index entries, vaultId ${meta.vaultId.slice(0, 8)}…)`);
    console.log('[obsidian-e2ee-sync] terminate TLS with nginx + HTTPS before exposing this to the internet');
  });
}

main().catch((err) => {
  console.error('[fatal] failed to start:', err);
  process.exit(1);
});
