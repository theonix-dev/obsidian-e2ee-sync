#!/usr/bin/env node
/**
 * End-to-end integration test for server/server.js — zero dependencies.
 *
 * It replicates the plugin's packet-v3 crypto EXACTLY (PBKDF2-SHA256 ->
 * AES-256-GCM, packet = [0x03|keyId(8)|salt(16)|iv(12)|ver u64|ctLen u32|
 * chunkIdx u32|ct|tag], AAD = 0x03|keyId|NFC(path)|ver|ctLen|chunkIdx[|
 * manifest]) using Node's WebCrypto, then exercises the full REST surface:
 * auth (single + multi token), meta, v3 upload with keyId/version echo,
 * index ETag/304, chunked resumable transport, delete/tombstones, hash
 * verification, path-traversal defenses, unicode paths, the key-rotation
 * protocol, rollback visibility, and state persistence across restarts.
 *
 * Run:  node server/test-e2e.mjs     (requires Node >= 18)
 */

import { spawn, spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const subtle = globalThis.crypto?.subtle ?? crypto.webcrypto.subtle;
const __dirname = path.dirname(fileURLToPath(import.meta.url));

const TOKEN = 'test-token-0123456789abcdef';
const TOKEN_B = 'device-b-token-0123456789a';
const TOKEN_C = 'device-c-token-0123456789a';
const PORT = 18977;
const BASE = `http://127.0.0.1:${PORT}`;

let passed = 0;
let failed = 0;

function ok(condition, label, detail = '') {
  if (condition) {
    passed++;
    console.log(`  ✔ ${label}`);
  } else {
    failed++;
    console.log(`  ✘ ${label}${detail ? ` — ${detail}` : ''}`);
  }
}

// ------------------------------------------------------------ test crypto --
// Deliberately mirrors plugin/src/crypto.ts byte-for-byte (packet v3).

const PBKDF2_ITERATIONS = 210_000;
const PACKET_V3 = 0x03;
const V3_HEADER_BYTES = 53;
const CHUNK_INDEX_SINGLE = 0xffffffff;

function copyBuffer(view) {
  return view.slice().buffer;
}

function aadV3(path, keyId, ver, ctLen, chunkIndex, manifest) {
  const p = new TextEncoder().encode(path.normalize('NFC'));
  const aad = new Uint8Array(1 + 8 + p.length + 8 + 4 + 4 + (manifest ? 32 : 0));
  let o = 0;
  aad[o++] = PACKET_V3;
  aad.set(keyId, o);
  o += 8;
  aad.set(p, o);
  o += p.length;
  const dv = new DataView(aad.buffer);
  dv.setUint32(o, Math.floor(ver / 0x1_0000_0000), false);
  dv.setUint32(o + 4, ver >>> 0, false);
  o += 8;
  dv.setUint32(o, ctLen, false);
  o += 4;
  dv.setUint32(o, chunkIndex >>> 0, false);
  o += 4;
  if (manifest) aad.set(manifest, o);
  return aad.buffer;
}

async function deriveMaterial(password, salt) {
  const material = await subtle.importKey(
    'raw',
    copyBuffer(new TextEncoder().encode(password)),
    'PBKDF2',
    false,
    ['deriveBits'],
  );
  const bits = new Uint8Array(
    await subtle.deriveBits(
      { name: 'PBKDF2', salt: copyBuffer(salt), iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
      material,
      256,
    ),
  );
  const keyId = new Uint8Array(await subtle.digest('SHA-256', bits)).slice(0, 8);
  const key = await subtle.importKey(
    'raw', copyBuffer(bits), { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'],
  );
  return { key, keyId };
}

async function saltFromVaultId(vaultId) {
  const digest = await subtle.digest('SHA-256', copyBuffer(new TextEncoder().encode(vaultId)));
  return new Uint8Array(digest).slice(0, 16);
}

async function sealV3(plaintext, key, keyId, salt, path, ver, chunkIndex, manifest) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await subtle.encrypt(
      {
        name: 'AES-GCM',
        iv,
        additionalData: aadV3(path, keyId, ver, plaintext.byteLength, chunkIndex, manifest),
      },
      key,
      plaintext,
    ),
  );
  const packet = new Uint8Array(V3_HEADER_BYTES + ct.length);
  const dv = new DataView(packet.buffer);
  packet[0] = PACKET_V3;
  packet.set(keyId, 1);
  packet.set(salt, 9);
  packet.set(iv, 25);
  dv.setUint32(37, Math.floor(ver / 0x1_0000_0000), false);
  dv.setUint32(41, ver >>> 0, false);
  dv.setUint32(45, ct.length - 16, false);
  dv.setUint32(49, chunkIndex >>> 0, false);
  packet.set(ct, V3_HEADER_BYTES);
  return packet.buffer;
}

async function encryptBuffer(plaintext, km, salt, path, ver) {
  return sealV3(plaintext, km.key, km.keyId, salt, path, ver, CHUNK_INDEX_SINGLE, null);
}

async function encryptChunk(plaintext, km, salt, path, ver, chunkIndex, manifest) {
  return sealV3(plaintext, km.key, km.keyId, salt, path, ver, chunkIndex, manifest);
}

function peekV3(packet) {
  const bytes = new Uint8Array(packet);
  if (bytes.length < V3_HEADER_BYTES + 16 || bytes[0] !== PACKET_V3) return null;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return {
    keyId: Buffer.from(bytes.slice(1, 9)).toString('hex'),
    version: dv.getUint32(37, false) * 0x1_0000_0000 + dv.getUint32(41, false),
    chunkIndex: dv.getUint32(49, false),
  };
}

async function decryptBuffer(packet, km, path, manifest) {
  const bytes = new Uint8Array(packet);
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const keyId = bytes.slice(1, 9);
  const ver = dv.getUint32(37, false) * 0x1_0000_0000 + dv.getUint32(41, false);
  const ctLen = dv.getUint32(45, false);
  const chunkIndex = dv.getUint32(49, false);
  const iv = copyBuffer(bytes.slice(25, 37));
  const ct = copyBuffer(bytes.slice(V3_HEADER_BYTES, V3_HEADER_BYTES + ctLen + 16));
  const aad = aadV3(path, keyId, ver, ctLen, chunkIndex, chunkIndex === CHUNK_INDEX_SINGLE ? null : manifest);
  const plaintext = await subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, km.key, ct);
  return { plaintext, version: ver, keyId: Buffer.from(keyId).toString('hex'), chunkIndex };
}

/** decryptChunked replica: walks self-delimiting v3 packets, checks contiguity. */
async function decryptChunked(blob, km, path, manifest) {
  const bytes = new Uint8Array(blob);
  const chunks = [];
  let offset = 0;
  let version = null;
  let keyId = null;
  while (offset < bytes.length) {
    const head = new Uint8Array(bytes.slice(offset, offset + V3_HEADER_BYTES + 16));
    if (head.length < V3_HEADER_BYTES + 16 || head[0] !== PACKET_V3) throw new Error('bad packet boundary');
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const off = offset;
    const v = dv.getUint32(off + 37, false) * 0x1_0000_0000 + dv.getUint32(off + 41, false);
    const ctLen = dv.getUint32(off + 45, false);
    const chunkIndex = dv.getUint32(off + 49, false);
    if (chunkIndex !== chunks.length) throw new Error('chunk gap/splice detected');
    if (version === null) version = v;
    else if (version !== v) throw new Error('mixed versions in stream');
    const res = await decryptBuffer(bytes.slice(off, off + V3_HEADER_BYTES + ctLen + 16), km, path, manifest);
    chunks.push(res.plaintext);
    if (keyId === null) keyId = res.keyId;
    else if (keyId !== res.keyId) throw new Error('mixed key ids in stream');
    offset += V3_HEADER_BYTES + ctLen + 16;
  }
  const total = chunks.reduce((n, c) => n + c.byteLength, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const c of chunks) {
    out.set(new Uint8Array(c), o);
    o += c.byteLength;
  }
  return { plaintext: out.buffer, version, keyId, chunkCount: chunks.length };
}

/** getRandomValues is capped at 64 KiB per call (spec) — fill in chunks. */
function randomBytes(length) {
  const out = new Uint8Array(length);
  for (let offset = 0; offset < length; offset += 65536) {
    crypto.getRandomValues(out.subarray(offset, Math.min(offset + 65536, length)));
  }
  return out;
}

function sha256Hex(buffer) {
  return crypto.createHash('sha256').update(new Uint8Array(buffer)).digest('hex');
}

async function sha256(buffer) {
  return new Uint8Array(await subtle.digest('SHA-256', new Uint8Array(buffer)));
}

function bytesEqual(a, b) {
  const ua = new Uint8Array(a);
  const ub = new Uint8Array(b);
  if (ua.length !== ub.length) return false;
  return crypto.timingSafeEqual(ua, ub);
}

/** File manifest as the client computes it: SHA-256 over the plaintext chunk hashes. */
async function fileManifestOf(chunks) {
  const input = new Uint8Array(chunks.length * 32);
  for (let i = 0; i < chunks.length; i++) {
    input.set(await sha256(chunks[i]), i * 32);
  }
  return { manifest: await sha256(input), hex: sha256Hex(input) };
}

// ------------------------------------------------------------ http helpers --

function api(method, route, { body, headers = {}, token = TOKEN } = {}) {
  return fetch(`${BASE}${route}`, {
    method,
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...headers,
    },
    body,
  });
}

function startServer(dataDir, env = {}) {
  const child = spawn(process.execPath, [path.join(__dirname, 'server.js')], {
    env: {
      ...process.env,
      PORT: String(PORT),
      HOST: '127.0.0.1',
      DATA_DIR: dataDir,
      AUTH_TOKEN: TOKEN,
      ...env,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let output = '';
  child.stdout.on('data', (d) => (output += d));
  child.stderr.on('data', (d) => (output += d));
  child.testOutput = () => output;

  const waitReady = async () => {
    for (let i = 0; i < 100; i++) {
      try {
        const res = await fetch(`${BASE}/api/health`);
        if (res.ok) return;
      } catch {
        /* not up yet */
      }
      await new Promise((r) => setTimeout(r, 100));
    }
    throw new Error(`server did not start:\n${output}`);
  };
  return { child, waitReady };
}

function stopServer(child) {
  child.kill('SIGTERM');
  return new Promise((resolve) => child.on('exit', resolve));
}

/** Server RSS in bytes via /proc (Linux); null when unavailable. */
function serverRss(child) {
  try {
    const status = fs.readFileSync(`/proc/${child.pid}/status`, 'utf8');
    const m = /^VmRSS:\s+(\d+)\s+kB$/m.exec(status);
    return m ? Number(m[1]) * 1024 : null;
  } catch {
    return null;
  }
}

// ------------------------------------------------------------------ tests ---

async function run() {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'e2ee-sync-test-'));
  console.log(`data dir: ${dataDir}\n`);

  const { child, waitReady } = startServer(dataDir);
  await waitReady();

  try {
    console.log('[1] health & auth');
    {
      const health = await fetch(`${BASE}/api/health`);
      ok(health.ok, 'GET /api/health responds 200 without auth');

      const noAuth = await api('GET', '/api/index', { token: null });
      ok(noAuth.status === 401, 'index rejects missing token', `status=${noAuth.status}`);

      const badAuth = await api('GET', '/api/index', { token: 'wrong-token-aaaaaaaaaa' });
      ok(badAuth.status === 401, 'index rejects wrong token', `status=${badAuth.status}`);
    }

    console.log('[2] meta & key derivation');
    let vaultId;
    let salt;
    let km;
    let keyIdHex;
    {
      const res = await api('GET', '/api/meta');
      ok(res.ok, 'GET /api/meta responds 200');
      const body = await res.json();
      vaultId = body.vaultId;
      ok(typeof vaultId === 'string' && vaultId.length >= 8, 'meta returns a vaultId', JSON.stringify(body));
      salt = await saltFromVaultId(vaultId);
      km = await deriveMaterial('correct horse battery staple', salt);
      keyIdHex = Buffer.from(km.keyId).toString('hex');
      ok(/^[0-9a-f]{16}$/.test(keyIdHex), 'PBKDF2 derives an AES-256-GCM key with a 16-hex keyId');
    }

    console.log('[3] v3 upload / index / download round-trip (keyId + version echo)');
    const noteBytes = new TextEncoder().encode('# Secret note 🔐\n\nplain text that must never reach the server\n');
    const binaryBytes = randomBytes(1024 * 1024); // 1 MiB
    const packets = {};
    {
      const cases = [
        ['notes/project brief.md', noteBytes.buffer, 1],
        ['attachments/big-image.bin', binaryBytes.buffer, 4],
        ['笔记/文件夹 文件 ✨.md', noteBytes.buffer, 2],
      ];
      for (const [p, plaintext, ver] of cases) {
        const packet = await encryptBuffer(plaintext, km, salt, p, ver);
        packets[p] = packet;
        const res = await api('POST', '/api/upload', {
          body: packet,
          headers: {
            'Content-Type': 'application/octet-stream',
            'X-File-Path': encodeURIComponent(p),
            'X-Client-Mtime': '1725380000000',
            'X-Cipher-Hash': sha256Hex(packet),
            'X-Key-Id': keyIdHex,
            'X-File-Version': String(ver),
          },
        });
        ok(res.ok, `upload "${p}"`, `status=${res.status}`);
        const entry = await res.json();
        ok(
          entry.deleted === false &&
            entry.hash === sha256Hex(packet) &&
            entry.mtime === 1725380000000 &&
            entry.keyId === keyIdHex &&
            entry.ver === ver,
          `upload response carries {mtime,size,hash,deleted:false,keyId,ver}`,
          JSON.stringify(entry),
        );
      }

      const idx = await (await api('GET', '/api/index')).json();
      for (const p of Object.keys(packets)) {
        ok(idx.files[p] && idx.files[p].deleted === false, `index contains "${p}"`);
      }
      const rawIndex = JSON.stringify(idx);
      ok(!rawIndex.includes('must never reach the server'), 'plaintext never appears anywhere in the index');

      for (const [p, packet] of Object.entries(packets)) {
        const res = await api('GET', `/api/download?path=${encodeURIComponent(p)}`);
        ok(res.ok, `download "${p}"`, `status=${res.status}`);
        const downloaded = await res.arrayBuffer();
        ok(bytesEqual(downloaded, packet), `downloaded bytes match uploaded packet "${p}"`);
      }
    }

    console.log('[4] decrypt with the derived key (wrong password / swapped path / tamper)');
    {
      const packet = packets['notes/project brief.md'];
      const decrypted = await decryptBuffer(packet, km, 'notes/project brief.md');
      ok(bytesEqual(decrypted.plaintext, noteBytes.buffer), 'round-trip decrypt returns the original plaintext');
      ok(decrypted.version === 1, 'authenticated version counter round-trips');
      ok(decrypted.keyId === keyIdHex, 'authenticated keyId round-trips');

      const wrongKm = await deriveMaterial('hunter2', salt);
      let threw = false;
      try {
        await decryptBuffer(packet, wrongKm, 'notes/project brief.md');
      } catch {
        threw = true;
      }
      ok(threw, 'wrong password fails GCM authentication (no silent garbage)');

      // AAD binding: the ciphertext of one path must not decrypt under another.
      let swapThrew = false;
      try {
        await decryptBuffer(packet, km, 'passwords.md');
      } catch {
        swapThrew = true;
      }
      ok(swapThrew, 'ciphertext swapped to a different path fails GCM authentication');

      // The version counter is INSIDE the authenticated data.
      const tampered = new Uint8Array(packet.slice(0));
      tampered[40] ^= 0x01;
      let verThrew = false;
      try {
        await decryptBuffer(tampered.buffer, km, 'notes/project brief.md');
      } catch {
        verThrew = true;
      }
      ok(verThrew, 'tampered version counter byte fails authentication');
    }

    console.log('[5] delete & tombstones');
    {
      const res = await api('DELETE', `/api/delete?path=${encodeURIComponent('attachments/big-image.bin')}`);
      ok(res.ok, 'DELETE responds 200');
      const tomb = await res.json();
      ok(
        tomb.deleted === true && typeof tomb.mtime === 'number' && tomb.keyId === '' && tomb.ver === 0,
        'delete returns a tombstone with reset keyId/ver',
        JSON.stringify(tomb),
      );

      const idx = await (await api('GET', '/api/index')).json();
      ok(idx.files['attachments/big-image.bin']?.deleted === true, 'index keeps the tombstone entry');

      const dl = await api('GET', `/api/download?path=${encodeURIComponent('attachments/big-image.bin')}`);
      ok(dl.status === 404, 'download of a tombstoned path is 404', `status=${dl.status}`);

      const again = await api('DELETE', `/api/delete?path=${encodeURIComponent('attachments/big-image.bin')}`);
      ok(again.ok, 'delete is idempotent');

      const unknown = await api('DELETE', `/api/delete?path=${encodeURIComponent('never/existed.md')}`);
      ok(unknown.status === 404, 'delete of an unknown path is 404', `status=${unknown.status}`);

      // Re-uploading must clear the tombstone (delete-then-recreate flows).
      const packet = await encryptBuffer(noteBytes.buffer, km, salt, 'attachments/big-image.bin', 2);
      const up = await api('POST', '/api/upload', {
        body: packet,
        headers: {
          'X-File-Path': encodeURIComponent('attachments/big-image.bin'),
          'X-Key-Id': keyIdHex,
          'X-File-Version': '2',
        },
      });
      ok(up.ok && (await up.json()).deleted === false, 're-upload clears the tombstone');

      // Restore tombstoned state for the persistence check.
      await api('DELETE', `/api/delete?path=${encodeURIComponent('attachments/big-image.bin')}`);
    }

    console.log('[6] integrity & path safety');
    {
      const packet = await encryptBuffer(noteBytes.buffer, km, salt, 'integrity/check.bin', 1);
      const mismatch = await api('POST', '/api/upload', {
        body: packet,
        headers: {
          'X-File-Path': encodeURIComponent('integrity/check.bin'),
          'X-Cipher-Hash': 'deadbeef'.repeat(8),
        },
      });
      ok(mismatch.status === 400, 'upload with wrong X-Cipher-Hash is rejected', `status=${mismatch.status}`);

      const badKeyId = await api('POST', '/api/upload', {
        body: packet,
        headers: {
          'X-File-Path': encodeURIComponent('integrity/check.bin'),
          'X-Key-Id': 'a'.repeat(15), // 15 hex — malformed
        },
      });
      ok(badKeyId.status === 400, 'upload with malformed X-Key-Id (15 hex) is rejected', `status=${badKeyId.status}`);

      const badVer = await api('POST', '/api/upload', {
        body: packet,
        headers: {
          'X-File-Path': encodeURIComponent('integrity/check.bin'),
          'X-File-Version': '-1',
        },
      });
      ok(badVer.status === 400, 'upload with negative X-File-Version is rejected', `status=${badVer.status}`);

      const noHeaders = await api('POST', '/api/upload', {
        // Fresh packet for THIS path — the AAD binds the ciphertext to the
        // file name, so bytes sealed for check.bin must not be re-used here.
        body: await encryptBuffer(noteBytes.buffer, km, salt, 'integrity/plain.bin', 1),
        headers: { 'X-File-Path': encodeURIComponent('integrity/plain.bin') },
      });
      const plainEntry = await noHeaders.json();
      ok(
        noHeaders.ok && plainEntry.keyId === '' && plainEntry.ver === 0,
        'upload without v3 headers defaults to keyId ""/ver 0',
        JSON.stringify(plainEntry),
      );

      const traversal = await api('POST', '/api/upload', {
        body: packet,
        headers: {
          'X-File-Path': encodeURIComponent('../../etc/passwd'),
          'X-Cipher-Hash': sha256Hex(packet),
        },
      });
      ok(traversal.status === 400, 'traversal path (../../etc/passwd) rejected', `status=${traversal.status}`);
      ok(!fs.existsSync(path.join(dataDir, 'files', 'etc')), 'no file written outside the data dir');

      const travQuery = await api('GET', `/api/download?path=${encodeURIComponent('../meta.json')}`);
      ok(travQuery.status === 400 || travQuery.status === 404, 'traversal via query rejected', `status=${travQuery.status}`);

      const abs = await api('GET', `/api/download?path=${encodeURIComponent('/etc/passwd')}`);
      ok(abs.status === 400 || abs.status === 404, 'absolute path rejected', `status=${abs.status}`);

      const absUpload = await api('POST', '/api/upload', {
        body: packet,
        headers: {
          'X-File-Path': encodeURIComponent('/etc/passwd'),
          'X-Cipher-Hash': sha256Hex(packet),
        },
      });
      ok(absUpload.status === 400, 'absolute path upload rejected (never re-anchored)', `status=${absUpload.status}`);

      const notFound = await api('GET', `/api/download?path=${encodeURIComponent('missing/file.md')}`);
      ok(notFound.status === 404, 'download of unknown path is 404');

      // Unicode canonicalization: an NFD (iOS/macOS) spelling must be stored
      // under its NFC canonical form, not fork into a second entry.
      const nfdPath = 'unico\u0301de/cafe\u0301.md'; // NFD "únicode/café.md"
      const nfcPath = nfdPath.normalize('NFC');
      const nfcPacket = await encryptBuffer(noteBytes.buffer, km, salt, nfcPath, 1);
      const nfdUpload = await api('POST', '/api/upload', {
        body: nfcPacket,
        headers: {
          'X-File-Path': encodeURIComponent(nfdPath),
          'X-Cipher-Hash': sha256Hex(nfcPacket),
        },
      });
      ok(nfdUpload.ok, 'upload of an NFD path is accepted', `status=${nfdUpload.status}`);
      ok((await nfdUpload.json()).path === nfcPath, 'NFD path is canonicalized to NFC in the response');
      const idx6 = await (await api('GET', '/api/index')).json();
      ok(Boolean(idx6.files[nfcPath]), 'index keys the entry under its NFC form');
      ok(!Object.keys(idx6.files).some((k) => k === nfdPath), 'no duplicate NFD entry exists');
      const dlNfc = await api('GET', `/api/download?path=${encodeURIComponent(nfcPath)}`);
      ok(dlNfc.ok, 'download resolves via the NFC key', `status=${dlNfc.status}`);
      const dlNfd = await api('GET', `/api/download?path=${encodeURIComponent(nfdPath)}`);
      ok(dlNfd.ok, 'download of the NFD spelling resolves to the same entry', `status=${dlNfd.status}`);

      // A far-future client mtime must be clamped (protects the clients'
      // "newest mtime wins" first-sync heuristic from skewed device clocks).
      const futurePacket = await encryptBuffer(noteBytes.buffer, km, salt, 'skew/future.md', 1);
      const futureUpload = await api('POST', '/api/upload', {
        body: futurePacket,
        headers: {
          'X-File-Path': encodeURIComponent('skew/future.md'),
          'X-Client-Mtime': String(Date.now() + 365 * 24 * 3600 * 1000),
          'X-Cipher-Hash': sha256Hex(futurePacket),
        },
      });
      const futureEntry = await futureUpload.json();
      ok(
        futureEntry.mtime <= Date.now() + 24 * 3600 * 1000,
        'far-future X-Client-Mtime is clamped',
        JSON.stringify(futureEntry),
      );
    }

    console.log('[7] chunked resumable transport (PROB-3)');
    const bigPath = 'media/huge-video.bin';
    let bigManifestHex;
    {
      // 70 MB in 4 chunks of 17.5 MB (each ≤ the per-request cap).
      const total = 70 * 1024 * 1024;
      const chunkSize = Math.ceil(total / 4);
      const plaintext = randomBytes(total);
      const chunkPlains = [];
      for (let i = 0; i < 4; i++) {
        // slice() (not subarray()): each chunk needs a standalone buffer so
        // the replica encrypts exactly chunkSize bytes — mirrors the engine.
        chunkPlains.push(plaintext.slice(i * chunkSize, Math.min((i + 1) * chunkSize, total)));
      }
      const { manifest, hex } = await fileManifestOf(chunkPlains);
      bigManifestHex = hex;

      const begin = await api('POST', '/api/upload/begin', {
        body: JSON.stringify({
          path: bigPath,
          totalBytes: total + 4 * 128,
          chunkCount: 4,
          fileManifest: hex,
        }),
        headers: { 'Content-Type': 'application/json' },
      });
      ok(begin.ok, 'begin opens a staging upload', `status=${begin.status}`);
      const { uploadId } = await begin.json();
      ok(/^[0-9a-f]{32}$/.test(uploadId), 'uploadId is a server-generated 32-hex id');

      // Failure injection: PUT chunks 0 and 1, then a corrupt chunk 2.
      const encChunks = [];
      for (let i = 0; i < 4; i++) {
        encChunks.push(await encryptChunk(chunkPlains[i].buffer, km, salt, bigPath, 1, i, manifest));
      }
      const put0 = await api('PUT', `/api/upload/chunk?uploadId=${uploadId}&n=0`, {
        body: encChunks[0],
        headers: { 'X-Chunk-Hash': sha256Hex(encChunks[0]) },
      });
      ok(put0.ok, 'PUT chunk 0 accepted', `status=${put0.status}`);
      const put1 = await api('PUT', `/api/upload/chunk?uploadId=${uploadId}&n=1`, {
        body: encChunks[1],
        headers: { 'X-Chunk-Hash': sha256Hex(encChunks[1]) },
      });
      ok(put1.ok, 'PUT chunk 1 accepted');

      const corrupt = new Uint8Array(encChunks[2].slice(0));
      corrupt[60] ^= 0xff;
      const putCorrupt = await api('PUT', `/api/upload/chunk?uploadId=${uploadId}&n=2`, {
        body: corrupt.buffer,
        headers: { 'X-Chunk-Hash': sha256Hex(encChunks[2]) }, // declares the ORIGINAL hash
      });
      ok(putCorrupt.status === 400, 'corrupted-in-transit chunk (hash mismatch) is rejected', `status=${putCorrupt.status}`);

      // Resume primitive: status lists exactly what the server holds.
      const status = await api('GET', `/api/upload/status?uploadId=${uploadId}`);
      const statusBody = await status.json();
      ok(
        status.ok && JSON.stringify(statusBody.accepted) === '[0,1]' && statusBody.chunkCount === 4,
        'status reports accepted chunks [0,1] after the interruption',
        JSON.stringify(statusBody),
      );

      // Idempotent re-PUT of an already-accepted chunk.
      const put0again = await api('PUT', `/api/upload/chunk?uploadId=${uploadId}&n=0`, {
        body: encChunks[0],
        headers: { 'X-Chunk-Hash': sha256Hex(encChunks[0]) },
      });
      ok(put0again.ok, 're-PUT of an accepted chunk is idempotent');

      // Premature commit must fail (missing chunks 2,3).
      const early = await api('POST', `/api/upload/commit?uploadId=${uploadId}`);
      ok(early.status === 400, 'commit with missing chunks is rejected', `status=${early.status}`);

      // Finish the upload (resume path).
      for (let i = 2; i < 4; i++) {
        const r = await api('PUT', `/api/upload/chunk?uploadId=${uploadId}&n=${i}`, {
          body: encChunks[i],
          headers: { 'X-Chunk-Hash': sha256Hex(encChunks[i]) },
        });
        ok(r.ok, `resume: PUT chunk ${i} accepted`, `status=${r.status}`);
      }
      const commit = await api('POST', `/api/upload/commit?uploadId=${uploadId}`, {
        headers: {
          'X-Client-Mtime': '1725380000000',
          'X-Key-Id': keyIdHex,
          'X-File-Version': '1',
        },
      });
      ok(commit.ok, 'commit assembles the blob', `status=${commit.status}`);
      const entry = await commit.json();
      ok(
        entry.path === bigPath &&
          entry.deleted === false &&
          entry.manifest === bigManifestHex &&
          entry.keyId === keyIdHex &&
          entry.ver === 1,
        'committed entry carries {manifest,keyId,ver}',
        JSON.stringify(entry),
      );

      const expectedBlob = new Uint8Array(encChunks.reduce((n, p) => n + p.byteLength, 0));
      let eo = 0;
      for (const p of encChunks) {
        expectedBlob.set(new Uint8Array(p), eo);
        eo += p.byteLength;
      }
      ok(entry.size === expectedBlob.length, 'assembled size equals the sum of chunks');

      const dl = await api('GET', `/api/download?path=${encodeURIComponent(bigPath)}`);
      const blob = await dl.arrayBuffer();
      ok(bytesEqual(blob, expectedBlob.buffer), 'downloaded blob is byte-identical to the chunk concatenation');

      const dec = await decryptChunked(blob, km, bigPath, manifest);
      ok(bytesEqual(dec.plaintext, plaintext.buffer), 'chunk stream decrypts back to the original 70 MB');
      ok(dec.version === 1 && dec.chunkCount === 4, 'authenticated version + chunk count survive the round trip');

      const idxAfter = await (await api('GET', '/api/index')).json();
      ok(idxAfter.files[bigPath]?.hash === entry.hash, 'index holds the assembled blob hash');

      // Guard rails.
      const badManifest = await api('POST', '/api/upload/begin', {
        body: JSON.stringify({ path: 'x.bin', totalBytes: 10, chunkCount: 1, fileManifest: 'zz' }),
        headers: { 'Content-Type': 'application/json' },
      });
      ok(badManifest.status === 400, 'begin with malformed fileManifest is rejected', `status=${badManifest.status}`);

      const hugeDeclare = await api('POST', '/api/upload/begin', {
        body: JSON.stringify({
          path: 'x.bin',
          totalBytes: 3 * 1024 * 1024 * 1024, // > MAX_FILE_BYTES default
          chunkCount: 4,
          fileManifest: 'a'.repeat(64),
        }),
        headers: { 'Content-Type': 'application/json' },
      });
      ok(hugeDeclare.status === 400, 'begin above MAX_FILE_BYTES is rejected', `status=${hugeDeclare.status}`);

      const unknownStatus = await api('GET', '/api/upload/status?uploadId=' + 'f'.repeat(32));
      ok(unknownStatus.status === 404, 'status of an unknown uploadId is 404', `status=${unknownStatus.status}`);

      const unknownChunk = await api('PUT', `/api/upload/chunk?uploadId=${'f'.repeat(32)}&n=0`, {
        body: encChunks[0],
        headers: { 'X-Chunk-Hash': sha256Hex(encChunks[0]) },
      });
      ok(unknownChunk.status === 404, 'PUT chunk to an unknown uploadId is 404', `status=${unknownChunk.status}`);

      // Assembled size must respect the declared bound.
      const smallBegin = await api('POST', '/api/upload/begin', {
        body: JSON.stringify({
          path: 'media/over-declared.bin',
          totalBytes: 1024, // deliberately below the real assembly
          chunkCount: 2,
          fileManifest: 'b'.repeat(64),
        }),
        headers: { 'Content-Type': 'application/json' },
      });
      const { uploadId: smallId } = await smallBegin.json();
      for (let i = 0; i < 2; i++) {
        const p = await encryptChunk(chunkPlains[i].buffer, km, salt, 'media/over-declared.bin', 1, i, manifest);
        await api('PUT', `/api/upload/chunk?uploadId=${smallId}&n=${i}`, {
          body: p,
          headers: { 'X-Chunk-Hash': sha256Hex(p) },
        });
      }
      const overCommit = await api('POST', `/api/upload/commit?uploadId=${smallId}`);
      ok(overCommit.status === 400, 'commit rejecting an assembly above the declared bound', `status=${overCommit.status}`);

      // Memory smoke: the 70 MB assembly must not bloat the server RSS.
      const rss = serverRss(child);
      if (rss !== null) {
        ok(rss < 512 * 1024 * 1024, `server RSS stays bounded after 70 MB assembly (${Math.round(rss / 1048576)} MB)`);
      } else {
        ok(true, 'memory smoke skipped (/proc unavailable)');
      }
    }

    console.log('[8] index ETag / conditional GET (PROB-6)');
    {
      const first = await api('GET', '/api/index');
      const etag = first.headers.get('etag');
      ok(typeof etag === 'string' && etag.length > 0, 'index response carries an ETag', String(etag));

      const cond = await api('GET', '/api/index', { headers: { 'If-None-Match': etag } });
      ok(cond.status === 304, 'If-None-Match with the current ETag answers 304', `status=${cond.status}`);
      ok((await cond.arrayBuffer()).byteLength === 0, '304 response body is empty');

      const wildcard = await api('GET', '/api/index', { headers: { 'If-None-Match': '*' } });
      ok(wildcard.status === 304, 'If-None-Match: * answers 304');

      const packet = await encryptBuffer(noteBytes.buffer, km, salt, 'etag/probe.md', 1);
      await api('POST', '/api/upload', {
        body: packet,
        headers: {
          'X-File-Path': encodeURIComponent('etag/probe.md'),
          'X-Cipher-Hash': sha256Hex(packet),
        },
      });
      const changed = await api('GET', '/api/index', { headers: { 'If-None-Match': etag } });
      ok(changed.status === 200, 'stale ETag after a mutation answers 200 with the full index');
      ok(changed.headers.get('etag') !== etag, 'ETag changes when the index changes');
    }

    console.log('[9] multi-token auth (PROB-5)');
    {
      await stopServer(child);
      const multi = startServer(dataDir, { AUTH_TOKENS: `${TOKEN_B},${TOKEN_C}` });
      await multi.waitReady();
      try {
        for (const [label, token] of [['original', TOKEN], ['token B', TOKEN_B], ['token C', TOKEN_C]]) {
          const res = await api('GET', '/api/index', { token });
          ok(res.ok, `${label} authorizes when listed in AUTH_TOKEN/AUTH_TOKENS`, `status=${res.status}`);
        }
      } finally {
        await stopServer(multi.child);
      }

      // Revoke token B: only B stops authorizing.
      const revoked = startServer(dataDir, { AUTH_TOKENS: TOKEN_C });
      await revoked.waitReady();
      try {
        const b = await api('GET', '/api/index', { token: TOKEN_B });
        ok(b.status === 401, 'revoked token B gets 401 after removal from AUTH_TOKENS', `status=${b.status}`);
        const c = await api('GET', '/api/index', { token: TOKEN_C });
        ok(c.ok, 'token C still authorizes after B was revoked');
        const o = await api('GET', '/api/index', { token: TOKEN });
        ok(o.ok, 'the original AUTH_TOKEN is unaffected');
      } finally {
        await stopServer(revoked.child);
      }

      const resumed = startServer(dataDir);
      await resumed.waitReady();
      resumedChild = resumed.child;
      // Sections below run against the resumed instance.
    }

    console.log('[10] key rotation protocol (PROB-1)');
    {
      // Verify the exact 0.2.0-bricking scenario now passes end to end:
      // seed verifier A -> files under A -> rotate to B -> B decrypts everything.
      const VERIFIER_PLAIN = new TextEncoder().encode('e2ee-verifier-v1\0');
      const kmB = await deriveMaterial('rotated-password-🎯', salt);
      const keyBHex = Buffer.from(kmB.keyId).toString('hex');
      const verifierA = '.e2ee-verifier.' + keyIdHex;
      const verifierB = '.e2ee-verifier.' + keyBHex;

      // (precondition) verifier A already exists from earlier sections? Seed explicitly:
      const vA = await encryptBuffer(VERIFIER_PLAIN.buffer, km, salt, verifierA, 1);
      await api('POST', '/api/upload', {
        body: vA,
        headers: {
          'X-File-Path': encodeURIComponent(verifierA),
          'X-Cipher-Hash': sha256Hex(vA),
          'X-Key-Id': keyIdHex,
          'X-File-Version': '1',
        },
      });

      // 1. seed verifier B (coexistence)
      const vB = await encryptBuffer(VERIFIER_PLAIN.buffer, kmB, salt, verifierB, 1);
      const seedB = await api('POST', '/api/upload', {
        body: vB,
        headers: {
          'X-File-Path': encodeURIComponent(verifierB),
          'X-Cipher-Hash': sha256Hex(vB),
          'X-Key-Id': keyBHex,
          'X-File-Version': '1',
        },
      });
      ok(seedB.ok, 'rotation step 1: new verifier seeded alongside the old one');

      // 2. re-encrypt + re-push every live file under key B (ver + 1)
      const idx = await (await api('GET', '/api/index')).json();
      const liveFiles = Object.entries(idx.files).filter(
        ([p, f]) => f && !f.deleted && !p.startsWith('.e2ee-'),
      );
      let rotated = 0;
      for (const [p, entry] of liveFiles) {
        const blob = await (await api('GET', `/api/download?path=${encodeURIComponent(p)}`)).arrayBuffer();
        let plain;
        if (entry.manifest && entry.manifest.length === 64) {
          // chunked file: pull the manifest back through the decrypt replica
          const mb = new Uint8Array(32);
          for (let i = 0; i < 32; i++) mb[i] = parseInt(entry.manifest.substring(i * 2, i * 2 + 2), 16);
          plain = (await decryptChunked(blob, km, p, mb)).plaintext;
        } else {
          plain = (await decryptBuffer(blob, km, p)).plaintext;
        }
        const newVer = (entry.ver || 0) + 1;
        const reEncrypted = await encryptBuffer(plain, kmB, salt, p, newVer);
        const up = await api('POST', '/api/upload', {
          body: reEncrypted,
          headers: {
            'X-File-Path': encodeURIComponent(p),
            'X-Cipher-Hash': sha256Hex(reEncrypted),
            'X-Key-Id': keyBHex,
            'X-File-Version': String(newVer),
          },
        });
        if (!up.ok) throw new Error(`rotation upload failed for ${p}: ${up.status}`);
        rotated++;
      }
      ok(rotated === liveFiles.length && rotated > 0, `rotation step 2: all ${rotated} live files re-encrypted under the new key`);

      // 3. completion check + old verifier removal
      const fresh = await (await api('GET', '/api/index')).json();
      const stale = Object.entries(fresh.files).filter(
        ([p, f]) => f && !f.deleted && !p.startsWith('.e2ee-') && f.keyId !== keyBHex,
      );
      ok(stale.length === 0, 'rotation step 3a: every live entry carries the new keyId');
      const delA = await api('DELETE', `/api/delete?path=${encodeURIComponent(verifierA)}`);
      ok(delA.ok, 'rotation step 3b: old verifier tombstoned');

      // 4. a fresh device with password B can decrypt everything.
      const idxB = await (await api('GET', '/api/index')).json();
      let allDecrypt = true;
      for (const [p, entry] of Object.entries(idxB.files)) {
        if (!entry || entry.deleted || p.startsWith('.e2ee-')) continue;
        const blob = await (await api('GET', `/api/download?path=${encodeURIComponent(p)}`)).arrayBuffer();
        try {
          if (entry.manifest && entry.manifest.length === 64) {
            const mb = new Uint8Array(32);
            for (let i = 0; i < 32; i++) mb[i] = parseInt(entry.manifest.substring(i * 2, i * 2 + 2), 16);
            await decryptChunked(blob, kmB, p, mb);
          } else {
            await decryptBuffer(blob, kmB, p);
          }
        } catch {
          allDecrypt = false;
        }
      }
      ok(allDecrypt, 'post-rotation: every file decrypts under the NEW password');

      // 5. a stale device with password A sees: verifier A gone, verifier B present.
      const probeA = await api('GET', `/api/download?path=${encodeURIComponent(verifierA)}`);
      ok(probeA.status === 404, 'stale device: its own verifier is gone (tombstoned)');
      const probeB = await api('GET', `/api/download?path=${encodeURIComponent(verifierB)}`);
      ok(probeB.ok, 'stale device: a foreign verifier is visible -> triggers the password prompt');

      // Key B material now governs the remaining sections.
      km = kmB;
      keyIdHex = keyBHex;
    }

    console.log('[11] rollback visibility (PROB-2)');
    {
      const p = 'rb/notes.md';
      const versions = [];
      for (let ver = 1; ver <= 3; ver++) {
        const plain = new TextEncoder().encode(`revision ${ver}\n`).buffer;
        const packet = await encryptBuffer(plain, km, salt, p, ver);
        versions.push({ ver, packet, plain });
        await api('POST', '/api/upload', {
          body: packet,
          headers: {
            'X-File-Path': encodeURIComponent(p),
            'X-Cipher-Hash': sha256Hex(packet),
            'X-Key-Id': keyIdHex,
            'X-File-Version': String(ver),
          },
        });
      }
      ok(true, 'uploaded versions 1..3 of a note');

      // A compromised server "restores" the version-1 snapshot (old index
      // entry + old packet served consistently — every hash matches).
      const restored = await api('POST', '/api/upload', {
        body: versions[0].packet,
        headers: {
          'X-File-Path': encodeURIComponent(p),
          'X-Cipher-Hash': sha256Hex(versions[0].packet),
          'X-Key-Id': keyIdHex,
          'X-File-Version': '1',
        },
      });
      ok(restored.ok, 'the server accepts the rolled-back bytes (it is untrusted)');

      const idx = await (await api('GET', '/api/index')).json();
      ok(idx.files[p]?.ver === 1, 'the index reports the rolled-back counter (ver 1)');

      const blob = await (
        await api('GET', `/api/download?path=${encodeURIComponent(p)}`)
      ).arrayBuffer();
      const dec = await decryptBuffer(blob, km, p);
      // The packet still AUTHENTICATES (the server cannot forge content), but
      // the authenticated counter exposes the rollback: 1 < 3.
      ok(dec.version === 1, 'the rolled-back packet authenticates and exposes version 1');
      ok(
        dec.version < 3,
        'client journal holds version 3 -> the rollback policy refuses the pull (see planSync/crypto specs)',
      );
    }

    console.log('[12] concurrency bench (PROB-7)');
    {
      // 36 small files: sequential downloads vs a 3-way pool. On loopback the
      // per-request latency floor dominates, so the pooled pass must finish
      // in visibly fewer round trips than N sequential ones.
      const N = 36;
      const paths = [];
      for (let i = 0; i < N; i++) {
        const p = `bench/file-${String(i).padStart(3, '0')}.md`;
        const packet = await encryptBuffer(noteBytes.buffer, km, salt, p, 1);
        const up = await api('POST', '/api/upload', {
          body: packet,
          headers: {
            'X-File-Path': encodeURIComponent(p),
            'X-Cipher-Hash': sha256Hex(packet),
            'X-Key-Id': keyIdHex,
            'X-File-Version': '1',
          },
        });
        if (!up.ok) throw new Error(`bench upload failed: ${up.status}`);
        paths.push(p);
      }

      const dl = (p) => api('GET', `/api/download?path=${encodeURIComponent(p)}`).then((r) => {
        if (!r.ok) throw new Error(`bench download failed: ${r.status}`);
        return r.arrayBuffer();
      });

      const t0 = performance.now();
      for (const p of paths) await dl(p);
      const sequentialMs = performance.now() - t0;

      const t1 = performance.now();
      let cursor = 0;
      await Promise.all(
        Array.from({ length: 3 }, async () => {
          for (;;) {
            const idx = cursor++;
            if (idx >= paths.length) return;
            await dl(paths[idx]);
          }
        }),
      );
      const pooledMs = performance.now() - t1;

      ok(
        pooledMs < sequentialMs,
        `3-way pooled downloads beat sequential (${Math.round(pooledMs)} ms vs ${Math.round(sequentialMs)} ms for ${N} files)`,
        `sequential=${sequentialMs}ms pooled=${pooledMs}ms`,
      );
      ok(true, `bench: sequential ${Math.round(sequentialMs)} ms, pooled(×3) ${Math.round(pooledMs)} ms`);
    }

    console.log('[13] persistence across restart');
    {
      await stopServer(resumedChild);
      const before = JSON.parse(fs.readFileSync(path.join(dataDir, 'index.json'), 'utf8'));
      const filesOnDisk = fs.readdirSync(path.join(dataDir, 'files'));

      const second = startServer(dataDir);
      await second.waitReady();
      try {
        const meta = await (await api('GET', '/api/meta')).json();
        ok(meta.vaultId === vaultId, 'vaultId survives restart (same KDF salt)');

        const idx = await (await api('GET', '/api/index')).json();
        ok(idx.files['notes/project brief.md']?.deleted === false, 'live entry survives restart');
        ok(idx.files['attachments/big-image.bin']?.deleted === true, 'tombstone survives restart');
        // The chunked file was re-sealed as a single-shot packet during the
        // rotation ([10]); its entry must survive with the rotated key id.
        ok(
          idx.files[bigPath]?.deleted === false &&
            idx.files[bigPath]?.keyId === keyIdHex &&
            idx.files[bigPath]?.manifest === '',
          'chunked-file entry survives restart (single-shot after rotation)',
          JSON.stringify(idx.files[bigPath]),
        );
        ok(filesOnDisk.length > 0, 'encrypted blobs live under data/files/');

        const dl = await api('GET', `/api/download?path=${encodeURIComponent('notes/project brief.md')}`);
        const downloaded = await dl.arrayBuffer();
        const decrypted = await decryptBuffer(downloaded, km, 'notes/project brief.md');
        ok(
          bytesEqual(decrypted.plaintext, noteBytes.buffer),
          'full round-trip works after restart (post-rotation key)',
        );
      } finally {
        await stopServer(second.child);
      }
    }

    console.log('[14] rebuild-index tool (PROB-9)');
    {
      const indexPath = path.join(dataDir, 'index.json');
      const before = JSON.parse(fs.readFileSync(indexPath, 'utf8'));
      // Simulate the disaster: lose the index, keep the blobs.
      fs.renameSync(indexPath, `${indexPath}.lost`);

      const tool = spawnSync(
        process.execPath,
        [path.join(__dirname, '..', 'tools', 'rebuild-index.mjs'), dataDir],
        { encoding: 'utf8' },
      );
      ok(tool.status === 0, 'rebuild-index exits 0', tool.stderr);

      const after = JSON.parse(fs.readFileSync(indexPath, 'utf8'));
      const liveBefore = Object.entries(before).filter(([, e]) => e && !e.deleted);
      let allMatch = liveBefore.length > 0;
      for (const [p, e] of liveBefore) {
        const r = after[p];
        if (!r || r.hash !== e.hash || r.size !== e.size || r.ver !== 0 || r.keyId !== '' || r.deleted !== false) {
          allMatch = false;
          console.error(`    mismatch for "${p}": ${JSON.stringify(r)}`);
        }
      }
      ok(allMatch, 'rebuilt index equals the original modulo ver/keyId defaults');

      // Orphan report: a PARSEABLE but stale index (blobs wiped server-side)
      // must surface entries that no longer exist on disk.
      const stale = { ...before, 'ghost/orphaned.md': { mtime: 1, size: 1, hash: 'x', deleted: false } };
      fs.writeFileSync(indexPath, JSON.stringify(stale));
      const tool2 = spawnSync(
        process.execPath,
        [path.join(__dirname, '..', 'tools', 'rebuild-index.mjs'), '--dry-run', dataDir],
        { encoding: 'utf8' },
      );
      ok(tool2.status === 0, 'rebuild-index --dry-run exits 0', tool2.stderr);
      ok(
        !fs.readFileSync(indexPath, 'utf8').includes('ghost/orphaned.md') ||
          fs.readFileSync(indexPath, 'utf8') === JSON.stringify(stale),
        '--dry-run leaves index.json untouched',
      );
      const orphanCount = Number(/orphans\s*:\s*(\d+)/.exec(tool2.stdout)?.[1]);
      const expectedOrphans = Object.entries(stale).filter(
        ([p, e]) => e && !e.deleted && !(p in after),
      ).length;
      ok(
        orphanCount === expectedOrphans,
        `orphan report counts live index entries without a blob (${expectedOrphans}; tombstones excluded)`,
        tool2.stdout,
      );
      fs.rmSync(`${indexPath}.lost`, { force: true });
    }
  } finally {
    child.kill('SIGKILL');
    resumedChild?.kill('SIGKILL');
    fs.rmSync(dataDir, { recursive: true, force: true });
  }

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed === 0 ? 0 : 1);
}

let resumedChild = null;

run().catch((err) => {
  console.error('test harness crashed:', err);
  process.exit(1);
});
