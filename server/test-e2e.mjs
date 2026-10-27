#!/usr/bin/env node
/**
 * End-to-end integration test for server/server.js — zero dependencies.
 *
 * It replicates the plugin's crypto EXACTLY (PBKDF2-SHA256 -> AES-256-GCM,
 * packet = [salt(16) | iv(12) | ciphertext+tag]) using Node's WebCrypto, then
 * exercises the full REST surface: auth, meta, upload, index, download,
 * delete/tombstone, hash verification, path-traversal defenses, unicode paths
 * and state persistence across a server restart.
 *
 * Run:  node server/test-e2e.mjs     (requires Node >= 18)
 */

import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const subtle = globalThis.crypto?.subtle ?? crypto.webcrypto.subtle;
const __dirname = path.dirname(fileURLToPath(import.meta.url));

const TOKEN = 'test-token-0123456789abcdef';
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
// Deliberately mirrors plugin/src/crypto.ts byte-for-byte.

const PBKDF2_ITERATIONS = 210_000;

function copyBuffer(view) {
  return view.slice().buffer;
}

async function deriveKey(password, salt) {
  const material = await subtle.importKey(
    'raw',
    copyBuffer(new TextEncoder().encode(password)),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return subtle.deriveKey(
    { name: 'PBKDF2', salt: copyBuffer(salt), iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

async function saltFromVaultId(vaultId) {
  const digest = await subtle.digest('SHA-256', copyBuffer(new TextEncoder().encode(vaultId)));
  return new Uint8Array(digest).slice(0, 16);
}

async function encryptBuffer(plaintext, key, salt) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext));
  const packet = new Uint8Array(16 + 12 + ciphertext.length);
  packet.set(salt, 0);
  packet.set(iv, 16);
  packet.set(ciphertext, 28);
  return packet.buffer;
}

async function decryptBuffer(packet, key) {
  const bytes = new Uint8Array(packet);
  const iv = bytes.slice(16, 28);
  const ciphertext = bytes.slice(28);
  return subtle.decrypt({ name: 'AES-GCM', iv: copyBuffer(iv) }, key, copyBuffer(ciphertext));
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

function bytesEqual(a, b) {
  const ua = new Uint8Array(a);
  const ub = new Uint8Array(b);
  if (ua.length !== ub.length) return false;
  return crypto.timingSafeEqual(ua, ub);
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

function startServer(dataDir) {
  const child = spawn(process.execPath, [path.join(__dirname, 'server.js')], {
    env: {
      ...process.env,
      PORT: String(PORT),
      HOST: '127.0.0.1',
      DATA_DIR: dataDir,
      AUTH_TOKEN: TOKEN,
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
    let key;
    {
      const res = await api('GET', '/api/meta');
      ok(res.ok, 'GET /api/meta responds 200');
      const body = await res.json();
      vaultId = body.vaultId;
      ok(typeof vaultId === 'string' && vaultId.length >= 8, 'meta returns a vaultId', JSON.stringify(body));
      salt = await saltFromVaultId(vaultId);
      key = await deriveKey('correct horse battery staple', salt);
      ok(key instanceof Object, 'PBKDF2 (210k iterations) derives an AES-256-GCM key');
    }

    console.log('[3] upload / index / download round-trip');
    const noteBytes = new TextEncoder().encode('# Secret note 🔐\n\nplain text that must never reach the server\n');
    const binaryBytes = randomBytes(1024 * 1024); // 1 MiB
    const packets = {};
    {
      const cases = [
        ['notes/project brief.md', noteBytes.buffer],
        ['attachments/big-image.bin', binaryBytes.buffer],
        ['笔记/文件夹 文件 ✨.md', noteBytes.buffer], // unicode + spaces
      ];
      for (const [p, plaintext] of cases) {
        const packet = await encryptBuffer(plaintext, key, salt);
        packets[p] = packet;
        const res = await api('POST', '/api/upload', {
          body: packet,
          headers: {
            'Content-Type': 'application/octet-stream',
            'X-File-Path': encodeURIComponent(p),
            'X-Client-Mtime': '1725380000000',
            'X-Cipher-Hash': sha256Hex(packet),
          },
        });
        ok(res.ok, `upload "${p}"`, `status=${res.status}`);
        const entry = await res.json();
        ok(entry.deleted === false && entry.hash === sha256Hex(packet) && entry.mtime === 1725380000000,
          `upload response carries {mtime,size,hash,deleted:false}`, JSON.stringify(entry));
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

    console.log('[4] decrypt with the derived key (and wrong-password failure)');
    {
      const packet = packets['notes/project brief.md'];
      const decrypted = await decryptBuffer(packet, key);
      ok(bytesEqual(decrypted, noteBytes.buffer), 'round-trip decrypt returns the original plaintext');

      const wrongKey = await deriveKey('hunter2', salt);
      let threw = false;
      try {
        await decryptBuffer(packet, wrongKey);
      } catch {
        threw = true;
      }
      ok(threw, 'wrong password fails GCM authentication (no silent garbage)');
    }

    console.log('[5] delete & tombstones');
    {
      const res = await api('DELETE', `/api/delete?path=${encodeURIComponent('attachments/big-image.bin')}`);
      ok(res.ok, 'DELETE responds 200');
      const tomb = await res.json();
      ok(tomb.deleted === true && typeof tomb.mtime === 'number', 'delete returns a tombstone', JSON.stringify(tomb));

      const idx = await (await api('GET', '/api/index')).json();
      ok(idx.files['attachments/big-image.bin']?.deleted === true, 'index keeps the tombstone entry');

      const dl = await api('GET', `/api/download?path=${encodeURIComponent('attachments/big-image.bin')}`);
      ok(dl.status === 404, 'download of a tombstoned path is 404', `status=${dl.status}`);

      const again = await api('DELETE', `/api/delete?path=${encodeURIComponent('attachments/big-image.bin')}`);
      ok(again.ok, 'delete is idempotent');

      const unknown = await api('DELETE', `/api/delete?path=${encodeURIComponent('never/existed.md')}`);
      ok(unknown.status === 404, 'delete of an unknown path is 404', `status=${unknown.status}`);

      // Re-uploading must clear the tombstone (delete-then-recreate flows).
      const packet = await encryptBuffer(noteBytes.buffer, key, salt);
      const up = await api('POST', '/api/upload', {
        body: packet,
        headers: { 'X-File-Path': encodeURIComponent('attachments/big-image.bin') },
      });
      ok(up.ok && (await up.json()).deleted === false, 're-upload clears the tombstone');

      // Restore tombstoned state for the persistence check.
      await api('DELETE', `/api/delete?path=${encodeURIComponent('attachments/big-image.bin')}`);
    }

    console.log('[6] integrity & path safety');
    {
      const packet = await encryptBuffer(noteBytes.buffer, key, salt);
      const mismatch = await api('POST', '/api/upload', {
        body: packet,
        headers: {
          'X-File-Path': encodeURIComponent('integrity/check.bin'),
          'X-Cipher-Hash': 'deadbeef'.repeat(8),
        },
      });
      ok(mismatch.status === 400, 'upload with wrong X-Cipher-Hash is rejected', `status=${mismatch.status}`);

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

      const notFound = await api('GET', `/api/download?path=${encodeURIComponent('missing/file.md')}`);
      ok(notFound.status === 404, 'download of unknown path is 404');
    }

    console.log('[7] persistence across restart');
    {
      child.kill('SIGTERM');
      await new Promise((resolve) => child.on('exit', resolve));

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
        ok(filesOnDisk.length > 0, 'encrypted blobs live under data/files/');

        const dl = await api('GET', `/api/download?path=${encodeURIComponent('notes/project brief.md')}`);
        const downloaded = await dl.arrayBuffer();
        const decrypted = await decryptBuffer(downloaded, key);
        ok(bytesEqual(decrypted, noteBytes.buffer), 'full round-trip works after restart');
      } finally {
        second.child.kill('SIGTERM');
        await new Promise((resolve) => second.child.on('exit', resolve));
      }
    }
  } finally {
    child.kill('SIGKILL');
    fs.rmSync(dataDir, { recursive: true, force: true });
  }

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed === 0 ? 0 : 1);
}

run().catch((err) => {
  console.error('test harness crashed:', err);
  process.exit(1);
});
