/**
 * Unit vectors for the packet-v3 format (PROB-1/2/3 verification):
 * header build/parse, AAD binding, chunk streams, splice/gap rejection,
 * version-counter policy and rollback detection.
 *
 * Runs against the REAL plugin/src/crypto.ts + syncEngine.ts via the
 * esbuild harness (see harness.mjs). No framework dependencies.
 */

import { finish, loadModule, ok, throws } from './harness.mjs';

const subtle = globalThis.crypto.subtle;
const PBKDF2_ITERATIONS = 210_000;

const PASSWORD = 'correct horse battery staple';
const OTHER_PASSWORD = 'hunter2';

function randomBytes(length) {
  const out = new Uint8Array(length);
  for (let offset = 0; offset < length; offset += 65536) {
    crypto.getRandomValues(out.subarray(offset, Math.min(offset + 65536, length)));
  }
  return out;
}

function bytesEqual(a, b) {
  const ua = new Uint8Array(a);
  const ub = new Uint8Array(b);
  if (ua.length !== ub.length) return false;
  let diff = 0;
  for (let i = 0; i < ua.length; i++) diff |= ua[i] ^ ub[i];
  return diff === 0;
}

const salt = new Uint8Array(16).fill(0xab);

async function derive(password) {
  const material = await subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveBits'],
  );
  const bits = new Uint8Array(
    await subtle.deriveBits(
      { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
      material,
      256,
    ),
  );
  const digest = new Uint8Array(await subtle.digest('SHA-256', bits));
  const keyId = digest.slice(0, 8);
  const key = await subtle.importKey(
    'raw', bits, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'],
  );
  bits.fill(0);
  return { key, keyId };
}

async function run() {
  const crypto = await loadModule('src/crypto.ts');
  const engine = await loadModule('src/syncEngine.ts');

  console.log('[1] key material & keyId');
  const km = await derive(PASSWORD);
  const kmOther = await derive(OTHER_PASSWORD);
  const sameKm = await derive(PASSWORD);
  ok(km.keyId.length === 8, 'keyId is 8 bytes');
  ok(
    crypto.toHex(km.keyId) === crypto.toHex(sameKm.keyId),
    'keyId is deterministic for (password, salt)',
  );
  ok(
    crypto.toHex(km.keyId) !== crypto.toHex(kmOther.keyId),
    'keyId differs for a different password',
  );
  const manager = new crypto.CryptoManager(PASSWORD, salt);
  const mOther = new crypto.CryptoManager(OTHER_PASSWORD, salt);
  ok(
    crypto.toHex((await manager.keyMaterial(salt)).keyId) === crypto.toHex(km.keyId),
    'CryptoManager derives the same keyId',
  );

  console.log('[2] v3 single-shot packet: build / parse / AAD vectors');
  const path = 'notes/project brief.md';
  const plaintext = new TextEncoder().encode('# secret 🔐 v3 test\n').buffer;
  const packet = await crypto.encryptBuffer(plaintext, km.key, km.keyId, salt, path, 7);
  ok(packet.byteLength === 53 + plaintext.byteLength + 16, 'packet size = header + ct + tag');
  ok(new Uint8Array(packet)[0] === 0x03, 'version byte is 0x03');

  const decrypted = await manager.decrypt(packet, path);
  ok(bytesEqual(decrypted.plaintext, plaintext), 'round-trip returns the original plaintext');
  function equal(actual, expected, label) { ok(actual === expected, label, `${actual} != ${expected}`); }
  equal(decrypted.version, 7, 'authenticated version counter round-trips');
  equal(decrypted.keyId, crypto.toHex(km.keyId), 'keyId round-trips');
  equal(decrypted.chunkIndex, crypto.CHUNK_INDEX_SINGLE, 'single-shot chunkIndex sentinel');

  // header field offsets: keyId at 1..9, ver u64 at 37..45 (u32 pair), ctLen at 45..49
  const hdr = new Uint8Array(packet);
  ok(
    crypto.toHex(hdr.slice(1, 9)) === crypto.toHex(km.keyId),
    'header exposes the public keyId at offset 1',
  );
  const dv = new DataView(hdr.buffer);
  ok(dv.getUint32(37, false) === 0 && dv.getUint32(41, false) === 7, 'version counter is u64 BE at 37..45');
  ok(dv.getUint32(45, false) === plaintext.byteLength, 'ctLen (excl. tag) at 45..49');

  const peek = crypto.peekV3(hdr);
  ok(peek && peek.keyId === crypto.toHex(km.keyId) && peek.version === 7, 'peekV3 reads keyId + version');
  ok(crypto.peekV3(new Uint8Array([0x02, 1, 2, 3])) === null, 'peekV3 rejects non-v3 input');

  console.log('[3] authentication failures (tamper / swap / wrong key)');
  await throws(
    () => manager.decrypt(packet, 'other/path.md'),
    'ciphertext swapped to a different path fails GCM authentication',
    /Decryption failed/,
  );
  await throws(
    () => mOther.decrypt(packet, path),
    'wrong password fails GCM authentication',
    /Decryption failed/,
  );

  const tampered = new Uint8Array(packet.slice(0));
  tampered[40] ^= 0x01; // inside the version counter
  await throws(
    () => manager.decrypt(tampered.buffer, path),
    'tampered version counter byte fails authentication (ver is INSIDE the AAD)',
  );

  const tamperedLen = new Uint8Array(packet.slice(0));
  tamperedLen[46] ^= 0x01; // ctLen field
  await throws(
    () => manager.decrypt(tamperedLen.buffer, path),
    'tampered ctLen field fails authentication',
  );

  const tamperedCt = new Uint8Array(packet.slice(0));
  tamperedCt[60] ^= 0xff;
  await throws(() => manager.decrypt(tamperedCt.buffer, path), 'tampered ciphertext fails authentication');

  console.log('[4] version counter policy');
  await throws(
    () => crypto.encryptBuffer(plaintext, km.key, km.keyId, salt, path, 0),
    'version 0 is rejected',
    /Invalid packet version/,
  );
  await throws(
    () => crypto.encryptBuffer(plaintext, km.key, km.keyId, salt, path, Number.MAX_SAFE_INTEGER + 1),
    'version above MAX_SAFE_INTEGER is rejected',
    /Invalid packet version/,
  );

  console.log('[5] v2/v1 read-only compatibility');
  // hand-built v2 packet: [0x02 | salt | iv | ct+tag], AAD = 0x02 || NFC(path)
  {
    const iv = randomBytes(12);
    const p2 = new TextEncoder().encode(path.normalize('NFC'));
    const aad2 = new Uint8Array(1 + p2.length);
    aad2[0] = 0x02;
    aad2.set(p2, 1);
    const ct = new Uint8Array(
      await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad2 }, km.key, plaintext),
    );
    const v2 = new Uint8Array(1 + 16 + 12 + ct.length);
    v2[0] = 0x02;
    v2.set(salt, 1);
    v2.set(iv, 17);
    v2.set(ct, 29);
    const dec = await manager.decrypt(v2.buffer, path);
    ok(bytesEqual(dec.plaintext, plaintext), 'v2 packet still decrypts (migration path)');
    equal(dec.version, null, 'v2 packet reports no version counter');
  }
  {
    // hand-built v1 packet: [salt | iv | ct+tag], no AAD
    const iv = randomBytes(12);
    const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, km.key, plaintext));
    const v1 = new Uint8Array(16 + 12 + ct.length);
    v1.set(salt, 0);
    v1.set(iv, 16);
    v1.set(ct, 28);
    const dec = await manager.decrypt(v1.buffer, path);
    ok(bytesEqual(dec.plaintext, plaintext), 'v1 packet still decrypts (migration path)');
  }

  console.log('[6] chunked streams (PROB-3)');
  const chunks = [
    randomBytes(1024 * 256),
    randomBytes(1024 * 256),
    randomBytes(1024 * 200),
  ];
  const chunkHashes = [];
  for (const c of chunks) chunkHashes.push(new Uint8Array(await subtle.digest('SHA-256', c)));
  let manifestInput = new Uint8Array(chunks.length * 32);
  chunkHashes.forEach((h, i) => manifestInput.set(h, i * 32));
  const manifest = new Uint8Array(await subtle.digest('SHA-256', manifestInput));

  const packets = [];
  for (let i = 0; i < chunks.length; i++) {
    packets.push(
      await crypto.encryptChunk(chunks[i].buffer, km.key, km.keyId, salt, path, 4, i, manifest),
    );
  }
  const blob = new Uint8Array(packets.reduce((n, p) => n + p.byteLength, 0));
  let off = 0;
  for (const p of packets) {
    blob.set(new Uint8Array(p), off);
    off += p.byteLength;
  }
  const assembled = await manager.decryptChunked(blob.buffer, path, manifest);
  const expectedPlain = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
  let eo = 0;
  for (const c of chunks) {
    expectedPlain.set(c, eo);
    eo += c.length;
  }
  ok(bytesEqual(assembled.plaintext, expectedPlain.buffer), 'chunk stream reassembles the plaintext');
  equal(assembled.version, 4, 'authenticated version carried by every chunk');
  equal(assembled.chunkCount, 3, 'chunk count reported');

  console.log('[7] splice / gap / mixed-stream rejection');
  {
    // chunks of a DIFFERENT content (different manifest) must not splice in
    const otherChunks = [randomBytes(1024 * 256), randomBytes(1024 * 256)];
    const otherHashes = [];
    for (const c of otherChunks) otherHashes.push(new Uint8Array(await subtle.digest('SHA-256', c)));
    let om = new Uint8Array(otherHashes.length * 32);
    otherHashes.forEach((h, i) => om.set(h, i * 32));
    const otherManifest = new Uint8Array(await subtle.digest('SHA-256', om));
    const foreign = await crypto.encryptChunk(
      otherChunks[0].buffer, km.key, km.keyId, salt, path, 4, 1, otherManifest,
    );
    const spliced = new Uint8Array(packets[0].byteLength + foreign.byteLength + packets[2].byteLength);
    spliced.set(new Uint8Array(packets[0]), 0);
    spliced.set(new Uint8Array(foreign), packets[0].byteLength);
    spliced.set(new Uint8Array(packets[2]), packets[0].byteLength + foreign.byteLength);
    await throws(
      () => manager.decryptChunked(spliced.buffer, path, manifest),
      'chunk encrypted under a different manifest cannot be spliced into the stream',
      /Decryption failed/,
    );
  }
  {
    // gap: chunks 0 and 2 concatenated (index 2 arrives where 1 is expected)
    const gapped = new Uint8Array(packets[0].byteLength + packets[2].byteLength);
    gapped.set(new Uint8Array(packets[0]), 0);
    gapped.set(new Uint8Array(packets[2]), packets[0].byteLength);
    await throws(
      () => manager.decryptChunked(gapped.buffer, path, manifest),
      'non-contiguous chunk indexes are rejected',
      /Decryption failed/,
    );
  }
  {
    // mixed versions across chunks of one stream
    const v5chunk = await crypto.encryptChunk(
      chunks[2].buffer, km.key, km.keyId, salt, path, 5, 2, manifest,
    );
    const mixed = new Uint8Array(packets[0].byteLength + packets[1].byteLength + v5chunk.byteLength);
    mixed.set(new Uint8Array(packets[0]), 0);
    mixed.set(new Uint8Array(packets[1]), packets[0].byteLength);
    mixed.set(new Uint8Array(v5chunk), packets[0].byteLength + packets[1].byteLength);
    await throws(
      () => manager.decryptChunked(mixed.buffer, path, manifest),
      'chunks with differing version counters are rejected',
      /Decryption failed/,
    );
  }
  {
    // wrong path binds the whole stream
    await throws(
      () => manager.decryptChunked(blob.buffer, 'other/file.md', manifest),
      'chunk stream swapped to another path fails authentication',
      /Decryption failed/,
    );
  }

  console.log('[8] foreign-salt rejection (CPU-exhaustion defense preserved)');
  {
    const foreignSalt = new Uint8Array(16).fill(0xcd);
    const strictManager = new crypto.CryptoManager(PASSWORD, salt);
    const control = await strictManager.decrypt(packet, path); // must NOT throw
    ok(control.version === 7, 'control: expectedSalt manager decrypts the vault packet');

    const bad = await crypto.encryptBuffer(plaintext, km.key, km.keyId, foreignSalt, path, 1);
    await throws(
      () => strictManager.decrypt(bad, path),
      'packet carrying a foreign salt is rejected before PBKDF2',
      /salt does not belong to this vault/,
    );
  }

  console.log('[9] rollback policy (PROB-2)');
  equal(engine.rollbackReason(undefined, 0), null, 'no record -> never a rollback');
  equal(engine.rollbackReason(0, 0), null, 'record without v3 history accepts v2 packets');
  equal(engine.rollbackReason(0, 1), null, 'record without v3 history accepts v3 packets');
  equal(engine.rollbackReason(3, 3), null, 'same version -> ok');
  equal(engine.rollbackReason(3, 4), null, 'higher version -> ok');
  ok(
    typeof engine.rollbackReason(3, 2) === 'string' && /Rollback detected/.test(engine.rollbackReason(3, 2)),
    'lower version -> refusal',
  );
  ok(
    typeof engine.rollbackReason(3, 0) === 'string' && /pre-v3 packet/.test(engine.rollbackReason(3, 0)),
    'v2 packet after v3 history -> refusal',
  );

  finish('crypto.spec');
}

run().catch((err) => {
  console.error('spec crashed:', err);
  process.exit(1);
});
