/**
 * Zero-knowledge E2EE helpers built exclusively on the Web Crypto API
 * (`globalThis.crypto.subtle`), which is available in Obsidian on desktop,
 * Android and iOS alike. No Node.js `crypto` module is used anywhere.
 *
 * Key derivation : PBKDF2 (SHA-256, 210 000 iterations) -> AES-256-GCM key.
 *                  The 256 derived bits are hashed once to publish a keyId
 *                  (first 8 bytes of SHA-256(key)) that identifies the key
 *                  WITHOUT revealing it — key rotation (packet v3) uses it to
 *                  route verifier lookups and to let a client detect "this
 *                  file was encrypted under a different password" before
 *                  attempting an expensive decrypt.
 * Salt strategy  : deterministic, vault-wide — first 16 bytes of
 *                  SHA-256(vaultId), where vaultId is stable server metadata.
 *                  The derived key material is cached per salt in memory so the
 *                  expensive PBKDF2 pass runs once per session. Packets
 *                  carrying any other salt are rejected outright (a hostile
 *                  server must not be able to force one 210k-iteration pass
 *                  per file with attacker-chosen salts).
 *
 * Packet format  : v3 (current): [ 0x03 | keyId(8) | salt(16) | IV(12) |
 *                      version u64 BE | ctLen u32 BE | chunkIndex u32 BE |
 *                      ciphertext | tag(16) ]
 *                  AAD = 0x03 || keyId || NFC(path) || version(8) ||
 *                        ctLen(4) || chunkIndex(4) ||
 *                        [ fileManifest(32) — chunk packets only ]
 *                  - the per-file version counter makes server-side rollbacks
 *                    detectable (PROB-2): the counter lives inside the
 *                    authenticated data, so the untrusted server cannot forge
 *                    or strip it;
 *                  - chunkIndex 0xFFFFFFFF marks a single-shot packet; every
 *                    other value is a chunk of a large file, authenticated
 *                    additionally against fileManifest =
 *                    SHA-256(SHA-256(plainChunk_0) || … || SHA-256(plainChunk_n))
 *                    so chunks of two different uploads can never be spliced
 *                    into one decryptable franken-file;
 *                  - ctLen makes every packet self-delimiting: a stored blob
 *                    that is a concatenation of chunk packets can be walked
 *                    without any out-of-band length table.
 *                  v2 (0.2.x, read-only compat): [ 0x02 | salt(16) | IV(12) |
 *                      ct+tag ], AAD = 0x02 || NFC(path). Still decryptable;
 *                      every re-push upgrades the file to v3.
 *                  v1 (0.1.x, read-only compat): [ salt(16) | IV(12) | ct+tag ],
 *                      no AAD. Still decryptable; every re-push upgrades.
 * IV policy      : a fresh 12-byte random IV (crypto.getRandomValues) on EVERY
 *                  encryption. IV reuse under the same key is catastrophic in
 *                  GCM and therefore structurally impossible here.
 */

const PBKDF2_ITERATIONS = 210_000;
const SALT_BYTES = 16;
const IV_BYTES = 12;
const KEY_ID_BYTES = 8;
const VERSION_BYTES = 8; // u64 BE
const CT_LEN_BYTES = 4; // u32 BE
const CHUNK_INDEX_BYTES = 4; // u32 BE
const MANIFEST_BYTES = 32;

/** v1 packet: header + empty plaintext + 16-byte GCM auth tag. */
const PACKET_V1_BYTES = SALT_BYTES + IV_BYTES + 16;
/** Version byte introduced with AAD binding (v2 packets). */
const PACKET_V2 = 0x02;
/** v2 packet: version byte + header + empty plaintext + tag. */
const PACKET_V2_BYTES = 1 + SALT_BYTES + IV_BYTES + 16;
/** Version byte introduced with keyId / version counter / chunking (v3). */
const PACKET_V3 = 0x03;
export const V3_HEADER_BYTES =
  1 + KEY_ID_BYTES + SALT_BYTES + IV_BYTES + VERSION_BYTES + CT_LEN_BYTES + CHUNK_INDEX_BYTES;
/** v3 packet: header + empty plaintext + tag. */
export const MIN_V3_BYTES = V3_HEADER_BYTES + 16;
/** chunkIndex value marking a whole-file (non-chunked) packet. */
export const CHUNK_INDEX_SINGLE = 0xffffffff;
/** Largest per-file version counter the wire format can carry safely in JS. */
export const MAX_VERSION = Number.MAX_SAFE_INTEGER;

export const PACKET_HEADER_BYTES = SALT_BYTES + IV_BYTES; // v1/v2 layouts

export class CryptoError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CryptoError';
  }
}

function subtle(): SubtleCrypto {
  const c = window.crypto;
  if (!c || !c.subtle) {
    throw new CryptoError('The Web Crypto API is unavailable on this device.');
  }
  return c.subtle;
}

/**
 * Copy a typed-array view into a standalone ArrayBuffer. Web Crypto accepts
 * views, but copying sidesteps any detached-buffer / TS BufferSource quirks
 * for the small fixed-size inputs (password, salt, IV).
 */
function copyBuffer(view: Uint8Array): ArrayBuffer {
  return view.slice().buffer as ArrayBuffer;
}

const encoder = new TextEncoder();

function aadV2(path: string): ArrayBuffer {
  const p = encoder.encode(path.normalize('NFC'));
  const aad = new Uint8Array(1 + p.length);
  aad[0] = PACKET_V2;
  aad.set(p, 1);
  return aad.buffer as ArrayBuffer;
}

/**
 * v3 AAD. Binds the ciphertext to: the key id, the canonical path, the
 * per-file version counter, the declared ciphertext length, the chunk index
 * and (chunk packets only) the file manifest hash.
 */
function aadV3(
  path: string,
  keyId: Uint8Array,
  version: number,
  ctLen: number,
  chunkIndex: number,
  fileManifest: Uint8Array | null,
): ArrayBuffer {
  const p = encoder.encode(path.normalize('NFC'));
  const manifestLen = fileManifest ? MANIFEST_BYTES : 0;
  const aad = new Uint8Array(
    1 + KEY_ID_BYTES + p.length + VERSION_BYTES + CT_LEN_BYTES + CHUNK_INDEX_BYTES + manifestLen,
  );
  let o = 0;
  aad[o++] = PACKET_V3;
  aad.set(keyId, o);
  o += KEY_ID_BYTES;
  aad.set(p, o);
  o += p.length;
  const dv = new DataView(aad.buffer);
  writeU64BE(dv, o, version); // no BigInt: u64 as a u32 pair (lib is ES2018)
  o += VERSION_BYTES;
  dv.setUint32(o, ctLen, false);
  o += CT_LEN_BYTES;
  dv.setUint32(o, chunkIndex >>> 0, false);
  o += CHUNK_INDEX_BYTES;
  if (fileManifest) aad.set(fileManifest, o);
  return aad.buffer as ArrayBuffer;
}

/** u64 BE write without BigInt (ES2018 lib): safe for versions up to 2^53. */
function writeU64BE(dv: DataView, offset: number, value: number): void {
  const v = Math.floor(value);
  dv.setUint32(offset, Math.floor(v / 0x1_0000_0000), false);
  dv.setUint32(offset + 4, v >>> 0, false);
}

/** u64 BE read without BigInt. Returns NaN on values above 2^53. */
function readU64BE(dv: DataView, offset: number): number {
  const hi = dv.getUint32(offset, false);
  const lo = dv.getUint32(offset + 4, false);
  return hi * 0x1_0000_0000 + lo;
}

/** Constant-time-ish equality for small byte strings (salts, verifiers). */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function toHex(bytes: Uint8Array): string {
  const digits = '0123456789abcdef';
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += digits[bytes[i] >> 4] + digits[bytes[i] & 0x0f];
  }
  return out;
}

/** Hex SHA-256 of arbitrary bytes (used for ciphertext hashing and manifests).
 *  Zero-copy for typed-array views — hashing must not duplicate multi-MB packets. */
export async function sha256Hex(data: ArrayBuffer | Uint8Array): Promise<string> {
  const input: BufferSource =
    data instanceof Uint8Array ? (data as Uint8Array<ArrayBuffer>) : new Uint8Array(data);
  const digest = await subtle().digest('SHA-256', input);
  return toHex(new Uint8Array(digest));
}

/** Raw SHA-256 digest as bytes (manifests need the bytes, not the hex form). */
export async function sha256Bytes(data: ArrayBuffer | Uint8Array): Promise<Uint8Array> {
  const input: BufferSource =
    data instanceof Uint8Array ? (data as Uint8Array<ArrayBuffer>) : new Uint8Array(data);
  const digest = await subtle().digest('SHA-256', input);
  return new Uint8Array(digest);
}

/** A derived key together with its public fingerprint. */
export interface KeyMaterial {
  /** Non-extractable AES-256-GCM key. */
  key: CryptoKey;
  /** First 8 bytes of SHA-256(key bytes) — public, safe to expose on the wire. */
  keyId: Uint8Array;
}

/**
 * PBKDF2-SHA256 -> 256 bits -> { AES-256-GCM key, keyId }.
 *
 * The raw bits exist as a Uint8Array only for the duration of this function
 * (importKey needs them; the exported CryptoKey is non-extractable). The local
 * copy is zeroed afterwards — best effort, as with any GC-managed runtime.
 */
export async function deriveKeyMaterial(
  password: string,
  salt: Uint8Array,
  iterations: number = PBKDF2_ITERATIONS,
): Promise<KeyMaterial> {
  if (salt.length !== SALT_BYTES) {
    throw new CryptoError(`Salt must be exactly ${SALT_BYTES} bytes.`);
  }
  const s = subtle();
  const material = await s.importKey(
    'raw',
    copyBuffer(new TextEncoder().encode(password)),
    'PBKDF2',
    false,
    ['deriveBits'],
  );
  const bits = new Uint8Array(
    await s.deriveBits(
      { name: 'PBKDF2', salt: copyBuffer(salt), iterations, hash: 'SHA-256' },
      material,
      256,
    ),
  );
  const keyId = (await sha256Bytes(bits)).slice(0, KEY_ID_BYTES);
  const key = await s.importKey(
    'raw',
    copyBuffer(bits),
    { name: 'AES-GCM', length: 256 },
    false, // non-extractable: the raw key bytes can never leave Web Crypto again
    ['encrypt', 'decrypt'],
  );
  bits.fill(0);
  return { key, keyId };
}

/** Backwards-compatible helper: derive just the CryptoKey. */
export async function deriveKey(
  password: string,
  salt: Uint8Array,
  iterations: number = PBKDF2_ITERATIONS,
): Promise<CryptoKey> {
  return (await deriveKeyMaterial(password, salt, iterations)).key;
}

/** Deterministic vault-wide salt: first 16 bytes of SHA-256(vaultId). */
export async function saltFromVaultId(vaultId: string): Promise<Uint8Array> {
  const digest = await subtle().digest(
    'SHA-256',
    copyBuffer(new TextEncoder().encode(vaultId)),
  );
  return new Uint8Array(digest).slice(0, SALT_BYTES);
}

export interface PacketMeta {
  /** 16-hex key id of the encrypting key (v3 only; null for v1/v2). */
  keyId: string | null;
  /** Authenticated per-file version counter (v3 only; null for v1/v2). */
  version: number | null;
  /** Chunk index (v3 only; CHUNK_INDEX_SINGLE for whole-file packets). */
  chunkIndex: number | null;
}

export interface DecryptedPacket extends PacketMeta {
  plaintext: ArrayBuffer;
}

/** Unauthenticated header peek — for cheap "foreign key?" checks. Never trusted. */
export function peekV3(packet: ArrayBuffer | Uint8Array): PacketMeta | null {
  const bytes = packet instanceof Uint8Array ? packet : new Uint8Array(packet);
  if (bytes.length < MIN_V3_BYTES || bytes[0] !== PACKET_V3) return null;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const keyId = toHex(bytes.subarray(1, 1 + KEY_ID_BYTES));
  const version = readU64BE(dv, 1 + KEY_ID_BYTES + SALT_BYTES + IV_BYTES);
  const ctLen = dv.getUint32(V3_HEADER_BYTES - CT_LEN_BYTES - CHUNK_INDEX_BYTES, false);
  const chunkIndex = dv.getUint32(V3_HEADER_BYTES - CHUNK_INDEX_BYTES, false);
  if (!Number.isFinite(version) || version > MAX_VERSION) return null;
  return { keyId, version, chunkIndex, ctLenHint: ctLen } as PacketMeta & { ctLenHint: number };
}

function assertVersionRange(version: number): number {
  const v = Math.floor(version);
  if (!Number.isFinite(v) || v < 1 || v > MAX_VERSION) {
    throw new CryptoError(`Invalid packet version counter: ${version}`);
  }
  return v;
}

/** Assemble a v3 packet: header + ciphertext + tag. */
async function sealV3(
  plaintext: ArrayBuffer | Uint8Array,
  key: CryptoKey,
  keyId: Uint8Array,
  salt: Uint8Array,
  path: string,
  version: number,
  chunkIndex: number,
  fileManifest: Uint8Array | null,
): Promise<ArrayBuffer> {
  const ver = assertVersionRange(version);
  const pt: Uint8Array<ArrayBuffer> =
    plaintext instanceof Uint8Array
      ? (plaintext as Uint8Array<ArrayBuffer>)
      : new Uint8Array(plaintext);
  const iv = window.crypto.getRandomValues(new Uint8Array(IV_BYTES));
  // AES-GCM appends exactly 16 tag bytes, so ctLen is known before sealing —
  // the AAD and the header field must carry the identical value.
  const ctLen = pt.length;
  const ciphertext = new Uint8Array(
    await subtle().encrypt(
      { name: 'AES-GCM', iv, additionalData: aadV3(path, keyId, ver, ctLen, chunkIndex, fileManifest) },
      key,
      pt,
    ),
  );
  const packet = new Uint8Array(V3_HEADER_BYTES + ciphertext.length);
  const dv = new DataView(packet.buffer);
  packet[0] = PACKET_V3;
  packet.set(keyId, 1);
  packet.set(salt, 1 + KEY_ID_BYTES);
  packet.set(iv, 1 + KEY_ID_BYTES + SALT_BYTES);
  const verOff = 1 + KEY_ID_BYTES + SALT_BYTES + IV_BYTES;
  writeU64BE(dv, verOff, ver);
  dv.setUint32(verOff + VERSION_BYTES, ctLen, false); // ciphertext bytes w/o tag
  dv.setUint32(verOff + VERSION_BYTES + CT_LEN_BYTES, chunkIndex >>> 0, false);
  packet.set(ciphertext, V3_HEADER_BYTES);
  return packet.buffer as ArrayBuffer;
}

/**
 * Encrypt a whole file into a single v3 packet (chunkIndex = SINGLE). Fresh IV
 * every call; the canonical path and the version counter are authenticated.
 */
export async function encryptBuffer(
  plaintext: ArrayBuffer,
  key: CryptoKey,
  keyId: Uint8Array,
  salt: Uint8Array,
  path: string,
  version: number,
): Promise<ArrayBuffer> {
  if (salt.length !== SALT_BYTES) {
    throw new CryptoError(`Salt must be exactly ${SALT_BYTES} bytes.`);
  }
  return sealV3(plaintext, key, keyId, salt, path, version, CHUNK_INDEX_SINGLE, null);
}

/** Encrypt one chunk of a large file (see the header comment for the layout). */
export async function encryptChunk(
  plaintextChunk: ArrayBuffer,
  key: CryptoKey,
  keyId: Uint8Array,
  salt: Uint8Array,
  path: string,
  version: number,
  chunkIndex: number,
  fileManifest: Uint8Array,
): Promise<ArrayBuffer> {
  if (salt.length !== SALT_BYTES) {
    throw new CryptoError(`Salt must be exactly ${SALT_BYTES} bytes.`);
  }
  if (fileManifest.length !== MANIFEST_BYTES) {
    throw new CryptoError('fileManifest must be exactly 32 bytes.');
  }
  return sealV3(plaintextChunk, key, keyId, salt, path, version, chunkIndex, fileManifest);
}

async function decryptAttempt(
  bytes: Uint8Array,
  offset: number,
  keyForSalt: (salt: Uint8Array) => Promise<CryptoKey>,
  aad: ArrayBuffer | null,
): Promise<ArrayBuffer> {
  const salt = bytes.slice(offset, offset + SALT_BYTES);
  const iv = copyBuffer(bytes.slice(offset + SALT_BYTES, offset + SALT_BYTES + IV_BYTES));
  const ciphertext = copyBuffer(bytes.slice(offset + SALT_BYTES + IV_BYTES));
  const key = await keyForSalt(salt);
  const algorithm: AesGcmParams = aad
    ? { name: 'AES-GCM', iv, additionalData: aad }
    : { name: 'AES-GCM', iv };
  return subtle().decrypt(algorithm, key, ciphertext);
}

function foreignOrCorrupt(path: string): CryptoError {
  return new CryptoError(
    `Decryption failed for ${path} — wrong E2EE password, corrupted file, or ciphertext not created for this path.`,
  );
}

/**
 * Parse + decrypt one single-shot v3 packet starting at `offset`. Chunk
 * packets (which need the caller-supplied manifest in the AAD) go through
 * decryptChunked instead. Returns the bytes consumed.
 */
async function decryptV3At(
  bytes: Uint8Array,
  offset: number,
  keyForSalt: (salt: Uint8Array) => Promise<CryptoKey>,
  path: string,
): Promise<DecryptedPacket & { length: number }> {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const keyId = bytes.slice(offset + 1, offset + 1 + KEY_ID_BYTES);
  const verOff = offset + 1 + KEY_ID_BYTES + SALT_BYTES + IV_BYTES;
  const version = readU64BE(dv, verOff);
  const ctLen = dv.getUint32(verOff + VERSION_BYTES, false);
  const chunkIndex = dv.getUint32(verOff + VERSION_BYTES + CT_LEN_BYTES, false);
  const salt = bytes.slice(offset + 1 + KEY_ID_BYTES, offset + 1 + KEY_ID_BYTES + SALT_BYTES);
  const ivOff = offset + 1 + KEY_ID_BYTES + SALT_BYTES;
  const iv = copyBuffer(bytes.slice(ivOff, ivOff + IV_BYTES));
  const ctStart = offset + V3_HEADER_BYTES;
  const ctEnd = ctStart + ctLen + 16;
  if (ctEnd > bytes.length || version > MAX_VERSION) throw foreignOrCorrupt(path);
  if (chunkIndex !== CHUNK_INDEX_SINGLE) throw foreignOrCorrupt(path);

  const key = await keyForSalt(salt);
  let plaintext: ArrayBuffer;
  try {
    plaintext = await subtle().decrypt(
      { name: 'AES-GCM', iv, additionalData: aadV3(path, keyId, version, ctLen, chunkIndex, null) },
      key,
      copyBuffer(bytes.subarray(ctStart, ctEnd)),
    );
  } catch {
    throw foreignOrCorrupt(path);
  }
  return {
    plaintext,
    keyId: toHex(keyId),
    version,
    chunkIndex,
    length: V3_HEADER_BYTES + ctLen + 16,
  };
}

/**
 * Decrypt a single-shot packet (a whole-file v3, v2 or v1 packet). v3 packets
 * verify the path/version-bearing AAD; v2/v1 packets remain readable for
 * migration. A tampered packet, swapped ciphertext or wrong password fails
 * GCM authentication and throws CryptoError — never silent garbage.
 */
export async function decryptBuffer(
  packet: ArrayBuffer,
  keyForSalt: (salt: Uint8Array) => Promise<CryptoKey>,
  path: string,
): Promise<DecryptedPacket> {
  const bytes = new Uint8Array(packet);
  if (bytes.length < PACKET_V1_BYTES) {
    throw new CryptoError('Encrypted packet is truncated or corrupt.');
  }

  // v3 candidate: leading 0x03. A legacy salt whose first byte happens to be
  // 0x03 parses as a bogus header and fails authentication — cascade to v2/v1.
  if (bytes[0] === PACKET_V3 && bytes.length >= MIN_V3_BYTES) {
    try {
      const res = await decryptV3At(bytes, 0, keyForSalt, path);
      if (res.length === bytes.length) {
        return { plaintext: res.plaintext, keyId: res.keyId, version: res.version, chunkIndex: res.chunkIndex };
      }
    } catch (err) {
      if (!(err instanceof CryptoError)) throw err;
      // Foreign-salt rejection is a policy error, not an auth failure — it
      // must surface verbatim (CPU-exhaustion defense), never cascade.
      if (/does not belong to this vault/.test(err.message)) throw err;
    }
    // fall through to v2/v1
  }
  if (bytes[0] === PACKET_V2 && bytes.length >= PACKET_V2_BYTES) {
    try {
      return {
        plaintext: await decryptAttempt(bytes, 1, keyForSalt, aadV2(path)),
        keyId: null,
        version: null,
        chunkIndex: null,
      };
    } catch (err) {
      if (!(err instanceof CryptoError) && !(err instanceof Error)) throw err;
      // fall through to v1 (legacy salt first byte coincidentally 0x02)
    }
  }
  try {
    return {
      plaintext: await decryptAttempt(bytes, 0, keyForSalt, null),
      keyId: null,
      version: null,
      chunkIndex: null,
    };
  } catch {
    throw foreignOrCorrupt(path);
  }
}

export interface DecryptedChunked {
  plaintext: ArrayBuffer;
  keyId: string;
  version: number;
  chunkCount: number;
}

/**
 * Decrypt a blob assembled from chunk packets (PROB-3 transport). Walks the
 * self-delimiting v3 packets, enforcing: contiguous chunk indexes from 0, one
 * shared keyId and version across all chunks, every chunk authenticated with
 * the file manifest. Any splice of chunks from a different upload (different
 * manifest, path or version) fails authentication here.
 */
export async function decryptChunked(
  blob: ArrayBuffer,
  keyForSalt: (salt: Uint8Array) => Promise<CryptoKey>,
  path: string,
  fileManifest: Uint8Array,
): Promise<DecryptedChunked> {
  if (fileManifest.length !== MANIFEST_BYTES) {
    throw new CryptoError('fileManifest must be exactly 32 bytes.');
  }
  const bytes = new Uint8Array(blob);
  if (bytes.length === 0 || bytes[0] !== PACKET_V3) {
    throw foreignOrCorrupt(path);
  }
  const chunks: ArrayBuffer[] = [];
  let keyId: string | null = null;
  let version: number | null = null;
  let offset = 0;
  while (offset < bytes.length) {
    if (bytes.length - offset < MIN_V3_BYTES || bytes[offset] !== PACKET_V3) {
      throw foreignOrCorrupt(path);
    }
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const hdrKeyId = bytes.slice(offset + 1, offset + 1 + KEY_ID_BYTES);
    const verOff = offset + 1 + KEY_ID_BYTES + SALT_BYTES + IV_BYTES;
    const v = readU64BE(dv, verOff);
    const ctLen = dv.getUint32(verOff + VERSION_BYTES, false);
    const chunkIndex = dv.getUint32(verOff + VERSION_BYTES + CT_LEN_BYTES, false);
    const salt = bytes.slice(offset + 1 + KEY_ID_BYTES, offset + 1 + KEY_ID_BYTES + SALT_BYTES);
    const ivOff = offset + 1 + KEY_ID_BYTES + SALT_BYTES;
    const iv = copyBuffer(bytes.slice(ivOff, ivOff + IV_BYTES));
    const ctStart = offset + V3_HEADER_BYTES;
    const ctEnd = ctStart + ctLen + 16;
    if (ctEnd > bytes.length || v > MAX_VERSION) throw foreignOrCorrupt(path);
    if (chunkIndex !== chunks.length) throw foreignOrCorrupt(path); // splice/gap
    const hexKeyId = toHex(hdrKeyId);
    if (keyId === null) keyId = hexKeyId;
    else if (keyId !== hexKeyId) throw foreignOrCorrupt(path); // mixed uploads
    if (version === null) version = v;
    else if (version !== v) throw foreignOrCorrupt(path);

    const key = await keyForSalt(salt);
    let plaintext: ArrayBuffer;
    try {
      plaintext = await subtle().decrypt(
        {
          name: 'AES-GCM',
          iv,
          additionalData: aadV3(path, hdrKeyId, v, ctLen, chunkIndex, fileManifest),
        },
        key,
        copyBuffer(bytes.subarray(ctStart, ctEnd)),
      );
    } catch {
      throw foreignOrCorrupt(path);
    }
    chunks.push(plaintext);
    offset = ctEnd;
  }
  if (keyId === null || version === null || chunks.length === 0) {
    throw foreignOrCorrupt(path);
  }
  const total = chunks.reduce((n, c) => n + c.byteLength, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const c of chunks) {
    out.set(new Uint8Array(c), o);
    o += c.byteLength;
  }
  return { plaintext: out.buffer as ArrayBuffer, keyId, version, chunkCount: chunks.length };
}

/**
 * Session-scoped facade that caches one KeyMaterial per distinct salt (in
 * practice: one, the deterministic vault salt). When `expectedSalt` is set
 * (normal operation), packets carrying any other salt are rejected before key
 * derivation. Recreate the manager when the user changes the password.
 */
export class CryptoManager {
  private readonly cache = new Map<string, KeyMaterial>();

  constructor(
    private readonly password: string,
    private readonly expectedSalt: Uint8Array | null = null,
  ) {}

  async keyMaterial(salt: Uint8Array): Promise<KeyMaterial> {
    if (this.expectedSalt && !bytesEqual(salt, this.expectedSalt)) {
      throw new CryptoError('Packet salt does not belong to this vault.');
    }
    const id = toHex(salt);
    let km = this.cache.get(id);
    if (!km) {
      km = await deriveKeyMaterial(this.password, salt);
      this.cache.set(id, km);
    }
    return km;
  }

  async keyForSalt(salt: Uint8Array): Promise<CryptoKey> {
    return (await this.keyMaterial(salt)).key;
  }

  async encrypt(plaintext: ArrayBuffer, salt: Uint8Array, path: string, version: number): Promise<ArrayBuffer> {
    const km = await this.keyMaterial(salt);
    return encryptBuffer(plaintext, km.key, km.keyId, salt, path, version);
  }

  async encryptChunk(
    plaintextChunk: ArrayBuffer,
    salt: Uint8Array,
    path: string,
    version: number,
    chunkIndex: number,
    fileManifest: Uint8Array,
  ): Promise<ArrayBuffer> {
    const km = await this.keyMaterial(salt);
    return encryptChunk(plaintextChunk, km.key, km.keyId, salt, path, version, chunkIndex, fileManifest);
  }

  async decrypt(packet: ArrayBuffer, path: string): Promise<DecryptedPacket> {
    return decryptBuffer(packet, (salt) => this.keyForSalt(salt), path);
  }

  async decryptChunked(blob: ArrayBuffer, path: string, fileManifest: Uint8Array): Promise<DecryptedChunked> {
    return decryptChunked(blob, (salt) => this.keyForSalt(salt), path, fileManifest);
  }
}
