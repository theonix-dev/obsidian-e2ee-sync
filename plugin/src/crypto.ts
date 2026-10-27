/**
 * Zero-knowledge E2EE helpers built exclusively on the Web Crypto API
 * (`globalThis.crypto.subtle`), which is available in Obsidian on desktop,
 * Android and iOS alike. No Node.js `crypto` module is used anywhere.
 *
 * Key derivation : PBKDF2 (SHA-256, 210 000 iterations) -> AES-256-GCM key.
 * Salt strategy  : deterministic, vault-wide — first 16 bytes of
 *                  SHA-256(vaultId), where vaultId is stable server metadata.
 *                  The derived CryptoKey is cached per salt in memory so the
 *                  expensive PBKDF2 pass runs once per session. Packets
 *                  carrying any other salt are rejected outright (a hostile
 *                  server must not be able to force one 210k-iteration pass
 *                  per file with attacker-chosen salts).
 * Packet format  : v2 (current): [ 0x02 | Salt (16) | IV (12) | ct + tag ]
 *                      AES-GCM additionalData (AAD) = 0x02 || NFC(path),
 *                      binding every ciphertext to its file path so a
 *                      storage-level swap of two packets fails authentication.
 *                  v1 (0.1.x, read-only compat): [ Salt | IV | ct + tag ],
 *                      no AAD. Still decryptable; every re-push upgrades the
 *                      file to v2.
 * IV policy      : a fresh 12-byte random IV (crypto.getRandomValues) on EVERY
 *                  encryption. IV reuse under the same key is catastrophic in
 *                  GCM and therefore structurally impossible here.
 */

const PBKDF2_ITERATIONS = 210_000;
const SALT_BYTES = 16;
const IV_BYTES = 12;
/** v1 packet: header + empty plaintext + 16-byte GCM auth tag. */
const PACKET_V1_BYTES = SALT_BYTES + IV_BYTES + 16;
/** Version byte introduced with AAD binding (v2 packets). */
const PACKET_V2 = 0x02;
/** v2 packet: version byte + header + empty plaintext + tag. */
const PACKET_V2_BYTES = 1 + SALT_BYTES + IV_BYTES + 16;

export const PACKET_HEADER_BYTES = SALT_BYTES + IV_BYTES;

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

/** AAD: version byte + NFC-normalized canonical path. Binds ciphertext to its
 *  file name so swapping packets between paths fails GCM authentication.
 *  Returns an exact-sized ArrayBuffer (always a valid BufferSource). */
function aadBuffer(path: string): ArrayBuffer {
  const p = new TextEncoder().encode(path.normalize('NFC'));
  const aad = new Uint8Array(1 + p.length);
  aad[0] = PACKET_V2;
  aad.set(p, 1);
  return aad.buffer as ArrayBuffer;
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

/** Hex SHA-256 of arbitrary bytes (used for ciphertext hashing). Zero-copy
 *  for typed-array views — hashing must not duplicate multi-MB packets. */
export async function sha256Hex(data: ArrayBuffer | Uint8Array): Promise<string> {
  const input: BufferSource =
    data instanceof Uint8Array ? (data as Uint8Array<ArrayBuffer>) : new Uint8Array(data);
  const digest = await subtle().digest('SHA-256', input);
  return toHex(new Uint8Array(digest));
}

/** PBKDF2-SHA256 -> non-extractable AES-256-GCM CryptoKey. */
export async function deriveKey(
  password: string,
  salt: Uint8Array,
  iterations: number = PBKDF2_ITERATIONS,
): Promise<CryptoKey> {
  if (salt.length !== SALT_BYTES) {
    throw new CryptoError(`Salt must be exactly ${SALT_BYTES} bytes.`);
  }
  const s = subtle();
  const material = await s.importKey(
    'raw',
    copyBuffer(new TextEncoder().encode(password)),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return s.deriveKey(
    { name: 'PBKDF2', salt: copyBuffer(salt), iterations, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    false, // non-extractable: the raw key bytes can never leave Web Crypto
    ['encrypt', 'decrypt'],
  );
}

/** Deterministic vault-wide salt: first 16 bytes of SHA-256(vaultId). */
export async function saltFromVaultId(vaultId: string): Promise<Uint8Array> {
  const digest = await subtle().digest(
    'SHA-256',
    copyBuffer(new TextEncoder().encode(vaultId)),
  );
  return new Uint8Array(digest).slice(0, SALT_BYTES);
}

/**
 * Encrypt into the [0x02 | salt | iv | ciphertext+tag] packet. Fresh IV every
 * call; the canonical path is authenticated as AAD.
 */
export async function encryptBuffer(
  plaintext: ArrayBuffer,
  key: CryptoKey,
  salt: Uint8Array,
  path: string,
): Promise<ArrayBuffer> {
  if (salt.length !== SALT_BYTES) {
    throw new CryptoError(`Salt must be exactly ${SALT_BYTES} bytes.`);
  }
  const iv = window.crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ciphertext = new Uint8Array(
    await subtle().encrypt(
      { name: 'AES-GCM', iv, additionalData: aadBuffer(path) },
      key,
      plaintext,
    ),
  );
  const packet = new Uint8Array(1 + SALT_BYTES + IV_BYTES + ciphertext.length);
  packet[0] = PACKET_V2;
  packet.set(salt, 1);
  packet.set(iv, 1 + SALT_BYTES);
  packet.set(ciphertext, 1 + SALT_BYTES + IV_BYTES);
  return packet.buffer as ArrayBuffer;
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

/**
 * Decrypt a packet for a specific canonical path. v2 packets verify the
 * path-bearing AAD; v1 packets (no AAD) remain readable for migration, with a
 * v1 retry when a legacy salt's first byte coincidentally equals 0x02. A
 * tampered packet, swapped ciphertext or wrong password fails GCM
 * authentication and throws CryptoError — never silent garbage.
 */
export async function decryptBuffer(
  packet: ArrayBuffer,
  keyForSalt: (salt: Uint8Array) => Promise<CryptoKey>,
  path: string,
): Promise<ArrayBuffer> {
  const bytes = new Uint8Array(packet);
  if (bytes.length < PACKET_V1_BYTES) {
    throw new CryptoError('Encrypted packet is truncated or corrupt.');
  }
  const additionalData = aadBuffer(path);
  if (bytes.length >= PACKET_V2_BYTES && bytes[0] === PACKET_V2) {
    try {
      return await decryptAttempt(bytes, 1, keyForSalt, additionalData);
    } catch (err) {
      if (err instanceof CryptoError) throw err; // e.g. foreign-salt rejection
      try {
        return await decryptAttempt(bytes, 0, keyForSalt, null);
      } catch {
        throw new CryptoError(
          'Decryption failed — wrong E2EE password, corrupted file, or ciphertext not created for this path.',
        );
      }
    }
  }
  try {
    return await decryptAttempt(bytes, 0, keyForSalt, null);
  } catch {
    throw new CryptoError(
      'Decryption failed — wrong E2EE password or corrupted file.',
    );
  }
}

/**
 * Session-scoped facade around derive/encrypt/decrypt that caches one key per
 * distinct salt (in practice: one, the deterministic vault salt). When
 * `expectedSalt` is set (normal operation), packets carrying any other salt
 * are rejected before key derivation. Recreate the manager when the user
 * changes the password.
 */
export class CryptoManager {
  private readonly cache = new Map<string, CryptoKey>();

  constructor(
    private readonly password: string,
    private readonly expectedSalt: Uint8Array | null = null,
  ) {}

  async keyForSalt(salt: Uint8Array): Promise<CryptoKey> {
    if (this.expectedSalt && !bytesEqual(salt, this.expectedSalt)) {
      throw new CryptoError('Packet salt does not belong to this vault.');
    }
    const id = toHex(salt);
    let key = this.cache.get(id);
    if (!key) {
      key = await deriveKey(this.password, salt);
      this.cache.set(id, key);
    }
    return key;
  }

  async encrypt(plaintext: ArrayBuffer, salt: Uint8Array, path: string): Promise<ArrayBuffer> {
    return encryptBuffer(plaintext, await this.keyForSalt(salt), salt, path);
  }

  async decrypt(packet: ArrayBuffer, path: string): Promise<ArrayBuffer> {
    return decryptBuffer(packet, (salt) => this.keyForSalt(salt), path);
  }
}
