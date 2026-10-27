/**
 * Zero-knowledge E2EE helpers built exclusively on the Web Crypto API
 * (`globalThis.crypto.subtle`), which is available in Obsidian on desktop,
 * Android and iOS alike. No Node.js `crypto` module is used anywhere.
 *
 * Key derivation : PBKDF2 (SHA-256, 210 000 iterations) -> AES-256-GCM key.
 * Salt strategy  : deterministic, vault-wide — first 16 bytes of
 *                  SHA-256(vaultId), where vaultId is stable server metadata.
 *                  The derived CryptoKey is cached per salt in memory so the
 *                  expensive PBKDF2 pass runs once per session.
 * Packet format  : [ Salt (16) | IV (12) | AES-GCM ciphertext + 128-bit tag ]
 *                  The salt is embedded in every packet so a future switch to
 *                  random per-file salts stays wire-compatible.
 * IV policy      : a fresh 12-byte random IV (crypto.getRandomValues) on EVERY
 *                  encryption. IV reuse under the same key is catastrophic in
 *                  GCM and therefore structurally impossible here.
 */

const PBKDF2_ITERATIONS = 210_000;
const SALT_BYTES = 16;
const IV_BYTES = 12;
/** Smallest valid packet: header + empty plaintext + 16-byte GCM auth tag. */
const MIN_PACKET_BYTES = SALT_BYTES + IV_BYTES + 16;

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
 * views, but copying sidesteps any detached-buffer / TS BufferSource quirks.
 */
function copyBuffer(view: Uint8Array): ArrayBuffer {
  return view.slice().buffer as ArrayBuffer;
}

export function toHex(bytes: Uint8Array): string {
  const digits = '0123456789abcdef';
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += digits[bytes[i] >> 4] + digits[bytes[i] & 0x0f];
  }
  return out;
}

/** Hex SHA-256 of arbitrary bytes (used for ciphertext hashing). */
export async function sha256Hex(data: ArrayBuffer | Uint8Array): Promise<string> {
  const input = data instanceof Uint8Array ? copyBuffer(data) : data;
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

/** Encrypt into the [salt | iv | ciphertext+tag] packet. Fresh IV every call. */
export async function encryptBuffer(
  plaintext: ArrayBuffer,
  key: CryptoKey,
  salt: Uint8Array,
): Promise<ArrayBuffer> {
  if (salt.length !== SALT_BYTES) {
    throw new CryptoError(`Salt must be exactly ${SALT_BYTES} bytes.`);
  }
  const iv = window.crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ciphertext = new Uint8Array(
    await subtle().encrypt({ name: 'AES-GCM', iv }, key, plaintext),
  );
  const packet = new Uint8Array(SALT_BYTES + IV_BYTES + ciphertext.length);
  packet.set(salt, 0);
  packet.set(iv, SALT_BYTES);
  packet.set(ciphertext, SALT_BYTES + IV_BYTES);
  return packet.buffer as ArrayBuffer;
}

/**
 * Decrypt a packet. The salt is read from the packet itself and resolved to a
 * CryptoKey through `keyForSalt`, which lets callers cache PBKDF2 results.
 * A tampered packet or wrong password fails GCM authentication and throws
 * CryptoError — it can never yield silent garbage.
 */
export async function decryptBuffer(
  packet: ArrayBuffer,
  keyForSalt: (salt: Uint8Array) => Promise<CryptoKey>,
): Promise<ArrayBuffer> {
  if (packet.byteLength < MIN_PACKET_BYTES) {
    throw new CryptoError('Encrypted packet is truncated or corrupt.');
  }
  const bytes = new Uint8Array(packet);
  const salt = bytes.slice(0, SALT_BYTES);
  const iv = bytes.slice(SALT_BYTES, SALT_BYTES + IV_BYTES);
  const ciphertext = bytes.slice(SALT_BYTES + IV_BYTES);
  const key = await keyForSalt(salt);
  try {
    return await subtle().decrypt(
      { name: 'AES-GCM', iv: copyBuffer(iv) },
      key,
      copyBuffer(ciphertext),
    );
  } catch {
    throw new CryptoError(
      'Decryption failed — wrong E2EE password or corrupted file.',
    );
  }
}

/**
 * Session-scoped facade around derive/encrypt/decrypt that caches one key per
 * distinct salt (in practice: one, the deterministic vault salt). Recreate the
 * manager when the user changes the password.
 */
export class CryptoManager {
  private readonly cache = new Map<string, CryptoKey>();

  constructor(private readonly password: string) {}

  async keyForSalt(salt: Uint8Array): Promise<CryptoKey> {
    const id = toHex(salt);
    let key = this.cache.get(id);
    if (!key) {
      key = await deriveKey(this.password, salt);
      this.cache.set(id, key);
    }
    return key;
  }

  async encrypt(plaintext: ArrayBuffer, salt: Uint8Array): Promise<ArrayBuffer> {
    return encryptBuffer(plaintext, await this.keyForSalt(salt), salt);
  }

  async decrypt(packet: ArrayBuffer): Promise<ArrayBuffer> {
    return decryptBuffer(packet, (salt) => this.keyForSalt(salt));
  }
}
