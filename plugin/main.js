/*
 * Obsidian E2EE Sync — bundled by esbuild. DO NOT EDIT MANUALLY.
 * Source lives in src/. Rebuild with: npm run build
 */
"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/main.ts
var main_exports = {};
__export(main_exports, {
  default: () => E2eeSyncPlugin,
  errorMessage: () => errorMessage
});
module.exports = __toCommonJS(main_exports);
var import_obsidian4 = require("obsidian");

// src/syncEngine.ts
var import_obsidian2 = require("obsidian");

// src/api.ts
var import_obsidian = require("obsidian");
var DEFAULT_TIMEOUT_MS = 3e4;
var MAX_ERROR_BODY_CHARS = 200;
var ApiError = class extends Error {
  constructor(message, status, isNetworkError = false) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.isNetworkError = isNetworkError;
  }
};
var SyncApi = class {
  constructor(baseUrl, token, options = {}) {
    this.token = token;
    var _a;
    this.baseUrl = baseUrl.trim().replace(/\/+$/, "");
    this.timeoutMs = (_a = options.timeoutMs) != null ? _a : DEFAULT_TIMEOUT_MS;
    this.assertTransportSecurity(this.baseUrl);
  }
  /**
   * Transport-layer HTTPS guard (defense in depth behind the settings-tab
   * validation): the bearer token must never travel over cleartext HTTP to a
   * remote host. Loopback/LAN hosts are exempted for local testing. TLS
   * certificate problems surface as network errors from requestUrl itself.
   */
  assertTransportSecurity(url) {
    let parsed;
    try {
      parsed = new URL(url);
    } catch (e) {
      throw new ApiError(`"${url}" is not a valid URL (include https://).`, 0);
    }
    const host = parsed.hostname;
    const isLocal = host === "localhost" || host === "127.0.0.1" || host === "[::1]";
    if (parsed.protocol !== "https:" && !isLocal) {
      throw new ApiError(
        "HTTPS is required for remote sync servers \u2014 refusing to send the API token over cleartext.",
        0
      );
    }
  }
  // ------------------------------------------------------------- internals
  buildUrl(endpoint, query) {
    const qs = query ? "?" + Object.entries(query).map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join("&") : "";
    return `${this.baseUrl}${endpoint}${qs}`;
  }
  async request(method, url, init = {}) {
    var _a, _b;
    const headers = {
      Authorization: `Bearer ${this.token}`,
      ...(_a = init.headers) != null ? _a : {}
    };
    const params = { url, method, headers, throw: false };
    if (init.body !== void 0) {
      params.body = init.body;
      headers["Content-Type"] = "application/octet-stream";
    }
    let response;
    try {
      response = await Promise.race([
        (0, import_obsidian.requestUrl)(params),
        new Promise(
          (_, reject) => window.setTimeout(
            () => reject(
              new ApiError(
                `Request timed out after ${this.timeoutMs} ms: ${method} ${url}`,
                0,
                true
              )
            ),
            this.timeoutMs
          )
        )
      ]);
    } catch (error) {
      if (error instanceof ApiError) throw error;
      throw new ApiError(
        `Network error: ${method} ${url} \u2014 ${error instanceof Error ? error.message : String(error)}`,
        -1,
        true
      );
    }
    if ((response.status < 200 || response.status >= 300) && response.status !== 304) {
      let detail = "";
      try {
        detail = ((_b = response.text) != null ? _b : "").slice(0, MAX_ERROR_BODY_CHARS);
      } catch (e) {
        detail = "";
      }
      throw new ApiError(
        `HTTP ${response.status} on ${method} ${url}${detail ? ` \u2014 ${detail}` : ""}`,
        response.status
      );
    }
    return response;
  }
  parseJson(response) {
    try {
      return JSON.parse(response.text);
    } catch (e) {
      throw new ApiError("Server returned a malformed JSON response.", 0);
    }
  }
  // ------------------------------------------------------------- endpoints
  /** Server metadata (stable vaultId used for the deterministic KDF salt). */
  async getMeta() {
    return this.parseJson(await this.request("GET", this.buildUrl("/api/meta")));
  }
  /**
   * Full server state, including tombstones. When `etag` from a previous
   * response is supplied and the index is unchanged, the server answers 304
   * and `notModified` is true (one cheap request ends an idle sync cycle).
   */
  async getIndex(etag) {
    var _a;
    const headers = {};
    if (etag) headers["If-None-Match"] = etag;
    const response = await this.request("GET", this.buildUrl("/api/index"), { headers });
    if (response.status === 304) {
      return { index: { files: {} }, etag: etag != null ? etag : "", notModified: true };
    }
    const index = this.parseJson(response);
    if (!index || typeof index !== "object" || !index.files) {
      throw new ApiError('Server index response is missing the "files" map.', 0);
    }
    const newEtag = (_a = this.responseHeader(response, "etag")) != null ? _a : "";
    return { index, etag: newEtag, notModified: false };
  }
  /** Case-insensitive header lookup on a requestUrl response. */
  responseHeader(response, name) {
    const headers = response.headers;
    if (!headers) return null;
    const lower = name.toLowerCase();
    for (const [k, v] of Object.entries(headers)) {
      if (k.toLowerCase() === lower) return v;
    }
    return null;
  }
  /**
   * Upload an encrypted packet. Metadata travels in headers (URL-encoded path)
   * so the body stays pure binary — no multipart overhead. `keyId` and
   * `fileVersion` are echoed by the server into its index (packet v3).
   */
  async upload(path, ciphertext, clientMtime, cipherHash, meta) {
    const headers = {
      "X-File-Path": encodeURIComponent(path),
      "X-Client-Mtime": String(Math.floor(clientMtime)),
      "X-Cipher-Hash": cipherHash
    };
    if (meta == null ? void 0 : meta.keyId) headers["X-Key-Id"] = meta.keyId;
    if ((meta == null ? void 0 : meta.fileVersion) !== void 0) headers["X-File-Version"] = String(meta.fileVersion);
    const response = await this.request("POST", this.buildUrl("/api/upload"), {
      body: ciphertext,
      headers
    });
    return this.parseJson(response);
  }
  // ------------------------------------------------ chunked transport (v3)
  /** Begin a resumable chunked upload; returns the staging upload id. */
  async beginUpload(request) {
    const response = await this.request("POST", this.buildUrl("/api/upload/begin"), {
      body: new TextEncoder().encode(JSON.stringify(request)).buffer,
      headers: { "Content-Type": "application/json" }
    });
    return this.parseJson(response);
  }
  /**
   * Upload one encrypted chunk. The server verifies the body against
   * `chunkHash` (SHA-256 of the ciphertext chunk) and stores it as part `n`.
   */
  async uploadChunk(uploadId, n, chunk, chunkHash) {
    const response = await this.request(
      "PUT",
      this.buildUrl("/api/upload/chunk", { uploadId, n: String(n) }),
      { body: chunk, headers: { "X-Chunk-Hash": chunkHash } }
    );
    return this.parseJson(response);
  }
  /** Which chunk numbers the server already holds — the resume primitive. */
  async uploadStatus(uploadId) {
    const response = await this.request(
      "GET",
      this.buildUrl("/api/upload/status", { uploadId })
    );
    return this.parseJson(response);
  }
  /** Assemble the staged chunks into the final file and index it. */
  async commitUpload(uploadId, meta) {
    const response = await this.request(
      "POST",
      this.buildUrl("/api/upload/commit", { uploadId }),
      {
        headers: {
          "X-Client-Mtime": String(Math.floor(meta.clientMtime)),
          "X-Key-Id": meta.keyId,
          "X-File-Version": String(meta.fileVersion)
        }
      }
    );
    return this.parseJson(response);
  }
  /** Download the encrypted packet for a path. */
  async download(path) {
    const response = await this.request("GET", this.buildUrl("/api/download", { path }));
    if (!response.arrayBuffer) {
      throw new ApiError(`Empty body received for ${path}.`, 0);
    }
    return response.arrayBuffer;
  }
  /** Delete a path server-side; the server keeps a tombstone in its index. */
  async deleteFile(path) {
    const response = await this.request("DELETE", this.buildUrl("/api/delete", { path }));
    return this.parseJson(response);
  }
  /** Settings-tab helper: verifies auth + reachability, returns live file count. */
  async testConnection() {
    const [meta, indexResult] = await Promise.all([this.getMeta(), this.getIndex()]);
    const live = Object.entries(indexResult.index.files).filter(
      ([p, f]) => f && !f.deleted && !p.startsWith(".e2ee-")
    ).length;
    return { fileCount: live, vaultId: meta.vaultId };
  }
};

// src/crypto.ts
var PBKDF2_ITERATIONS = 21e4;
var SALT_BYTES = 16;
var IV_BYTES = 12;
var KEY_ID_BYTES = 8;
var VERSION_BYTES = 8;
var CT_LEN_BYTES = 4;
var CHUNK_INDEX_BYTES = 4;
var MANIFEST_BYTES = 32;
var PACKET_V1_BYTES = SALT_BYTES + IV_BYTES + 16;
var PACKET_V2 = 2;
var PACKET_V2_BYTES = 1 + SALT_BYTES + IV_BYTES + 16;
var PACKET_V3 = 3;
var V3_HEADER_BYTES = 1 + KEY_ID_BYTES + SALT_BYTES + IV_BYTES + VERSION_BYTES + CT_LEN_BYTES + CHUNK_INDEX_BYTES;
var MIN_V3_BYTES = V3_HEADER_BYTES + 16;
var CHUNK_INDEX_SINGLE = 4294967295;
var MAX_VERSION = Number.MAX_SAFE_INTEGER;
var PACKET_HEADER_BYTES = SALT_BYTES + IV_BYTES;
var CryptoError = class extends Error {
  constructor(message) {
    super(message);
    this.name = "CryptoError";
  }
};
function subtle() {
  const c = window.crypto;
  if (!c || !c.subtle) {
    throw new CryptoError("The Web Crypto API is unavailable on this device.");
  }
  return c.subtle;
}
function copyBuffer(view) {
  return view.slice().buffer;
}
var encoder = new TextEncoder();
function aadV2(path) {
  const p = encoder.encode(path.normalize("NFC"));
  const aad = new Uint8Array(1 + p.length);
  aad[0] = PACKET_V2;
  aad.set(p, 1);
  return aad.buffer;
}
function aadV3(path, keyId, version, ctLen, chunkIndex, fileManifest) {
  const p = encoder.encode(path.normalize("NFC"));
  const manifestLen = fileManifest ? MANIFEST_BYTES : 0;
  const aad = new Uint8Array(
    1 + KEY_ID_BYTES + p.length + VERSION_BYTES + CT_LEN_BYTES + CHUNK_INDEX_BYTES + manifestLen
  );
  let o = 0;
  aad[o++] = PACKET_V3;
  aad.set(keyId, o);
  o += KEY_ID_BYTES;
  aad.set(p, o);
  o += p.length;
  const dv = new DataView(aad.buffer);
  writeU64BE(dv, o, version);
  o += VERSION_BYTES;
  dv.setUint32(o, ctLen, false);
  o += CT_LEN_BYTES;
  dv.setUint32(o, chunkIndex >>> 0, false);
  o += CHUNK_INDEX_BYTES;
  if (fileManifest) aad.set(fileManifest, o);
  return aad.buffer;
}
function writeU64BE(dv, offset, value) {
  const v = Math.floor(value);
  dv.setUint32(offset, Math.floor(v / 4294967296), false);
  dv.setUint32(offset + 4, v >>> 0, false);
}
function readU64BE(dv, offset) {
  const hi = dv.getUint32(offset, false);
  const lo = dv.getUint32(offset + 4, false);
  return hi * 4294967296 + lo;
}
function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
function toHex(bytes) {
  const digits = "0123456789abcdef";
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += digits[bytes[i] >> 4] + digits[bytes[i] & 15];
  }
  return out;
}
async function sha256Hex(data) {
  const input = data instanceof Uint8Array ? data : new Uint8Array(data);
  const digest = await subtle().digest("SHA-256", input);
  return toHex(new Uint8Array(digest));
}
async function sha256Bytes(data) {
  const input = data instanceof Uint8Array ? data : new Uint8Array(data);
  const digest = await subtle().digest("SHA-256", input);
  return new Uint8Array(digest);
}
async function deriveKeyMaterial(password, salt, iterations = PBKDF2_ITERATIONS) {
  if (salt.length !== SALT_BYTES) {
    throw new CryptoError(`Salt must be exactly ${SALT_BYTES} bytes.`);
  }
  const s = subtle();
  const material = await s.importKey(
    "raw",
    copyBuffer(new TextEncoder().encode(password)),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = new Uint8Array(
    await s.deriveBits(
      { name: "PBKDF2", salt: copyBuffer(salt), iterations, hash: "SHA-256" },
      material,
      256
    )
  );
  const keyId = (await sha256Bytes(bits)).slice(0, KEY_ID_BYTES);
  const key = await s.importKey(
    "raw",
    copyBuffer(bits),
    { name: "AES-GCM", length: 256 },
    false,
    // non-extractable: the raw key bytes can never leave Web Crypto again
    ["encrypt", "decrypt"]
  );
  bits.fill(0);
  return { key, keyId };
}
async function deriveKey(password, salt, iterations = PBKDF2_ITERATIONS) {
  return (await deriveKeyMaterial(password, salt, iterations)).key;
}
async function saltFromVaultId(vaultId) {
  const digest = await subtle().digest(
    "SHA-256",
    copyBuffer(new TextEncoder().encode(vaultId))
  );
  return new Uint8Array(digest).slice(0, SALT_BYTES);
}
function peekV3(packet) {
  const bytes = packet instanceof Uint8Array ? packet : new Uint8Array(packet);
  if (bytes.length < MIN_V3_BYTES || bytes[0] !== PACKET_V3) return null;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const keyId = toHex(bytes.subarray(1, 1 + KEY_ID_BYTES));
  const version = readU64BE(dv, 1 + KEY_ID_BYTES + SALT_BYTES + IV_BYTES);
  const ctLen = dv.getUint32(V3_HEADER_BYTES - CT_LEN_BYTES - CHUNK_INDEX_BYTES, false);
  const chunkIndex = dv.getUint32(V3_HEADER_BYTES - CHUNK_INDEX_BYTES, false);
  if (!Number.isFinite(version) || version > MAX_VERSION) return null;
  return { keyId, version, chunkIndex, ctLenHint: ctLen };
}
function assertVersionRange(version) {
  const v = Math.floor(version);
  if (!Number.isFinite(v) || v < 1 || v > MAX_VERSION) {
    throw new CryptoError(`Invalid packet version counter: ${version}`);
  }
  return v;
}
async function sealV3(plaintext, key, keyId, salt, path, version, chunkIndex, fileManifest) {
  const ver = assertVersionRange(version);
  const pt = plaintext instanceof Uint8Array ? plaintext : new Uint8Array(plaintext);
  const iv = window.crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ctLen = pt.length;
  const ciphertext = new Uint8Array(
    await subtle().encrypt(
      { name: "AES-GCM", iv, additionalData: aadV3(path, keyId, ver, ctLen, chunkIndex, fileManifest) },
      key,
      pt
    )
  );
  const packet = new Uint8Array(V3_HEADER_BYTES + ciphertext.length);
  const dv = new DataView(packet.buffer);
  packet[0] = PACKET_V3;
  packet.set(keyId, 1);
  packet.set(salt, 1 + KEY_ID_BYTES);
  packet.set(iv, 1 + KEY_ID_BYTES + SALT_BYTES);
  const verOff = 1 + KEY_ID_BYTES + SALT_BYTES + IV_BYTES;
  writeU64BE(dv, verOff, ver);
  dv.setUint32(verOff + VERSION_BYTES, ctLen, false);
  dv.setUint32(verOff + VERSION_BYTES + CT_LEN_BYTES, chunkIndex >>> 0, false);
  packet.set(ciphertext, V3_HEADER_BYTES);
  return packet.buffer;
}
async function encryptBuffer(plaintext, key, keyId, salt, path, version) {
  if (salt.length !== SALT_BYTES) {
    throw new CryptoError(`Salt must be exactly ${SALT_BYTES} bytes.`);
  }
  return sealV3(plaintext, key, keyId, salt, path, version, CHUNK_INDEX_SINGLE, null);
}
async function encryptChunk(plaintextChunk, key, keyId, salt, path, version, chunkIndex, fileManifest) {
  if (salt.length !== SALT_BYTES) {
    throw new CryptoError(`Salt must be exactly ${SALT_BYTES} bytes.`);
  }
  if (fileManifest.length !== MANIFEST_BYTES) {
    throw new CryptoError("fileManifest must be exactly 32 bytes.");
  }
  return sealV3(plaintextChunk, key, keyId, salt, path, version, chunkIndex, fileManifest);
}
async function decryptAttempt(bytes, offset, keyForSalt, aad) {
  const salt = bytes.slice(offset, offset + SALT_BYTES);
  const iv = copyBuffer(bytes.slice(offset + SALT_BYTES, offset + SALT_BYTES + IV_BYTES));
  const ciphertext = copyBuffer(bytes.slice(offset + SALT_BYTES + IV_BYTES));
  const key = await keyForSalt(salt);
  const algorithm = aad ? { name: "AES-GCM", iv, additionalData: aad } : { name: "AES-GCM", iv };
  return subtle().decrypt(algorithm, key, ciphertext);
}
function foreignOrCorrupt(path) {
  return new CryptoError(
    `Decryption failed for ${path} \u2014 wrong E2EE password, corrupted file, or ciphertext not created for this path.`
  );
}
async function decryptV3At(bytes, offset, keyForSalt, path) {
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
  let plaintext;
  try {
    plaintext = await subtle().decrypt(
      { name: "AES-GCM", iv, additionalData: aadV3(path, keyId, version, ctLen, chunkIndex, null) },
      key,
      copyBuffer(bytes.subarray(ctStart, ctEnd))
    );
  } catch (e) {
    throw foreignOrCorrupt(path);
  }
  return {
    plaintext,
    keyId: toHex(keyId),
    version,
    chunkIndex,
    length: V3_HEADER_BYTES + ctLen + 16
  };
}
async function decryptBuffer(packet, keyForSalt, path) {
  const bytes = new Uint8Array(packet);
  if (bytes.length < PACKET_V1_BYTES) {
    throw new CryptoError("Encrypted packet is truncated or corrupt.");
  }
  if (bytes[0] === PACKET_V3 && bytes.length >= MIN_V3_BYTES) {
    try {
      const res = await decryptV3At(bytes, 0, keyForSalt, path);
      if (res.length === bytes.length) {
        return { plaintext: res.plaintext, keyId: res.keyId, version: res.version, chunkIndex: res.chunkIndex };
      }
    } catch (err) {
      if (!(err instanceof CryptoError)) throw err;
      if (/does not belong to this vault/.test(err.message)) throw err;
    }
  }
  if (bytes[0] === PACKET_V2 && bytes.length >= PACKET_V2_BYTES) {
    try {
      return {
        plaintext: await decryptAttempt(bytes, 1, keyForSalt, aadV2(path)),
        keyId: null,
        version: null,
        chunkIndex: null
      };
    } catch (err) {
      if (!(err instanceof CryptoError) && !(err instanceof Error)) throw err;
    }
  }
  try {
    return {
      plaintext: await decryptAttempt(bytes, 0, keyForSalt, null),
      keyId: null,
      version: null,
      chunkIndex: null
    };
  } catch (e) {
    throw foreignOrCorrupt(path);
  }
}
async function decryptChunked(blob, keyForSalt, path, fileManifest) {
  if (fileManifest.length !== MANIFEST_BYTES) {
    throw new CryptoError("fileManifest must be exactly 32 bytes.");
  }
  const bytes = new Uint8Array(blob);
  if (bytes.length === 0 || bytes[0] !== PACKET_V3) {
    throw foreignOrCorrupt(path);
  }
  const chunks = [];
  let keyId = null;
  let version = null;
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
    if (chunkIndex !== chunks.length) throw foreignOrCorrupt(path);
    const hexKeyId = toHex(hdrKeyId);
    if (keyId === null) keyId = hexKeyId;
    else if (keyId !== hexKeyId) throw foreignOrCorrupt(path);
    if (version === null) version = v;
    else if (version !== v) throw foreignOrCorrupt(path);
    const key = await keyForSalt(salt);
    let plaintext;
    try {
      plaintext = await subtle().decrypt(
        {
          name: "AES-GCM",
          iv,
          additionalData: aadV3(path, hdrKeyId, v, ctLen, chunkIndex, fileManifest)
        },
        key,
        copyBuffer(bytes.subarray(ctStart, ctEnd))
      );
    } catch (e) {
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
  return { plaintext: out.buffer, keyId, version, chunkCount: chunks.length };
}
var CryptoManager = class {
  constructor(password, expectedSalt = null) {
    this.password = password;
    this.expectedSalt = expectedSalt;
    this.cache = /* @__PURE__ */ new Map();
  }
  async keyMaterial(salt) {
    if (this.expectedSalt && !bytesEqual(salt, this.expectedSalt)) {
      throw new CryptoError("Packet salt does not belong to this vault.");
    }
    const id = toHex(salt);
    let km = this.cache.get(id);
    if (!km) {
      km = await deriveKeyMaterial(this.password, salt);
      this.cache.set(id, km);
    }
    return km;
  }
  async keyForSalt(salt) {
    return (await this.keyMaterial(salt)).key;
  }
  async encrypt(plaintext, salt, path, version) {
    const km = await this.keyMaterial(salt);
    return encryptBuffer(plaintext, km.key, km.keyId, salt, path, version);
  }
  async encryptChunk(plaintextChunk, salt, path, version, chunkIndex, fileManifest) {
    const km = await this.keyMaterial(salt);
    return encryptChunk(plaintextChunk, km.key, km.keyId, salt, path, version, chunkIndex, fileManifest);
  }
  async decrypt(packet, path) {
    return decryptBuffer(packet, (salt) => this.keyForSalt(salt), path);
  }
  async decryptChunked(blob, path, fileManifest) {
    return decryptChunked(blob, (salt) => this.keyForSalt(salt), path, fileManifest);
  }
};

// src/ignore.ts
function escapeRegex(ch) {
  return /[a-zA-Z0-9_-]/.test(ch) ? ch : `\\${ch}`;
}
function globToRegexSource(glob) {
  let out = "";
  let i = 0;
  while (i < glob.length) {
    if (glob.startsWith("**/", i)) {
      out += "(?:.*/)?";
      i += 3;
      continue;
    }
    if (glob.startsWith("/**/", i)) {
      out += "(?:/.*)?/";
      i += 4;
      continue;
    }
    if (glob[i] === "*" && glob[i + 1] === "*") {
      out += ".*";
      i += 2;
      continue;
    }
    const ch = glob[i];
    if (ch === "*") out += "[^/]*";
    else if (ch === "?") out += "[^/]";
    else out += escapeRegex(ch);
    i++;
  }
  return out;
}
function compileLine(raw) {
  let pattern = raw.trim();
  if (pattern === "" || pattern.startsWith("#")) return null;
  const dirOnly = pattern.endsWith("/");
  if (dirOnly) pattern = pattern.slice(0, -1);
  if (pattern === "") return null;
  const anchored = pattern.includes("/");
  pattern = pattern.replace(/^\/+/, "");
  if (pattern === "") return null;
  const source = globToRegexSource(pattern);
  const flags = "";
  if (anchored) {
    return {
      source: pattern,
      regex: new RegExp(`^${source}$`, flags),
      segmentMatch: false,
      dirOnly
    };
  }
  return {
    source: pattern,
    regex: new RegExp(`^${source}$`, flags),
    segmentMatch: true,
    dirOnly
  };
}
function compileIgnorePatterns(text) {
  const lines = (text != null ? text : "").split(/\r?\n/);
  const compiled = [];
  const accepted = [];
  for (const line of lines) {
    const c = compileLine(line);
    if (c) {
      compiled.push(c);
      accepted.push(c.source + (c.dirOnly ? "/" : ""));
    }
  }
  const segmentsOf = (path) => path.split("/").filter((s) => s !== "");
  const ancestorsOf = (path) => {
    const segs = segmentsOf(path);
    const out = [];
    for (let i = 1; i < segs.length; i++) out.push(segs.slice(0, i).join("/"));
    return out;
  };
  return {
    patterns: accepted,
    isIgnored(path) {
      if (compiled.length === 0) return false;
      const clean = path.replace(/^\/+/, "");
      if (clean === "") return false;
      const segs = segmentsOf(clean);
      const ancestors = ancestorsOf(clean);
      for (const c of compiled) {
        if (c.segmentMatch) {
          const segCount = c.dirOnly ? segs.length - 1 : segs.length;
          for (let i = 0; i < segCount; i++) {
            if (c.regex.test(segs[i])) return true;
          }
          continue;
        }
        if (!c.dirOnly && c.regex.test(clean)) return true;
        for (const dir of ancestors) {
          if (c.regex.test(dir)) return true;
        }
      }
      return false;
    }
  };
}
function ignoreMatcherFromSources(...sources) {
  return compileIgnorePatterns(sources.filter((s) => s && s.trim() !== "").join("\n"));
}

// src/merge.ts
var MERGE_MAX_BYTES = 512 * 1024;
var MAX_DIFF_D = 2048;
function splitLines(text) {
  const lines = [];
  const parts = text.split("\n");
  let trailingNewline = false;
  if (parts.length > 0 && parts[parts.length - 1] === "") {
    trailingNewline = true;
    parts.pop();
  }
  let crlf = 0;
  let lf = 0;
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i];
    const hadEol = i < parts.length - 1 || trailingNewline;
    if (part.endsWith("\r")) {
      if (hadEol) crlf++;
      lines.push(part.slice(0, -1));
    } else {
      if (hadEol) lf++;
      lines.push(part);
    }
  }
  const eol = crlf + lf === 0 ? null : crlf > lf ? "\r\n" : "\n";
  return { lines, trailingNewline, eol };
}
function matchMap(a, b, maxD) {
  const n = a.length;
  const m = b.length;
  const out = new Int32Array(n).fill(-1);
  if (n === 0 && m === 0) return out;
  if (n === 0 || m === 0) return out;
  const dCap = Math.min(maxD, n + m);
  const offset = dCap;
  const v = new Int32Array(2 * dCap + 1);
  const trace = [];
  let foundD = -1;
  for (let d = 0; d <= dCap; d++) {
    trace.push(v.slice(offset - d, offset + d + 1));
    for (let k = -d; k <= d; k += 2) {
      let x2;
      if (k === -d || k !== d && v[offset + k - 1] < v[offset + k + 1]) {
        x2 = v[offset + k + 1];
      } else {
        x2 = v[offset + k - 1] + 1;
      }
      let y2 = x2 - k;
      while (x2 < n && y2 < m && a[x2] === b[y2]) {
        x2++;
        y2++;
      }
      v[offset + k] = x2;
      if (x2 >= n && y2 >= m) {
        foundD = d;
        break;
      }
    }
    if (foundD >= 0) break;
  }
  if (foundD < 0) return null;
  const pairs = [];
  let x = n;
  let y = m;
  for (let d = foundD; d >= 0; d--) {
    if (d === 0) {
      while (x > 0 && y > 0) {
        pairs.push(x - 1, y - 1);
        x--;
        y--;
      }
      break;
    }
    const vt = trace[d];
    const k = x - y;
    const goDown = k === -d || k !== d && vt[k - 1 + d] < vt[k + 1 + d];
    const prevK = goDown ? k + 1 : k - 1;
    const prevX = vt[prevK + d];
    const prevY = prevX - prevK;
    while (x > prevX && y > prevY) {
      pairs.push(x - 1, y - 1);
      x--;
      y--;
    }
    x = prevX;
    y = prevY;
  }
  for (let i = 0; i < pairs.length; i += 2) {
    out[pairs[i]] = pairs[i + 1];
  }
  return out;
}
function listEquals(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
function sideHunks(matches, side) {
  const hunks = [];
  const n = matches.length;
  if (n === 0) {
    if (side.length > 0) {
      hunks.push({ baseStart: 0, baseEnd: 0, sideStart: 0, sideEnd: side.length });
    }
    return hunks;
  }
  let prevMatch = -1;
  let lastMatchedBase = -1;
  for (let i2 = 0; i2 < n; i2++) {
    const m = matches[i2];
    if (m === -1) continue;
    if (i2 === 0) {
      if (m > 0) {
        hunks.push({ baseStart: 0, baseEnd: 0, sideStart: 0, sideEnd: m });
      }
    } else if (i2 - lastMatchedBase === 1 && prevMatch >= 0 && m - prevMatch > 1) {
      hunks.push({ baseStart: i2, baseEnd: i2, sideStart: prevMatch + 1, sideEnd: m });
    }
    prevMatch = m;
    lastMatchedBase = i2;
  }
  if (matches[n - 1] !== -1 && prevMatch < side.length - 1) {
    hunks.push({ baseStart: n, baseEnd: n, sideStart: prevMatch + 1, sideEnd: side.length });
  }
  let i = 0;
  while (i < n) {
    if (matches[i] !== -1) {
      i++;
      continue;
    }
    let j = i;
    while (j < n && matches[j] === -1) j++;
    hunks.push({
      baseStart: i,
      baseEnd: j,
      sideStart: i === 0 ? 0 : matches[i - 1] + 1,
      sideEnd: j === n ? side.length : matches[j]
    });
    i = j;
  }
  return hunks.sort((a, b) => a.baseStart - b.baseStart || a.baseEnd - b.baseEnd);
}
function hunksInteract(a, b) {
  const aEmpty = a.baseStart === a.baseEnd;
  const bEmpty = b.baseStart === b.baseEnd;
  if (aEmpty && bEmpty) return a.baseStart === b.baseStart;
  if (aEmpty) return b.baseStart <= a.baseStart && a.baseStart <= b.baseEnd;
  if (bEmpty) return a.baseStart <= b.baseStart && b.baseStart <= a.baseEnd;
  return a.baseStart < b.baseEnd && b.baseStart < a.baseEnd;
}
function sideContent(base, side, hunks, lo, hi) {
  const out = [];
  let cursor = lo;
  for (const h of hunks) {
    if (h.baseStart > cursor) for (let k = cursor; k < h.baseStart; k++) out.push(base[k]);
    for (let k = h.sideStart; k < h.sideEnd; k++) out.push(side[k]);
    if (h.baseEnd > cursor) cursor = h.baseEnd;
  }
  for (let k = cursor; k < hi; k++) out.push(base[k]);
  return out;
}
function mergeLines(base, ours, theirs, mo, mt) {
  const out = [];
  let tailSource = "base";
  const emit = (lines, source) => {
    if (lines.length === 0) return;
    for (const l of lines) out.push(l);
    tailSource = source;
  };
  const oursHunks = sideHunks(mo, ours);
  const theirsHunks = sideHunks(mt, theirs);
  const all = [
    ...oursHunks.map((h) => ({ ...h, o: true })),
    ...theirsHunks.map((h) => ({ ...h, o: false }))
  ].sort((a, b) => a.baseStart - b.baseStart || a.baseEnd - b.baseEnd);
  let prevHi = 0;
  let lo = 0;
  let hi = 0;
  let group = [];
  const flushRegion = () => {
    if (group.length === 0) return true;
    const oGroup = group.filter((h) => h.o);
    const tGroup = group.filter((h) => !h.o);
    const bChunk = base.slice(lo, hi);
    const oChunk = sideContent(base, ours, oGroup, lo, hi);
    const tChunk = sideContent(base, theirs, tGroup, lo, hi);
    const oChanged = !listEquals(oChunk, bChunk);
    const tChanged = !listEquals(tChunk, bChunk);
    group = [];
    if (!oChanged && !tChanged) emit(bChunk, "base");
    else if (!oChanged) emit(tChunk, "theirs");
    else if (!tChanged) emit(oChunk, "ours");
    else if (listEquals(oChunk, tChunk)) emit(oChunk, "ours");
    else return false;
    return true;
  };
  const advance = (next) => {
    if (group.length > 0) {
      if (!flushRegion()) return false;
      prevHi = hi;
    }
    if (next > prevHi) emit(base.slice(prevHi, next), "base");
    prevHi = next;
    return true;
  };
  for (const h of all) {
    let touch = false;
    if (group.length > 0) {
      for (const r of group) {
        if (hunksInteract(h, r)) {
          touch = true;
          break;
        }
      }
    }
    if (touch) {
      lo = Math.min(lo, h.baseStart);
      hi = Math.max(hi, h.baseEnd);
      group.push(h);
      continue;
    }
    if (!advance(h.baseStart)) return null;
    lo = h.baseStart;
    hi = h.baseEnd;
    group.push(h);
  }
  if (!advance(base.length)) return null;
  return { lines: out, tailSource };
}
function merge3(base, ours, theirs, opts = {}) {
  var _a, _b, _c, _d;
  const maxBytes = (_a = opts.maxBytes) != null ? _a : MERGE_MAX_BYTES;
  if (base.length > maxBytes || ours.length > maxBytes || theirs.length > maxBytes) {
    return { kind: "conflict", reason: "note is too large for auto-merge" };
  }
  if (ours === theirs) return { kind: "merged", text: ours };
  if (base === ours) return { kind: "merged", text: theirs };
  if (base === theirs) return { kind: "merged", text: ours };
  const b = splitLines(base);
  const o = splitLines(ours);
  const t = splitLines(theirs);
  const mo = matchMap(b.lines, o.lines, MAX_DIFF_D);
  const mt = matchMap(b.lines, t.lines, MAX_DIFF_D);
  if (!mo || !mt) {
    return { kind: "conflict", reason: "versions are too divergent to auto-merge" };
  }
  const merged = mergeLines(b.lines, o.lines, t.lines, mo, mt);
  if (!merged) {
    return { kind: "conflict", reason: "both sides edited the same region" };
  }
  const dominant = (_d = (_c = (_b = o.eol) != null ? _b : t.eol) != null ? _c : b.eol) != null ? _d : "\n";
  const trailing = merged.tailSource === "ours" ? o.trailingNewline : merged.tailSource === "theirs" ? t.trailingNewline : b.trailingNewline;
  const text = merged.lines.length === 0 ? "" : merged.lines.join(dominant) + (trailing ? dominant : "");
  return { kind: "merged", text };
}

// src/util.ts
function errorMessage(error) {
  if (error instanceof Error && error.message) return error.message;
  if (typeof error === "string") return error;
  try {
    return JSON.stringify(error);
  } catch (e) {
    return String(error);
  }
}
var PHASE_VERBS = {
  push: "uploading",
  pull: "downloading",
  conflict: "resolving",
  delete: "deleting",
  forget: "cleaning"
};
function formatProgress(p) {
  var _a;
  const verb = (_a = PHASE_VERBS[p.phase]) != null ? _a : "syncing";
  const base = `${p.done}/${p.total} \u2014 ${verb} ${p.currentPath}`;
  if (p.chunk && p.chunk.count > 1) {
    const pct = Math.min(100, Math.max(0, Math.round(p.chunk.index / p.chunk.count * 100)));
    return `${base} (${pct}%)`;
  }
  return base;
}
function isLocalHost(hostname) {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
}
function validateServerUrl(url) {
  const trimmed = url.trim();
  if (!trimmed) return null;
  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch (e) {
    return "This is not a valid URL (did you include https:// ?).";
  }
  if (parsed.protocol !== "https:" && !isLocalHost(parsed.hostname)) {
    return "The URL is not HTTPS \u2014 your API token would travel in cleartext. Use HTTPS except for local testing.";
  }
  if (parsed.username || parsed.password) {
    return "The URL must not contain credentials.";
  }
  return null;
}

// src/syncEngine.ts
var DEBOUNCE_MS = 2500;
var IGNORE_WINDOW_MS = 500;
var JOURNAL_FLUSH_EVERY = 20;
var VERIFIER_PREFIX = ".e2ee-verifier.";
var VERIFIER_LEGACY_PATH = ".e2ee-sync-verifier.v1";
var VERIFIER_PLAINTEXT = new TextEncoder().encode("e2ee-verifier-v1\0");
function verifierPathFor(keyIdHex) {
  return VERIFIER_PREFIX + keyIdHex;
}
function isVerifierPath(p) {
  return p === VERIFIER_LEGACY_PATH || p.startsWith(VERIFIER_PREFIX);
}
function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return out;
}
var MAX_FILE_BYTES = 2 * 1024 * 1024 * 1024;
var CHUNKED_ABOVE_BYTES = 16 * 1024 * 1024;
var CHUNK_PLAINTEXT_BYTES = 8 * 1024 * 1024;
var CHUNK_RETRIES = 2;
var EXCLUDED_PREFIXES = [".trash/"];
var IGNORE_FILE = ".syncignore";
var EXCLUDED_NAMES = /* @__PURE__ */ new Set([".DS_Store", "Thumbs.db", "desktop.ini", IGNORE_FILE]);
function canonicalPath(p) {
  return (0, import_obsidian2.normalizePath)(p).normalize("NFC");
}
function isSyncablePath(p, configDir, ignores) {
  if (isVerifierPath(p)) return false;
  const name = p.slice(p.lastIndexOf("/") + 1);
  if (EXCLUDED_NAMES.has(name)) return false;
  const prefixes = [`${configDir.replace(/\/+$/, "")}/`, ...EXCLUDED_PREFIXES];
  for (const prefix of prefixes) {
    if (p === prefix.slice(0, -1) || p.startsWith(prefix)) return false;
  }
  if (ignores == null ? void 0 : ignores.isIgnored(p)) return false;
  return true;
}
var CONFLICT_PROMPT_LIMIT = 5;
function planSync(locals, remote, journal, configDir, ignores) {
  var _a;
  const ops = [];
  const byLower = /* @__PURE__ */ new Map();
  for (const p of locals.keys()) {
    const lower = p.toLowerCase();
    const group = (_a = byLower.get(lower)) != null ? _a : [];
    group.push(p);
    byLower.set(lower, group);
  }
  const caseRenamed = /* @__PURE__ */ new Set();
  for (const [, group] of byLower) {
    if (group.length < 2) continue;
    group.sort();
    for (const p of group.slice(1)) {
      caseRenamed.add(p);
      ops.push({ action: "case-rename", path: p, local: locals.get(p) });
    }
  }
  const paths = /* @__PURE__ */ new Set([
    ...locals.keys(),
    ...Object.keys(journal),
    ...remote.keys()
  ]);
  for (const path of paths) {
    if (!isSyncablePath(path, configDir, ignores)) continue;
    if (caseRenamed.has(path)) continue;
    const local = locals.get(path);
    const record = journal[path];
    const entry = remote.get(path);
    const rem = entry == null ? void 0 : entry.info;
    const remoteKey = entry == null ? void 0 : entry.key;
    if (rem && !rem.deleted) {
      const remoteChanged = !record || rem.hash !== record.remoteHash;
      if (local) {
        const localChanged = !record || local.stat.mtime > record.localMtime;
        if (localChanged && remoteChanged) {
          if (record) {
            ops.push({ action: "conflict", path, local, remote: rem, remoteKey });
          } else if (rem.mtime >= local.stat.mtime) {
            ops.push({ action: "pull", path, local, remote: rem, remoteKey });
          } else {
            ops.push({ action: "push", path, local });
          }
        } else if (localChanged) {
          ops.push({ action: "push", path, local });
        } else if (remoteChanged) {
          ops.push({ action: "pull", path, local, remote: rem, remoteKey });
        }
      } else if (record && !remoteChanged) {
        ops.push({ action: "delete-remote", path, remote: rem, remoteKey });
      } else {
        ops.push({ action: "pull", path, remote: rem, remoteKey });
      }
    } else {
      if (!local) {
        if (record) ops.push({ action: "forget", path });
        continue;
      }
      const localChanged = !record || local.stat.mtime > record.localMtime;
      if (localChanged) {
        ops.push({ action: "push", path, local });
      } else {
        ops.push({ action: "delete-local", path, local });
      }
    }
  }
  return ops;
}
function findCaseVariant(path, localPaths) {
  const lower = path.toLowerCase();
  for (const p of localPaths) {
    if (p !== path && p.toLowerCase() === lower) return p;
  }
  return null;
}
function rollbackReason(recordVersion, packetVersion) {
  if (recordVersion === void 0 || recordVersion <= 0) return null;
  if (packetVersion === 0) {
    return `Rollback detected: the file arrived as a pre-v3 packet after version ${recordVersion} was already synced \u2014 refusing to overwrite local state.`;
  }
  if (packetVersion < recordVersion) {
    return `Rollback detected: the file arrived as version ${packetVersion}, but this device already synced version ${recordVersion} \u2014 refusing to overwrite local state.`;
  }
  return null;
}
var SyncEngine = class _SyncEngine {
  constructor(ctx) {
    this.ctx = ctx;
    this.api = null;
    this.apiSignature = "";
    this.crypto = null;
    this.cryptoPassword = "";
    this.vaultId = "";
    this.salt = null;
    this.keyIdHex = "";
    /** Live password override set after a successful password-challenge prompt. */
    this.passwordOverride = null;
    /** ETag of the last fully processed index (PROB-6 idle-cycle shortcut). */
    this.lastIndexEtag = "";
    /** True while a password rotation is streaming re-encryption (PROB-1). */
    this.rotating = false;
    /** True while the current run was started explicitly by the user (IMP-2). */
    this.runInteractive = false;
    /** Conflicts asked so far in the current run (IMP-2 batching rule). */
    this.conflictsAsked = 0;
    /** Serializes conflict prompts — one modal at a time despite the pool. */
    this.conflictPromptChain = Promise.resolve();
    /** Where the running cycle's progress counter stands (IMP-3). */
    this.progressState = null;
    /** IMP-5: compiled ignore matcher, cached by (settings + .syncignore) text. */
    this.ignoreCache = null;
    /** Canonical paths we are writing ourselves; vault events for them are ignored. */
    this.ignorePaths = /* @__PURE__ */ new Set();
    /** Per-path debounce timers, keyed by canonical path. */
    this.debounces = /* @__PURE__ */ new Map();
    /** All pending raw timer ids so dispose() can clear everything. */
    this.pendingTimers = /* @__PURE__ */ new Set();
    this.running = false;
    this.rerunRequested = false;
    this.journalOpsSinceFlush = 0;
    /** Local files snapshot of the running cycle (case-collision checks). */
    this.planLocals = null;
    this.configDir = ctx.app.vault.configDir;
  }
  /** Read the vault-root `.syncignore` (device-local policy; never synced). */
  async readSyncIgnoreFile() {
    const file = this.ctx.app.vault.getAbstractFileByPath(IGNORE_FILE);
    if (!(file instanceof import_obsidian2.TFile)) return "";
    try {
      return new TextDecoder().decode(await this.ctx.app.vault.readBinary(file));
    } catch (e) {
      return "";
    }
  }
  /** Fresh matcher from the settings textarea + `.syncignore`, cached by content. */
  async currentIgnoreMatcher() {
    var _a;
    const fileText = await this.readSyncIgnoreFile();
    const signature = `${(_a = this.ctx.getSettings().ignorePatterns) != null ? _a : ""}\0${fileText}`;
    if (this.ignoreCache && this.ignoreCache.signature === signature) {
      return this.ignoreCache.matcher;
    }
    const matcher = ignoreMatcherFromSources(this.ctx.getSettings().ignorePatterns, fileText);
    this.ignoreCache = { signature, matcher };
    return matcher;
  }
  /** Synchronous matcher for event hot paths (uses the last cached compile). */
  ignoreMatcherSync() {
    var _a, _b;
    return (_b = (_a = this.ignoreCache) == null ? void 0 : _a.matcher) != null ? _b : ignoreMatcherFromSources(this.ctx.getSettings().ignorePatterns);
  }
  dispose() {
    for (const t of this.debounces.values()) window.clearTimeout(t);
    this.debounces.clear();
    for (const t of this.pendingTimers) window.clearTimeout(t);
    this.pendingTimers.clear();
    this.ignorePaths.clear();
  }
  /** Drop cached key material (password changed, or plugin unloading). */
  invalidateCrypto() {
    this.crypto = null;
    this.cryptoPassword = "";
    this.vaultId = "";
    this.salt = null;
    this.keyIdHex = "";
  }
  // ------------------------------------------------------------ event input
  onLocalCreated(path) {
    this.onLocalTouched(path);
  }
  onLocalModified(path) {
    this.onLocalTouched(path);
  }
  onLocalDeleted(path) {
    this.onLocalTouched(path);
  }
  /**
   * A rename is equivalent to deleting oldPath and creating newPath. The plan
   * logic handles both halves naturally, so we just schedule a sync run.
   */
  onLocalRenamed(oldPath, newPath) {
    const ignores = this.ignoreMatcherSync();
    const oldSyncable = isSyncablePath(canonicalPath(oldPath), this.configDir, ignores);
    const newSyncable = isSyncablePath(canonicalPath(newPath), this.configDir, ignores);
    if (oldSyncable) this.onLocalTouched(oldPath);
    if (newSyncable) this.onLocalTouched(newPath);
  }
  onLocalTouched(rawPath) {
    const path = canonicalPath(rawPath);
    if (!isSyncablePath(path, this.configDir, this.ignoreMatcherSync()) || this.ignorePaths.has(path)) return;
    const existing = this.debounces.get(path);
    if (existing !== void 0) window.clearTimeout(existing);
    const timer = window.setTimeout(() => {
      this.debounces.delete(path);
      this.pendingTimers.delete(timer);
      this.requestSync();
    }, DEBOUNCE_MS);
    this.debounces.set(path, timer);
    this.pendingTimers.add(timer);
  }
  /** Fire-and-forget entry point (ribbon, debounced events, auto-sync). */
  requestSync() {
    if (this.running) {
      this.rerunRequested = true;
      return;
    }
    void this.runFullSync().catch(() => {
    });
  }
  // ------------------------------------------------------------ main cycle
  async runFullSync(interactive = false) {
    var _a, _b;
    if (this.running) {
      this.rerunRequested = true;
      return null;
    }
    this.running = true;
    this.runInteractive = interactive;
    this.conflictsAsked = 0;
    try {
      const settings = this.ctx.getSettings();
      const password = (_a = this.passwordOverride) != null ? _a : settings.encryptionPassword;
      if (!settings.serverUrl || !settings.apiToken || !password) {
        this.ctx.setStatus("error", "not configured (see plugin settings)");
        this.ctx.notify("E2EE Sync: set server URL, API token and E2EE password in the plugin settings first.");
        return null;
      }
      const api = this.ensureApi(settings);
      const indexResult = await api.getIndex(this.lastIndexEtag || void 0);
      if (indexResult.notModified) {
        this.ctx.setStatus("synced");
        return {
          pushed: 0,
          pulled: 0,
          conflicts: 0,
          merged: 0,
          skipped: 0,
          deletedLocal: 0,
          deletedRemote: 0,
          failures: []
        };
      }
      const setup = await this.ensureSetup(api, password, indexResult.index);
      this.lastIndexEtag = indexResult.etag;
      this.ctx.setStatus("syncing");
      const remote = this.canonicalizeRemote((_b = indexResult.index.files) != null ? _b : {});
      const ignores = await this.currentIgnoreMatcher();
      const locals = this.collectLocalFiles(ignores);
      const journal = this.ctx.getJournal();
      if (!settings.enableMarkdownAutoMerge) {
        for (const record of Object.values(journal)) {
          if ((record == null ? void 0 : record.basePlain) !== void 0) delete record.basePlain;
        }
      }
      const plan = planSync(locals, remote, journal, this.configDir, ignores);
      let ignoreFlagsChanged = false;
      for (const [path, rec] of Object.entries(journal)) {
        if (!rec) continue;
        if (isSyncablePath(path, this.configDir, ignores)) {
          if (rec.ignored) {
            delete rec.ignored;
            ignoreFlagsChanged = true;
          }
        } else if (!rec.ignored) {
          rec.ignored = true;
          ignoreFlagsChanged = true;
        }
      }
      if (ignoreFlagsChanged) this.markJournalDirty();
      this.planLocals = locals;
      const deletes = plan.filter((op) => op.action === "delete-local");
      if (deletes.length > 0 && deletes.length >= this.massDeleteThreshold(locals.size) && this.ctx.confirmMassDeletion && !await this.ctx.confirmMassDeletion(deletes.length, locals.size)) {
        for (const op of deletes) op.action = "forget";
        this.ctx.notify(
          `E2EE Sync: refused ${deletes.length} remote deletion(s) without confirmation \u2014 the local files were kept and will be re-uploaded. Verify the server before syncing again.`,
          15e3
        );
      }
      const summary = await this.executePlan(plan, setup);
      await this.flushJournal(true);
      this.ctx.setStatus(
        summary.failures.length === 0 ? "synced" : "error",
        summary.failures.length === 0 ? void 0 : `${summary.failures.length} file(s) failed`
      );
      if (summary.conflicts > 0 || summary.merged > 0 || summary.skipped > 0 || summary.failures.length > 0) {
        const parts = [
          `${summary.pushed} pushed`,
          `${summary.pulled} pulled`,
          `${summary.conflicts} conflicts`,
          ...summary.merged > 0 ? [`${summary.merged} auto-merged`] : [],
          ...summary.skipped > 0 ? [`${summary.skipped} skipped`] : [],
          `${summary.deletedLocal + summary.deletedRemote} deletions`
        ];
        this.ctx.notify(`E2EE Sync finished \u2014 ${parts.join(", ")}.`, 8e3);
      }
      return summary;
    } catch (error) {
      const offline = error instanceof ApiError && error.isNetworkError;
      this.ctx.setStatus(offline ? "offline" : "error", errorMessage(error));
      this.ctx.notify(`E2EE Sync failed: ${errorMessage(error)}`, 8e3);
      return null;
    } finally {
      this.running = false;
      this.planLocals = null;
      if (this.rerunRequested) {
        this.rerunRequested = false;
        const timer = window.setTimeout(() => {
          this.pendingTimers.delete(timer);
          this.requestSync();
        }, 100);
        this.pendingTimers.add(timer);
      }
    }
  }
  // ------------------------------------------------------------- planning
  /**
   * Fold the raw index into a canonical-key map. When an NFD and an NFC
   * spelling of the same path both exist (pre-normalization 0.1.x data), the
   * live entry wins over a tombstone; API operations keep using the raw key.
   */
  canonicalizeRemote(files) {
    const remote = /* @__PURE__ */ new Map();
    for (const [key, info] of Object.entries(files)) {
      if (!info) continue;
      const canon = canonicalPath(key);
      const prev = remote.get(canon);
      if (!prev || prev.info.deleted && !info.deleted) {
        remote.set(canon, { key, info });
      }
    }
    return remote;
  }
  collectLocalFiles(ignores) {
    const out = /* @__PURE__ */ new Map();
    for (const file of this.ctx.app.vault.getFiles()) {
      const path = canonicalPath(file.path);
      if (!isSyncablePath(path, this.configDir, ignores)) continue;
      if (!out.has(path)) out.set(path, file);
    }
    return out;
  }
  /** More than this many (or this fraction of) remote deletions in one cycle
   *  requires the user's explicit consent — guards against server-side wipes. */
  massDeleteThreshold(localCount) {
    return Math.max(5, Math.floor(localCount * 0.1));
  }
  // ------------------------------------------------------------ execution
  /**
   * Fixed-size worker pool (PROB-7): pulls N items through `fn` with at most
   * `concurrency` in flight. JS single-threadedness makes the shared `next`
   * index race-free.
   */
  async runPool(items, concurrency, fn) {
    let next = 0;
    const workers = Array.from(
      { length: Math.max(1, Math.min(concurrency, items.length)) },
      async () => {
        for (; ; ) {
          const idx = next++;
          if (idx >= items.length) return;
          await fn(items[idx]);
        }
      }
    );
    await Promise.all(workers);
  }
  /** IMP-3: map a planned action to its progress phase. */
  static progressPhase(action) {
    switch (action) {
      case "push":
        return "push";
      case "pull":
        return "pull";
      case "conflict":
      case "case-rename":
        return "conflict";
      case "delete-local":
      case "delete-remote":
        return "delete";
      case "forget":
        return "forget";
    }
  }
  /** IMP-3: report progress to the context, if a UI subscribed. */
  emitProgress(chunk) {
    const s = this.progressState;
    if (!s || !this.ctx.setProgress) return;
    const p = { done: s.done, total: s.total, phase: s.phase, currentPath: s.path };
    if (chunk) p.chunk = chunk;
    this.ctx.setProgress(p);
  }
  /**
   * Execute the plan with bounded parallelism (PROB-7): downloads ×3, uploads
   * (pushes + conflicts) ×2, destructive/local-mutating ops serialized ×1.
   * The planner emits exactly one op per path, so per-path ordering is
   * preserved by construction; memory stays bounded because payloads are
   * ≤ CHUNK_PLAINTEXT_BYTES per transfer after PROB-3.
   */
  async executePlan(plan, setup) {
    const summary = {
      pushed: 0,
      pulled: 0,
      conflicts: 0,
      merged: 0,
      skipped: 0,
      deletedLocal: 0,
      deletedRemote: 0,
      failures: []
    };
    let done = 0;
    const total = plan.length;
    const runOp = async (op) => {
      this.progressState = { done, total, phase: _SyncEngine.progressPhase(op.action), path: op.path };
      this.emitProgress();
      try {
        switch (op.action) {
          case "forget":
            this.ctx.setJournalEntry(op.path, null);
            this.markJournalDirty();
            break;
          case "push":
            await this.doPush(op, setup, summary);
            break;
          case "pull":
            await this.doPull(op, setup, summary);
            break;
          case "conflict":
            await this.doConflict(op, setup, summary);
            break;
          case "case-rename":
            await this.doCaseRename(op, summary);
            break;
          case "delete-local":
            await this.doDeleteLocal(op, summary);
            break;
          case "delete-remote":
            await this.doDeleteRemote(op, setup, summary);
            break;
        }
      } catch (error) {
        summary.failures.push({ path: op.path, error: errorMessage(error) });
      } finally {
        done++;
        if (this.progressState) this.progressState.done = done;
        this.emitProgress();
      }
    };
    const forgets = [];
    const downloads = [];
    const uploads = [];
    const serialized = [];
    for (const op of plan) {
      if (op.action === "forget") forgets.push(op);
      else if (op.action === "pull") downloads.push(op);
      else if (op.action === "push" || op.action === "conflict") uploads.push(op);
      else serialized.push(op);
    }
    for (const op of forgets) await runOp(op);
    await this.runPool(serialized, 1, runOp);
    await this.runPool(uploads, 2, runOp);
    await this.runPool(downloads, 3, runOp);
    this.progressState = null;
    if (summary.failures.length > 0) {
      const first = summary.failures[0];
      this.ctx.notify(
        `E2EE Sync: ${summary.failures.length} file(s) failed. First: ${first.path} \u2014 ${first.error}`,
        1e4
      );
    }
    return summary;
  }
  /** Read, encrypt and upload one vault file; then update its journal entry. */
  async doPush(op, setup, summary) {
    var _a;
    const file = this.ctx.app.vault.getAbstractFileByPath(op.local ? op.local.path : op.path);
    if (!(file instanceof import_obsidian2.TFile)) return;
    if (file.stat.size > MAX_FILE_BYTES) {
      throw new Error(
        `${op.path} is ${Math.round(file.stat.size / 1048576)} MB \u2014 above the sync limit of ${Math.round(MAX_FILE_BYTES / 1048576)} MB.`
      );
    }
    const plaintext = await this.ctx.app.vault.readBinary(file);
    const record = this.ctx.getJournal()[op.path];
    const version = ((_a = record == null ? void 0 : record.remoteVersion) != null ? _a : 0) + 1;
    const uploaded = await this.encryptAndUpload(
      setup,
      op.path,
      plaintext,
      file.stat.mtime,
      version
    );
    const journalEntry = {
      localMtime: file.stat.mtime,
      remoteHash: uploaded.hash,
      remoteMtime: uploaded.mtime,
      remoteVersion: version
    };
    this.setMergeBase(op.path, journalEntry, plaintext);
    this.ctx.setJournalEntry(op.path, journalEntry);
    this.markJournalDirty();
    summary.pushed++;
  }
  /**
   * Encrypt `plaintext` for `path` under the setup's key at `version` and
   * upload it — single-shot for small files, chunked and resumable above
   * CHUNKED_ABOVE_BYTES (PROB-3). Returns the server's index entry.
   */
  async encryptAndUpload(setup, path, plaintext, clientMtime, version) {
    const bytes = new Uint8Array(plaintext);
    if (plaintext.byteLength <= CHUNKED_ABOVE_BYTES) {
      const packet = await setup.crypto.encrypt(plaintext, setup.salt, path, version);
      return setup.api.upload(path, packet, clientMtime, await sha256Hex(new Uint8Array(packet)), {
        keyId: setup.keyIdHex,
        fileVersion: version
      });
    }
    const slices = [];
    for (let o = 0; o < bytes.length; o += CHUNK_PLAINTEXT_BYTES) {
      slices.push([o, Math.min(o + CHUNK_PLAINTEXT_BYTES, bytes.length)]);
    }
    let manifestInput = new Uint8Array(slices.length * 32);
    for (let i = 0; i < slices.length; i++) {
      const [o, end] = slices[i];
      const h = await sha256Bytes(bytes.subarray(o, end));
      manifestInput.set(h, i * 32);
    }
    const fileManifest = await sha256Bytes(manifestInput);
    manifestInput = new Uint8Array(0);
    const { uploadId } = await setup.api.beginUpload({
      path,
      // Declared assembled-size bound: plaintext + per-chunk header/tag
      // overhead. The server rejects assemblies that would exceed it (or its
      // own MAX_FILE_BYTES, whichever is smaller).
      totalBytes: plaintext.byteLength + slices.length * 128,
      chunkCount: slices.length,
      fileManifest: toHex(fileManifest)
    });
    for (let i = 0; i < slices.length; i++) {
      const [o, end] = slices[i];
      const chunkPlain = bytes.slice(o, end);
      const packet = await setup.crypto.encryptChunk(
        chunkPlain.buffer,
        setup.salt,
        path,
        version,
        i,
        fileManifest
      );
      await this.putChunkWithRetry(setup, uploadId, i, packet);
      this.emitProgress({ index: i + 1, count: slices.length });
    }
    return setup.api.commitUpload(uploadId, {
      clientMtime,
      keyId: setup.keyIdHex,
      fileVersion: version
    });
  }
  /** PUT one chunk with bounded retries (network errors) and status-based resume. */
  async putChunkWithRetry(setup, uploadId, n, packet) {
    let lastError = null;
    for (let attempt = 0; attempt <= CHUNK_RETRIES; attempt++) {
      try {
        await setup.api.uploadChunk(uploadId, n, packet, await sha256Hex(new Uint8Array(packet)));
        return;
      } catch (error) {
        lastError = error;
        if (!(error instanceof ApiError) || !error.isNetworkError) throw error;
        await new Promise((r) => window.setTimeout(r, 500 * (attempt + 1)));
      }
    }
    try {
      const status = await setup.api.uploadStatus(uploadId);
      if (status.accepted.includes(n)) return;
    } catch (e) {
    }
    throw lastError;
  }
  /** Download, decrypt and write one remote file; then update its journal. */
  async doPull(op, setup, summary) {
    var _a, _b, _c, _d, _e, _f;
    const remote = op.remote;
    if (!remote) throw new Error("Pull planned without remote metadata.");
    let packet;
    try {
      packet = await setup.api.download((_a = op.remoteKey) != null ? _a : op.path);
    } catch (error) {
      if (error instanceof ApiError && error.status === 404) {
        this.ctx.setJournalEntry(op.path, null);
        this.markJournalDirty();
        return;
      }
      throw error;
    }
    const actualHash = await sha256Hex(new Uint8Array(packet));
    if (actualHash !== remote.hash) {
      throw new Error(
        `Integrity check failed: downloaded bytes do not match the server index (rollback or corruption) \u2014 refusing to overwrite ${op.path}.`
      );
    }
    const record = this.ctx.getJournal()[op.path];
    const manifest = remote.manifest && remote.manifest.length === 64 ? remote.manifest : null;
    if (record && ((_b = remote.ver) != null ? _b : 0) > 0 && ((_c = remote.ver) != null ? _c : 0) < record.remoteVersion) {
      throw new Error(
        `Rollback detected: server reports version ${remote.ver} for ${op.path}, but this device already synced version ${record.remoteVersion} \u2014 refusing the pull.`
      );
    }
    let plaintext;
    let packetVersion;
    if (manifest) {
      const manifestBytes = hexToBytes(manifest);
      const peek = peekV3(new Uint8Array(packet));
      if (peek && peek.keyId && peek.keyId !== setup.keyIdHex) {
        throw new CryptoError(
          `${op.path} was encrypted with a different E2EE password (key ${peek.keyId.slice(0, 8)}\u2026). If the password was changed on another device, update it in the plugin settings.`
        );
      }
      const res = await setup.crypto.decryptChunked(packet, op.path, manifestBytes);
      plaintext = res.plaintext;
      packetVersion = res.version;
    } else {
      const peek = peekV3(new Uint8Array(packet));
      if (peek && peek.keyId && peek.keyId !== setup.keyIdHex) {
        throw new CryptoError(
          `${op.path} was encrypted with a different E2EE password (key ${peek.keyId.slice(0, 8)}\u2026). If the password was changed on another device, update it in the plugin settings.`
        );
      }
      const res = await setup.crypto.decrypt(packet, op.path);
      plaintext = res.plaintext;
      packetVersion = (_d = res.version) != null ? _d : 0;
    }
    const refusal = record ? rollbackReason(record.remoteVersion, packetVersion) : null;
    if (refusal) throw new Error(`${refusal} (${op.path})`);
    const caseVariant = findCaseVariant(op.path, (_f = (_e = this.planLocals) == null ? void 0 : _e.keys()) != null ? _f : []);
    const targetPath = caseVariant ? this.uniqueConflictPath(op.path, "_remote-case_") : op.path;
    if (caseVariant) {
      this.ctx.notify(
        `Case collision: "${op.path}" and "${caseVariant}" differ only by letter case \u2014 the downloaded copy was saved as "${targetPath}".`,
        12e3
      );
    }
    const existing = this.ctx.app.vault.getAbstractFileByPath(
      !caseVariant && op.local ? op.local.path : targetPath
    );
    if (existing && !(existing instanceof import_obsidian2.TFile)) {
      throw new Error(`Local path exists but is a folder: ${targetPath}`);
    }
    this.beginIgnore(targetPath);
    try {
      if (existing) {
        await this.ctx.app.vault.modifyBinary(existing, plaintext);
      } else {
        await this.ensureParentFolder(targetPath);
        await this.ctx.app.vault.createBinary(targetPath, plaintext);
      }
    } catch (error) {
      this.ignorePaths.delete(targetPath);
      throw error;
    }
    const written = this.ctx.app.vault.getAbstractFileByPath(targetPath);
    const journalEntry = {
      localMtime: written instanceof import_obsidian2.TFile ? written.stat.mtime : Date.now(),
      remoteHash: remote.hash,
      remoteMtime: remote.mtime,
      remoteVersion: packetVersion
    };
    this.setMergeBase(targetPath, journalEntry, plaintext);
    this.ctx.setJournalEntry(targetPath, journalEntry);
    if (caseVariant) this.ctx.setJournalEntry(op.path, null);
    this.markJournalDirty();
    summary.pulled++;
  }
  // ------------------------------------------------- Markdown merge (IMP-1)
  /** Is the opt-in three-way Markdown merge active for this cycle? */
  mergeBaseEnabled() {
    return this.ctx.getSettings().enableMarkdownAutoMerge === true;
  }
  /** Only .md notes up to the merge size cap are auto-merge candidates. */
  isMergeCandidate(path, byteLength) {
    return /\.md$/i.test(path) && byteLength <= MERGE_MAX_BYTES;
  }
  /**
   * Record (or drop) the merge base on a fresh journal entry. The base is
   * plaintext at rest in data.json — stored only while the toggle is on and
   * only for eligible notes, purged otherwise.
   */
  setMergeBase(path, entry, plaintext) {
    if (plaintext !== null && this.mergeBaseEnabled() && this.isMergeCandidate(path, plaintext.byteLength)) {
      entry.basePlain = new TextDecoder().decode(plaintext);
    } else {
      delete entry.basePlain;
    }
  }
  /**
   * IMP-1: attempt a three-way merge of a conflicted Markdown note.
   * base = the journal's stored copy, ours = the local file, theirs = the
   * decrypted remote packet (integrity-checked like a pull). On a clean merge
   * the result is written locally and pushed to the original path; any
   * overlap returns false and the caller falls back to keep-both. Hard
   * failures (network, crypto) propagate — the next cycle retries.
   */
  async tryMarkdownMerge(op, setup, summary, record) {
    var _a, _b, _c;
    if (!op.local || !op.remote || !(record == null ? void 0 : record.basePlain)) return false;
    if (!this.isMergeCandidate(op.path, record.basePlain.length)) return false;
    const local = this.ctx.app.vault.getAbstractFileByPath(op.local.path);
    if (!(local instanceof import_obsidian2.TFile)) return false;
    if (local.stat.size > MERGE_MAX_BYTES) return false;
    const remote = op.remote;
    let packet;
    try {
      packet = await setup.api.download((_a = op.remoteKey) != null ? _a : op.path);
    } catch (e) {
      return false;
    }
    if (await sha256Hex(new Uint8Array(packet)) !== remote.hash) return false;
    const manifest = remote.manifest && remote.manifest.length === 64 ? remote.manifest : null;
    const theirs = manifest ? (await setup.crypto.decryptChunked(packet, op.path, hexToBytes(manifest))).plaintext : (await setup.crypto.decrypt(packet, op.path)).plaintext;
    const ours = await this.ctx.app.vault.readBinary(local);
    const decoder = new TextDecoder();
    const result = merge3(record.basePlain, decoder.decode(ours), decoder.decode(theirs));
    if (result.kind !== "merged") return false;
    const mergedBytes = new TextEncoder().encode(result.text);
    const mergedBuffer = mergedBytes.buffer;
    this.beginIgnore(op.path);
    try {
      await this.ctx.app.vault.modifyBinary(local, mergedBuffer);
    } catch (error) {
      this.ignorePaths.delete(op.path);
      throw error;
    }
    const written = this.ctx.app.vault.getAbstractFileByPath(op.path);
    const mtime = written instanceof import_obsidian2.TFile ? written.stat.mtime : local.stat.mtime;
    const version = Math.max((_b = record.remoteVersion) != null ? _b : 0, (_c = remote.ver) != null ? _c : 0) + 1;
    const uploaded = await this.encryptAndUpload(setup, op.path, mergedBuffer, mtime, version);
    const journalEntry = {
      localMtime: mtime,
      remoteHash: uploaded.hash,
      remoteMtime: uploaded.mtime,
      remoteVersion: version
    };
    this.setMergeBase(op.path, journalEntry, mergedBuffer);
    this.ctx.setJournalEntry(op.path, journalEntry);
    this.markJournalDirty();
    summary.merged++;
    this.ctx.notify(`Conflict in ${op.path} resolved by Markdown auto-merge.`, 6e3);
    return true;
  }
  /**
   * IMP-2: route a conflict to the user's choice. Auto-sync runs prompt for
   * at most CONFLICT_PROMPT_LIMIT conflicts and batch keep-both for the rest
   * (UI-storm guard); prompts are serialized so the upload pool can never
   * stack two modals. Null (Esc) resolves to keep-both.
   */
  askConflictResolution(path) {
    const ask = this.ctx.resolveConflict;
    if (!ask) return Promise.resolve("both");
    if (!this.runInteractive && this.conflictsAsked >= CONFLICT_PROMPT_LIMIT) {
      return Promise.resolve("both");
    }
    this.conflictsAsked++;
    const run = this.conflictPromptChain.then(() => ask(path));
    this.conflictPromptChain = run.then(
      () => void 0,
      () => void 0
    );
    return run;
  }
  /** IMP-2 "keep mine": overwrite the remote original with the local version. */
  async pushLocalOverRemote(op, setup, summary, record) {
    var _a, _b, _c;
    const local = this.ctx.app.vault.getAbstractFileByPath(op.local ? op.local.path : op.path);
    if (!(local instanceof import_obsidian2.TFile)) return;
    const plaintext = await this.ctx.app.vault.readBinary(local);
    const version = Math.max((_a = record == null ? void 0 : record.remoteVersion) != null ? _a : 0, (_c = (_b = op.remote) == null ? void 0 : _b.ver) != null ? _c : 0) + 1;
    const uploaded = await this.encryptAndUpload(
      setup,
      op.path,
      plaintext,
      local.stat.mtime,
      version
    );
    const entry = {
      localMtime: local.stat.mtime,
      remoteHash: uploaded.hash,
      remoteMtime: uploaded.mtime,
      remoteVersion: version
    };
    this.setMergeBase(op.path, entry, plaintext);
    this.ctx.setJournalEntry(op.path, entry);
    this.markJournalDirty();
    summary.pushed++;
    this.ctx.notify(`Conflict in ${op.path} resolved: your version was kept.`, 6e3);
  }
  /**
   * "Keep both" conflict resolution — ordered so a failure never leaves
   * duplicate debris and a retry is idempotent:
   *  1. upload the local version to <name>_conflict_<timestamp>.<ext> FIRST,
   *  2. only then create the local copy of it and journal it,
   *  3. download the remote version into the original path.
   * When the Markdown auto-merge (IMP-1) is enabled and produces a clean
   * three-way merge, the conflict resolves without any duplicate copy.
   * With the interactive hook (IMP-2) the user picks the outcome instead.
   */
  async doConflict(op, setup, summary) {
    var _a;
    if (!op.local) return;
    const local = this.ctx.app.vault.getAbstractFileByPath(op.local.path);
    if (!(local instanceof import_obsidian2.TFile)) return;
    const record = this.ctx.getJournal()[op.path];
    if (this.mergeBaseEnabled()) {
      const merged = await this.tryMarkdownMerge(op, setup, summary, record);
      if (merged) return;
    }
    const choice = await this.askConflictResolution(op.path);
    if (choice === "skip") {
      summary.skipped++;
      this.ctx.notify(`Conflict in ${op.path} skipped \u2014 it will be offered again next sync.`, 6e3);
      return;
    }
    if (choice === "mine") {
      await this.pushLocalOverRemote(op, setup, summary, record);
      return;
    }
    if (choice === "remote") {
      await this.doPull({ ...op, local: void 0, remoteKey: op.remoteKey }, setup, summary);
      this.ctx.notify(`Conflict in ${op.path} resolved: the server version was kept.`, 6e3);
      return;
    }
    const conflictPath = this.uniqueConflictPath(op.path);
    const localCopy = await this.ctx.app.vault.readBinary(local);
    const version = ((_a = record == null ? void 0 : record.remoteVersion) != null ? _a : 0) + 1;
    const uploaded = await this.encryptAndUpload(
      setup,
      conflictPath,
      localCopy,
      local.stat.mtime,
      version
    );
    this.beginIgnore(conflictPath);
    try {
      await this.ctx.app.vault.createBinary(conflictPath, localCopy);
    } catch (error) {
      this.ignorePaths.delete(conflictPath);
      throw error;
    }
    const written = this.ctx.app.vault.getAbstractFileByPath(conflictPath);
    const conflictEntry = {
      localMtime: written instanceof import_obsidian2.TFile ? written.stat.mtime : local.stat.mtime,
      remoteHash: uploaded.hash,
      remoteMtime: uploaded.mtime,
      remoteVersion: version
    };
    this.setMergeBase(conflictPath, conflictEntry, null);
    this.ctx.setJournalEntry(conflictPath, conflictEntry);
    this.markJournalDirty();
    await this.doPull({ ...op, local: void 0, remoteKey: op.remoteKey }, setup, summary);
    summary.conflicts++;
    this.ctx.notify(
      `Conflict detected in file: ${op.path}
Both versions kept \u2014 local copy saved as: ${conflictPath}`,
      1e4
    );
  }
  /** Keep-both for two local files differing only by ASCII case (PROB-4). */
  async doCaseRename(op, summary) {
    const file = op.local instanceof import_obsidian2.TFile ? op.local : null;
    const target = file != null ? file : this.ctx.app.vault.getAbstractFileByPath(op.path);
    if (!(target instanceof import_obsidian2.TFile)) return;
    const renamed = this.uniqueConflictPath(op.path, "_case-collision_");
    this.beginIgnore(op.path);
    this.beginIgnore(renamed);
    try {
      await this.ctx.app.vault.rename(target, renamed);
    } catch (error) {
      this.ignorePaths.delete(op.path);
      this.ignorePaths.delete(renamed);
      throw error;
    }
    this.ctx.setJournalEntry(op.path, null);
    this.markJournalDirty();
    summary.conflicts++;
    this.ctx.notify(
      `Case collision: "${op.path}" and another file differ only by letter case \u2014 renamed to "${renamed}" so both are kept.`,
      12e3
    );
  }
  async doDeleteLocal(op, summary) {
    const file = this.ctx.app.vault.getAbstractFileByPath(op.local ? op.local.path : op.path);
    if (file instanceof import_obsidian2.TFile) {
      this.beginIgnore(op.path);
      try {
        await this.ctx.app.vault.trash(file, true);
      } catch (error) {
        this.ignorePaths.delete(op.path);
        throw error;
      }
    }
    this.ctx.setJournalEntry(op.path, null);
    this.markJournalDirty();
    summary.deletedLocal++;
  }
  async doDeleteRemote(op, setup, summary) {
    var _a;
    try {
      await setup.api.deleteFile((_a = op.remoteKey) != null ? _a : op.path);
    } catch (error) {
      if (error instanceof ApiError && error.status === 404) {
      } else {
        throw error;
      }
    }
    this.ctx.setJournalEntry(op.path, null);
    this.markJournalDirty();
    summary.deletedRemote++;
  }
  // --------------------------------------------------- restore from server (IMP-4)
  /**
   * Fresh-clone path: wipe this device's sync journal and re-download every
   * live file from the server. Never deletes — with an empty journal and an
   * empty local snapshot the planner can only plan pulls, so the
   * mass-deletion guard is inapplicable by construction. Existing local files
   * are overwritten with the server copy (that is the point of a restore);
   * local files absent from the server are left untouched.
   *
   * `confirm` receives the dry-run live-file count before anything is wiped;
   * a false resolve aborts without changes. Rollback version checks do not
   * apply to the wiped journal — a restore intentionally re-baselines the
   * device on the server's current state.
   */
  async restoreFromServer(confirm) {
    var _a, _b, _c;
    const settings = this.ctx.getSettings();
    const password = (_a = this.passwordOverride) != null ? _a : settings.encryptionPassword;
    if (!settings.serverUrl || !settings.apiToken || !password) {
      this.ctx.notify("E2EE Sync: set server URL, API token and E2EE password in the plugin settings first.");
      return null;
    }
    if (this.running) {
      this.ctx.notify("E2EE Sync: a sync is already running \u2014 try again when it finishes.");
      return null;
    }
    this.running = true;
    try {
      const api = this.ensureApi(settings);
      const { index } = await api.getIndex();
      const setup = await this.ensureSetup(api, password, index);
      const liveCount = Object.entries((_b = index.files) != null ? _b : {}).filter(
        ([p, f]) => f && !f.deleted && !isVerifierPath(canonicalPath(p))
      ).length;
      if (confirm && !await confirm(liveCount)) {
        this.ctx.setStatus("idle");
        return null;
      }
      for (const path of Object.keys(this.ctx.getJournal())) {
        this.ctx.setJournalEntry(path, null);
      }
      this.lastIndexEtag = "";
      const remote = this.canonicalizeRemote((_c = index.files) != null ? _c : {});
      const ignores = await this.currentIgnoreMatcher();
      const plan = planSync(/* @__PURE__ */ new Map(), remote, {}, this.configDir, ignores);
      this.planLocals = this.collectLocalFiles(ignores);
      this.ctx.setStatus("syncing", `restoring ${liveCount} file(s)\u2026`);
      const summary = await this.executePlan(plan, setup);
      await this.flushJournal(true);
      this.ctx.setStatus(
        summary.failures.length === 0 ? "synced" : "error",
        summary.failures.length === 0 ? void 0 : `${summary.failures.length} file(s) failed`
      );
      return { pulled: summary.pulled, failures: summary.failures.length };
    } catch (error) {
      this.ctx.setStatus("error", errorMessage(error));
      this.ctx.notify(`E2EE Sync: restore failed \u2014 ${errorMessage(error)}`, 8e3);
      return null;
    } finally {
      this.planLocals = null;
      this.running = false;
    }
  }
  // ---------------------------------------------------- integrity audit (PROB-10)
  /** Result of a full-store integrity verification. */
  async verifyIntegrity() {
    var _a;
    const settings = this.ctx.getSettings();
    const password = (_a = this.passwordOverride) != null ? _a : settings.encryptionPassword;
    if (!settings.serverUrl || !settings.apiToken || !password) {
      this.ctx.notify("E2EE Sync: set server URL, API token and E2EE password first.");
      return null;
    }
    try {
      const api = this.ensureApi(settings);
      const { index } = await api.getIndex();
      const setup = await this.ensureSetup(api, password, index);
      const targets = Object.entries(index.files).filter(([p, f]) => f && !f.deleted && !isVerifierPath(canonicalPath(p))).map(([key, info]) => ({ key, path: canonicalPath(key), info }));
      const report = {
        checked: 0,
        hashMismatch: [],
        decryptFailed: [],
        failures: []
      };
      await this.runPool(targets, 3, async ({ key, path, info }) => {
        try {
          const blob = await api.download(key);
          report.checked++;
          if (await sha256Hex(new Uint8Array(blob)) !== info.hash) {
            report.hashMismatch.push(path);
            return;
          }
          if (info.manifest && info.manifest.length === 64) {
            await setup.crypto.decryptChunked(blob, path, hexToBytes(info.manifest));
          } else {
            await setup.crypto.decrypt(blob, path);
          }
        } catch (error) {
          if (error instanceof CryptoError) report.decryptFailed.push(path);
          else report.failures.push({ path, error: errorMessage(error) });
        }
      });
      return report;
    } catch (error) {
      this.ctx.notify(`E2EE Sync: integrity verification failed \u2014 ${errorMessage(error)}`, 8e3);
      return null;
    }
  }
  /**
   * Re-push the intact local copies of the given paths (ver + 1), repairing
   * server-side damage detected by verifyIntegrity. Paths without a healthy
   * local file are skipped and reported.
   */
  async repairPaths(paths) {
    var _a;
    const settings = this.ctx.getSettings();
    const password = (_a = this.passwordOverride) != null ? _a : settings.encryptionPassword;
    const api = this.ensureApi(settings);
    const meta = await api.getMeta();
    const salt = await saltFromVaultId(meta.vaultId);
    const cryptoMgr = new CryptoManager(password, salt);
    const km = await cryptoMgr.keyMaterial(salt);
    const setup = { api, crypto: cryptoMgr, salt, keyIdHex: toHex(km.keyId) };
    const repaired = [];
    const skipped = [];
    await this.runPool(paths, 2, async (path) => {
      var _a2;
      try {
        const file = this.ctx.app.vault.getAbstractFileByPath(path);
        if (!(file instanceof import_obsidian2.TFile)) {
          skipped.push(path);
          return;
        }
        const plaintext = await this.ctx.app.vault.readBinary(file);
        const record = this.ctx.getJournal()[path];
        const version = ((_a2 = record == null ? void 0 : record.remoteVersion) != null ? _a2 : 0) + 1;
        const uploaded = await this.encryptAndUpload(setup, path, plaintext, file.stat.mtime, version);
        const repairEntry = {
          localMtime: file.stat.mtime,
          remoteHash: uploaded.hash,
          remoteMtime: uploaded.mtime,
          remoteVersion: version
        };
        this.setMergeBase(path, repairEntry, plaintext);
        this.ctx.setJournalEntry(path, repairEntry);
        this.markJournalDirty();
        repaired.push(path);
      } catch (e) {
        skipped.push(path);
      }
    });
    await this.flushJournal(true);
    return { repaired, skipped };
  }
  // ---------------------------------------------------- password rotation
  /**
   * PROB-1 — rotate the vault's E2EE password without bricking sync:
   *  1. verify the OLD password against the current verifier (fail-closed,
   *     nothing is modified on a mismatch),
   *  2. seed a verifier for the new key (both coexist),
   *  3. re-encrypt and re-push every live file under the new key, version
   *     counters carrying over (+1),
   *  4. once every live entry carries the new keyId, remove the old verifier.
   * The journal survives — version counters, not hashes, carry the history.
   * Interrupted rotations are resumable: files already under the new key are
   * skipped when the same rotation is rerun.
   */
  async rotatePassword(oldPassword, newPassword) {
    var _a, _b, _c;
    if (oldPassword === newPassword) {
      throw new Error("The new E2EE password must differ from the current one.");
    }
    if (this.rotating) throw new Error("A password rotation is already in progress.");
    this.rotating = true;
    try {
      const settings = this.ctx.getSettings();
      const api = this.ensureApi(settings);
      const meta = await api.getMeta();
      const salt = await saltFromVaultId(meta.vaultId);
      const oldManager = new CryptoManager(oldPassword, salt);
      const oldKm = await oldManager.keyMaterial(salt);
      const oldHex = toHex(oldKm.keyId);
      const newManager = new CryptoManager(newPassword, salt);
      const newKm = await newManager.keyMaterial(salt);
      const newHex = toHex(newKm.keyId);
      const oldSetup = {
        api,
        crypto: oldManager,
        salt,
        keyIdHex: oldHex
      };
      const { index } = await api.getIndex();
      await this.checkVerifier(oldSetup, index);
      const probeEntry = Object.entries(index.files).find(
        ([p, f]) => f && !f.deleted && !isVerifierPath(canonicalPath(p))
      );
      if (probeEntry && probeEntry[1].keyId !== "" && probeEntry[1].keyId !== oldHex) {
        throw new Error(
          "The current password does not match this vault (files carry a different key id). Rotation aborted before any change."
        );
      }
      if (probeEntry && !probeEntry[1].keyId) {
        const blob = await api.download(probeEntry[0]);
        try {
          await oldManager.decrypt(blob, canonicalPath(probeEntry[0]));
        } catch (e) {
          throw new Error(
            "The current password does not match this vault (probe file failed to decrypt). Rotation aborted before any change."
          );
        }
      }
      const newSetup = {
        api,
        crypto: newManager,
        salt,
        keyIdHex: newHex
      };
      await this.seedVerifier(newSetup);
      const remoteFiles = Object.entries(index.files).filter(
        ([p, f]) => f && !f.deleted && !isVerifierPath(canonicalPath(p))
      );
      let done = 0;
      for (const [rawKey, entry] of remoteFiles) {
        const path = canonicalPath(rawKey);
        if (entry.keyId === newHex) {
          done++;
          continue;
        }
        const blob = await api.download(rawKey);
        const actualHash = await sha256Hex(new Uint8Array(blob));
        if (actualHash !== entry.hash) {
          throw new Error(
            `Integrity check failed for ${path} during rotation \u2014 the server index and stored bytes disagree. Rotation aborted; nothing was overwritten.`
          );
        }
        const manifest = entry.manifest && entry.manifest.length === 64 ? entry.manifest : null;
        let plaintext;
        if (manifest) {
          plaintext = (await oldManager.decryptChunked(blob, path, hexToBytes(manifest))).plaintext;
        } else {
          plaintext = (await oldManager.decrypt(blob, path)).plaintext;
        }
        const record = this.ctx.getJournal()[path];
        const version = Math.max((_a = record == null ? void 0 : record.remoteVersion) != null ? _a : 0, (_b = entry.ver) != null ? _b : 0) + 1;
        const uploaded = await this.encryptAndUpload(newSetup, path, plaintext, Date.now(), version);
        const rotationEntry = {
          localMtime: (_c = record == null ? void 0 : record.localMtime) != null ? _c : Date.now(),
          remoteHash: uploaded.hash,
          remoteMtime: uploaded.mtime,
          remoteVersion: version
        };
        this.setMergeBase(path, rotationEntry, plaintext);
        this.ctx.setJournalEntry(path, rotationEntry);
        this.markJournalDirty();
        done++;
        if (done % 10 === 0 || done === remoteFiles.length) {
          this.ctx.setStatus("syncing", `rotating keys \u2014 ${done}/${remoteFiles.length} files`);
          await this.flushJournal();
        }
      }
      const { index: fresh } = await api.getIndex();
      const stale = Object.entries(fresh.files).filter(
        ([p, f]) => f && !f.deleted && !isVerifierPath(canonicalPath(p)) && f.keyId !== newHex
      );
      if (stale.length === 0) {
        for (const oldPath of [verifierPathFor(oldHex), VERIFIER_LEGACY_PATH]) {
          try {
            await api.deleteFile(oldPath);
          } catch (error) {
            if (!(error instanceof ApiError) || error.status !== 404) throw error;
          }
        }
        this.ctx.notify(
          `E2EE password rotated: ${done} file(s) re-encrypted. Enter the same new password on every other device when prompted.`,
          12e3
        );
      } else {
        this.ctx.notify(
          `E2EE password rotation left ${stale.length} file(s) under the old key (they decrypt with the old password only). Run the rotation again from this device to finish converting them.`,
          15e3
        );
      }
      this.passwordOverride = newPassword;
      this.invalidateCrypto();
      this.lastIndexEtag = "";
      await this.flushJournal(true);
    } finally {
      this.rotating = false;
    }
  }
  // ------------------------------------------------------------- plumbing
  ensureApi(settings) {
    const signature = `${settings.serverUrl}\0${settings.apiToken}`;
    if (!this.api || this.apiSignature !== signature) {
      this.api = this.ctx.createApi ? this.ctx.createApi(settings.serverUrl, settings.apiToken) : new SyncApi(settings.serverUrl, settings.apiToken);
      this.apiSignature = signature;
    }
    return this.api;
  }
  async ensureSetup(api, password, index) {
    var _a;
    const meta = await api.getMeta();
    if (!this.crypto || this.cryptoPassword !== password || this.vaultId !== meta.vaultId) {
      const salt2 = await saltFromVaultId(meta.vaultId);
      this.salt = salt2;
      this.crypto = new CryptoManager(password, salt2);
      this.cryptoPassword = password;
      this.vaultId = meta.vaultId;
      const km = await this.crypto.keyMaterial(salt2);
      this.keyIdHex = toHex(km.keyId);
    }
    const salt = this.salt;
    if (!salt || !this.crypto) throw new Error("Crypto setup failed unexpectedly.");
    const setup = { api, crypto: this.crypto, salt, keyIdHex: this.keyIdHex };
    await this.ensurePasswordVerifier(setup, index);
    return {
      api,
      crypto: this.crypto,
      salt: (_a = this.salt) != null ? _a : salt,
      keyIdHex: this.keyIdHex
    };
  }
  /**
   * Fail-closed key check built on per-key verifiers (PROB-1):
   *
   *  - our verifier present + decrypts  -> current key, proceed;
   *  - our verifier absent, a legacy 0.2.0 verifier decrypts -> pre-v3 vault,
   *    upgrade by seeding our per-key verifier;
   *  - verifiers exist for keys we do not know -> the password was rotated on
   *    another device (or is wrong): recoverable prompt, then one retry with
   *    the supplied password;
   *  - a legacy verifier exists but does NOT decrypt -> genuinely wrong
   *    password against a 0.2.0 vault: fatal (nothing is seeded, nothing is
   *    modified) — the 0.2.0 anti-clobber guarantee is preserved;
   *  - populated vault with no verifiers at all (0.1.x-era data), or an empty
   *    vault -> seed our verifier.
   */
  async ensurePasswordVerifier(setup, index) {
    try {
      await this.checkVerifier(setup, index);
      return;
    } catch (error) {
      if (!(error instanceof CryptoError)) throw error;
      const reason = /changed on another device/.test(error.message) ? "changed" : "wrong";
      const prompted = await this.promptForNewPassword(reason);
      if (!prompted) throw error;
    }
    const salt = this.salt;
    const crypto = this.crypto;
    if (!salt || !crypto) throw new Error("Crypto setup failed unexpectedly.");
    const freshSetup = {
      api: setup.api,
      crypto,
      salt,
      keyIdHex: this.keyIdHex
    };
    const { index: freshIndex } = await setup.api.getIndex();
    await this.checkVerifier(freshSetup, freshIndex);
  }
  /** Ask the user for the current vault password (rotation on another device). */
  async promptForNewPassword(reason) {
    if (!this.ctx.promptPassword) return false;
    const settings = this.ctx.getSettings();
    const api = this.ensureApi(settings);
    const password = await this.ctx.promptPassword(reason);
    if (!password) return false;
    this.passwordOverride = password;
    this.invalidateCrypto();
    const meta = await api.getMeta();
    const salt = await saltFromVaultId(meta.vaultId);
    this.salt = salt;
    this.crypto = new CryptoManager(password, salt);
    this.cryptoPassword = password;
    this.vaultId = meta.vaultId;
    const km = await this.crypto.keyMaterial(salt);
    this.keyIdHex = toHex(km.keyId);
    return true;
  }
  /** Verifier check + seeding; throws CryptoError with the classified reason. */
  async checkVerifier(setup, index) {
    const ourPath = verifierPathFor(setup.keyIdHex);
    const decrypts = async (path) => {
      let packet;
      try {
        packet = await setup.api.download(path);
      } catch (error) {
        if (error instanceof ApiError && error.status === 404) return "missing";
        throw error;
      }
      try {
        const { plaintext } = await setup.crypto.decrypt(packet, path);
        const plain = new Uint8Array(plaintext);
        return plain.length === VERIFIER_PLAINTEXT.length && bytesEqual(plain, VERIFIER_PLAINTEXT) ? "yes" : "no";
      } catch (error) {
        if (error instanceof CryptoError) return "no";
        throw error;
      }
    };
    if (await decrypts(ourPath) === "yes") return;
    const otherVerifiers = [];
    let liveForeign = 0;
    let liveFiles = 0;
    for (const [p, f] of Object.entries(index.files)) {
      if (!f) continue;
      const canon = canonicalPath(p);
      if (isVerifierPath(canon)) {
        if (canon !== ourPath) otherVerifiers.push(canon);
        continue;
      }
      if (!f.deleted) {
        liveFiles++;
        if (f.keyId && f.keyId !== setup.keyIdHex) liveForeign++;
      }
    }
    if (otherVerifiers.length > 0 || liveForeign > 0) {
      throw new CryptoError(
        "The E2EE password was changed on another device (or this password is wrong). Enter the current password to continue syncing."
      );
    }
    const legacy = await decrypts(VERIFIER_LEGACY_PATH);
    if (legacy === "yes") {
      await this.seedVerifier(setup);
      return;
    }
    if (legacy === "no") {
      throw new CryptoError(
        "Wrong E2EE password for this vault (verifier check failed). Correct it in the plugin settings before syncing \u2014 nothing was changed on the server."
      );
    }
    await this.seedVerifier(setup);
  }
  /** Create (or refresh) the verifier entry for the setup's key. */
  async seedVerifier(setup) {
    const path = verifierPathFor(setup.keyIdHex);
    const packet = await setup.crypto.encrypt(
      VERIFIER_PLAINTEXT.buffer,
      setup.salt,
      path,
      1
    );
    await setup.api.upload(path, packet, Date.now(), await sha256Hex(new Uint8Array(packet)), {
      keyId: setup.keyIdHex,
      fileVersion: 1
    });
  }
  beginIgnore(path) {
    this.ignorePaths.add(path);
    const timer = window.setTimeout(() => {
      this.pendingTimers.delete(timer);
      this.ignorePaths.delete(path);
    }, IGNORE_WINDOW_MS);
    this.pendingTimers.add(timer);
  }
  /** createFolder() is not reliably recursive — walk each segment down. */
  async ensureParentFolder(filePath) {
    const slash = filePath.lastIndexOf("/");
    if (slash <= 0) return;
    const folderPath = filePath.slice(0, slash);
    const existing = this.ctx.app.vault.getAbstractFileByPath(folderPath);
    if (existing instanceof import_obsidian2.TFolder) return;
    if (existing) throw new Error(`'${folderPath}' exists and is not a folder.`);
    let current = "";
    for (const segment of folderPath.split("/")) {
      current = current ? `${current}/${segment}` : segment;
      const entry = this.ctx.app.vault.getAbstractFileByPath(current);
      if (entry instanceof import_obsidian2.TFolder) continue;
      if (entry) throw new Error(`'${current}' exists and is not a folder.`);
      try {
        await this.ctx.app.vault.createFolder(current);
      } catch (e) {
        const raced = this.ctx.app.vault.getAbstractFileByPath(current);
        if (!(raced instanceof import_obsidian2.TFolder)) throw new Error(`'${current}' exists and is not a folder.`);
      }
    }
  }
  conflictStamp(d = /* @__PURE__ */ new Date()) {
    const pad = (n) => String(n).padStart(2, "0");
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}_${pad(d.getHours())}-${pad(d.getMinutes())}-${pad(d.getSeconds())}`;
  }
  /** filename.md -> filename<marker>YYYY-MM-DD_HH-mm-ss[_N].md */
  uniqueConflictPath(original, marker = "_conflict_") {
    const slash = original.lastIndexOf("/");
    const dir = slash >= 0 ? original.slice(0, slash + 1) : "";
    const name = slash >= 0 ? original.slice(slash + 1) : original;
    const dot = name.lastIndexOf(".");
    const base = dot > 0 ? name.slice(0, dot) : name;
    const ext = dot > 0 ? name.slice(dot) : "";
    let candidate = `${dir}${base}${marker}${this.conflictStamp()}${ext}`;
    let attempt = 2;
    while (this.ctx.app.vault.getAbstractFileByPath(candidate)) {
      candidate = `${dir}${base}${marker}${this.conflictStamp()}_${attempt++}${ext}`;
    }
    return candidate;
  }
  markJournalDirty() {
    this.journalOpsSinceFlush++;
    if (this.journalOpsSinceFlush >= JOURNAL_FLUSH_EVERY) {
      this.journalOpsSinceFlush = 0;
      void this.ctx.persist().catch(() => {
      });
    }
  }
  async flushJournal(force = false) {
    if (force || this.journalOpsSinceFlush > 0) {
      this.journalOpsSinceFlush = 0;
      await this.ctx.persist();
    }
  }
};

// src/settings.ts
var import_obsidian3 = require("obsidian");
var INTRO_TEXT = "Files are encrypted on this device (AES-256-GCM, PBKDF2-derived key) before they are uploaded. The server only ever stores ciphertext. File contents never leave this device unencrypted \u2014 but note that file paths, sizes and timestamps are visible to the server.";
var E2eeSyncSettingTab = class extends import_obsidian3.PluginSettingTab {
  constructor(app, plugin) {
    super(app, plugin);
    this.plugin = plugin;
  }
  getSettingDefinitions() {
    const plugin = this.plugin;
    return [
      {
        type: "group",
        heading: "E2EE Vault Sync",
        items: [
          { name: "How it works", desc: INTRO_TEXT },
          {
            name: "Server URL",
            desc: "Base URL of your sync server, e.g. https://sync.example.com. HTTPS is required for remote hosts.",
            control: {
              type: "text",
              key: "serverUrl",
              placeholder: "https://sync.example.com",
              validate: (value) => {
                var _a;
                return (_a = validateServerUrl(String(value))) != null ? _a : void 0;
              }
            }
          },
          {
            name: "API token",
            desc: "Bearer token configured on the server (AUTH_TOKEN).",
            control: {
              type: "secret",
              key: "apiToken"
            }
          },
          {
            name: "E2EE password",
            desc: "Derives the encryption key (PBKDF2, 210 000 iterations). Never sent to the server. All devices syncing this vault must use the same password \u2014 changing it starts a streamed key rotation (every file is re-encrypted and re-uploaded; other devices are prompted for the new password).",
            control: {
              type: "secret",
              key: "encryptionPassword"
            }
          },
          {
            name: "Keep the E2EE password on this device",
            desc: "When on (default), the password is stored in this plugin\u2019s data.json inside your vault. Turn it off if the vault is backed up to a cloud you do not fully trust: the password is then kept in memory only and re-asked after each app restart. The API token remains stored either way.",
            control: {
              type: "toggle",
              key: "rememberEncryptionPassword"
            }
          },
          {
            name: "Auto-sync interval (minutes)",
            desc: "Sync automatically every N minutes (1\u20131440). 0 disables periodic sync.",
            control: {
              type: "number",
              key: "autoSyncMinutes",
              min: 0,
              max: 1440,
              validate: (value) => {
                const n = Number(value);
                if (!Number.isInteger(n) || n < 0 || n > 1440) {
                  return "Enter an integer between 0 and 1440.";
                }
                return void 0;
              }
            }
          },
          {
            name: "Ignore patterns",
            desc: 'One glob per line \u2014 these paths never sync and are never deleted from the server: "private/" (a folder at any depth), "*.bak", "notes/draft.md". Patterns with a slash are anchored to the vault root; "*" and "?" stay inside one folder level, "**" crosses them. A .syncignore file in the vault root is merged with this list.',
            control: {
              type: "textarea",
              key: "ignorePatterns",
              placeholder: "private/\n*.bak"
            }
          },
          {
            name: "Auto-merge Markdown conflicts",
            desc: "EXPERIMENTAL, off by default. When two devices edit different parts of the same note, the changes are merged automatically instead of keeping both copies (overlapping edits still keep both). Trade-off: to compute a merge this device stores a plaintext copy of the last synced state of every .md note in the plugin\u2019s data.json \u2014 unencrypted at rest inside your vault (the notes themselves are plaintext there too, but tools that read data.json would see note content even if the notes were moved elsewhere).",
            control: {
              type: "toggle",
              key: "enableMarkdownAutoMerge"
            }
          },
          {
            name: "Sync hidden configuration (experimental)",
            desc: 'Syncs allowlisted files from the .obsidian folder through a separate "config/" namespace (same encryption, separate journal section). Default groups: appearance.json, app.json, hotkeys.json, snippets/, themes/ and plugin code (main.js, manifest.json, styles.css). plugins/<id>/data.json and workspace.json stay device-local unless you opt in \u2014 they can propagate secrets or per-device UI state between machines.',
            control: {
              type: "toggle",
              key: "configSync.enabled"
            }
          },
          {
            name: "appearance.json",
            desc: "Theme selection and appearance settings.",
            control: { type: "toggle", key: "configSync.appearance" }
          },
          {
            name: "app.json",
            desc: "Core app settings (editor behaviour, attachment folder\u2026).",
            control: { type: "toggle", key: "configSync.app" }
          },
          {
            name: "hotkeys.json",
            desc: "Custom keyboard shortcuts.",
            control: { type: "toggle", key: "configSync.hotkeys" }
          },
          {
            name: "snippets/",
            desc: "CSS snippets.",
            control: { type: "toggle", key: "configSync.snippets" }
          },
          {
            name: "themes/",
            desc: "Installed themes.",
            control: { type: "toggle", key: "configSync.themes" }
          },
          {
            name: "Plugin code (main.js / manifest.json / styles.css)",
            desc: "Installed community plugin bundles \u2014 lets a new device skip re-downloading plugins.",
            control: { type: "toggle", key: "configSync.pluginCode" }
          },
          {
            name: "Plugin data (plugins/<id>/data.json)",
            desc: "CAUTION: plugin settings may contain tokens/secrets and are not designed to merge across devices. Off by default.",
            control: { type: "toggle", key: "configSync.pluginData" }
          },
          {
            name: "workspace.json",
            desc: "CAUTION: open tabs and layout are per-device by design. Off by default.",
            control: { type: "toggle", key: "configSync.workspace" }
          },
          {
            name: "Test connection",
            desc: "Checks reachability, the API token and key derivation (GET /api/index).",
            action: () => {
              void this.runConnectionTest();
            }
          },
          {
            name: "Sync now",
            desc: "Run a full synchronization cycle immediately.",
            action: () => {
              this.plugin.requestManualSync();
            }
          },
          {
            name: "Sync journal",
            desc: `This device remembers the last synced state of every file in its plugin data. Conflicts keep both versions: the remote one keeps the original name, the local one is copied to "name_conflict_<timestamp>". The ${this.app.vault.configDir}/ and .trash/ folders are never synchronized.`
          }
        ]
      }
    ];
  }
  getControlValue(key) {
    const dot = key.indexOf(".");
    if (dot > 0) {
      const [group, field] = [key.slice(0, dot), key.slice(dot + 1)];
      const nested = this.plugin.settings[group];
      return nested == null ? void 0 : nested[field];
    }
    return this.plugin.settings[key];
  }
  async setControlValue(key, value) {
    const plugin = this.plugin;
    const dot = key.indexOf(".");
    if (dot > 0) {
      const [group, field] = [key.slice(0, dot), key.slice(dot + 1)];
      const nested = plugin.settings[group];
      if (nested) {
        nested[field] = value;
        await plugin.saveSettings();
      }
      return;
    }
    if (key === "encryptionPassword") {
      const password = String(value != null ? value : "");
      const oldPassword = plugin.effectivePassword;
      if (plugin.settings.rememberEncryptionPassword) {
        plugin.settings.encryptionPassword = password;
      } else {
        plugin.sessionPassword = password;
        plugin.settings.encryptionPassword = "";
      }
      await plugin.onEncryptionPasswordChanged(oldPassword);
      return;
    }
    if (key === "rememberEncryptionPassword") {
      const remember = Boolean(value);
      if (remember) {
        plugin.settings.encryptionPassword = plugin.sessionPassword;
      } else {
        plugin.sessionPassword = plugin.settings.encryptionPassword;
        plugin.settings.encryptionPassword = "";
      }
      plugin.settings.rememberEncryptionPassword = remember;
      await plugin.saveSettings();
      return;
    }
    plugin.settings[key] = value;
    await plugin.saveSettings();
    if (key === "autoSyncMinutes") {
      this.plugin.setAutoSync(Number(value) || 0);
    }
  }
  async runConnectionTest() {
    const s = this.plugin.settings;
    try {
      if (!s.serverUrl || !s.apiToken) {
        throw new Error("Enter the server URL and API token first.");
      }
      const problem = validateServerUrl(s.serverUrl);
      if (problem) new import_obsidian3.Notice(`\u26A0\uFE0F ${problem}`, 6e3);
      const api = new SyncApi(s.serverUrl, s.apiToken);
      const result = await api.testConnection();
      await deriveKey("probe", await saltFromVaultId(result.vaultId), 1e3);
      new import_obsidian3.Notice(
        `\u2705 Connected \u2014 ${result.fileCount} file(s) on the server (vault ${result.vaultId.slice(0, 8)}\u2026).`,
        6e3
      );
    } catch (error) {
      new import_obsidian3.Notice(`\u274C ${errorMessage(error)}`, 1e4);
    }
  }
};

// src/types.ts
var DEFAULT_CONFIG_SYNC = {
  enabled: false,
  appearance: true,
  app: true,
  hotkeys: true,
  snippets: true,
  themes: true,
  pluginCode: true,
  pluginData: false,
  workspace: false
};
var DEFAULT_SETTINGS = {
  serverUrl: "",
  apiToken: "",
  encryptionPassword: "",
  autoSyncMinutes: 5,
  rememberEncryptionPassword: true,
  enableMarkdownAutoMerge: false,
  ignorePatterns: "",
  configSync: DEFAULT_CONFIG_SYNC
};

// src/main.ts
var STARTUP_SYNC_DELAY_MS = 4e3;
function confirmDialog(app, title, body, confirmText) {
  return new Promise((resolve) => {
    let settled = false;
    const settle = (value) => {
      if (!settled) {
        settled = true;
        resolve(value);
      }
    };
    new class extends import_obsidian4.Modal {
      constructor() {
        super(app);
      }
      onOpen() {
        this.titleEl.setText(title);
        this.contentEl.createEl("p", { text: body });
        const row = this.contentEl.createDiv({ cls: "modal-button-container" });
        const cancel = row.createEl("button", { text: "Cancel" });
        const confirm = row.createEl("button", { text: confirmText, cls: "mod-cta" });
        cancel.onclick = () => {
          settle(false);
          this.close();
        };
        confirm.onclick = () => {
          settle(true);
          this.close();
        };
      }
      onClose() {
        settle(false);
        super.onClose();
      }
    }().open();
  });
}
var PasswordPromptModal = class extends import_obsidian4.Modal {
  constructor(app, onSubmit) {
    super(app);
    this.onSubmit = onSubmit;
  }
  onOpen() {
    let settled = false;
    const settle = (value) => {
      if (!settled) {
        settled = true;
        this.onSubmit(value);
      }
    };
    this.titleEl.setText("E2EE Sync: E2EE password required");
    this.contentEl.createEl("p", {
      text: "This device is configured to keep the E2EE password in memory only. Enter it to unlock sync for this session \u2014 it will not be written to disk."
    });
    const input = this.contentEl.createEl("input", { type: "password" });
    input.placeholder = "E2EE password";
    const row = this.contentEl.createDiv({ cls: "modal-button-container" });
    const cancel = row.createEl("button", { text: "Not now" });
    const unlock = row.createEl("button", { text: "Unlock sync", cls: "mod-cta" });
    const submit = () => {
      settle(input.value || null);
      this.close();
    };
    cancel.onclick = () => {
      settle(null);
      this.close();
    };
    unlock.onclick = submit;
    input.addEventListener("keydown", (evt) => {
      if (evt.key === "Enter") submit();
    });
    window.setTimeout(() => input.focus(), 50);
  }
  onClose() {
    super.onClose();
  }
};
var IntegrityReportModal = class extends import_obsidian4.Modal {
  constructor(app, hashMismatch, decryptFailed, otherFailures, onAction) {
    super(app);
    this.hashMismatch = hashMismatch;
    this.decryptFailed = decryptFailed;
    this.otherFailures = otherFailures;
    this.onAction = onAction;
  }
  onOpen() {
    this.titleEl.setText("E2EE Sync: integrity problems found");
    const list = (title, items) => {
      if (items.length === 0) return;
      this.contentEl.createEl("h4", { text: `${title} (${items.length})` });
      const ul = this.contentEl.createEl("ul");
      for (const item of items.slice(0, 20)) ul.createEl("li", { text: item });
      if (items.length > 20) ul.createEl("li", { text: `\u2026 and ${items.length - 20} more` });
    };
    list("Stored bytes do not match the server index (rollback or corruption)", this.hashMismatch);
    list("Cannot be decrypted with this device\u2019s key (wrong password or foreign key)", this.decryptFailed);
    list("Other failures", this.otherFailures);
    this.contentEl.createEl("p", {
      text: "Repair re-uploads the intact local copy of every affected file (version history advances by one). Files without a healthy local copy are skipped."
    });
    const row = this.contentEl.createEl("div", { cls: "modal-button-container" });
    const close = row.createEl("button", { text: "Close" });
    const repair = row.createEl("button", { text: "Repair from local copies", cls: "mod-warning" });
    const done = (value) => {
      this.close();
      void this.onAction(value);
    };
    close.onclick = () => done(false);
    repair.onclick = () => done(true);
  }
};
var ConflictModal = class extends import_obsidian4.Modal {
  constructor(app, path, onSubmit) {
    super(app);
    this.path = path;
    this.onSubmit = onSubmit;
  }
  onOpen() {
    let settled = false;
    const settle = (value) => {
      if (!settled) {
        settled = true;
        this.onSubmit(value);
      }
    };
    this.titleEl.setText("E2EE Sync: conflict");
    this.contentEl.createEl("p", {
      text: `This device and the server both changed "${this.path}". Choose which version to keep \u2014 the other one will not survive this choice.`
    });
    const row = this.contentEl.createEl("div", { cls: "modal-button-container" });
    const button = (text, cls, choice, confirm = false) => {
      const b = row.createEl("button", { text, cls: confirm ? "mod-cta" : cls });
      b.onclick = () => {
        settle(choice);
        this.close();
      };
      return b;
    };
    button("Keep mine", "", "mine");
    button("Keep remote", "", "remote");
    button("Keep both", "", "both", true);
    button("Skip", "", "skip");
    this.contentEl.createEl("p", {
      text: '"Keep mine" uploads your version (the server copy is replaced). "Keep remote" discards your local edits. "Keep both" saves your version as a _conflict_ copy. "Skip" decides nothing and asks again on the next sync.',
      cls: "setting-item-description"
    });
  }
  onClose() {
    this.onSubmit(null);
    super.onClose();
  }
};
var E2eeSyncPlugin = class extends import_obsidian4.Plugin {
  constructor() {
    super(...arguments);
    this.settings = { ...DEFAULT_SETTINGS };
    this.journal = {};
    /** IMP-6: separate journal section for the config/ server namespace. */
    this.configJournal = {};
    /** Live password when rememberEncryptionPassword is false (never persisted). */
    this.sessionPassword = "";
    this.statusBarEl = null;
    this.ribbonEl = null;
    this.autoSyncTimer = null;
    this.oneShotTimers = /* @__PURE__ */ new Set();
    this.lastErrorNotice = "";
  }
  /** The password in force right now: persisted value or the session value. */
  get effectivePassword() {
    return this.settings.rememberEncryptionPassword ? this.settings.encryptionPassword : this.sessionPassword;
  }
  async onload() {
    var _a, _b, _c, _d, _e, _f, _g;
    const data = (_a = await this.loadData()) != null ? _a : {};
    this.settings = {
      ...DEFAULT_SETTINGS,
      ...(_b = data.settings) != null ? _b : {},
      // Nested group defaults survive partial persisted configSync objects.
      configSync: { ...DEFAULT_CONFIG_SYNC, ...(_d = (_c = data.settings) == null ? void 0 : _c.configSync) != null ? _d : {} }
    };
    this.journal = (_e = data.journal) != null ? _e : {};
    this.configJournal = (_f = data.configJournal) != null ? _f : {};
    for (const key of Object.keys(this.journal)) {
      const canonical = canonicalPath(key);
      const record = this.journal[key];
      delete this.journal[key];
      if (record) {
        (_g = record.remoteVersion) != null ? _g : record.remoteVersion = 0;
        if (!this.journal[canonical]) this.journal[canonical] = record;
      }
    }
    this.engine = new SyncEngine({
      app: this.app,
      getSettings: () => ({ ...this.settings, encryptionPassword: this.effectivePassword }),
      getJournal: () => this.journal,
      setJournalEntry: (path, record) => {
        if (record) this.journal[path] = record;
        else delete this.journal[path];
      },
      persist: () => this.saveData({ settings: this.settings, journal: this.journal, configJournal: this.configJournal }),
      setStatus: (status, message) => this.updateStatus(status, message),
      notify: (message, timeout) => new import_obsidian4.Notice(message, timeout != null ? timeout : 6e3),
      confirmMassDeletion: (deletedCount, localCount) => confirmDialog(
        this.app,
        "E2EE Sync: mass deletion detected",
        `The server reports ${deletedCount} of your ${localCount} files as deleted. This can mean another device cleaned the vault \u2014 or that the server (or API token) was compromised. "Keep my local files" cancels these deletions; the kept files are re-uploaded on the next sync, so nothing is lost either way.`,
        "Delete as instructed"
      ),
      promptPassword: (reason) => this.promptForChangedPassword(reason),
      resolveConflict: (path) => new Promise((resolve) => {
        new ConflictModal(this.app, path, resolve).open();
      }),
      setProgress: (progress) => this.showProgress(progress)
    });
    this.addSettingTab(new E2eeSyncSettingTab(this.app, this));
    this.ribbonEl = this.addRibbonIcon("refresh-cw", "E2EE Sync: sync now", () => {
      this.requestManualSync();
    });
    this.statusBarEl = this.addStatusBarItem();
    this.addCommand({
      id: "force-full-sync",
      name: "Force full sync",
      callback: () => this.requestManualSync()
    });
    this.addCommand({
      id: "enter-session-password",
      name: "Enter the E2EE password for this session",
      callback: () => this.promptForSessionPassword()
    });
    this.addCommand({
      id: "verify-vault-integrity",
      name: "Verify vault integrity",
      callback: () => this.runIntegrityCheck()
    });
    this.addCommand({
      id: "restore-from-server",
      name: "Restore from server",
      callback: () => void this.runRestoreFromServer()
    });
    this.app.workspace.onLayoutReady(() => this.onLayoutReady());
    this.updateStatus("idle");
  }
  onunload() {
    var _a;
    void this.saveData({ settings: this.settings, journal: this.journal, configJournal: this.configJournal }).catch(() => {
    });
    (_a = this.engine) == null ? void 0 : _a.dispose();
    if (this.autoSyncTimer !== null) window.clearInterval(this.autoSyncTimer);
    for (const t of this.oneShotTimers) window.clearTimeout(t);
    this.oneShotTimers.clear();
  }
  // ------------------------------------------------------------- settings
  async saveSettings() {
    const settings = {
      ...this.settings,
      encryptionPassword: this.settings.rememberEncryptionPassword ? this.settings.encryptionPassword : ""
      // session-only mode: the password never reaches data.json
    };
    await this.saveData({ settings, journal: this.journal, configJournal: this.configJournal });
  }
  /**
   * PROB-1: a password change no longer resets the journal — it streams a
   * coordinated rotation (seed new verifier → re-encrypt every live file with
   * version counters carried over → drop the old verifier). Other devices are
   * prompted for the new password on their next sync. The journal survives.
   */
  async onEncryptionPasswordChanged(oldPassword) {
    const newPassword = this.effectivePassword;
    if (!oldPassword || oldPassword === newPassword) {
      await this.saveSettings();
      return;
    }
    const confirmed = await confirmDialog(
      this.app,
      "E2EE Sync: rotate the vault encryption key?",
      "Every file on the server will be downloaded, re-encrypted with the new password and re-uploaded (version history is preserved). Run this on the most up-to-date device first; other devices will ask for the new password on their next sync. Keep the device awake until the rotation finishes.",
      "Rotate now"
    );
    if (!confirmed) {
      if (this.settings.rememberEncryptionPassword) {
        this.settings.encryptionPassword = oldPassword;
      } else {
        this.sessionPassword = oldPassword;
        this.settings.encryptionPassword = "";
      }
      await this.saveSettings();
      new import_obsidian4.Notice("E2EE Sync: rotation cancelled \u2014 the previous password stays in force.", 8e3);
      return;
    }
    this.updateStatus("syncing", "rotating encryption keys\u2026");
    try {
      await this.engine.rotatePassword(oldPassword, newPassword);
      this.updateStatus("synced");
      this.setAutoSync(this.settings.autoSyncMinutes);
      this.engine.requestSync();
    } catch (error) {
      if (this.settings.rememberEncryptionPassword) {
        this.settings.encryptionPassword = oldPassword;
      } else {
        this.sessionPassword = oldPassword;
        this.settings.encryptionPassword = "";
      }
      await this.saveSettings();
      this.updateStatus("error", errorMessage(error));
      new import_obsidian4.Notice(`E2EE Sync: rotation failed \u2014 ${errorMessage(error)}`, 12e3);
    }
  }
  /** Engine callback: verifiers of unknown keys exist — the password changed elsewhere. */
  async promptForChangedPassword(reason) {
    const app = this.app;
    const title = reason === "changed" ? "E2EE Sync: the E2EE password was changed on another device" : "E2EE Sync: this E2EE password does not match the vault";
    return new Promise((resolve) => {
      new class extends import_obsidian4.Modal {
        constructor() {
          super(app);
        }
        onOpen() {
          this.titleEl.setText(title);
          this.contentEl.createEl("p", {
            text: "Enter the current E2EE password to unlock sync for this vault. Nothing is uploaded until the password is confirmed against the server verifier."
          });
          const input = this.contentEl.createEl("input", { type: "password" });
          input.placeholder = "Current E2EE password";
          const row = this.contentEl.createEl("div", { cls: "modal-button-container" });
          const cancel = row.createEl("button", { text: "Not now" });
          const unlock = row.createEl("button", { text: "Unlock sync", cls: "mod-cta" });
          const submit = () => {
            this.close();
            resolve(input.value || null);
          };
          cancel.onclick = () => {
            this.close();
            resolve(null);
          };
          unlock.onclick = submit;
          input.addEventListener("keydown", (evt) => {
            if (evt.key === "Enter") submit();
          });
          window.setTimeout(() => input.focus(), 50);
        }
        onClose() {
          super.onClose();
        }
      }().open();
    });
  }
  // ------------------------------------------------------------- syncing
  requestManualSync() {
    if (!this.settings.serverUrl || !this.settings.apiToken) {
      new import_obsidian4.Notice("E2EE Sync: set the server URL and API token in the plugin settings first.", 6e3);
      return;
    }
    if (!this.effectivePassword) {
      this.promptForSessionPassword();
      return;
    }
    void this.engine.runFullSync(true);
  }
  /** PROB-10: verify every remote entry (hash + decryptability), offer repair. */
  async runIntegrityCheck() {
    if (!this.settings.serverUrl || !this.settings.apiToken || !this.effectivePassword) {
      new import_obsidian4.Notice("E2EE Sync: configure the plugin before verifying integrity.", 6e3);
      return;
    }
    this.updateStatus("syncing", "verifying vault integrity\u2026");
    const report = await this.engine.verifyIntegrity();
    if (!report) {
      this.updateStatus("error", "integrity verification failed");
      return;
    }
    const issues = [...report.hashMismatch, ...report.decryptFailed];
    if (issues.length === 0 && report.failures.length === 0) {
      this.updateStatus("synced");
      new import_obsidian4.Notice(
        `\u2705 E2EE Sync: integrity verified \u2014 ${report.checked} file(s) checked, no problems found.`,
        8e3
      );
      return;
    }
    this.updateStatus("error", `${issues.length} integrity problem(s)`);
    new IntegrityReportModal(
      this.app,
      report.hashMismatch,
      report.decryptFailed,
      report.failures.map((f) => `${f.path} \u2014 ${f.error}`),
      async (repair) => {
        if (!repair) return;
        this.updateStatus("syncing", "repairing\u2026");
        const { repaired, skipped } = await this.engine.repairPaths(issues);
        this.updateStatus(repaired.length > 0 ? "synced" : "error");
        new import_obsidian4.Notice(
          `E2EE Sync: repaired ${repaired.length} file(s) from local copies` + (skipped.length > 0 ? `; ${skipped.length} skipped (no intact local copy: ${skipped.slice(0, 3).join(", ")}\u2026)` : "."),
          12e3
        );
      }
    ).open();
  }
  /** Ask for the password when session-only mode has nothing in memory. */
  promptForSessionPassword() {
    if (this.settings.rememberEncryptionPassword || this.sessionPassword) return;
    new PasswordPromptModal(this.app, (password) => {
      if (!password) {
        this.updateStatus("error", "E2EE password not entered (session-only mode)");
        return;
      }
      this.sessionPassword = password;
      this.setAutoSync(this.settings.autoSyncMinutes);
      this.engine.requestSync();
    }).open();
  }
  /**
   * IMP-4: explicit fresh-clone path — wipe this device's journal and pull
   * every live file. The engine reports the dry-run count into the dialog.
   */
  async runRestoreFromServer() {
    if (!this.settings.serverUrl || !this.settings.apiToken || !this.effectivePassword) {
      new import_obsidian4.Notice("E2EE Sync: configure the plugin before restoring.", 6e3);
      return;
    }
    this.updateStatus("syncing", "preparing restore\u2026");
    const result = await this.engine.restoreFromServer(
      async (liveCount) => confirmDialog(
        this.app,
        "E2EE Sync: restore from server?",
        `The server holds ${liveCount} file(s). This wipes this device's sync journal and re-downloads everything from scratch. Local files are never deleted \u2014 files that already exist are overwritten with the server copy, and files the server does not have stay where they are. Use this on a new or broken device.`,
        "Restore now"
      )
    );
    if (!result) return;
    new import_obsidian4.Notice(
      `E2EE Sync: restore finished \u2014 ${result.pulled} file(s) downloaded` + (result.failures > 0 ? `, ${result.failures} failed.` : "."),
      1e4
    );
  }
  /** (Re)install the periodic sync timer; minutes <= 0 disables it. */
  setAutoSync(minutes) {
    if (this.autoSyncTimer !== null) {
      window.clearInterval(this.autoSyncTimer);
      this.autoSyncTimer = null;
    }
    const m = Math.min(Math.max(Math.floor(minutes), 0), 1440);
    if (m <= 0 || !this.isConfigured()) return;
    this.autoSyncTimer = window.setInterval(
      () => this.engine.requestSync(),
      m * 6e4
    );
  }
  isConfigured() {
    const s = this.settings;
    return Boolean(s.serverUrl && s.apiToken && this.effectivePassword);
  }
  onLayoutReady() {
    this.registerEvent(
      this.app.vault.on("create", (file) => {
        if (file instanceof import_obsidian4.TFile) this.engine.onLocalCreated(file.path);
      })
    );
    this.registerEvent(
      this.app.vault.on("modify", (file) => {
        if (file instanceof import_obsidian4.TFile) this.engine.onLocalModified(file.path);
      })
    );
    this.registerEvent(
      this.app.vault.on("delete", (file) => {
        if (file instanceof import_obsidian4.TFile) this.engine.onLocalDeleted(file.path);
      })
    );
    this.registerEvent(
      this.app.vault.on("rename", (file, oldPath) => {
        if (file instanceof import_obsidian4.TFile) this.engine.onLocalRenamed(oldPath, file.path);
      })
    );
    if (this.settings.serverUrl && this.settings.apiToken) {
      if (!this.effectivePassword && !this.settings.rememberEncryptionPassword) {
        this.promptForSessionPassword();
        return;
      }
      this.setAutoSync(this.settings.autoSyncMinutes);
      const timer = window.setTimeout(() => {
        this.oneShotTimers.delete(timer);
        this.engine.requestSync();
      }, STARTUP_SYNC_DELAY_MS);
      this.oneShotTimers.add(timer);
    }
  }
  // ------------------------------------------------------------- status ui
  /**
   * IMP-3: live cycle progress in the status bar (and the ribbon label, since
   * the status bar is hidden on mobile) while the engine is mid-run. The
   * status class stays 'syncing'; the next updateStatus() call resets the text.
   */
  showProgress(progress) {
    const text = formatProgress(progress);
    if (this.statusBarEl) this.statusBarEl.setText(`E2EE Sync: ${text}`);
    if (this.ribbonEl) this.ribbonEl.setAttribute("aria-label", `E2EE Sync: ${text}`);
  }
  updateStatus(status, message) {
    const icons = {
      idle: "refresh-cw",
      syncing: "refresh-cw",
      synced: "check",
      error: "alert-triangle",
      offline: "cloud-off"
    };
    const labels = {
      idle: "idle",
      syncing: "syncing\u2026",
      synced: "synced",
      error: "error",
      offline: "offline"
    };
    if (this.ribbonEl) {
      (0, import_obsidian4.setIcon)(this.ribbonEl, icons[status]);
      this.ribbonEl.className = `clickable-icon ribbon-clickable e2ee-ribbon-${status}`;
      this.ribbonEl.setAttribute("aria-label", `E2EE Sync: ${message != null ? message : labels[status]}`);
    }
    if (this.statusBarEl) {
      this.statusBarEl.setText(`E2EE Sync: ${labels[status]}`);
      this.statusBarEl.className = `status-bar-item e2ee-${status}`;
      if (message) this.statusBarEl.setAttribute("aria-label", message);
    }
    if ((status === "error" || status === "offline") && message && message !== this.lastErrorNotice) {
      this.lastErrorNotice = message;
      new import_obsidian4.Notice(`E2EE Sync: ${message}`, 8e3);
    }
    if (status === "syncing") this.lastErrorNotice = "";
  }
};
