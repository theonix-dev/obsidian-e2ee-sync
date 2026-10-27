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
    const isLocal = host === "localhost" || host === "127.0.0.1" || host === "[::1]" || host.endsWith(".local");
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
    if (response.status < 200 || response.status >= 300) {
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
  /** Full server state, including tombstones. */
  async getIndex() {
    const index = this.parseJson(
      await this.request("GET", this.buildUrl("/api/index"))
    );
    if (!index || typeof index !== "object" || !index.files) {
      throw new ApiError('Server index response is missing the "files" map.', 0);
    }
    return index;
  }
  /**
   * Upload an encrypted packet. Metadata travels in headers (URL-encoded path)
   * so the body stays pure binary — no multipart overhead.
   */
  async upload(path, ciphertext, clientMtime, cipherHash) {
    const response = await this.request("POST", this.buildUrl("/api/upload"), {
      body: ciphertext,
      headers: {
        "X-File-Path": encodeURIComponent(path),
        "X-Client-Mtime": String(Math.floor(clientMtime)),
        "X-Cipher-Hash": cipherHash
      }
    });
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
    const [meta, index] = await Promise.all([this.getMeta(), this.getIndex()]);
    const live = Object.values(index.files).filter((f) => f && !f.deleted).length;
    return { fileCount: live, vaultId: meta.vaultId };
  }
};

// src/crypto.ts
var PBKDF2_ITERATIONS = 21e4;
var SALT_BYTES = 16;
var IV_BYTES = 12;
var MIN_PACKET_BYTES = SALT_BYTES + IV_BYTES + 16;
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
function toHex(bytes) {
  const digits = "0123456789abcdef";
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += digits[bytes[i] >> 4] + digits[bytes[i] & 15];
  }
  return out;
}
async function sha256Hex(data) {
  const input = data instanceof Uint8Array ? copyBuffer(data) : data;
  const digest = await subtle().digest("SHA-256", input);
  return toHex(new Uint8Array(digest));
}
async function deriveKey(password, salt, iterations = PBKDF2_ITERATIONS) {
  if (salt.length !== SALT_BYTES) {
    throw new CryptoError(`Salt must be exactly ${SALT_BYTES} bytes.`);
  }
  const s = subtle();
  const material = await s.importKey(
    "raw",
    copyBuffer(new TextEncoder().encode(password)),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return s.deriveKey(
    { name: "PBKDF2", salt: copyBuffer(salt), iterations, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    // non-extractable: the raw key bytes can never leave Web Crypto
    ["encrypt", "decrypt"]
  );
}
async function saltFromVaultId(vaultId) {
  const digest = await subtle().digest(
    "SHA-256",
    copyBuffer(new TextEncoder().encode(vaultId))
  );
  return new Uint8Array(digest).slice(0, SALT_BYTES);
}
async function encryptBuffer(plaintext, key, salt) {
  if (salt.length !== SALT_BYTES) {
    throw new CryptoError(`Salt must be exactly ${SALT_BYTES} bytes.`);
  }
  const iv = window.crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ciphertext = new Uint8Array(
    await subtle().encrypt({ name: "AES-GCM", iv }, key, plaintext)
  );
  const packet = new Uint8Array(SALT_BYTES + IV_BYTES + ciphertext.length);
  packet.set(salt, 0);
  packet.set(iv, SALT_BYTES);
  packet.set(ciphertext, SALT_BYTES + IV_BYTES);
  return packet.buffer;
}
async function decryptBuffer(packet, keyForSalt) {
  if (packet.byteLength < MIN_PACKET_BYTES) {
    throw new CryptoError("Encrypted packet is truncated or corrupt.");
  }
  const bytes = new Uint8Array(packet);
  const salt = bytes.slice(0, SALT_BYTES);
  const iv = bytes.slice(SALT_BYTES, SALT_BYTES + IV_BYTES);
  const ciphertext = bytes.slice(SALT_BYTES + IV_BYTES);
  const key = await keyForSalt(salt);
  try {
    return await subtle().decrypt(
      { name: "AES-GCM", iv: copyBuffer(iv) },
      key,
      copyBuffer(ciphertext)
    );
  } catch (e) {
    throw new CryptoError(
      "Decryption failed \u2014 wrong E2EE password or corrupted file."
    );
  }
}
var CryptoManager = class {
  constructor(password) {
    this.password = password;
    this.cache = /* @__PURE__ */ new Map();
  }
  async keyForSalt(salt) {
    const id = toHex(salt);
    let key = this.cache.get(id);
    if (!key) {
      key = await deriveKey(this.password, salt);
      this.cache.set(id, key);
    }
    return key;
  }
  async encrypt(plaintext, salt) {
    return encryptBuffer(plaintext, await this.keyForSalt(salt), salt);
  }
  async decrypt(packet) {
    return decryptBuffer(packet, (salt) => this.keyForSalt(salt));
  }
};

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
function isLocalHost(hostname) {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]" || hostname.endsWith(".local");
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
var EXCLUDED_PREFIXES = [".obsidian/", ".trash/"];
function isSyncablePath(p) {
  for (const prefix of EXCLUDED_PREFIXES) {
    if (p === prefix.slice(0, -1) || p.startsWith(prefix)) return false;
  }
  return true;
}
var SyncEngine = class {
  constructor(ctx) {
    this.ctx = ctx;
    this.api = null;
    this.apiSignature = "";
    this.crypto = null;
    this.cryptoPassword = "";
    this.vaultId = "";
    this.salt = null;
    /** Paths we are writing ourselves; vault events for them are ignored. */
    this.ignorePaths = /* @__PURE__ */ new Set();
    /** Per-path debounce timers, keyed by path. */
    this.debounces = /* @__PURE__ */ new Map();
    /** All pending raw timer ids so dispose() can clear everything. */
    this.pendingTimers = /* @__PURE__ */ new Set();
    this.running = false;
    this.rerunRequested = false;
    this.journalOpsSinceFlush = 0;
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
    const oldSyncable = isSyncablePath(oldPath);
    const newSyncable = isSyncablePath(newPath);
    if (oldSyncable) this.onLocalTouched(oldPath);
    if (newSyncable) this.onLocalTouched(newPath);
  }
  onLocalTouched(path) {
    if (!isSyncablePath(path) || this.ignorePaths.has(path)) return;
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
  async runFullSync() {
    var _a;
    if (this.running) {
      this.rerunRequested = true;
      return null;
    }
    this.running = true;
    try {
      const settings = this.ctx.getSettings();
      if (!settings.serverUrl || !settings.apiToken || !settings.encryptionPassword) {
        this.ctx.setStatus("error", "not configured (see plugin settings)");
        this.ctx.notify("E2EE Sync: set server URL, API token and E2EE password in the plugin settings first.");
        return null;
      }
      const setup = await this.ensureSetup();
      this.ctx.setStatus("syncing");
      const remoteIndex = await setup.api.getIndex();
      const remote = (_a = remoteIndex.files) != null ? _a : {};
      const locals = this.collectLocalFiles();
      const journal = this.ctx.getJournal();
      const plan = this.planSync(locals, remote, journal);
      const summary = await this.executePlan(plan, setup);
      await this.flushJournal(true);
      this.ctx.setStatus(
        summary.failures.length === 0 ? "synced" : "error",
        summary.failures.length === 0 ? void 0 : `${summary.failures.length} file(s) failed`
      );
      if (summary.conflicts > 0 || summary.failures.length > 0) {
        const parts = [
          `${summary.pushed} pushed`,
          `${summary.pulled} pulled`,
          `${summary.conflicts} conflicts`,
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
  collectLocalFiles() {
    const out = /* @__PURE__ */ new Map();
    for (const file of this.ctx.app.vault.getFiles()) {
      if (isSyncablePath(file.path)) out.set(file.path, file);
    }
    return out;
  }
  /** Pure decision function — no I/O, straightforward to reason about. */
  planSync(locals, remote, journal) {
    const paths = /* @__PURE__ */ new Set([
      ...locals.keys(),
      ...Object.keys(journal),
      ...Object.keys(remote)
    ]);
    const ops = [];
    for (const path of paths) {
      if (!isSyncablePath(path)) continue;
      const local = locals.get(path);
      const record = journal[path];
      const rem = remote[path];
      if (rem && !rem.deleted) {
        const remoteChanged = !record || rem.hash !== record.remoteHash;
        if (local) {
          const localChanged = !record || local.stat.mtime > record.localMtime;
          if (localChanged && remoteChanged) {
            if (record) {
              ops.push({ action: "conflict", path, local, remote: rem });
            } else if (rem.mtime >= local.stat.mtime) {
              ops.push({ action: "pull", path, local, remote: rem });
            } else {
              ops.push({ action: "push", path, local, remote: rem });
            }
          } else if (localChanged) {
            ops.push({ action: "push", path, local });
          } else if (remoteChanged) {
            ops.push({ action: "pull", path, local, remote: rem });
          }
        } else if (record && !remoteChanged) {
          ops.push({ action: "delete-remote", path, remote: rem });
        } else {
          ops.push({ action: "pull", path, remote: rem });
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
  // ------------------------------------------------------------ execution
  async executePlan(plan, setup) {
    const summary = {
      pushed: 0,
      pulled: 0,
      conflicts: 0,
      deletedLocal: 0,
      deletedRemote: 0,
      failures: []
    };
    for (const op of plan) {
      try {
        switch (op.action) {
          case "forget":
            this.ctx.setJournalEntry(op.path, null);
            this.markJournalDirty();
            break;
          case "push":
            await this.doPush(op.path, setup, summary);
            break;
          case "pull":
            await this.doPull(op, setup, summary);
            break;
          case "conflict":
            await this.doConflict(op, setup, summary);
            break;
          case "delete-local":
            await this.doDeleteLocal(op.path, summary);
            break;
          case "delete-remote":
            await this.doDeleteRemote(op, setup, summary);
            break;
        }
      } catch (error) {
        summary.failures.push({ path: op.path, error: errorMessage(error) });
      }
    }
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
  async doPush(path, setup, summary) {
    const file = this.ctx.app.vault.getAbstractFileByPath(path);
    if (!(file instanceof import_obsidian2.TFile)) return;
    const plaintext = await this.ctx.app.vault.readBinary(file);
    const packet = await setup.crypto.encrypt(plaintext, setup.salt);
    const cipherHash = await sha256Hex(packet);
    const uploaded = await setup.api.upload(path, packet, file.stat.mtime, cipherHash);
    this.ctx.setJournalEntry(path, {
      localMtime: file.stat.mtime,
      remoteHash: uploaded && uploaded.hash ? uploaded.hash : cipherHash,
      remoteMtime: uploaded && uploaded.mtime ? uploaded.mtime : Date.now()
    });
    this.markJournalDirty();
    summary.pushed++;
  }
  /** Download, decrypt and write one remote file; then update its journal. */
  async doPull(op, setup, summary) {
    const remote = op.remote;
    if (!remote) throw new Error("Pull planned without remote metadata.");
    let packet;
    try {
      packet = await setup.api.download(op.path);
    } catch (error) {
      if (error instanceof ApiError && error.status === 404) {
        this.ctx.setJournalEntry(op.path, null);
        this.markJournalDirty();
        return;
      }
      throw error;
    }
    const plaintext = await setup.crypto.decrypt(packet);
    const existing = this.ctx.app.vault.getAbstractFileByPath(op.path);
    if (existing && !(existing instanceof import_obsidian2.TFile)) {
      throw new Error(`Local path exists but is a folder: ${op.path}`);
    }
    this.beginIgnore(op.path);
    try {
      if (existing) {
        await this.ctx.app.vault.modifyBinary(existing, plaintext);
      } else {
        await this.ensureParentFolder(op.path);
        await this.ctx.app.vault.createBinary(op.path, plaintext);
      }
    } catch (error) {
      this.ignorePaths.delete(op.path);
      throw error;
    }
    const written = this.ctx.app.vault.getAbstractFileByPath(op.path);
    this.ctx.setJournalEntry(op.path, {
      localMtime: written instanceof import_obsidian2.TFile ? written.stat.mtime : Date.now(),
      remoteHash: remote.hash,
      remoteMtime: remote.mtime
    });
    this.markJournalDirty();
    summary.pulled++;
  }
  /**
   * "Keep both" conflict resolution:
   *  1. copy the local version to <name>_conflict_<timestamp>.<ext> and push
   *     that copy immediately (it must not depend on a later sync cycle),
   *  2. download the remote version into the original path.
   */
  async doConflict(op, setup, summary) {
    const local = op.local;
    if (!local) return;
    const conflictPath = this.uniqueConflictPath(op.path);
    const localCopy = await this.ctx.app.vault.readBinary(local);
    this.beginIgnore(conflictPath);
    try {
      await this.ctx.app.vault.createBinary(conflictPath, localCopy);
    } catch (error) {
      this.ignorePaths.delete(conflictPath);
      throw error;
    }
    await this.doPush(conflictPath, setup, summary);
    await this.doPull({ ...op, local: void 0 }, setup, summary);
    summary.conflicts++;
    this.ctx.notify(
      `Conflict detected in file: ${op.path}
Both versions kept \u2014 local copy saved as: ${conflictPath}`,
      1e4
    );
  }
  async doDeleteLocal(path, summary) {
    const file = this.ctx.app.vault.getAbstractFileByPath(path);
    if (file instanceof import_obsidian2.TFile) {
      this.beginIgnore(path);
      try {
        await this.ctx.app.vault.trash(file, true);
      } catch (error) {
        this.ignorePaths.delete(path);
        throw error;
      }
    }
    this.ctx.setJournalEntry(path, null);
    this.markJournalDirty();
    summary.deletedLocal++;
  }
  async doDeleteRemote(op, setup, summary) {
    try {
      await setup.api.deleteFile(op.path);
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
  // ------------------------------------------------------------- plumbing
  async ensureSetup() {
    const settings = this.ctx.getSettings();
    const signature = `${settings.serverUrl}\0${settings.apiToken}`;
    if (!this.api || this.apiSignature !== signature) {
      this.api = new SyncApi(settings.serverUrl, settings.apiToken);
      this.apiSignature = signature;
    }
    const meta = await this.api.getMeta();
    if (!this.crypto || this.cryptoPassword !== settings.encryptionPassword || this.vaultId !== meta.vaultId) {
      this.salt = await saltFromVaultId(meta.vaultId);
      this.crypto = new CryptoManager(settings.encryptionPassword);
      this.cryptoPassword = settings.encryptionPassword;
      this.vaultId = meta.vaultId;
    }
    const salt = this.salt;
    if (!salt || !this.crypto) throw new Error("Crypto setup failed unexpectedly.");
    return { api: this.api, crypto: this.crypto, salt };
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
      await this.ctx.app.vault.createFolder(current);
    }
  }
  conflictStamp(d = /* @__PURE__ */ new Date()) {
    const pad = (n) => String(n).padStart(2, "0");
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}_${pad(d.getHours())}-${pad(d.getMinutes())}-${pad(d.getSeconds())}`;
  }
  /** filename.md -> filename_conflict_YYYY-MM-DD_HH-mm-ss.md */
  uniqueConflictPath(original) {
    const slash = original.lastIndexOf("/");
    const dir = slash >= 0 ? original.slice(0, slash + 1) : "";
    const name = slash >= 0 ? original.slice(slash + 1) : original;
    const dot = name.lastIndexOf(".");
    const base = dot > 0 ? name.slice(0, dot) : name;
    const ext = dot > 0 ? name.slice(dot) : "";
    let candidate = `${dir}${base}_conflict_${this.conflictStamp()}${ext}`;
    let attempt = 2;
    while (this.ctx.app.vault.getAbstractFileByPath(candidate)) {
      candidate = `${dir}${base}_conflict_${this.conflictStamp()}_${attempt++}${ext}`;
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
var E2eeSyncSettingTab = class extends import_obsidian3.PluginSettingTab {
  constructor(app, plugin) {
    super(app, plugin);
    this.plugin = plugin;
  }
  display() {
    var _a;
    const { containerEl } = this;
    containerEl.empty();
    const s = this.plugin.settings;
    let initialPassword = s.encryptionPassword;
    containerEl.createEl("h2", { text: "E2EE Vault Sync" });
    const intro = containerEl.createEl("p", {
      cls: "e2ee-setting-note"
    });
    intro.setText(
      "Files are encrypted on this device (AES-256-GCM, PBKDF2-derived key) before they are uploaded. The server only ever stores ciphertext. File contents never leave this device unencrypted \u2014 but note that file paths, sizes and timestamps are visible to the server."
    );
    const urlWarning = containerEl.createEl("div", { cls: "e2ee-setting-warning" });
    new import_obsidian3.Setting(containerEl).setName("Server URL").setDesc("Base URL of your sync server, e.g. https://sync.example.com").addText(
      (text) => text.setPlaceholder("https://sync.example.com").setValue(s.serverUrl).onChange(async (value) => {
        s.serverUrl = value.trim();
        const problem = validateServerUrl(s.serverUrl);
        urlWarning.setText(problem != null ? problem : "");
        await this.plugin.saveSettings();
      })
    );
    urlWarning.setText((_a = validateServerUrl(s.serverUrl)) != null ? _a : "");
    new import_obsidian3.Setting(containerEl).setName("API token").setDesc("Bearer token configured on the server (AUTH_TOKEN).").addText((text) => {
      text.inputEl.type = "password";
      text.setPlaceholder("paste the token");
      return text.setValue(s.apiToken).onChange(async (value) => {
        s.apiToken = value.trim();
        await this.plugin.saveSettings();
      });
    });
    new import_obsidian3.Setting(containerEl).setName("E2EE password").setDesc(
      "Used to derive the encryption key (PBKDF2, 210 000 iterations). Never sent to the server. All devices syncing this vault must use the same password. Changing it re-encrypts and re-uploads every file on the next sync."
    ).addText((text) => {
      text.inputEl.type = "password";
      return text.setValue(s.encryptionPassword).onChange(async (value) => {
        s.encryptionPassword = value;
        await this.plugin.saveSettings();
        if (value !== initialPassword) {
          initialPassword = value;
          await this.plugin.onEncryptionPasswordChanged();
        }
      });
    });
    new import_obsidian3.Setting(containerEl).setName("Auto-sync interval (minutes)").setDesc("Sync automatically every N minutes (1\u20131440). 0 disables periodic sync. Changes also apply immediately.").addText(
      (text) => text.setValue(String(s.autoSyncMinutes)).onChange(async (value) => {
        const minutes = Math.floor(Number(value));
        s.autoSyncMinutes = Number.isFinite(minutes) ? Math.min(Math.max(minutes, 0), 1440) : 0;
        await this.plugin.saveSettings();
        this.plugin.setAutoSync(s.autoSyncMinutes);
      })
    );
    new import_obsidian3.Setting(containerEl).setName("Connection test").setDesc("Checks reachability, the API token and key derivation (GET /api/index).").addButton(
      (button) => button.setButtonText("Test connection").onClick(async () => {
        const btn = button.buttonEl;
        btn.disabled = true;
        btn.setText("Testing\u2026");
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
        } finally {
          btn.disabled = false;
          btn.setText("Test connection");
        }
      })
    );
    new import_obsidian3.Setting(containerEl).setName("Sync now").setDesc("Run a full synchronization cycle immediately.").addButton(
      (button) => button.setButtonText("Sync now").onClick(() => {
        this.plugin.requestManualSync();
      })
    );
    const footer = containerEl.createEl("p", { cls: "e2ee-setting-note" });
    footer.setText(
      'Sync journal: this device remembers the last synced state of every file in its plugin data. Conflicts keep both versions: the remote one keeps the original name, the local one is copied to "<name>_conflict_<timestamp>". The .obsidian/ and .trash/ folders are never synchronized.'
    );
  }
};

// src/types.ts
var DEFAULT_SETTINGS = {
  serverUrl: "",
  apiToken: "",
  encryptionPassword: "",
  autoSyncMinutes: 5
};

// src/main.ts
var STARTUP_SYNC_DELAY_MS = 4e3;
var E2eeSyncPlugin = class extends import_obsidian4.Plugin {
  constructor() {
    super(...arguments);
    this.settings = { ...DEFAULT_SETTINGS };
    this.journal = {};
    this.statusBarEl = null;
    this.ribbonEl = null;
    this.autoSyncTimer = null;
    this.oneShotTimers = /* @__PURE__ */ new Set();
    this.lastErrorNotice = "";
  }
  async onload() {
    var _a, _b, _c;
    const data = (_a = await this.loadData()) != null ? _a : {};
    this.settings = { ...DEFAULT_SETTINGS, ...(_b = data.settings) != null ? _b : {} };
    this.journal = (_c = data.journal) != null ? _c : {};
    this.engine = new SyncEngine({
      app: this.app,
      getSettings: () => this.settings,
      getJournal: () => this.journal,
      setJournalEntry: (path, record) => {
        if (record) this.journal[path] = record;
        else delete this.journal[path];
      },
      persist: () => this.saveData({ settings: this.settings, journal: this.journal }),
      setStatus: (status, message) => this.updateStatus(status, message),
      notify: (message, timeout) => new import_obsidian4.Notice(message, timeout != null ? timeout : 6e3)
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
    this.app.workspace.onLayoutReady(() => this.onLayoutReady());
    this.updateStatus("idle");
  }
  onunload() {
    var _a;
    (_a = this.engine) == null ? void 0 : _a.dispose();
    if (this.autoSyncTimer !== null) window.clearInterval(this.autoSyncTimer);
    for (const t of this.oneShotTimers) window.clearTimeout(t);
    this.oneShotTimers.clear();
  }
  // ------------------------------------------------------------- settings
  async saveSettings() {
    await this.saveData({ settings: this.settings, journal: this.journal });
  }
  /**
   * A changed password means every existing journal record is meaningless (the
   * remote ciphertext was produced with a different key). Reset the journal so
   * the next sync re-encrypts and re-uploads everything from this device.
   */
  async onEncryptionPasswordChanged() {
    this.engine.invalidateCrypto();
    this.journal = {};
    await this.saveSettings();
    new import_obsidian4.Notice(
      "E2EE password changed. Every file will be re-encrypted and re-uploaded on the next sync \u2014 run it first on the device with the most up-to-date vault.",
      12e3
    );
  }
  // ------------------------------------------------------------- syncing
  requestManualSync() {
    void this.engine.runFullSync();
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
    return Boolean(s.serverUrl && s.apiToken && s.encryptionPassword);
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
    if (this.isConfigured()) {
      this.setAutoSync(this.settings.autoSyncMinutes);
      const timer = window.setTimeout(() => {
        this.oneShotTimers.delete(timer);
        this.engine.requestSync();
      }, STARTUP_SYNC_DELAY_MS);
      this.oneShotTimers.add(timer);
    }
  }
  // ------------------------------------------------------------- status ui
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
