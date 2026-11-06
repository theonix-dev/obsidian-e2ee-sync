/**
 * REST client for the VPS sync server.
 *
 * Networking rules for cross-platform compatibility:
 *  - `requestUrl` from the `obsidian` package is used EXCLUSIVELY. It works on
 *    desktop and mobile and bypasses CORS restrictions.
 *  - No Node.js `http`/`https`/`net`, no Electron `net`, no XMLHttpRequest.
 *  - `throw: false` makes requestUrl return non-2xx responses instead of
 *    throwing, so HTTP status handling is fully explicit here.
 *
 * Every request carries `Authorization: Bearer <token>` and is bounded by a
 * manual timeout (requestUrl has none of its own).
 */

import { requestUrl } from 'obsidian';
import type { RequestUrlParam, RequestUrlResponse } from 'obsidian';
import type { RemoteFileInfo, RemoteIndex, ServerMeta } from './types';

const DEFAULT_TIMEOUT_MS = 30_000;
const MAX_ERROR_BODY_CHARS = 200;

export class ApiError extends Error {
  /** HTTP status code; 0/-1 for timeout / network-level failures. */
  readonly status: number;
  /** True when the failure looks like connectivity, not a server response. */
  readonly isNetworkError: boolean;

  constructor(message: string, status: number, isNetworkError = false) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.isNetworkError = isNetworkError;
  }
}

export interface ApiOptions {
  timeoutMs?: number;
}

/** Result of `getIndex` — carries the ETag for conditional requests (PROB-6). */
export interface IndexResult {
  index: RemoteIndex;
  /** ETag returned by the server ('' when none); feed back into getIndex(). */
  etag: string;
  /** True when the server answered 304 Not Modified for the supplied ETag. */
  notModified: boolean;
}

export class SyncApi {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;

  constructor(baseUrl: string, private readonly token: string, options: ApiOptions = {}) {
    this.baseUrl = baseUrl.trim().replace(/\/+$/, '');
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.assertTransportSecurity(this.baseUrl);
  }

  /**
   * Transport-layer HTTPS guard (defense in depth behind the settings-tab
   * validation): the bearer token must never travel over cleartext HTTP to a
   * remote host. Loopback/LAN hosts are exempted for local testing. TLS
   * certificate problems surface as network errors from requestUrl itself.
   */
  private assertTransportSecurity(url: string): void {
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      throw new ApiError(`"${url}" is not a valid URL (include https://).`, 0);
    }
    const host = parsed.hostname;
    // Loopback only: mDNS ".local" names can be spoofed on hostile networks,
    // so they no longer qualify for the cleartext exemption.
    const isLocal = host === 'localhost' || host === '127.0.0.1' || host === '[::1]';
    if (parsed.protocol !== 'https:' && !isLocal) {
      throw new ApiError(
        'HTTPS is required for remote sync servers — refusing to send the API token over cleartext.',
        0,
      );
    }
  }

  // ------------------------------------------------------------- internals

  private buildUrl(endpoint: string, query?: Record<string, string>): string {
    const qs = query
      ? '?' +
        Object.entries(query)
          .map(([k, v]) => `${k}=${encodeURIComponent(v)}`)
          .join('&')
      : '';
    return `${this.baseUrl}${endpoint}${qs}`;
  }

  private async request(
    method: string,
    url: string,
    init: { body?: ArrayBuffer; headers?: Record<string, string> } = {},
  ): Promise<RequestUrlResponse> {
    const headers: Record<string, string> = {
      Authorization: `Bearer ${this.token}`,
      ...(init.headers ?? {}),
    };
    const params: RequestUrlParam = { url, method, headers, throw: false };
    if (init.body !== undefined) {
      params.body = init.body;
      headers['Content-Type'] = 'application/octet-stream';
    }

    let response: RequestUrlResponse;
    try {
      response = await Promise.race([
        requestUrl(params),
        new Promise<never>((_, reject) =>
          window.setTimeout(
            () =>
              reject(
                new ApiError(
                  `Request timed out after ${this.timeoutMs} ms: ${method} ${url}`,
                  0,
                  true,
                ),
              ),
            this.timeoutMs,
          ),
        ),
      ]);
    } catch (error) {
      if (error instanceof ApiError) throw error;
      // requestUrl still rejects on network-level failures (offline, DNS, TLS…).
      throw new ApiError(
        `Network error: ${method} ${url} — ${error instanceof Error ? error.message : String(error)}`,
        -1,
        true,
      );
    }

    // 304 Not Modified is a success for conditional GET /api/index requests.
    if ((response.status < 200 || response.status >= 300) && response.status !== 304) {
      let detail = '';
      try {
        detail = (response.text ?? '').slice(0, MAX_ERROR_BODY_CHARS);
      } catch {
        detail = '';
      }
      throw new ApiError(
        `HTTP ${response.status} on ${method} ${url}${detail ? ` — ${detail}` : ''}`,
        response.status,
      );
    }
    return response;
  }

  private parseJson<T>(response: RequestUrlResponse): T {
    try {
      return JSON.parse(response.text) as T;
    } catch {
      throw new ApiError('Server returned a malformed JSON response.', 0);
    }
  }

  // ------------------------------------------------------------- endpoints

  /** Server metadata (stable vaultId used for the deterministic KDF salt). */
  async getMeta(): Promise<ServerMeta> {
    return this.parseJson(await this.request('GET', this.buildUrl('/api/meta')));
  }

  /**
   * Full server state, including tombstones. When `etag` from a previous
   * response is supplied and the index is unchanged, the server answers 304
   * and `notModified` is true (one cheap request ends an idle sync cycle).
   */
  async getIndex(etag?: string): Promise<IndexResult> {
    const headers: Record<string, string> = {};
    if (etag) headers['If-None-Match'] = etag;
    const response = await this.request('GET', this.buildUrl('/api/index'), { headers });
    if (response.status === 304) {
      return { index: { files: {} }, etag: etag ?? '', notModified: true };
    }
    const index = this.parseJson<RemoteIndex>(response);
    if (!index || typeof index !== 'object' || !index.files) {
      throw new ApiError('Server index response is missing the "files" map.', 0);
    }
    const newEtag = this.responseHeader(response, 'etag') ?? '';
    return { index, etag: newEtag, notModified: false };
  }

  /** Case-insensitive header lookup on a requestUrl response. */
  private responseHeader(response: RequestUrlResponse, name: string): string | null {
    const headers = response.headers as Record<string, string> | undefined;
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
  async upload(
    path: string,
    ciphertext: ArrayBuffer,
    clientMtime: number,
    cipherHash: string,
    meta?: { keyId?: string; fileVersion?: number },
  ): Promise<RemoteFileInfo> {
    const headers: Record<string, string> = {
      'X-File-Path': encodeURIComponent(path),
      'X-Client-Mtime': String(Math.floor(clientMtime)),
      'X-Cipher-Hash': cipherHash,
    };
    if (meta?.keyId) headers['X-Key-Id'] = meta.keyId;
    if (meta?.fileVersion !== undefined) headers['X-File-Version'] = String(meta.fileVersion);
    const response = await this.request('POST', this.buildUrl('/api/upload'), {
      body: ciphertext,
      headers,
    });
    return this.parseJson<RemoteFileInfo>(response);
  }

  // ------------------------------------------------ chunked transport (v3)

  /** Begin a resumable chunked upload; returns the staging upload id. */
  async beginUpload(request: {
    path: string;
    totalBytes: number;
    chunkCount: number;
    fileManifest: string; // 64-hex SHA-256 over the plaintext chunk hashes
  }): Promise<{ uploadId: string }> {
    const response = await this.request('POST', this.buildUrl('/api/upload/begin'), {
      body: new TextEncoder().encode(JSON.stringify(request)).buffer as ArrayBuffer,
      headers: { 'Content-Type': 'application/json' },
    });
    return this.parseJson<{ uploadId: string }>(response);
  }

  /**
   * Upload one encrypted chunk. The server verifies the body against
   * `chunkHash` (SHA-256 of the ciphertext chunk) and stores it as part `n`.
   */
  async uploadChunk(
    uploadId: string,
    n: number,
    chunk: ArrayBuffer,
    chunkHash: string,
  ): Promise<{ accepted: number[] }> {
    const response = await this.request(
      'PUT',
      this.buildUrl('/api/upload/chunk', { uploadId, n: String(n) }),
      { body: chunk, headers: { 'X-Chunk-Hash': chunkHash } },
    );
    return this.parseJson<{ accepted: number[] }>(response);
  }

  /** Which chunk numbers the server already holds — the resume primitive. */
  async uploadStatus(uploadId: string): Promise<{ accepted: number[]; chunkCount: number }> {
    const response = await this.request(
      'GET',
      this.buildUrl('/api/upload/status', { uploadId }),
    );
    return this.parseJson<{ accepted: number[]; chunkCount: number }>(response);
  }

  /** Assemble the staged chunks into the final file and index it. */
  async commitUpload(
    uploadId: string,
    meta: { clientMtime: number; keyId: string; fileVersion: number },
  ): Promise<RemoteFileInfo> {
    const response = await this.request(
      'POST',
      this.buildUrl('/api/upload/commit', { uploadId }),
      {
        headers: {
          'X-Client-Mtime': String(Math.floor(meta.clientMtime)),
          'X-Key-Id': meta.keyId,
          'X-File-Version': String(meta.fileVersion),
        },
      },
    );
    return this.parseJson<RemoteFileInfo>(response);
  }

  /** Download the encrypted packet for a path. */
  async download(path: string): Promise<ArrayBuffer> {
    const response = await this.request('GET', this.buildUrl('/api/download', { path }));
    if (!response.arrayBuffer) {
      throw new ApiError(`Empty body received for ${path}.`, 0);
    }
    return response.arrayBuffer;
  }

  /** Delete a path server-side; the server keeps a tombstone in its index. */
  async deleteFile(path: string): Promise<RemoteFileInfo> {
    const response = await this.request('DELETE', this.buildUrl('/api/delete', { path }));
    return this.parseJson<RemoteFileInfo>(response);
  }

  /** Settings-tab helper: verifies auth + reachability, returns live file count. */
  async testConnection(): Promise<{ fileCount: number; vaultId: string }> {
    const [meta, indexResult] = await Promise.all([this.getMeta(), this.getIndex()]);
    // Internal reserved entries (password verifiers) are not user files.
    const live = Object.entries(indexResult.index.files).filter(
      ([p, f]) => f && !f.deleted && !p.startsWith('.e2ee-'),
    ).length;
    return { fileCount: live, vaultId: meta.vaultId };
  }
}
