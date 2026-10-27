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
    const isLocal =
      host === 'localhost' || host === '127.0.0.1' || host === '[::1]' || host.endsWith('.local');
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

    if (response.status < 200 || response.status >= 300) {
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

  /** Full server state, including tombstones. */
  async getIndex(): Promise<RemoteIndex> {
    const index = this.parseJson<RemoteIndex>(
      await this.request('GET', this.buildUrl('/api/index')),
    );
    if (!index || typeof index !== 'object' || !index.files) {
      throw new ApiError('Server index response is missing the "files" map.', 0);
    }
    return index;
  }

  /**
   * Upload an encrypted packet. Metadata travels in headers (URL-encoded path)
   * so the body stays pure binary — no multipart overhead.
   */
  async upload(
    path: string,
    ciphertext: ArrayBuffer,
    clientMtime: number,
    cipherHash: string,
  ): Promise<RemoteFileInfo> {
    const response = await this.request('POST', this.buildUrl('/api/upload'), {
      body: ciphertext,
      headers: {
        'X-File-Path': encodeURIComponent(path),
        'X-Client-Mtime': String(Math.floor(clientMtime)),
        'X-Cipher-Hash': cipherHash,
      },
    });
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
    const [meta, index] = await Promise.all([this.getMeta(), this.getIndex()]);
    const live = Object.values(index.files).filter((f) => f && !f.deleted).length;
    return { fileCount: live, vaultId: meta.vaultId };
  }
}
