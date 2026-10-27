/** Shared types for the E2EE sync plugin. */

/** One entry of the server-side index (`GET /api/index`). */
export interface RemoteFileInfo {
  /** Server-side mtime (ms since epoch). For tombstones this is the deletion time. */
  mtime: number;
  /** Ciphertext size in bytes. 0 for tombstones. */
  size: number;
  /** Hex SHA-256 of the ciphertext. Empty string for tombstones. */
  hash: string;
  /** True when the file was deleted on another device (tombstone). */
  deleted: boolean;
}

/** Response of `GET /api/index`. */
export interface RemoteIndex {
  files: Record<string, RemoteFileInfo>;
}

/** Response of `GET /api/meta`. */
export interface ServerMeta {
  vaultId: string;
}

/**
 * Local sync journal entry: what the file looked like locally and remotely at
 * the moment of the last successful sync of that path. Stored in data.json.
 */
export interface SyncRecord {
  /** Local mtime right after the last sync of this file. */
  localMtime: number;
  /** Ciphertext hash the server had at that time. */
  remoteHash: string;
  /** Server mtime at that time. */
  remoteMtime: number;
}

export type SyncStatus = 'idle' | 'syncing' | 'synced' | 'error' | 'offline';

export interface PluginSettings {
  /** Base URL of the sync server, e.g. https://sync.example.com */
  serverUrl: string;
  /** Bearer token for the server. */
  apiToken: string;
  /**
   * E2EE password. Never leaves this device. When rememberEncryptionPassword
   * is false this stays empty on disk and the live value is kept in memory
   * only (re-entered once per app session).
   */
  encryptionPassword: string;
  /** Periodic sync interval in minutes; 0 disables automatic syncing. */
  autoSyncMinutes: number;
  /** When false, the password is held in memory only, never in data.json. */
  rememberEncryptionPassword: boolean;
}

export const DEFAULT_SETTINGS: PluginSettings = {
  serverUrl: '',
  apiToken: '',
  encryptionPassword: '',
  autoSyncMinutes: 5,
  rememberEncryptionPassword: true,
};

/** Shape of the plugin's persisted data.json. */
export interface PluginData {
  settings?: Partial<PluginSettings>;
  journal?: Record<string, SyncRecord>;
}
