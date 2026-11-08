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
  /** 16-hex key id of the encrypting key ('' for pre-v3 entries and tombstones). */
  keyId?: string;
  /** Server-echoed per-file version counter (0 for pre-v3 entries and tombstones). */
  ver?: number;
  /** File manifest hash for chunk-assembled blobs ('' for single-shot files). */
  manifest?: string;
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
  /**
   * Last authenticated per-file version counter seen for this path (packet v3).
   * A remote packet with a lower counter is a server-side rollback and is
   * refused. 0 = never seen a v3 packet for this path.
   */
  remoteVersion: number;
  /**
   * IMP-1 (opt-in Markdown auto-merge): plaintext of the last synced copy of
   * this .md note — the merge base for three-way conflict resolution. Stored
   * ONLY while enableMarkdownAutoMerge is on (plaintext at rest in data.json);
   * purged from every record when the toggle is off.
   */
  basePlain?: string;
  /**
   * IMP-5: set while the path matches the user's ignore patterns. Ignored
   * records keep their history but plan no operations — ignoring never
   * deletes; the server entry is left untouched.
   */
  ignored?: boolean;
  /**
   * IMP-7: plaintext chunk hashes (hex) of the last content-defined-chunking
   * upload of this file — the delta-planning primitive. Capped at 2048
   * chunks (~128 MiB at the 64 KiB average) to bound journal size; absent
   * for single-shot uploads and over-cap files.
   */
  baseChunkHashes?: string[];
}

export type SyncStatus = 'idle' | 'syncing' | 'synced' | 'error' | 'offline';

/**
 * IMP-6: per-group allowlist of the hidden configuration folder
 * (.obsidian/). Device-local, dangerous-to-propagate entries are excluded by
 * default; everything outside the known groups never syncs.
 */
export interface ConfigSyncSettings {
  /** Master switch — off by default. */
  enabled: boolean;
  /** appearance.json */
  appearance: boolean;
  /** app.json */
  app: boolean;
  /** hotkeys.json */
  hotkeys: boolean;
  /** snippets/ */
  snippets: boolean;
  /** themes/ */
  themes: boolean;
  /** plugins/<id>/{main.js,manifest.json,styles.css} */
  pluginCode: boolean;
  /** plugins/<id>/data.json — device-local by default (opt in deliberately). */
  pluginData: boolean;
  /** workspace.json — device-local by default (opt in deliberately). */
  workspace: boolean;
}

export const DEFAULT_CONFIG_SYNC: ConfigSyncSettings = {
  enabled: false,
  appearance: true,
  app: true,
  hotkeys: true,
  snippets: true,
  themes: true,
  pluginCode: true,
  pluginData: false,
  workspace: false,
};

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
  /**
   * IMP-1: opt-in automatic three-way merge of Markdown conflicts. OFF by
   * default — when on, the last synced copy of each .md note is stored as
   * merge base (plaintext) in this plugin's data.json.
   */
  enableMarkdownAutoMerge: boolean;
  /**
   * IMP-5: newline-separated glob patterns of vault paths that must never
   * sync. Merged with the vault-root `.syncignore` file at every cycle.
   */
  ignorePatterns: string;
  /** IMP-6: hidden-configuration (.obsidian/) sync groups. */
  configSync: ConfigSyncSettings;
  /**
   * IMP-8: skip automatic syncs while the device reports a metered
   * connection. Only effective where the platform exposes a trustworthy
   * connection type (Android WebView); iOS does not and is never blocked.
   */
  wifiOnly: boolean;
}

export const DEFAULT_SETTINGS: PluginSettings = {
  serverUrl: '',
  apiToken: '',
  encryptionPassword: '',
  autoSyncMinutes: 5,
  rememberEncryptionPassword: true,
  enableMarkdownAutoMerge: false,
  ignorePatterns: '',
  configSync: DEFAULT_CONFIG_SYNC,
  wifiOnly: false,
};

/** Shape of the plugin's persisted data.json. */
export interface PluginData {
  settings?: Partial<PluginSettings>;
  journal?: Record<string, SyncRecord>;
  /** IMP-6: separate journal section for the config/ server namespace. */
  configJournal?: Record<string, SyncRecord>;
}
