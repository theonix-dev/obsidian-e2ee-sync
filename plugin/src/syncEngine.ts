/**
 * Three-way sync engine (packet v3).
 *
 * For every path it compares three states:
 *   Local      — the file as it exists in the vault right now (mtime).
 *   Record     — the local sync journal (what local + remote looked like at
 *                the last successful sync of that path).
 *   Remote     — the server index entry (ciphertext hash, tombstone flag,
 *                version counter, key id).
 *
 * Decisions therefore never rely on comparing local vs. server wall clocks,
 * which makes the engine immune to clock drift between devices:
 *
 *   local changed only  (mtime > record.localMtime, remote hash unchanged)  -> PUSH
 *   remote changed only (hash != record.remoteHash, local mtime unchanged)  -> PULL
 *   both changed                                                            -> CONFLICT
 *     (keep both: local copy -> *_conflict_<timestamp>.<ext>, remote -> original)
 *   remote tombstoned, local untouched                                      -> DELETE LOCAL
 *   remote tombstoned, local modified                                       -> PUSH (resurrect)
 *   local deleted, remote unchanged since record                            -> DELETE REMOTE
 *
 * Renames need no special casing: the generic rules see the old path as
 * "deleted locally, remote unchanged" (tombstone) and the new path as a new
 * local file (push) — exactly DELETE oldPath + UPLOAD newPath.
 *
 * Security invariants against a malicious server:
 *   - Every path is canonicalized to Unicode NFC before it is journaled,
 *     hashed, used as AES-GCM AAD or sent to the server (iOS/macOS produce
 *     NFD filenames; a single canonical form prevents forked entries).
 *   - Downloaded ciphertext is verified against the index hash before it is
 *     decrypted or written (rollback/replay defense).
 *   - Per-key verifiers (.e2ee-verifier.<keyId>) prove this device derives
 *     the same key as the vault's current encryptor BEFORE anything is pushed
 *     (wrong-password devices cannot clobber the store). A verifier belonging
 *     to an unknown key means the password was rotated elsewhere — a
 *     recoverable prompt, not a deadlock (PROB-1).
 *   - Every v3 packet carries an authenticated per-file version counter. A
 *     packet whose counter is lower than the last one recorded in the journal
 *     is a full-state or per-file server rollback and is refused loudly
 *     (PROB-2). The untrusted server cannot forge or strip the counter.
 *   - Mass remote deletions require explicit user confirmation.
 *   - Chunk-assembled blobs are authenticated per chunk against a file
 *     manifest (SHA-256 over the plaintext chunk hashes) — chunks of two
 *     different uploads can never be spliced into one decryptable file.
 */

import { TFile, TFolder, normalizePath } from 'obsidian';
import type { App } from 'obsidian';
import { ApiError, SyncApi } from './api';

// Re-exported so embedders and specs can classify engine failures without a
// second module instance of the api layer.
export { ApiError };
import {
  CryptoError,
  CryptoManager,
  bytesEqual,
  peekV3,
  saltFromVaultId,
  sha256Bytes,
  sha256Hex,
  toHex,
} from './crypto';
import type { PluginSettings, RemoteFileInfo, RemoteIndex, SyncRecord, SyncStatus } from './types';
import { ignoreMatcherFromSources } from './ignore';
import type { IgnoreMatcher } from './ignore';
import { MERGE_MAX_BYTES, merge3 } from './merge';
import type { ProgressLike } from './util';
import { errorMessage } from './util';

/** Per-file debounce window for local vault events (ms). */
const DEBOUNCE_MS = 2500;
/** How long a path stays in the ignore set after our own write (ms). */
const IGNORE_WINDOW_MS = 500;
/** Persist the journal at least every N mutations (plus once per sync run). */
const JOURNAL_FLUSH_EVERY = 20;

/**
 * Reserved server-side paths holding password verifiers. Present in the
 * index but never treated as vault content by any client. One verifier per
 * key id (rotation coexistence, PROB-1) plus the legacy 0.2.0 path.
 */
const VERIFIER_PREFIX = '.e2ee-verifier.';
const VERIFIER_LEGACY_PATH = '.e2ee-sync-verifier.v1';
const VERIFIER_PLAINTEXT = new TextEncoder().encode('e2ee-verifier-v1\u0000');

function verifierPathFor(keyIdHex: string): string {
  return VERIFIER_PREFIX + keyIdHex;
}

function isVerifierPath(p: string): boolean {
  return p === VERIFIER_LEGACY_PATH || p.startsWith(VERIFIER_PREFIX);
}

/** 64-hex string -> 32 bytes (manifest parsing). */
function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * Largest single file the engine will sync — mirrors the server's
 * MAX_FILE_BYTES default (assembled cap of the chunked transport).
 */
const MAX_FILE_BYTES = 2 * 1024 * 1024 * 1024;
/** Files above this size travel through the chunked, resumable path. */
const CHUNKED_ABOVE_BYTES = 16 * 1024 * 1024;
/** Plaintext bytes per chunk on the chunked path (≤ the server's per-request cap). */
const CHUNK_PLAINTEXT_BYTES = 8 * 1024 * 1024;
/** Per-chunk network retries (network-level failures only), with backoff. */
const CHUNK_RETRIES = 2;

/** Vault folders that must never round-trip to the server. */
const EXCLUDED_PREFIXES = ['.trash/'];
/** IMP-5: the device-local ignore policy file itself never syncs. */
export const IGNORE_FILE = '.syncignore';
/** OS-generated junk and device-local policy files that never round-trip. */
const EXCLUDED_NAMES = new Set(['.DS_Store', 'Thumbs.db', 'desktop.ini', IGNORE_FILE]);

/**
 * Single canonical form for journal keys, remote keys, AAD and API
 * transmission: Obsidian's normalizePath (slash/dot cleanup) plus explicit
 * NFC Unicode normalization.
 */
export function canonicalPath(p: string): string {
  return normalizePath(p).normalize('NFC');
}

/**
 * Whether a vault-relative path may sync. `ignores` (IMP-5) carries the
 * user's glob patterns; ignored paths are excluded from every plan and never
 * deleted server-side.
 */
export function isSyncablePath(p: string, configDir: string, ignores?: IgnoreMatcher | null): boolean {
  if (isVerifierPath(p)) return false;
  const name = p.slice(p.lastIndexOf('/') + 1);
  if (EXCLUDED_NAMES.has(name)) return false;
  const prefixes = [`${configDir.replace(/\/+$/, '')}/`, ...EXCLUDED_PREFIXES];
  for (const prefix of prefixes) {
    if (p === prefix.slice(0, -1) || p.startsWith(prefix)) return false;
  }
  if (ignores?.isIgnored(p)) return false;
  return true;
}

export type SyncAction =
  | 'push'
  | 'pull'
  | 'conflict'
  | 'delete-local'
  | 'delete-remote'
  | 'case-rename'
  | 'forget';

/** IMP-2: user's choice for a conflicted file (null = Esc = keep both). */
export type ConflictResolution = 'mine' | 'remote' | 'both' | 'skip';

/** Auto-sync runs ask for at most this many conflicts; the rest batch keep-both. */
const CONFLICT_PROMPT_LIMIT = 5;

export interface SyncSummary {
  pushed: number;
  pulled: number;
  conflicts: number;
  /** IMP-1: conflicts resolved by the opt-in Markdown three-way merge. */
  merged: number;
  /** IMP-2: conflicts the user chose to leave untouched for a later cycle. */
  skipped: number;
  deletedLocal: number;
  deletedRemote: number;
  failures: Array<{ path: string; error: string }>;
}

interface PlannedOp {
  action: SyncAction;
  /** Canonical path — journal key, AAD input and preferred storage key. */
  path: string;
  /** Raw index key for API calls when it differs from the canonical form
   *  (pre-NFC entries uploaded by 0.1.x clients). */
  remoteKey?: string;
  local?: FileStatLike;
  remote?: RemoteFileInfo;
}

/** A remote index entry resolved under its canonical key. */
interface RemoteEntry {
  key: string;
  info: RemoteFileInfo;
}

interface SyncSetup {
  api: SyncApi;
  crypto: CryptoManager;
  salt: Uint8Array;
  keyIdHex: string;
}

export interface EngineContext {
  app: App;
  getSettings: () => PluginSettings;
  getJournal: () => Record<string, SyncRecord>;
  /** record === null removes the entry. */
  setJournalEntry: (path: string, record: SyncRecord | null) => void;
  persist: () => Promise<void>;
  setStatus: (status: SyncStatus, message?: string) => void;
  notify: (message: string, timeout?: number) => void;
  /** Return false to veto a batch of remote-reported deletions (mass-wipe guard). */
  confirmMassDeletion?(deletedCount: number, localCount: number): Promise<boolean>;
  /**
   * The server presented verifiers belonging to a key this device does not
   * know — the E2EE password was changed on another device (or is wrong).
   * Ask the user; resolve with the password to use, or null to abort.
   */
  promptPassword?(reason: 'changed' | 'wrong'): Promise<string | null>;
  /**
   * Test seam: construct the REST client. Production callers omit it and the
   * engine builds SyncApi itself; specs inject a fake server transport.
   */
  createApi?(serverUrl: string, token: string): SyncApi;
  /**
   * IMP-2: ask the user how to resolve a conflicted file. Resolve with the
   * choice, or null for "keep both" (Esc). Omitted => silent keep-both.
   */
  resolveConflict?(path: string): Promise<ConflictResolution | null>;
  /**
   * IMP-3: progress of the running cycle — emitted on every op start/completion
   * and per chunk of large-file uploads. Omitted => no progress UI.
   */
  setProgress?(progress: ProgressLike): void;
}

// ------------------------------------------------------------ pure planner --
// Extracted as pure functions so the exhaustive decision matrix
// (plugin/test/planSync.spec.mjs, PROB-4) can exercise every cell without I/O.

/** Minimal structural stand-in for TFile inside the planner. */
export interface FileStatLike {
  path: string;
  stat: { mtime: number };
}

/**
 * Pure decision function — no I/O. Maps {local, record, remote} triples to
 * planned actions per the decision table in the file header. Additionally
 * guards case-insensitive filesystems: two local paths differing only by
 * ASCII case plan a keep-both rename for the second, and a remote pull whose
 * target collides (case-insensitively) with a different local path is
 * downgraded to a conflict so the local file is never silently overwritten.
 */
export function planSync(
  locals: Map<string, FileStatLike>,
  remote: Map<string, { key: string; info: RemoteFileInfo }>,
  journal: Record<string, SyncRecord>,
  configDir: string,
  ignores?: IgnoreMatcher | null,
): Array<{ action: SyncAction; path: string; remoteKey?: string; local?: FileStatLike; remote?: RemoteFileInfo }> {
  const ops: Array<{
    action: SyncAction;
    path: string;
    remoteKey?: string;
    local?: FileStatLike;
    remote?: RemoteFileInfo;
  }> = [];

  // Local-vs-local case collisions: on case-insensitive filesystems the two
  // spellings are one file; keep-both by renaming the lexicographically later
  // one (never overwrite). A REMOTE path colliding only case-wise with a
  // different local file needs no planner rule: it plans as an ordinary pull
  // and the write-time guard in doPull (findCaseVariant) redirects the write.
  const byLower = new Map<string, string[]>();
  for (const p of locals.keys()) {
    const lower = p.toLowerCase();
    const group = byLower.get(lower) ?? [];
    group.push(p);
    byLower.set(lower, group);
  }
  const caseRenamed = new Set<string>();
  for (const [, group] of byLower) {
    if (group.length < 2) continue;
    group.sort();
    for (const p of group.slice(1)) {
      caseRenamed.add(p);
      ops.push({ action: 'case-rename', path: p, local: locals.get(p) });
    }
  }

  const paths = new Set<string>([
    ...locals.keys(),
    ...Object.keys(journal),
    ...remote.keys(),
  ]);

  for (const path of paths) {
    if (!isSyncablePath(path, configDir, ignores)) continue;
    if (caseRenamed.has(path)) continue; // handled by the rename op above

    const local = locals.get(path);
    const record = journal[path];
    const entry = remote.get(path);
    const rem = entry?.info;
    const remoteKey = entry?.key;

    if (rem && !rem.deleted) {
      // ---- live remote entry -------------------------------------------
      const remoteChanged = !record || rem.hash !== record.remoteHash;
      if (local) {
        const localChanged = !record || local.stat.mtime > record.localMtime;
        if (localChanged && remoteChanged) {
          if (record) {
            ops.push({ action: 'conflict', path, local, remote: rem, remoteKey });
          } else if (rem.mtime >= local.stat.mtime) {
            // Both sides known, never synced on this device (typical when
            // restoring a vault from a backup): newest mtime wins.
            ops.push({ action: 'pull', path, local, remote: rem, remoteKey });
          } else {
            ops.push({ action: 'push', path, local });
          }
        } else if (localChanged) {
          ops.push({ action: 'push', path, local });
        } else if (remoteChanged) {
          ops.push({ action: 'pull', path, local, remote: rem, remoteKey });
        }
        // else: identical on both ends — nothing to do.
      } else if (record && !remoteChanged) {
        // Deleted locally, untouched remotely -> propagate the deletion.
        ops.push({ action: 'delete-remote', path, remote: rem, remoteKey });
      } else {
        // No local copy; either a brand-new device or the file was deleted
        // locally while remotely modified -> remote wins, pull it back.
        ops.push({ action: 'pull', path, remote: rem, remoteKey });
      }
    } else {
      // ---- tombstoned or unknown on the server --------------------------
      if (!local) {
        // Nothing anywhere: drop any stale journal entry. The server
        // tombstone itself is kept for other devices.
        if (record) ops.push({ action: 'forget', path });
        continue;
      }
      const localChanged = !record || local.stat.mtime > record.localMtime;
      if (localChanged) {
        // Deleted on the server but modified here (or untracked here — we
        // never destroy data we cannot vouch for): keep it and re-upload.
        ops.push({ action: 'push', path, local });
      } else {
        // Deleted on another device, untouched here: propagate locally.
        ops.push({ action: 'delete-local', path, local });
      }
    }
  }
  return ops;
}

/**
 * Case-variant lookup used at write time: a remote path whose ASCII-case
 * variant is occupied by a DIFFERENT local file must never be written under
 * its own name on case-insensitive filesystems.
 */
export function findCaseVariant(path: string, localPaths: Iterable<string>): string | null {
  const lower = path.toLowerCase();
  for (const p of localPaths) {
    if (p !== path && p.toLowerCase() === lower) return p;
  }
  return null;
}

/**
 * PROB-2 decision: does an authenticated packet version violate the journal's
 * history? Returns a human-readable refusal reason, or null when the pull may
 * proceed. `packetVersion === 0` means "pre-v3 packet (no counter)" — after a
 * v3 packet has been seen, a v2/v1 packet is by construction older state.
 */
export function rollbackReason(
  recordVersion: number | undefined,
  packetVersion: number,
): string | null {
  if (recordVersion === undefined || recordVersion <= 0) return null;
  if (packetVersion === 0) {
    return (
      `Rollback detected: the file arrived as a pre-v3 packet after version ` +
      `${recordVersion} was already synced — refusing to overwrite local state.`
    );
  }
  if (packetVersion < recordVersion) {
    return (
      `Rollback detected: the file arrived as version ${packetVersion}, but this device ` +
      `already synced version ${recordVersion} — refusing to overwrite local state.`
    );
  }
  return null;
}

// --------------------------------------------------------------- engine ----

export class SyncEngine {
  private api: SyncApi | null = null;
  private apiSignature = '';
  private crypto: CryptoManager | null = null;
  private cryptoPassword = '';
  private vaultId = '';
  private salt: Uint8Array | null = null;
  private keyIdHex = '';
  /** Live password override set after a successful password-challenge prompt. */
  private passwordOverride: string | null = null;
  /** ETag of the last fully processed index (PROB-6 idle-cycle shortcut). */
  private lastIndexEtag = '';
  /** True while a password rotation is streaming re-encryption (PROB-1). */
  private rotating = false;
  /** True while the current run was started explicitly by the user (IMP-2). */
  private runInteractive = false;
  /** Conflicts asked so far in the current run (IMP-2 batching rule). */
  private conflictsAsked = 0;
  /** Serializes conflict prompts — one modal at a time despite the pool. */
  private conflictPromptChain: Promise<void> = Promise.resolve();
  /** Where the running cycle's progress counter stands (IMP-3). */
  private progressState: { done: number; total: number; phase: string; path: string } | null = null;
  /** IMP-5: compiled ignore matcher, cached by (settings + .syncignore) text. */
  private ignoreCache: { signature: string; matcher: IgnoreMatcher } | null = null;

  /** Read the vault-root `.syncignore` (device-local policy; never synced). */
  private async readSyncIgnoreFile(): Promise<string> {
    const file = this.ctx.app.vault.getAbstractFileByPath(IGNORE_FILE);
    if (!(file instanceof TFile)) return '';
    try {
      return new TextDecoder().decode(await this.ctx.app.vault.readBinary(file));
    } catch {
      return '';
    }
  }

  /** Fresh matcher from the settings textarea + `.syncignore`, cached by content. */
  private async currentIgnoreMatcher(): Promise<IgnoreMatcher> {
    const fileText = await this.readSyncIgnoreFile();
    const signature = `${this.ctx.getSettings().ignorePatterns ?? ''}\u0000${fileText}`;
    if (this.ignoreCache && this.ignoreCache.signature === signature) {
      return this.ignoreCache.matcher;
    }
    const matcher = ignoreMatcherFromSources(this.ctx.getSettings().ignorePatterns, fileText);
    this.ignoreCache = { signature, matcher };
    return matcher;
  }

  /** Synchronous matcher for event hot paths (uses the last cached compile). */
  private ignoreMatcherSync(): IgnoreMatcher {
    return (
      this.ignoreCache?.matcher ??
      ignoreMatcherFromSources(this.ctx.getSettings().ignorePatterns)
    );
  }

  /** Canonical paths we are writing ourselves; vault events for them are ignored. */
  private readonly ignorePaths = new Set<string>();
  /** Per-path debounce timers, keyed by canonical path. */
  private readonly debounces = new Map<string, number>();
  /** All pending raw timer ids so dispose() can clear everything. */
  private readonly pendingTimers = new Set<number>();

  private running = false;
  private rerunRequested = false;
  private journalOpsSinceFlush = 0;
  /** Obsidian's configuration folder (Vault#configDir) — excluded from sync. */
  private readonly configDir: string;
  /** Local files snapshot of the running cycle (case-collision checks). */
  private planLocals: Map<string, TFile> | null = null;

  constructor(private readonly ctx: EngineContext) {
    this.configDir = ctx.app.vault.configDir;
  }

  dispose(): void {
    for (const t of this.debounces.values()) window.clearTimeout(t);
    this.debounces.clear();
    for (const t of this.pendingTimers) window.clearTimeout(t);
    this.pendingTimers.clear();
    this.ignorePaths.clear();
  }

  /** Drop cached key material (password changed, or plugin unloading). */
  invalidateCrypto(): void {
    this.crypto = null;
    this.cryptoPassword = '';
    this.vaultId = '';
    this.salt = null;
    this.keyIdHex = '';
  }

  // ------------------------------------------------------------ event input

  onLocalCreated(path: string): void {
    this.onLocalTouched(path);
  }

  onLocalModified(path: string): void {
    this.onLocalTouched(path);
  }

  onLocalDeleted(path: string): void {
    this.onLocalTouched(path);
  }

  /**
   * A rename is equivalent to deleting oldPath and creating newPath. The plan
   * logic handles both halves naturally, so we just schedule a sync run.
   */
  onLocalRenamed(oldPath: string, newPath: string): void {
    const ignores = this.ignoreMatcherSync();
    const oldSyncable = isSyncablePath(canonicalPath(oldPath), this.configDir, ignores);
    const newSyncable = isSyncablePath(canonicalPath(newPath), this.configDir, ignores);
    if (oldSyncable) this.onLocalTouched(oldPath);
    if (newSyncable) this.onLocalTouched(newPath);
  }

  private onLocalTouched(rawPath: string): void {
    const path = canonicalPath(rawPath);
    if (!isSyncablePath(path, this.configDir, this.ignoreMatcherSync()) || this.ignorePaths.has(path)) return;
    const existing = this.debounces.get(path);
    if (existing !== undefined) window.clearTimeout(existing);

    const timer = window.setTimeout(() => {
      this.debounces.delete(path);
      this.pendingTimers.delete(timer);
      this.requestSync();
    }, DEBOUNCE_MS);
    this.debounces.set(path, timer);
    this.pendingTimers.add(timer);
  }

  /** Fire-and-forget entry point (ribbon, debounced events, auto-sync). */
  requestSync(): void {
    if (this.running) {
      this.rerunRequested = true;
      return;
    }
    void this.runFullSync().catch(() => {
      // runFullSync never rethrows — this is purely a safety net.
    });
  }

  // ------------------------------------------------------------ main cycle

  async runFullSync(interactive = false): Promise<SyncSummary | null> {
    if (this.running) {
      this.rerunRequested = true;
      return null;
    }
    this.running = true;
    this.runInteractive = interactive;
    this.conflictsAsked = 0;
    try {
      const settings = this.ctx.getSettings();
      const password = this.passwordOverride ?? settings.encryptionPassword;
      if (!settings.serverUrl || !settings.apiToken || !password) {
        this.ctx.setStatus('error', 'not configured (see plugin settings)');
        this.ctx.notify('E2EE Sync: set server URL, API token and E2EE password in the plugin settings first.');
        return null;
      }

      const api = this.ensureApi(settings);

      // PROB-6: the index request comes first, conditionally. A 304 means
      // nothing changed anywhere since the last processed cycle — the whole
      // sync ends here at the cost of one cheap request.
      const indexResult = await api.getIndex(this.lastIndexEtag || undefined);
      if (indexResult.notModified) {
        this.ctx.setStatus('synced');
        return {
          pushed: 0, pulled: 0, conflicts: 0, merged: 0, skipped: 0,
          deletedLocal: 0, deletedRemote: 0, failures: [],
        };
      }

      const setup = await this.ensureSetup(api, password, indexResult.index);
      this.lastIndexEtag = indexResult.etag;
      this.ctx.setStatus('syncing');

      const remote = this.canonicalizeRemote(indexResult.index.files ?? {});
      const ignores = await this.currentIgnoreMatcher();
      const locals = this.collectLocalFiles(ignores);
      const journal = this.ctx.getJournal();

      // IMP-1 hygiene: with the toggle off no merge base may stay at rest in
      // data.json — purge every stored plaintext copy.
      if (!settings.enableMarkdownAutoMerge) {
        for (const record of Object.values(journal)) {
          if (record?.basePlain !== undefined) delete record.basePlain;
        }
      }

      const plan: PlannedOp[] = planSync(locals, remote, journal, this.configDir, ignores);

      // IMP-5 bookkeeping: flag records of newly-ignored paths ("ignored",
      // left untouched on the server) and clear the flag when a path becomes
      // syncable again.
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

      // Mass-wipe guard: a compromised server (or stolen token) can forge
      // tombstones. Unusual volumes of remote deletions require consent.
      const deletes = plan.filter((op) => op.action === 'delete-local');
      if (
        deletes.length > 0 &&
        deletes.length >= this.massDeleteThreshold(locals.size) &&
        this.ctx.confirmMassDeletion &&
        !(await this.ctx.confirmMassDeletion(deletes.length, locals.size))
      ) {
        for (const op of deletes) op.action = 'forget'; // keep local files; they re-upload next cycle
        this.ctx.notify(
          `E2EE Sync: refused ${deletes.length} remote deletion(s) without confirmation — ` +
            'the local files were kept and will be re-uploaded. Verify the server before syncing again.',
          15000,
        );
      }

      const summary = await this.executePlan(plan, setup);

      await this.flushJournal(true);
      this.ctx.setStatus(summary.failures.length === 0 ? 'synced' : 'error',
        summary.failures.length === 0 ? undefined : `${summary.failures.length} file(s) failed`);

      if (summary.conflicts > 0 || summary.merged > 0 || summary.skipped > 0 || summary.failures.length > 0) {
        const parts = [
          `${summary.pushed} pushed`,
          `${summary.pulled} pulled`,
          `${summary.conflicts} conflicts`,
          ...(summary.merged > 0 ? [`${summary.merged} auto-merged`] : []),
          ...(summary.skipped > 0 ? [`${summary.skipped} skipped`] : []),
          `${summary.deletedLocal + summary.deletedRemote} deletions`,
        ];
        this.ctx.notify(`E2EE Sync finished — ${parts.join(', ')}.`, 8000);
      }
      return summary;
    } catch (error) {
      const offline = error instanceof ApiError && error.isNetworkError;
      this.ctx.setStatus(offline ? 'offline' : 'error', errorMessage(error));
      this.ctx.notify(`E2EE Sync failed: ${errorMessage(error)}`, 8000);
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
  private canonicalizeRemote(files: Record<string, RemoteFileInfo>): Map<string, RemoteEntry> {
    const remote = new Map<string, RemoteEntry>();
    for (const [key, info] of Object.entries(files)) {
      if (!info) continue;
      const canon = canonicalPath(key);
      const prev = remote.get(canon);
      if (!prev || (prev.info.deleted && !info.deleted)) {
        remote.set(canon, { key, info });
      }
    }
    return remote;
  }

  private collectLocalFiles(ignores?: IgnoreMatcher | null): Map<string, TFile> {
    const out = new Map<string, TFile>();
    for (const file of this.ctx.app.vault.getFiles()) {
      const path = canonicalPath(file.path);
      if (!isSyncablePath(path, this.configDir, ignores)) continue;
      // Two local files canonicalizing to the same key (an NFD/NFC pair on a
      // normalization-sensitive FS): the first one wins; the duplicate is
      // re-planned as an unsynced file once the primary is resolved.
      if (!out.has(path)) out.set(path, file);
    }
    return out;
  }

  /** More than this many (or this fraction of) remote deletions in one cycle
   *  requires the user's explicit consent — guards against server-side wipes. */
  private massDeleteThreshold(localCount: number): number {
    return Math.max(5, Math.floor(localCount * 0.1));
  }

  // ------------------------------------------------------------ execution

  /**
   * Fixed-size worker pool (PROB-7): pulls N items through `fn` with at most
   * `concurrency` in flight. JS single-threadedness makes the shared `next`
   * index race-free.
   */
  private async runPool<T>(items: T[], concurrency: number, fn: (item: T) => Promise<void>): Promise<void> {
    let next = 0;
    const workers = Array.from(
      { length: Math.max(1, Math.min(concurrency, items.length)) },
      async () => {
        for (;;) {
          const idx = next++;
          if (idx >= items.length) return;
          await fn(items[idx]);
        }
      },
    );
    await Promise.all(workers);
  }

  /** IMP-3: map a planned action to its progress phase. */
  private static progressPhase(action: SyncAction): string {
    switch (action) {
      case 'push': return 'push';
      case 'pull': return 'pull';
      case 'conflict':
      case 'case-rename': return 'conflict';
      case 'delete-local':
      case 'delete-remote': return 'delete';
      case 'forget': return 'forget';
    }
  }

  /** IMP-3: report progress to the context, if a UI subscribed. */
  private emitProgress(chunk?: { index: number; count: number }): void {
    const s = this.progressState;
    if (!s || !this.ctx.setProgress) return;
    const p: ProgressLike = { done: s.done, total: s.total, phase: s.phase, currentPath: s.path };
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
  private async executePlan(plan: PlannedOp[], setup: SyncSetup): Promise<SyncSummary> {
    const summary: SyncSummary = {
      pushed: 0,
      pulled: 0,
      conflicts: 0,
      merged: 0,
      skipped: 0,
      deletedLocal: 0,
      deletedRemote: 0,
      failures: [],
    };

    let done = 0;
    const total = plan.length;
    const runOp = async (op: PlannedOp): Promise<void> => {
      this.progressState = { done, total, phase: SyncEngine.progressPhase(op.action), path: op.path };
      this.emitProgress();
      try {
        switch (op.action) {
          case 'forget':
            this.ctx.setJournalEntry(op.path, null);
            this.markJournalDirty();
            break;
          case 'push':
            await this.doPush(op, setup, summary);
            break;
          case 'pull':
            await this.doPull(op, setup, summary);
            break;
          case 'conflict':
            await this.doConflict(op, setup, summary);
            break;
          case 'case-rename':
            await this.doCaseRename(op, summary);
            break;
          case 'delete-local':
            await this.doDeleteLocal(op, summary);
            break;
          case 'delete-remote':
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

    // Journal bookkeeping first (no I/O), then parallel lanes. One op per
    // path guarantees no lane can conflict with another over the same file.
    const forgets: PlannedOp[] = [];
    const downloads: PlannedOp[] = [];
    const uploads: PlannedOp[] = [];
    const serialized: PlannedOp[] = [];
    for (const op of plan) {
      if (op.action === 'forget') forgets.push(op);
      else if (op.action === 'pull') downloads.push(op);
      else if (op.action === 'push' || op.action === 'conflict') uploads.push(op);
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
        `E2EE Sync: ${summary.failures.length} file(s) failed. First: ${first.path} — ${first.error}`,
        10000,
      );
    }
    return summary;
  }

  /** Read, encrypt and upload one vault file; then update its journal entry. */
  private async doPush(op: PlannedOp, setup: SyncSetup, summary: SyncSummary): Promise<void> {
    // Look the file up under its on-disk name; the op.path is canonical.
    const file = this.ctx.app.vault.getAbstractFileByPath(op.local ? op.local.path : op.path);
    if (!(file instanceof TFile)) return; // deleted mid-sync; next cycle tombstones it

    if (file.stat.size > MAX_FILE_BYTES) {
      throw new Error(
        `${op.path} is ${Math.round(file.stat.size / 1048576)} MB — above the sync limit of ` +
          `${Math.round(MAX_FILE_BYTES / 1048576)} MB.`,
      );
    }

    const plaintext = await this.ctx.app.vault.readBinary(file);
    const record = this.ctx.getJournal()[op.path];
    const version = (record?.remoteVersion ?? 0) + 1;
    const uploaded = await this.encryptAndUpload(
      setup, op.path, plaintext, file.stat.mtime, version,
    );

    const journalEntry: SyncRecord = {
      localMtime: file.stat.mtime,
      remoteHash: uploaded.hash,
      remoteMtime: uploaded.mtime,
      remoteVersion: version,
    };
    // After a successful push local == remote, so the pushed content is the
    // next merge base (IMP-1; only stored when the toggle is on).
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
  private async encryptAndUpload(
    setup: SyncSetup,
    path: string,
    plaintext: ArrayBuffer,
    clientMtime: number,
    version: number,
  ): Promise<RemoteFileInfo> {
    const bytes = new Uint8Array(plaintext);
    if (plaintext.byteLength <= CHUNKED_ABOVE_BYTES) {
      const packet = await setup.crypto.encrypt(plaintext, setup.salt, path, version);
      return setup.api.upload(path, packet, clientMtime, await sha256Hex(new Uint8Array(packet)), {
        keyId: setup.keyIdHex,
        fileVersion: version,
      });
    }

    // ---- chunked path: one v3 packet per 8 MiB plaintext slice, all bound
    // to a single file manifest (SHA-256 over the plaintext chunk hashes).
    const slices: Array<[number, number]> = [];
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
    manifestInput = new Uint8Array(0); // release the intermediate buffer

    const { uploadId } = await setup.api.beginUpload({
      path,
      // Declared assembled-size bound: plaintext + per-chunk header/tag
      // overhead. The server rejects assemblies that would exceed it (or its
      // own MAX_FILE_BYTES, whichever is smaller).
      totalBytes: plaintext.byteLength + slices.length * 128,
      chunkCount: slices.length,
      fileManifest: toHex(fileManifest),
    });

    for (let i = 0; i < slices.length; i++) {
      const [o, end] = slices[i];
      // slice().buffer copies the view into an exact-size standalone buffer,
      // giving the plaintext chunk the same isolation Web Crypto expects.
      const chunkPlain = bytes.slice(o, end);
      const packet = await setup.crypto.encryptChunk(
        chunkPlain.buffer as ArrayBuffer, setup.salt, path, version, i, fileManifest,
      );
      await this.putChunkWithRetry(setup, uploadId, i, packet);
      // IMP-3: per-file percentage while a large upload is in flight.
      this.emitProgress({ index: i + 1, count: slices.length });
    }

    return setup.api.commitUpload(uploadId, {
      clientMtime,
      keyId: setup.keyIdHex,
      fileVersion: version,
    });
  }

  /** PUT one chunk with bounded retries (network errors) and status-based resume. */
  private async putChunkWithRetry(
    setup: SyncSetup,
    uploadId: string,
    n: number,
    packet: ArrayBuffer,
  ): Promise<void> {
    let lastError: unknown = null;
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
    // One resume pass: ask the server what it actually holds.
    try {
      const status = await setup.api.uploadStatus(uploadId);
      if (status.accepted.includes(n)) return;
    } catch {
      /* fall through to rethrow */
    }
    throw lastError;
  }

  /** Download, decrypt and write one remote file; then update its journal. */
  private async doPull(op: PlannedOp, setup: SyncSetup, summary: SyncSummary): Promise<void> {
    const remote = op.remote;
    if (!remote) throw new Error('Pull planned without remote metadata.');

    let packet: ArrayBuffer;
    try {
      packet = await setup.api.download(op.remoteKey ?? op.path);
    } catch (error) {
      if (error instanceof ApiError && error.status === 404) {
        // Deleted on another device between index and download — accept it.
        this.ctx.setJournalEntry(op.path, null);
        this.markJournalDirty();
        return;
      }
      throw error;
    }

    // The index hash is the only server-issued claim we can independently
    // check: reject rollback/replay and disk-vs-index divergence loudly,
    // before decryption or any local write.
    const actualHash = await sha256Hex(new Uint8Array(packet));
    if (actualHash !== remote.hash) {
      throw new Error(
        `Integrity check failed: downloaded bytes do not match the server index ` +
          `(rollback or corruption) — refusing to overwrite ${op.path}.`,
      );
    }

    const record = this.ctx.getJournal()[op.path];
    const manifest = remote.manifest && remote.manifest.length === 64 ? remote.manifest : null;

    // Cheap pre-decrypt rollback check from the (untrusted) index counters —
    // authoritative verification happens on the authenticated packet below.
    if (record && (remote.ver ?? 0) > 0 && (remote.ver ?? 0) < record.remoteVersion) {
      throw new Error(
        `Rollback detected: server reports version ${remote.ver} for ${op.path}, ` +
          `but this device already synced version ${record.remoteVersion} — refusing the pull.`,
      );
    }

    let plaintext: ArrayBuffer;
    let packetVersion: number;
    if (manifest) {
      const manifestBytes = hexToBytes(manifest);
      const peek = peekV3(new Uint8Array(packet));
      if (peek && peek.keyId && peek.keyId !== setup.keyIdHex) {
        throw new CryptoError(
          `${op.path} was encrypted with a different E2EE password (key ${peek.keyId.slice(0, 8)}…). ` +
            'If the password was changed on another device, update it in the plugin settings.',
        );
      }
      const res = await setup.crypto.decryptChunked(packet, op.path, manifestBytes);
      plaintext = res.plaintext;
      packetVersion = res.version;
    } else {
      const peek = peekV3(new Uint8Array(packet));
      if (peek && peek.keyId && peek.keyId !== setup.keyIdHex) {
        throw new CryptoError(
          `${op.path} was encrypted with a different E2EE password (key ${peek.keyId.slice(0, 8)}…). ` +
            'If the password was changed on another device, update it in the plugin settings.',
        );
      }
      const res = await setup.crypto.decrypt(packet, op.path); // CryptoError on wrong password
      plaintext = res.plaintext;
      packetVersion = res.version ?? 0;
    }

    // PROB-2: the authenticated version counter must never move backwards.
    const refusal = record ? rollbackReason(record.remoteVersion, packetVersion) : null;
    if (refusal) throw new Error(`${refusal} (${op.path})`);

    // PROB-4: on case-insensitive filesystems a pull must never overwrite a
    // different local file that differs only by ASCII case.
    const caseVariant = findCaseVariant(op.path, this.planLocals?.keys() ?? []);
    const targetPath = caseVariant
      ? this.uniqueConflictPath(op.path, '_remote-case_')
      : op.path;
    if (caseVariant) {
      this.ctx.notify(
        `Case collision: "${op.path}" and "${caseVariant}" differ only by letter case — ` +
          `the downloaded copy was saved as "${targetPath}".`,
        12000,
      );
    }

    // Match the local counterpart under its on-disk name when we know it.
    const existing = this.ctx.app.vault.getAbstractFileByPath(
      !caseVariant && op.local ? op.local.path : targetPath,
    );
    if (existing && !(existing instanceof TFile)) {
      throw new Error(`Local path exists but is a folder: ${targetPath}`);
    }

    this.beginIgnore(targetPath); // our own write must not re-trigger sync
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

    // The write bumps the local mtime to "now" — the journal must record that
    // exact value, otherwise the next cycle would mistake our own pull for a
    // local modification and push it right back.
    const written = this.ctx.app.vault.getAbstractFileByPath(targetPath);
    const journalEntry: SyncRecord = {
      localMtime: written instanceof TFile ? written.stat.mtime : Date.now(),
      remoteHash: remote.hash,
      remoteMtime: remote.mtime,
      remoteVersion: packetVersion,
    };
    // The pulled copy is the next merge base (IMP-1).
    this.setMergeBase(targetPath, journalEntry, plaintext);
    this.ctx.setJournalEntry(targetPath, journalEntry);
    if (caseVariant) this.ctx.setJournalEntry(op.path, null);
    this.markJournalDirty();
    summary.pulled++;
  }

  // ------------------------------------------------- Markdown merge (IMP-1)

  /** Is the opt-in three-way Markdown merge active for this cycle? */
  private mergeBaseEnabled(): boolean {
    return this.ctx.getSettings().enableMarkdownAutoMerge === true;
  }

  /** Only .md notes up to the merge size cap are auto-merge candidates. */
  private isMergeCandidate(path: string, byteLength: number): boolean {
    return /\.md$/i.test(path) && byteLength <= MERGE_MAX_BYTES;
  }

  /**
   * Record (or drop) the merge base on a fresh journal entry. The base is
   * plaintext at rest in data.json — stored only while the toggle is on and
   * only for eligible notes, purged otherwise.
   */
  private setMergeBase(path: string, entry: SyncRecord, plaintext: ArrayBuffer | null): void {
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
  private async tryMarkdownMerge(
    op: PlannedOp,
    setup: SyncSetup,
    summary: SyncSummary,
    record: SyncRecord | undefined,
  ): Promise<boolean> {
    if (!op.local || !op.remote || !record?.basePlain) return false;
    if (!this.isMergeCandidate(op.path, record.basePlain.length)) return false;

    const local = this.ctx.app.vault.getAbstractFileByPath(op.local.path);
    if (!(local instanceof TFile)) return false;
    if (local.stat.size > MERGE_MAX_BYTES) return false;

    // theirs: download + verify + decrypt exactly like doPull would.
    const remote = op.remote;
    let packet: ArrayBuffer;
    try {
      packet = await setup.api.download(op.remoteKey ?? op.path);
    } catch {
      return false; // remote vanished mid-sync — keep-both flow re-checks
    }
    if ((await sha256Hex(new Uint8Array(packet))) !== remote.hash) return false;
    const manifest = remote.manifest && remote.manifest.length === 64 ? remote.manifest : null;
    const theirs = manifest
      ? (await setup.crypto.decryptChunked(packet, op.path, hexToBytes(manifest))).plaintext
      : (await setup.crypto.decrypt(packet, op.path)).plaintext;

    const ours = await this.ctx.app.vault.readBinary(local);
    const decoder = new TextDecoder();
    const result = merge3(record.basePlain, decoder.decode(ours), decoder.decode(theirs));
    if (result.kind !== 'merged') return false;

    // 1. Write the merged note locally (our own write must not re-trigger sync).
    const mergedBytes = new TextEncoder().encode(result.text);
    const mergedBuffer = mergedBytes.buffer as ArrayBuffer;
    this.beginIgnore(op.path);
    try {
      await this.ctx.app.vault.modifyBinary(local, mergedBuffer);
    } catch (error) {
      this.ignorePaths.delete(op.path);
      throw error;
    }

    // 2. Push the merged content to the original path. A failure here leaves
    //    the merged local file unjournaled — the next cycle plans a push and
    //    converges (no data can be lost: theirs is untouched on the server).
    const written = this.ctx.app.vault.getAbstractFileByPath(op.path);
    const mtime = written instanceof TFile ? written.stat.mtime : local.stat.mtime;
    const version = Math.max(record.remoteVersion ?? 0, remote.ver ?? 0) + 1;
    const uploaded = await this.encryptAndUpload(setup, op.path, mergedBuffer, mtime, version);
    const journalEntry: SyncRecord = {
      localMtime: mtime,
      remoteHash: uploaded.hash,
      remoteMtime: uploaded.mtime,
      remoteVersion: version,
    };
    this.setMergeBase(op.path, journalEntry, mergedBuffer);
    this.ctx.setJournalEntry(op.path, journalEntry);
    this.markJournalDirty();

    summary.merged++;
    this.ctx.notify(`Conflict in ${op.path} resolved by Markdown auto-merge.`, 6000);
    return true;
  }

  /**
   * IMP-2: route a conflict to the user's choice. Auto-sync runs prompt for
   * at most CONFLICT_PROMPT_LIMIT conflicts and batch keep-both for the rest
   * (UI-storm guard); prompts are serialized so the upload pool can never
   * stack two modals. Null (Esc) resolves to keep-both.
   */
  private askConflictResolution(path: string): Promise<ConflictResolution | null> {
    const ask = this.ctx.resolveConflict;
    if (!ask) return Promise.resolve('both');
    if (!this.runInteractive && this.conflictsAsked >= CONFLICT_PROMPT_LIMIT) {
      return Promise.resolve('both');
    }
    this.conflictsAsked++;
    const run = this.conflictPromptChain.then(() => ask(path));
    this.conflictPromptChain = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  /** IMP-2 "keep mine": overwrite the remote original with the local version. */
  private async pushLocalOverRemote(
    op: PlannedOp,
    setup: SyncSetup,
    summary: SyncSummary,
    record: SyncRecord | undefined,
  ): Promise<void> {
    const local = this.ctx.app.vault.getAbstractFileByPath(op.local ? op.local.path : op.path);
    if (!(local instanceof TFile)) return;
    const plaintext = await this.ctx.app.vault.readBinary(local);
    const version = Math.max(record?.remoteVersion ?? 0, op.remote?.ver ?? 0) + 1;
    const uploaded = await this.encryptAndUpload(
      setup, op.path, plaintext, local.stat.mtime, version,
    );
    const entry: SyncRecord = {
      localMtime: local.stat.mtime,
      remoteHash: uploaded.hash,
      remoteMtime: uploaded.mtime,
      remoteVersion: version,
    };
    this.setMergeBase(op.path, entry, plaintext);
    this.ctx.setJournalEntry(op.path, entry);
    this.markJournalDirty();
    summary.pushed++;
    this.ctx.notify(`Conflict in ${op.path} resolved: your version was kept.`, 6000);
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
  private async doConflict(op: PlannedOp, setup: SyncSetup, summary: SyncSummary): Promise<void> {
    if (!op.local) return;
    const local = this.ctx.app.vault.getAbstractFileByPath(op.local.path);
    if (!(local instanceof TFile)) return; // vanished mid-sync; next cycle retries

    const record = this.ctx.getJournal()[op.path];
    if (this.mergeBaseEnabled()) {
      const merged = await this.tryMarkdownMerge(op, setup, summary, record);
      if (merged) return;
    }

    const choice = await this.askConflictResolution(op.path);
    if (choice === 'skip') {
      // Leave local and remote untouched; the conflict re-plans next cycle.
      summary.skipped++;
      this.ctx.notify(`Conflict in ${op.path} skipped — it will be offered again next sync.`, 6000);
      return;
    }
    if (choice === 'mine') {
      await this.pushLocalOverRemote(op, setup, summary, record);
      return;
    }
    if (choice === 'remote') {
      // The local edits are discarded (the modal says so up front).
      // doPull journals and counts the pull itself.
      await this.doPull({ ...op, local: undefined, remoteKey: op.remoteKey }, setup, summary);
      this.ctx.notify(`Conflict in ${op.path} resolved: the server version was kept.`, 6000);
      return;
    }

    const conflictPath = this.uniqueConflictPath(op.path);
    const localCopy = await this.ctx.app.vault.readBinary(local);
    const version = (record?.remoteVersion ?? 0) + 1;

    // 1. Preserve the local version remotely first — a network failure here
    //    leaves no local debris and the next cycle simply retries.
    const uploaded = await this.encryptAndUpload(
      setup, conflictPath, localCopy, local.stat.mtime, version,
    );

    // 2. Materialize the copy locally and journal it.
    this.beginIgnore(conflictPath);
    try {
      await this.ctx.app.vault.createBinary(conflictPath, localCopy);
    } catch (error) {
      this.ignorePaths.delete(conflictPath);
      throw error;
    }
    const written = this.ctx.app.vault.getAbstractFileByPath(conflictPath);
    const conflictEntry: SyncRecord = {
      localMtime: written instanceof TFile ? written.stat.mtime : local.stat.mtime,
      remoteHash: uploaded.hash,
      remoteMtime: uploaded.mtime,
      remoteVersion: version,
    };
    // A fresh conflict copy has no common ancestor yet — no merge base.
    this.setMergeBase(conflictPath, conflictEntry, null);
    this.ctx.setJournalEntry(conflictPath, conflictEntry);
    this.markJournalDirty();

    // 3. Remote wins the original path.
    await this.doPull({ ...op, local: undefined, remoteKey: op.remoteKey }, setup, summary);

    summary.conflicts++;
    this.ctx.notify(
      `Conflict detected in file: ${op.path}\nBoth versions kept — local copy saved as: ${conflictPath}`,
      10000,
    );
  }

  /** Keep-both for two local files differing only by ASCII case (PROB-4). */
  private async doCaseRename(
    op: PlannedOp,
    summary: SyncSummary,
  ): Promise<void> {
    const file = op.local instanceof TFile ? op.local : null;
    const target = file ?? this.ctx.app.vault.getAbstractFileByPath(op.path);
    if (!(target instanceof TFile)) return;
    const renamed = this.uniqueConflictPath(op.path, '_case-collision_');
    this.beginIgnore(op.path);
    this.beginIgnore(renamed);
    try {
      await this.ctx.app.vault.rename(target, renamed);
    } catch (error) {
      this.ignorePaths.delete(op.path);
      this.ignorePaths.delete(renamed);
      throw error;
    }
    // The renamed file is untracked; the old key is forgotten so a possible
    // remote entry under it resolves through the normal rules next cycle.
    this.ctx.setJournalEntry(op.path, null);
    this.markJournalDirty();
    summary.conflicts++;
    this.ctx.notify(
      `Case collision: "${op.path}" and another file differ only by letter case — ` +
        `renamed to "${renamed}" so both are kept.`,
      12000,
    );
  }

  private async doDeleteLocal(op: PlannedOp, summary: SyncSummary): Promise<void> {
    const file = this.ctx.app.vault.getAbstractFileByPath(op.local ? op.local.path : op.path);
    if (file instanceof TFile) {
      this.beginIgnore(op.path);
      try {
        await this.ctx.app.vault.trash(file, true); // system trash; .trash is excluded from sync
      } catch (error) {
        this.ignorePaths.delete(op.path);
        throw error;
      }
    }
    this.ctx.setJournalEntry(op.path, null);
    this.markJournalDirty();
    summary.deletedLocal++;
  }

  private async doDeleteRemote(op: PlannedOp, setup: SyncSetup, summary: SyncSummary): Promise<void> {
    try {
      await setup.api.deleteFile(op.remoteKey ?? op.path);
    } catch (error) {
      if (error instanceof ApiError && error.status === 404) {
        // Already deleted on another device (tombstone still present for us).
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
  async restoreFromServer(
    confirm?: (liveCount: number) => Promise<boolean>,
  ): Promise<{ pulled: number; failures: number } | null> {
    const settings = this.ctx.getSettings();
    const password = this.passwordOverride ?? settings.encryptionPassword;
    if (!settings.serverUrl || !settings.apiToken || !password) {
      this.ctx.notify('E2EE Sync: set server URL, API token and E2EE password in the plugin settings first.');
      return null;
    }
    if (this.running) {
      this.ctx.notify('E2EE Sync: a sync is already running — try again when it finishes.');
      return null;
    }
    this.running = true;
    try {
      const api = this.ensureApi(settings);
      const { index } = await api.getIndex(); // unconditional — no 304 shortcut
      const setup = await this.ensureSetup(api, password, index);

      const liveCount = Object.entries(index.files ?? {}).filter(
        ([p, f]) => f && !f.deleted && !isVerifierPath(canonicalPath(p)),
      ).length;
      if (confirm && !(await confirm(liveCount))) {
        this.ctx.setStatus('idle');
        return null;
      }

      for (const path of Object.keys(this.ctx.getJournal())) {
        this.ctx.setJournalEntry(path, null);
      }
      this.lastIndexEtag = '';

      const remote = this.canonicalizeRemote(index.files ?? {});
      const ignores = await this.currentIgnoreMatcher();
      const plan: PlannedOp[] = planSync(new Map(), remote, {}, this.configDir, ignores);
      // planLocals feeds the write-time case-collision guard in doPull.
      this.planLocals = this.collectLocalFiles(ignores);
      this.ctx.setStatus('syncing', `restoring ${liveCount} file(s)…`);
      const summary = await this.executePlan(plan, setup);
      await this.flushJournal(true);
      this.ctx.setStatus(
        summary.failures.length === 0 ? 'synced' : 'error',
        summary.failures.length === 0 ? undefined : `${summary.failures.length} file(s) failed`,
      );
      return { pulled: summary.pulled, failures: summary.failures.length };
    } catch (error) {
      this.ctx.setStatus('error', errorMessage(error));
      this.ctx.notify(`E2EE Sync: restore failed — ${errorMessage(error)}`, 8000);
      return null;
    } finally {
      this.planLocals = null;
      this.running = false;
    }
  }

  // ---------------------------------------------------- integrity audit (PROB-10)

  /** Result of a full-store integrity verification. */
  async verifyIntegrity(): Promise<{
    checked: number;
    hashMismatch: string[];
    decryptFailed: string[];
    failures: Array<{ path: string; error: string }>;
  } | null> {
    const settings = this.ctx.getSettings();
    const password = this.passwordOverride ?? settings.encryptionPassword;
    if (!settings.serverUrl || !settings.apiToken || !password) {
      this.ctx.notify('E2EE Sync: set server URL, API token and E2EE password first.');
      return null;
    }
    try {
      const api = this.ensureApi(settings);
      const { index } = await api.getIndex();
      const setup = await this.ensureSetup(api, password, index);

      const targets = Object.entries(index.files)
        .filter(([p, f]) => f && !f.deleted && !isVerifierPath(canonicalPath(p)))
        .map(([key, info]) => ({ key, path: canonicalPath(key), info }));

      const report = {
        checked: 0,
        hashMismatch: [] as string[],
        decryptFailed: [] as string[],
        failures: [] as Array<{ path: string; error: string }>,
      };

      await this.runPool(targets, 3, async ({ key, path, info }) => {
        try {
          const blob = await api.download(key);
          report.checked++;
          if ((await sha256Hex(new Uint8Array(blob))) !== info.hash) {
            report.hashMismatch.push(path); // server index and stored bytes disagree
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
      this.ctx.notify(`E2EE Sync: integrity verification failed — ${errorMessage(error)}`, 8000);
      return null;
    }
  }

  /**
   * Re-push the intact local copies of the given paths (ver + 1), repairing
   * server-side damage detected by verifyIntegrity. Paths without a healthy
   * local file are skipped and reported.
   */
  async repairPaths(paths: string[]): Promise<{ repaired: string[]; skipped: string[] }> {
    const settings = this.ctx.getSettings();
    const password = this.passwordOverride ?? settings.encryptionPassword;
    const api = this.ensureApi(settings);
    const meta = await api.getMeta();
    const salt = await saltFromVaultId(meta.vaultId);
    const cryptoMgr = new CryptoManager(password, salt);
    const km = await cryptoMgr.keyMaterial(salt);
    const setup: SyncSetup = { api, crypto: cryptoMgr, salt, keyIdHex: toHex(km.keyId) };

    const repaired: string[] = [];
    const skipped: string[] = [];
    await this.runPool(paths, 2, async (path) => {
      try {
        const file = this.ctx.app.vault.getAbstractFileByPath(path);
        if (!(file instanceof TFile)) {
          skipped.push(path);
          return;
        }
        const plaintext = await this.ctx.app.vault.readBinary(file);
        const record = this.ctx.getJournal()[path];
        const version = (record?.remoteVersion ?? 0) + 1;
        const uploaded = await this.encryptAndUpload(setup, path, plaintext, file.stat.mtime, version);
        const repairEntry: SyncRecord = {
          localMtime: file.stat.mtime,
          remoteHash: uploaded.hash,
          remoteMtime: uploaded.mtime,
          remoteVersion: version,
        };
        this.setMergeBase(path, repairEntry, plaintext);
        this.ctx.setJournalEntry(path, repairEntry);
        this.markJournalDirty();
        repaired.push(path);
      } catch {
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
  async rotatePassword(oldPassword: string, newPassword: string): Promise<void> {
    if (oldPassword === newPassword) {
      throw new Error('The new E2EE password must differ from the current one.');
    }
    if (this.rotating) throw new Error('A password rotation is already in progress.');
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

      // 1. Fail-closed check of the old password before touching anything.
      const oldSetup: SyncSetup = {
        api, crypto: oldManager, salt, keyIdHex: oldHex,
      };
      const { index } = await api.getIndex();
      await this.checkVerifier(oldSetup, index);

      // 1b. On a vault that predates verifiers (0.1.x) the verifier check
      // cannot distinguish right from wrong passwords — prove the old key
      // against one live file before mutating anything.
      const probeEntry = Object.entries(index.files).find(
        ([p, f]) => f && !f.deleted && !isVerifierPath(canonicalPath(p)),
      );
      if (probeEntry && probeEntry[1].keyId !== '' && probeEntry[1].keyId !== oldHex) {
        throw new Error(
          'The current password does not match this vault (files carry a different key id). ' +
            'Rotation aborted before any change.',
        );
      }
      if (probeEntry && !probeEntry[1].keyId) {
        const blob = await api.download(probeEntry[0]);
        try {
          await oldManager.decrypt(blob, canonicalPath(probeEntry[0]));
        } catch {
          throw new Error(
            'The current password does not match this vault (probe file failed to decrypt). ' +
              'Rotation aborted before any change.',
          );
        }
      }

      // 2. Seed the new verifier (old and new coexist until completion).
      const newSetup: SyncSetup = {
        api, crypto: newManager, salt, keyIdHex: newHex,
      };
      await this.seedVerifier(newSetup);

      // 3. Re-encrypt every live file (verifier entries excluded).
      const remoteFiles = Object.entries(index.files).filter(
        ([p, f]) => f && !f.deleted && !isVerifierPath(canonicalPath(p)),
      );
      let done = 0;
      for (const [rawKey, entry] of remoteFiles) {
        const path = canonicalPath(rawKey);
        if (entry.keyId === newHex) {
          done++; // previous interrupted rotation already converted this file
          continue;
        }
        const blob = await api.download(rawKey);
        const actualHash = await sha256Hex(new Uint8Array(blob));
        if (actualHash !== entry.hash) {
          throw new Error(
            `Integrity check failed for ${path} during rotation — the server index and stored ` +
              'bytes disagree. Rotation aborted; nothing was overwritten.',
          );
        }
        const manifest = entry.manifest && entry.manifest.length === 64 ? entry.manifest : null;
        let plaintext: ArrayBuffer;
        if (manifest) {
          plaintext = (await oldManager.decryptChunked(blob, path, hexToBytes(manifest))).plaintext;
        } else {
          plaintext = (await oldManager.decrypt(blob, path)).plaintext;
        }
        const record = this.ctx.getJournal()[path];
        const version = Math.max(record?.remoteVersion ?? 0, entry.ver ?? 0) + 1;
        const uploaded = await this.encryptAndUpload(newSetup, path, plaintext, Date.now(), version);
        const rotationEntry: SyncRecord = {
          localMtime: record?.localMtime ?? Date.now(),
          remoteHash: uploaded.hash,
          remoteMtime: uploaded.mtime,
          remoteVersion: version,
        };
        this.setMergeBase(path, rotationEntry, plaintext);
        this.ctx.setJournalEntry(path, rotationEntry);
        this.markJournalDirty();
        done++;
        if (done % 10 === 0 || done === remoteFiles.length) {
          this.ctx.setStatus('syncing', `rotating keys — ${done}/${remoteFiles.length} files`);
          await this.flushJournal();
        }
      }

      // 4. Completion check: every live entry under the new key -> drop the
      //    old verifier. Otherwise keep it (mid-rotation state) and warn.
      const { index: fresh } = await api.getIndex();
      const stale = Object.entries(fresh.files).filter(
        ([p, f]) =>
          f && !f.deleted && !isVerifierPath(canonicalPath(p)) && f.keyId !== newHex,
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
          `E2EE password rotated: ${done} file(s) re-encrypted. ` +
            'Enter the same new password on every other device when prompted.',
          12000,
        );
      } else {
        this.ctx.notify(
          `E2EE password rotation left ${stale.length} file(s) under the old key ` +
            '(they decrypt with the old password only). Run the rotation again from this device ' +
            'to finish converting them.',
          15000,
        );
      }

      this.passwordOverride = newPassword;
      this.invalidateCrypto();
      this.lastIndexEtag = ''; // force a full cycle next run
      await this.flushJournal(true);
    } finally {
      this.rotating = false;
    }
  }

  // ------------------------------------------------------------- plumbing

  private ensureApi(settings: PluginSettings): SyncApi {
    const signature = `${settings.serverUrl}\u0000${settings.apiToken}`;
    if (!this.api || this.apiSignature !== signature) {
      this.api = this.ctx.createApi
        ? this.ctx.createApi(settings.serverUrl, settings.apiToken)
        : new SyncApi(settings.serverUrl, settings.apiToken);
      this.apiSignature = signature;
    }
    return this.api;
  }

  private async ensureSetup(
    api: SyncApi,
    password: string,
    index: RemoteIndex,
  ): Promise<SyncSetup> {
    // Fetch meta every changed cycle: it is one tiny request and detects a
    // server wipe (new vaultId) whose salt change invalidates the cached key.
    // Idle cycles never reach this point (304 shortcut in runFullSync).
    const meta = await api.getMeta();
    if (
      !this.crypto ||
      this.cryptoPassword !== password ||
      this.vaultId !== meta.vaultId
    ) {
      const salt = await saltFromVaultId(meta.vaultId);
      // expectedSalt: packets carrying a foreign salt are rejected before the
      // expensive PBKDF2 pass (hostile-server CPU exhaustion defense).
      this.salt = salt;
      this.crypto = new CryptoManager(password, salt);
      this.cryptoPassword = password;
      this.vaultId = meta.vaultId;
      const km = await this.crypto.keyMaterial(salt);
      this.keyIdHex = toHex(km.keyId);
    }
    const salt = this.salt;
    if (!salt || !this.crypto) throw new Error('Crypto setup failed unexpectedly.');
    const setup: SyncSetup = { api, crypto: this.crypto, salt, keyIdHex: this.keyIdHex };
    await this.ensurePasswordVerifier(setup, index);
    // The verifier flow may have replaced the crypto state (password prompt);
    // always hand out a setup built from the CURRENT engine fields.
    return {
      api,
      crypto: this.crypto,
      salt: this.salt ?? salt,
      keyIdHex: this.keyIdHex,
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
  private async ensurePasswordVerifier(setup: SyncSetup, index: RemoteIndex): Promise<void> {
    try {
      await this.checkVerifier(setup, index);
      return;
    } catch (error) {
      if (!(error instanceof CryptoError)) throw error;
      const reason = /changed on another device/.test(error.message) ? 'changed' : 'wrong';
      const prompted = await this.promptForNewPassword(reason);
      if (!prompted) throw error;
    }
    // Retried with a user-supplied password — the engine's crypto state was
    // rebuilt by the prompt flow, so re-check with the CURRENT key material.
    const salt = this.salt;
    const crypto = this.crypto;
    if (!salt || !crypto) throw new Error('Crypto setup failed unexpectedly.');
    const freshSetup: SyncSetup = {
      api: setup.api, crypto, salt, keyIdHex: this.keyIdHex,
    };
    const { index: freshIndex } = await setup.api.getIndex();
    await this.checkVerifier(freshSetup, freshIndex);
  }

  /** Ask the user for the current vault password (rotation on another device). */
  private async promptForNewPassword(reason: 'changed' | 'wrong'): Promise<boolean> {
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
  private async checkVerifier(setup: SyncSetup, index: RemoteIndex): Promise<void> {
    const ourPath = verifierPathFor(setup.keyIdHex);

    /** 'yes' | 'no' | 'missing' — did the entry at `path` decrypt with our key? */
    const decrypts = async (path: string): Promise<'yes' | 'no' | 'missing'> => {
      let packet: ArrayBuffer;
      try {
        packet = await setup.api.download(path);
      } catch (error) {
        if (error instanceof ApiError && error.status === 404) return 'missing';
        throw error;
      }
      try {
        const { plaintext } = await setup.crypto.decrypt(packet, path);
        const plain = new Uint8Array(plaintext);
        return plain.length === VERIFIER_PLAINTEXT.length && bytesEqual(plain, VERIFIER_PLAINTEXT)
          ? 'yes'
          : 'no';
      } catch (error) {
        if (error instanceof CryptoError) return 'no';
        throw error;
      }
    };

    // 1. Our per-key verifier present and decrypting -> done.
    if ((await decrypts(ourPath)) === 'yes') return;

    // 2. Classify the vault from the index.
    const otherVerifiers: string[] = [];
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

    // 3. Verifiers for unknown keys / foreign-keyed files -> the password was
    //    rotated on another device (or is wrong). Recoverable via prompt.
    if (otherVerifiers.length > 0 || liveForeign > 0) {
      throw new CryptoError(
        'The E2EE password was changed on another device (or this password is wrong). ' +
          'Enter the current password to continue syncing.',
      );
    }

    // 4. Legacy verifier (0.1/0.2 vault): decrypting -> upgrade to per-key;
    //    present but NOT decrypting -> genuinely wrong password, fail closed.
    const legacy = await decrypts(VERIFIER_LEGACY_PATH);
    if (legacy === 'yes') {
      await this.seedVerifier(setup);
      return;
    }
    if (legacy === 'no') {
      throw new CryptoError(
        'Wrong E2EE password for this vault (verifier check failed). Correct it in the ' +
          'plugin settings before syncing — nothing was changed on the server.',
      );
    }

    // 5. No verifiers at all: a 0.1.x-era vault (never had one) or an empty
    //    vault — seed ours. A wrong password on a populated 0.1.x vault is
    //    caught later by per-file decryption failures, never by overwriting.
    await this.seedVerifier(setup);
  }

  /** Create (or refresh) the verifier entry for the setup's key. */
  private async seedVerifier(setup: SyncSetup): Promise<void> {
    const path = verifierPathFor(setup.keyIdHex);
    const packet = await setup.crypto.encrypt(
      VERIFIER_PLAINTEXT.buffer as ArrayBuffer,
      setup.salt,
      path,
      1,
    );
    await setup.api.upload(path, packet, Date.now(), await sha256Hex(new Uint8Array(packet)), {
      keyId: setup.keyIdHex,
      fileVersion: 1,
    });
  }

  private beginIgnore(path: string): void {
    this.ignorePaths.add(path);
    const timer = window.setTimeout(() => {
      this.pendingTimers.delete(timer);
      this.ignorePaths.delete(path);
    }, IGNORE_WINDOW_MS);
    this.pendingTimers.add(timer);
  }

  /** createFolder() is not reliably recursive — walk each segment down. */
  private async ensureParentFolder(filePath: string): Promise<void> {
    const slash = filePath.lastIndexOf('/');
    if (slash <= 0) return;
    const folderPath = filePath.slice(0, slash);
    const existing = this.ctx.app.vault.getAbstractFileByPath(folderPath);
    if (existing instanceof TFolder) return;
    if (existing) throw new Error(`'${folderPath}' exists and is not a folder.`);

    let current = '';
    for (const segment of folderPath.split('/')) {
      current = current ? `${current}/${segment}` : segment;
      const entry = this.ctx.app.vault.getAbstractFileByPath(current);
      if (entry instanceof TFolder) continue;
      if (entry) throw new Error(`'${current}' exists and is not a folder.`);
      try {
        await this.ctx.app.vault.createFolder(current);
      } catch {
        // Raced with a concurrent pull creating the same folder (worker pool):
        // tolerate it if the folder now exists.
        const raced = this.ctx.app.vault.getAbstractFileByPath(current);
        if (!(raced instanceof TFolder)) throw new Error(`'${current}' exists and is not a folder.`);
      }
    }
  }

  private conflictStamp(d = new Date()): string {
    const pad = (n: number) => String(n).padStart(2, '0');
    return (
      `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}` +
      `_${pad(d.getHours())}-${pad(d.getMinutes())}-${pad(d.getSeconds())}`
    );
  }

  /** filename.md -> filename<marker>YYYY-MM-DD_HH-mm-ss[_N].md */
  private uniqueConflictPath(original: string, marker = '_conflict_'): string {
    const slash = original.lastIndexOf('/');
    const dir = slash >= 0 ? original.slice(0, slash + 1) : '';
    const name = slash >= 0 ? original.slice(slash + 1) : original;
    const dot = name.lastIndexOf('.');
    const base = dot > 0 ? name.slice(0, dot) : name;
    const ext = dot > 0 ? name.slice(dot) : '';

    let candidate = `${dir}${base}${marker}${this.conflictStamp()}${ext}`;
    let attempt = 2;
    while (this.ctx.app.vault.getAbstractFileByPath(candidate)) {
      candidate = `${dir}${base}${marker}${this.conflictStamp()}_${attempt++}${ext}`;
    }
    return candidate;
  }

  private markJournalDirty(): void {
    this.journalOpsSinceFlush++;
    if (this.journalOpsSinceFlush >= JOURNAL_FLUSH_EVERY) {
      this.journalOpsSinceFlush = 0;
      void this.ctx.persist().catch(() => {});
    }
  }

  private async flushJournal(force = false): Promise<void> {
    if (force || this.journalOpsSinceFlush > 0) {
      this.journalOpsSinceFlush = 0;
      await this.ctx.persist();
    }
  }
}
