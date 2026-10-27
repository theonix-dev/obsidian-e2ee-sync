/**
 * Three-way sync engine.
 *
 * For every path it compares three states:
 *   Local      — the file as it exists in the vault right now (mtime).
 *   Record     — the local sync journal (what local + remote looked like at
 *                the last successful sync of that path).
 *   Remote     — the server index entry (ciphertext hash, tombstone flag).
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
 *   - A reserved verifier entry proves this device derives the same key as
 *     the vault's original encryptor BEFORE anything is pushed (wrong-password
 *     devices cannot clobber the store).
 *   - Mass remote deletions require explicit user confirmation.
 */

import { TFile, TFolder, normalizePath } from 'obsidian';
import type { App } from 'obsidian';
import { ApiError, SyncApi } from './api';
import {
  CryptoError,
  CryptoManager,
  bytesEqual,
  saltFromVaultId,
  sha256Hex,
} from './crypto';
import type { PluginSettings, RemoteFileInfo, SyncRecord, SyncStatus } from './types';
import { errorMessage } from './util';

/** Per-file debounce window for local vault events (ms). */
const DEBOUNCE_MS = 2500;
/** How long a path stays in the ignore set after our own write (ms). */
const IGNORE_WINDOW_MS = 500;
/** Persist the journal at least every N mutations (plus once per sync run). */
const JOURNAL_FLUSH_EVERY = 20;

/**
 * Reserved server-side path holding the password verifier. Present in the
 * index but never treated as vault content by any client.
 */
const VERIFIER_PATH = '.e2ee-sync-verifier.v1';
const VERIFIER_PLAINTEXT = new TextEncoder().encode('e2ee-verifier-v1\u0000');

/** Largest single file the engine will sync (keep in lockstep with the
 *  server's MAX_BODY_BYTES default). */
const MAX_SYNCABLE_BYTES = 256 * 1024 * 1024;

/** Vault folders that must never round-trip to the server. */
const EXCLUDED_PREFIXES = ['.trash/'];
/** OS-generated junk that must never round-trip to the server. */
const EXCLUDED_NAMES = new Set(['.DS_Store', 'Thumbs.db', 'desktop.ini']);

/**
 * Single canonical form for journal keys, remote keys, AAD and API
 * transmission: Obsidian's normalizePath (slash/dot cleanup) plus explicit
 * NFC Unicode normalization.
 */
export function canonicalPath(p: string): string {
  return normalizePath(p).normalize('NFC');
}

export function isSyncablePath(p: string, configDir: string): boolean {
  if (p === VERIFIER_PATH) return false;
  const name = p.slice(p.lastIndexOf('/') + 1);
  if (EXCLUDED_NAMES.has(name)) return false;
  const prefixes = [`${configDir.replace(/\/+$/, '')}/`, ...EXCLUDED_PREFIXES];
  for (const prefix of prefixes) {
    if (p === prefix.slice(0, -1) || p.startsWith(prefix)) return false;
  }
  return true;
}

export type SyncAction =
  | 'push'
  | 'pull'
  | 'conflict'
  | 'delete-local'
  | 'delete-remote'
  | 'forget';

export interface SyncSummary {
  pushed: number;
  pulled: number;
  conflicts: number;
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
  local?: TFile;
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
}

export class SyncEngine {
  private api: SyncApi | null = null;
  private apiSignature = '';
  private crypto: CryptoManager | null = null;
  private cryptoPassword = '';
  private vaultId = '';
  private salt: Uint8Array | null = null;

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
    const oldSyncable = isSyncablePath(canonicalPath(oldPath), this.configDir);
    const newSyncable = isSyncablePath(canonicalPath(newPath), this.configDir);
    if (oldSyncable) this.onLocalTouched(oldPath);
    if (newSyncable) this.onLocalTouched(newPath);
  }

  private onLocalTouched(rawPath: string): void {
    const path = canonicalPath(rawPath);
    if (!isSyncablePath(path, this.configDir) || this.ignorePaths.has(path)) return;
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

  async runFullSync(): Promise<SyncSummary | null> {
    if (this.running) {
      this.rerunRequested = true;
      return null;
    }
    this.running = true;
    try {
      const settings = this.ctx.getSettings();
      if (!settings.serverUrl || !settings.apiToken || !settings.encryptionPassword) {
        this.ctx.setStatus('error', 'not configured (see plugin settings)');
        this.ctx.notify('E2EE Sync: set server URL, API token and E2EE password in the plugin settings first.');
        return null;
      }

      const setup = await this.ensureSetup();
      this.ctx.setStatus('syncing');

      const remoteIndex = await setup.api.getIndex();
      const remote = this.canonicalizeRemote(remoteIndex.files ?? {});
      const locals = this.collectLocalFiles();
      const journal = this.ctx.getJournal();

      const plan = this.planSync(locals, remote, journal);

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

      if (summary.conflicts > 0 || summary.failures.length > 0) {
        const parts = [
          `${summary.pushed} pushed`,
          `${summary.pulled} pulled`,
          `${summary.conflicts} conflicts`,
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

  private collectLocalFiles(): Map<string, TFile> {
    const out = new Map<string, TFile>();
    for (const file of this.ctx.app.vault.getFiles()) {
      const path = canonicalPath(file.path);
      if (!isSyncablePath(path, this.configDir)) continue;
      // Two local files canonicalizing to the same key (an NFD/NFC pair on a
      // normalization-sensitive FS): the first one wins; the duplicate is
      // re-planned as an unsynced file once the primary is resolved.
      if (!out.has(path)) out.set(path, file);
    }
    return out;
  }

  /** Pure decision function — no I/O, straightforward to reason about. */
  private planSync(
    locals: Map<string, TFile>,
    remote: Map<string, RemoteEntry>,
    journal: Record<string, SyncRecord>,
  ): PlannedOp[] {
    const paths = new Set<string>([
      ...locals.keys(),
      ...Object.keys(journal),
      ...remote.keys(),
    ]);

    const ops: PlannedOp[] = [];
    for (const path of paths) {
      if (!isSyncablePath(path, this.configDir)) continue;

      const local: TFile | undefined = locals.get(path);
      const record: SyncRecord | undefined = journal[path];
      const entry: RemoteEntry | undefined = remote.get(path);
      const rem: RemoteFileInfo | undefined = entry?.info;
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
   * More than this many (or this fraction of) remote deletions in one cycle
   * requires the user's explicit consent — guards against server-side wipes.
   */
  private massDeleteThreshold(localCount: number): number {
    return Math.max(5, Math.floor(localCount * 0.1));
  }

  // ------------------------------------------------------------ execution

  private async executePlan(plan: PlannedOp[], setup: SyncSetup): Promise<SyncSummary> {
    const summary: SyncSummary = {
      pushed: 0,
      pulled: 0,
      conflicts: 0,
      deletedLocal: 0,
      deletedRemote: 0,
      failures: [],
    };

    for (const op of plan) {
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
          case 'delete-local':
            await this.doDeleteLocal(op, summary);
            break;
          case 'delete-remote':
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

    if (file.stat.size > MAX_SYNCABLE_BYTES) {
      throw new Error(
        `${op.path} is ${Math.round(file.stat.size / 1048576)} MB — above the sync limit of ` +
          `${Math.round(MAX_SYNCABLE_BYTES / 1048576)} MB. Sync it manually or raise the limit.`,
      );
    }

    const plaintext = await this.ctx.app.vault.readBinary(file);
    const packet = await setup.crypto.encrypt(plaintext, setup.salt, op.path);
    const cipherHash = await sha256Hex(new Uint8Array(packet));
    const uploaded = await setup.api.upload(op.path, packet, file.stat.mtime, cipherHash);

    this.ctx.setJournalEntry(op.path, {
      localMtime: file.stat.mtime,
      remoteHash: uploaded && uploaded.hash ? uploaded.hash : cipherHash,
      remoteMtime: uploaded && uploaded.mtime ? uploaded.mtime : Date.now(),
    });
    this.markJournalDirty();
    summary.pushed++;
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

    const plaintext = await setup.crypto.decrypt(packet, op.path); // CryptoError on wrong password

    // Match the local counterpart under its on-disk name when we know it.
    const existing = this.ctx.app.vault.getAbstractFileByPath(op.local ? op.local.path : op.path);
    if (existing && !(existing instanceof TFile)) {
      throw new Error(`Local path exists but is a folder: ${op.path}`);
    }

    this.beginIgnore(op.path); // our own write must not re-trigger sync
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

    // The write bumps the local mtime to "now" — the journal must record that
    // exact value, otherwise the next cycle would mistake our own pull for a
    // local modification and push it right back.
    const written = this.ctx.app.vault.getAbstractFileByPath(op.path);
    this.ctx.setJournalEntry(op.path, {
      localMtime: written instanceof TFile ? written.stat.mtime : Date.now(),
      remoteHash: remote.hash,
      remoteMtime: remote.mtime,
    });
    this.markJournalDirty();
    summary.pulled++;
  }

  /**
   * "Keep both" conflict resolution — ordered so a failure never leaves
   * duplicate debris and a retry is idempotent:
   *  1. upload the local version to <name>_conflict_<timestamp>.<ext> FIRST,
   *  2. only then create the local copy of it and journal it,
   *  3. download the remote version into the original path.
   */
  private async doConflict(op: PlannedOp, setup: SyncSetup, summary: SyncSummary): Promise<void> {
    const local = op.local;
    if (!local) return;

    const conflictPath = this.uniqueConflictPath(op.path);
    const localCopy = await this.ctx.app.vault.readBinary(local);

    // 1. Preserve the local version remotely first — a network failure here
    //    leaves no local debris and the next cycle simply retries.
    const packet = await setup.crypto.encrypt(localCopy, setup.salt, conflictPath);
    const cipherHash = await sha256Hex(new Uint8Array(packet));
    const uploaded = await setup.api.upload(conflictPath, packet, local.stat.mtime, cipherHash);

    // 2. Materialize the copy locally and journal it.
    this.beginIgnore(conflictPath);
    try {
      await this.ctx.app.vault.createBinary(conflictPath, localCopy);
    } catch (error) {
      this.ignorePaths.delete(conflictPath);
      throw error;
    }
    const written = this.ctx.app.vault.getAbstractFileByPath(conflictPath);
    this.ctx.setJournalEntry(conflictPath, {
      localMtime: written instanceof TFile ? written.stat.mtime : local.stat.mtime,
      remoteHash: uploaded && uploaded.hash ? uploaded.hash : cipherHash,
      remoteMtime: uploaded && uploaded.mtime ? uploaded.mtime : Date.now(),
    });
    this.markJournalDirty();

    // 3. Remote wins the original path.
    await this.doPull({ ...op, local: undefined, remoteKey: op.remoteKey }, setup, summary);

    summary.conflicts++;
    this.ctx.notify(
      `Conflict detected in file: ${op.path}\nBoth versions kept — local copy saved as: ${conflictPath}`,
      10000,
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

  // ------------------------------------------------------------- plumbing

  private async ensureSetup(): Promise<SyncSetup> {
    const settings = this.ctx.getSettings();
    const signature = `${settings.serverUrl}\u0000${settings.apiToken}`;
    if (!this.api || this.apiSignature !== signature) {
      this.api = new SyncApi(settings.serverUrl, settings.apiToken);
      this.apiSignature = signature;
    }

    // Fetch meta every run: it is one tiny request and detects a server wipe
    // (new vaultId) whose salt change invalidates the cached key.
    const meta = await this.api.getMeta();
    if (
      !this.crypto ||
      this.cryptoPassword !== settings.encryptionPassword ||
      this.vaultId !== meta.vaultId
    ) {
      const salt = await saltFromVaultId(meta.vaultId);
      // expectedSalt: packets carrying a foreign salt are rejected before the
      // expensive PBKDF2 pass (hostile-server CPU exhaustion defense).
      this.salt = salt;
      this.crypto = new CryptoManager(settings.encryptionPassword, salt);
      this.cryptoPassword = settings.encryptionPassword;
      this.vaultId = meta.vaultId;
    }
    const salt = this.salt;
    if (!salt || !this.crypto) throw new Error('Crypto setup failed unexpectedly.');
    const setup: SyncSetup = { api: this.api, crypto: this.crypto, salt };
    await this.ensurePasswordVerifier(setup);
    return setup;
  }

  /**
   * Fail-closed key check: refuse to touch vault data unless this device's
   * password decrypts the vault verifier stored at a reserved server path.
   * This is what stops a wrongly-configured second device from overwriting
   * the whole store with ciphertext nobody else can decrypt. A verifier
   * mis-seeded onto an otherwise EMPTY server may be re-created; on a
   * non-empty vault a mismatch is fatal.
   */
  private async ensurePasswordVerifier(setup: SyncSetup): Promise<void> {
    let packet: ArrayBuffer | null = null;
    try {
      packet = await setup.api.download(VERIFIER_PATH);
    } catch (error) {
      if (!(error instanceof ApiError) || error.status !== 404) throw error;
    }

    if (packet) {
      let matches = false;
      try {
        const plain = new Uint8Array(await setup.crypto.decrypt(packet, VERIFIER_PATH));
        matches =
          plain.length === VERIFIER_PLAINTEXT.length && bytesEqual(plain, VERIFIER_PLAINTEXT);
      } catch (error) {
        if (error instanceof CryptoError) {
          matches = false; // authentication failure — likely wrong password
        } else {
          throw error;
        }
      }
      if (matches) return;

      const index = await setup.api.getIndex();
      const liveFiles = Object.entries(index.files).filter(
        ([p, f]) => canonicalPath(p) !== VERIFIER_PATH && f && !f.deleted,
      ).length;
      if (liveFiles > 0) {
        throw new CryptoError(
          'Wrong E2EE password for this vault (verifier check failed). Correct it in the ' +
            'plugin settings before syncing — nothing was changed on the server.',
        );
      }
      // Verifier from a misconfigured device, vault still empty: safe to re-seed.
    }

    const seeded = await setup.crypto.encrypt(
      VERIFIER_PLAINTEXT.buffer as ArrayBuffer,
      setup.salt,
      VERIFIER_PATH,
    );
    await setup.api.upload(
      VERIFIER_PATH,
      seeded,
      Date.now(),
      await sha256Hex(new Uint8Array(seeded)),
    );
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
      await this.ctx.app.vault.createFolder(current);
    }
  }

  private conflictStamp(d = new Date()): string {
    const pad = (n: number) => String(n).padStart(2, '0');
    return (
      `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}` +
      `_${pad(d.getHours())}-${pad(d.getMinutes())}-${pad(d.getSeconds())}`
    );
  }

  /** filename.md -> filename_conflict_YYYY-MM-DD_HH-mm-ss.md */
  private uniqueConflictPath(original: string): string {
    const slash = original.lastIndexOf('/');
    const dir = slash >= 0 ? original.slice(0, slash + 1) : '';
    const name = slash >= 0 ? original.slice(slash + 1) : original;
    const dot = name.lastIndexOf('.');
    const base = dot > 0 ? name.slice(0, dot) : name;
    const ext = dot > 0 ? name.slice(dot) : '';

    let candidate = `${dir}${base}_conflict_${this.conflictStamp()}${ext}`;
    let attempt = 2;
    while (this.ctx.app.vault.getAbstractFileByPath(candidate)) {
      candidate = `${dir}${base}_conflict_${this.conflictStamp()}_${attempt++}${ext}`;
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
