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
 */

import { TFile, TFolder } from 'obsidian';
import type { App } from 'obsidian';
import { ApiError, SyncApi } from './api';
import { CryptoManager, saltFromVaultId, sha256Hex } from './crypto';
import type { PluginSettings, RemoteFileInfo, SyncRecord, SyncStatus } from './types';
import { errorMessage } from './util';

/** Per-file debounce window for local vault events (ms). */
const DEBOUNCE_MS = 2500;
/** How long a path stays in the ignore set after our own write (ms). */
const IGNORE_WINDOW_MS = 500;
/** Persist the journal at least every N mutations (plus once per sync run). */
const JOURNAL_FLUSH_EVERY = 20;

/** Vault folders that must never round-trip to the server. */
const EXCLUDED_PREFIXES = ['.obsidian/', '.trash/'];

export function isSyncablePath(p: string): boolean {
  for (const prefix of EXCLUDED_PREFIXES) {
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
  path: string;
  local?: TFile;
  remote?: RemoteFileInfo;
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
}

export class SyncEngine {
  private api: SyncApi | null = null;
  private apiSignature = '';
  private crypto: CryptoManager | null = null;
  private cryptoPassword = '';
  private vaultId = '';
  private salt: Uint8Array | null = null;

  /** Paths we are writing ourselves; vault events for them are ignored. */
  private readonly ignorePaths = new Set<string>();
  /** Per-path debounce timers, keyed by path. */
  private readonly debounces = new Map<string, number>();
  /** All pending raw timer ids so dispose() can clear everything. */
  private readonly pendingTimers = new Set<number>();

  private running = false;
  private rerunRequested = false;
  private journalOpsSinceFlush = 0;

  constructor(private readonly ctx: EngineContext) {}

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
    const oldSyncable = isSyncablePath(oldPath);
    const newSyncable = isSyncablePath(newPath);
    if (oldSyncable) this.onLocalTouched(oldPath);
    if (newSyncable) this.onLocalTouched(newPath);
  }

  private onLocalTouched(path: string): void {
    if (!isSyncablePath(path) || this.ignorePaths.has(path)) return;
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
      const remote = remoteIndex.files ?? {};
      const locals = this.collectLocalFiles();
      const journal = this.ctx.getJournal();

      const plan = this.planSync(locals, remote, journal);
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

  private collectLocalFiles(): Map<string, TFile> {
    const out = new Map<string, TFile>();
    for (const file of this.ctx.app.vault.getFiles()) {
      if (isSyncablePath(file.path)) out.set(file.path, file);
    }
    return out;
  }

  /** Pure decision function — no I/O, straightforward to reason about. */
  private planSync(
    locals: Map<string, TFile>,
    remote: Record<string, RemoteFileInfo>,
    journal: Record<string, SyncRecord>,
  ): PlannedOp[] {
    const paths = new Set<string>([
      ...locals.keys(),
      ...Object.keys(journal),
      ...Object.keys(remote),
    ]);

    const ops: PlannedOp[] = [];
    for (const path of paths) {
      if (!isSyncablePath(path)) continue;

      const local: TFile | undefined = locals.get(path);
      const record: SyncRecord | undefined = journal[path];
      const rem: RemoteFileInfo | undefined = remote[path];

      if (rem && !rem.deleted) {
        // ---- live remote entry -------------------------------------------
        const remoteChanged = !record || rem.hash !== record.remoteHash;
        if (local) {
          const localChanged = !record || local.stat.mtime > record.localMtime;
          if (localChanged && remoteChanged) {
            if (record) {
              ops.push({ action: 'conflict', path, local, remote: rem });
            } else if (rem.mtime >= local.stat.mtime) {
              // Both sides known, never synced on this device (typical when
              // restoring a vault from a backup): newest mtime wins.
              ops.push({ action: 'pull', path, local, remote: rem });
            } else {
              ops.push({ action: 'push', path, local, remote: rem });
            }
          } else if (localChanged) {
            ops.push({ action: 'push', path, local });
          } else if (remoteChanged) {
            ops.push({ action: 'pull', path, local, remote: rem });
          }
          // else: identical on both ends — nothing to do.
        } else if (record && !remoteChanged) {
          // Deleted locally, untouched remotely -> propagate the deletion.
          ops.push({ action: 'delete-remote', path, remote: rem });
        } else {
          // No local copy; either a brand-new device or the file was deleted
          // locally while remotely modified -> remote wins, pull it back.
          ops.push({ action: 'pull', path, remote: rem });
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
            await this.doPush(op.path, setup, summary);
            break;
          case 'pull':
            await this.doPull(op, setup, summary);
            break;
          case 'conflict':
            await this.doConflict(op, setup, summary);
            break;
          case 'delete-local':
            await this.doDeleteLocal(op.path, summary);
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
  private async doPush(path: string, setup: SyncSetup, summary: SyncSummary): Promise<void> {
    const file = this.ctx.app.vault.getAbstractFileByPath(path);
    if (!(file instanceof TFile)) return; // deleted mid-sync; next cycle tombstones it

    const plaintext = await this.ctx.app.vault.readBinary(file);
    const packet = await setup.crypto.encrypt(plaintext, setup.salt);
    const cipherHash = await sha256Hex(packet);
    const uploaded = await setup.api.upload(path, packet, file.stat.mtime, cipherHash);

    this.ctx.setJournalEntry(path, {
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
      packet = await setup.api.download(op.path);
    } catch (error) {
      if (error instanceof ApiError && error.status === 404) {
        // Deleted on another device between index and download — accept it.
        this.ctx.setJournalEntry(op.path, null);
        this.markJournalDirty();
        return;
      }
      throw error;
    }

    const plaintext = await setup.crypto.decrypt(packet); // CryptoError on wrong password

    const existing = this.ctx.app.vault.getAbstractFileByPath(op.path);
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
   * "Keep both" conflict resolution:
   *  1. copy the local version to <name>_conflict_<timestamp>.<ext> and push
   *     that copy immediately (it must not depend on a later sync cycle),
   *  2. download the remote version into the original path.
   */
  private async doConflict(op: PlannedOp, setup: SyncSetup, summary: SyncSummary): Promise<void> {
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

    // Push the preserved local copy right away.
    await this.doPush(conflictPath, setup, summary);

    // Remote wins the original path.
    await this.doPull({ ...op, local: undefined }, setup, summary);

    summary.conflicts++;
    this.ctx.notify(
      `Conflict detected in file: ${op.path}\nBoth versions kept — local copy saved as: ${conflictPath}`,
      10000,
    );
  }

  private async doDeleteLocal(path: string, summary: SyncSummary): Promise<void> {
    const file = this.ctx.app.vault.getAbstractFileByPath(path);
    if (file instanceof TFile) {
      this.beginIgnore(path);
      try {
        await this.ctx.app.vault.trash(file, true); // system trash; .trash is excluded from sync
      } catch (error) {
        this.ignorePaths.delete(path);
        throw error;
      }
    }
    this.ctx.setJournalEntry(path, null);
    this.markJournalDirty();
    summary.deletedLocal++;
  }

  private async doDeleteRemote(op: PlannedOp, setup: SyncSetup, summary: SyncSummary): Promise<void> {
    try {
      await setup.api.deleteFile(op.path);
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
      this.salt = await saltFromVaultId(meta.vaultId);
      this.crypto = new CryptoManager(settings.encryptionPassword);
      this.cryptoPassword = settings.encryptionPassword;
      this.vaultId = meta.vaultId;
    }
    const salt = this.salt;
    if (!salt || !this.crypto) throw new Error('Crypto setup failed unexpectedly.');
    return { api: this.api, crypto: this.crypto, salt };
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
