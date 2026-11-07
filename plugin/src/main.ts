/**
 * E2EE Vault Sync — plugin entry point.
 *
 * Lifecycle, vault event wiring (deferred until layout is ready so initial
 * vault indexing never looks like user activity), status UI (status bar on
 * desktop, mirrored on the ribbon icon because the status bar is hidden on
 * mobile), the command palette entry, and the security-relevant UI prompts
 * (mass-deletion confirmation, per-session E2EE password).
 */

import { Modal, Notice, Plugin, TFile, setIcon } from 'obsidian';
import type { App } from 'obsidian';
import { SyncEngine, canonicalPath } from './syncEngine';
import type { ConflictResolution } from './syncEngine';
import { E2eeSyncSettingTab } from './settings';
import { DEFAULT_CONFIG_SYNC, DEFAULT_SETTINGS } from './types';
import type { PluginData, PluginSettings, SyncRecord, SyncStatus } from './types';
import type { ProgressLike } from './util';
import { errorMessage, formatProgress } from './util';

const STARTUP_SYNC_DELAY_MS = 4000;

/** Generic two-button confirmation dialog resolving to true (confirm) / false. */
function confirmDialog(app: App, title: string, body: string, confirmText: string): Promise<boolean> {
  return new Promise((resolve) => {
    let settled = false;
    const settle = (value: boolean) => {
      if (!settled) {
        settled = true;
        resolve(value);
      }
    };
    new (class extends Modal {
      constructor() {
        super(app);
      }
      onOpen(): void {
        this.titleEl.setText(title);
        this.contentEl.createEl('p', { text: body });
        const row = this.contentEl.createDiv({ cls: 'modal-button-container' });
        const cancel = row.createEl('button', { text: 'Cancel' });
        const confirm = row.createEl('button', { text: confirmText, cls: 'mod-cta' });
        cancel.onclick = () => {
          settle(false);
          this.close();
        };
        confirm.onclick = () => {
          settle(true);
          this.close();
        };
      }
      onClose(): void {
        settle(false); // dismissed via Esc/backdrop — treat as "keep local files"
        super.onClose();
      }
    })().open();
  });
}

/** One-shot password prompt for session-only password mode. */
class PasswordPromptModal extends Modal {
  constructor(app: App, private readonly onSubmit: (password: string | null) => void) {
    super(app);
  }

  onOpen(): void {
    let settled = false;
    const settle = (value: string | null) => {
      if (!settled) {
        settled = true;
        this.onSubmit(value);
      }
    };
    this.titleEl.setText('E2EE Sync: E2EE password required');
    this.contentEl.createEl('p', {
      text:
        'This device is configured to keep the E2EE password in memory only. ' +
        'Enter it to unlock sync for this session — it will not be written to disk.',
    });
    const input = this.contentEl.createEl('input', { type: 'password' });
    input.placeholder = 'E2EE password';
    const row = this.contentEl.createDiv({ cls: 'modal-button-container' });
    const cancel = row.createEl('button', { text: 'Not now' });
    const unlock = row.createEl('button', { text: 'Unlock sync', cls: 'mod-cta' });
    const submit = () => {
      settle(input.value || null);
      this.close();
    };
    cancel.onclick = () => {
      settle(null);
      this.close();
    };
    unlock.onclick = submit;
    input.addEventListener('keydown', (evt) => {
      if (evt.key === 'Enter') submit();
    });
    window.setTimeout(() => input.focus(), 50);
  }

  onClose(): void {
    // Esc/backdrop close without a choice: nothing to do — onSubmit was either
    // already called by the buttons or the user will trigger sync again.
    super.onClose();
  }
}

/** PROB-10: integrity report with grouped issues and a repair-all action. */
class IntegrityReportModal extends Modal {
  constructor(
    app: App,
    private readonly hashMismatch: string[],
    private readonly decryptFailed: string[],
    private readonly otherFailures: string[],
    private readonly onAction: (repair: boolean) => void,
  ) {
    super(app);
  }

  onOpen(): void {
    this.titleEl.setText('E2EE Sync: integrity problems found');
    const list = (title: string, items: string[]) => {
      if (items.length === 0) return;
      this.contentEl.createEl('h4', { text: `${title} (${items.length})` });
      const ul = this.contentEl.createEl('ul');
      for (const item of items.slice(0, 20)) ul.createEl('li', { text: item });
      if (items.length > 20) ul.createEl('li', { text: `… and ${items.length - 20} more` });
    };
    list('Stored bytes do not match the server index (rollback or corruption)', this.hashMismatch);
    list('Cannot be decrypted with this device\u2019s key (wrong password or foreign key)', this.decryptFailed);
    list('Other failures', this.otherFailures);

    this.contentEl.createEl('p', {
      text:
        'Repair re-uploads the intact local copy of every affected file (version history ' +
        'advances by one). Files without a healthy local copy are skipped.',
    });
    const row = this.contentEl.createEl('div', { cls: 'modal-button-container' });
    const close = row.createEl('button', { text: 'Close' });
    const repair = row.createEl('button', { text: 'Repair from local copies', cls: 'mod-warning' });
    const done = (value: boolean) => {
      this.close();
      void this.onAction(value);
    };
    close.onclick = () => done(false);
    repair.onclick = () => done(true);
  }
}

/** IMP-2: per-conflict decision modal. Esc/backdrop = keep both (old default). */
class ConflictModal extends Modal {
  constructor(
    app: App,
    private readonly path: string,
    private readonly onSubmit: (choice: ConflictResolution | null) => void,
  ) {
    super(app);
  }

  onOpen(): void {
    let settled = false;
    const settle = (value: ConflictResolution | null) => {
      if (!settled) {
        settled = true;
        this.onSubmit(value);
      }
    };
    this.titleEl.setText('E2EE Sync: conflict');
    this.contentEl.createEl('p', {
      text:
        `This device and the server both changed "${this.path}". ` +
        'Choose which version to keep — the other one will not survive this choice.',
    });
    const row = this.contentEl.createEl('div', { cls: 'modal-button-container' });
    const button = (text: string, cls: string, choice: ConflictResolution | null, confirm = false) => {
      const b = row.createEl('button', { text, cls: confirm ? 'mod-cta' : cls });
      b.onclick = () => {
        settle(choice);
        this.close();
      };
      return b;
    };
    button('Keep mine', '', 'mine');
    button('Keep remote', '', 'remote');
    button('Keep both', '', 'both', true);
    button('Skip', '', 'skip');
    this.contentEl.createEl('p', {
      text: '"Keep mine" uploads your version (the server copy is replaced). "Keep remote" discards ' +
        'your local edits. "Keep both" saves your version as a _conflict_ copy. "Skip" decides nothing ' +
        'and asks again on the next sync.',
      cls: 'setting-item-description',
    });
  }

  onClose(): void {
    this.onSubmit(null); // settled guard in onSubmit's owner maps null to keep-both
    super.onClose();
  }
}

export default class E2eeSyncPlugin extends Plugin {
  settings: PluginSettings = { ...DEFAULT_SETTINGS };
  journal: Record<string, SyncRecord> = {};
  /** IMP-6: separate journal section for the config/ server namespace. */
  configJournal: Record<string, SyncRecord> = {};
  engine!: SyncEngine;

  /** Live password when rememberEncryptionPassword is false (never persisted). */
  sessionPassword = '';

  private statusBarEl: HTMLElement | null = null;
  private ribbonEl: HTMLElement | null = null;
  private autoSyncTimer: number | null = null;
  private readonly oneShotTimers = new Set<number>();
  private lastErrorNotice = '';

  /** The password in force right now: persisted value or the session value. */
  get effectivePassword(): string {
    return this.settings.rememberEncryptionPassword
      ? this.settings.encryptionPassword
      : this.sessionPassword;
  }

  async onload(): Promise<void> {
    const data: PluginData = (await this.loadData()) ?? {};
    this.settings = {
      ...DEFAULT_SETTINGS,
      ...(data.settings ?? {}),
      // Nested group defaults survive partial persisted configSync objects.
      configSync: { ...DEFAULT_CONFIG_SYNC, ...(data.settings?.configSync ?? {}) },
    };
    this.journal = data.journal ?? {};
    this.configJournal = data.configJournal ?? {};

    // Migrate pre-NFC journal keys so records survive the canonicalization of
    // paths (iOS/macOS NFD spellings now share one canonical key). Records
    // from pre-v3 releases gain a zero version counter (no v3 packet seen).
    for (const key of Object.keys(this.journal)) {
      const canonical = canonicalPath(key);
      const record = this.journal[key];
      delete this.journal[key];
      if (record) {
        record.remoteVersion ??= 0;
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
      getConfigJournal: () => this.configJournal,
      setConfigJournalEntry: (path, record) => {
        if (record) this.configJournal[path] = record;
        else delete this.configJournal[path];
      },
      persist: () => this.saveData({ settings: this.settings, journal: this.journal, configJournal: this.configJournal }),
      setStatus: (status, message) => this.updateStatus(status, message),
      notify: (message, timeout) => new Notice(message, timeout ?? 6000),
      confirmMassDeletion: (deletedCount, localCount) =>
        confirmDialog(
          this.app,
          'E2EE Sync: mass deletion detected',
          `The server reports ${deletedCount} of your ${localCount} files as deleted. ` +
            'This can mean another device cleaned the vault — or that the server (or API token) was ' +
            'compromised. "Keep my local files" cancels these deletions; the kept files are re-uploaded ' +
            'on the next sync, so nothing is lost either way.',
          'Delete as instructed',
        ),
      promptPassword: (reason) => this.promptForChangedPassword(reason),
      resolveConflict: (path) =>
        new Promise<ConflictResolution | null>((resolve) => {
          new ConflictModal(this.app, path, resolve).open();
        }),
      setProgress: (progress) => this.showProgress(progress),
    });

    this.addSettingTab(new E2eeSyncSettingTab(this.app, this));

    this.ribbonEl = this.addRibbonIcon('refresh-cw', 'E2EE Sync: sync now', () => {
      this.requestManualSync();
    });

    // Hidden by Obsidian on mobile — the ribbon icon mirrors the state there.
    this.statusBarEl = this.addStatusBarItem();

    this.addCommand({
      id: 'force-full-sync',
      name: 'Force full sync',
      callback: () => this.requestManualSync(),
    });

    this.addCommand({
      id: 'enter-session-password',
      name: 'Enter the E2EE password for this session',
      callback: () => this.promptForSessionPassword(),
    });

    this.addCommand({
      id: 'verify-vault-integrity',
      name: 'Verify vault integrity',
      callback: () => this.runIntegrityCheck(),
    });

    this.addCommand({
      id: 'restore-from-server',
      name: 'Restore from server',
      callback: () => void this.runRestoreFromServer(),
    });

    // Event subscriptions happen only once the vault is fully loaded,
    // otherwise initial indexing would masquerade as thousands of edits.
    this.app.workspace.onLayoutReady(() => this.onLayoutReady());

    this.updateStatus('idle');
  }

  onunload(): void {
    // Persist any journal mutations since the last engine flush (up to 19 ops
    // can otherwise be lost when Obsidian closes mid-sync).
    void this.saveData({ settings: this.settings, journal: this.journal, configJournal: this.configJournal }).catch(() => {});
    this.engine?.dispose();
    if (this.autoSyncTimer !== null) window.clearInterval(this.autoSyncTimer);
    for (const t of this.oneShotTimers) window.clearTimeout(t);
    this.oneShotTimers.clear();
  }

  // ------------------------------------------------------------- settings

  async saveSettings(): Promise<void> {
    const settings: PluginSettings = {
      ...this.settings,
      encryptionPassword: this.settings.rememberEncryptionPassword
        ? this.settings.encryptionPassword
        : '', // session-only mode: the password never reaches data.json
    };
    await this.saveData({ settings, journal: this.journal, configJournal: this.configJournal });
  }

  /**
   * PROB-1: a password change no longer resets the journal — it streams a
   * coordinated rotation (seed new verifier → re-encrypt every live file with
   * version counters carried over → drop the old verifier). Other devices are
   * prompted for the new password on their next sync. The journal survives.
   */
  async onEncryptionPasswordChanged(oldPassword: string): Promise<void> {
    const newPassword = this.effectivePassword;
    if (!oldPassword || oldPassword === newPassword) {
      await this.saveSettings();
      return;
    }
    const confirmed = await confirmDialog(
      this.app,
      'E2EE Sync: rotate the vault encryption key?',
      'Every file on the server will be downloaded, re-encrypted with the new password and ' +
        're-uploaded (version history is preserved). Run this on the most up-to-date device first; ' +
        'other devices will ask for the new password on their next sync. Keep the device awake ' +
        'until the rotation finishes.',
      'Rotate now',
    );
    if (!confirmed) {
      // Declined: restore the previous password.
      if (this.settings.rememberEncryptionPassword) {
        this.settings.encryptionPassword = oldPassword;
      } else {
        this.sessionPassword = oldPassword;
        this.settings.encryptionPassword = '';
      }
      await this.saveSettings();
      new Notice('E2EE Sync: rotation cancelled — the previous password stays in force.', 8000);
      return;
    }

    this.updateStatus('syncing', 'rotating encryption keys…');
    try {
      await this.engine.rotatePassword(oldPassword, newPassword);
      this.updateStatus('synced');
      this.setAutoSync(this.settings.autoSyncMinutes);
      this.engine.requestSync();
    } catch (error) {
      // Fail-closed: restore the old password, nothing was modified.
      if (this.settings.rememberEncryptionPassword) {
        this.settings.encryptionPassword = oldPassword;
      } else {
        this.sessionPassword = oldPassword;
        this.settings.encryptionPassword = '';
      }
      await this.saveSettings();
      this.updateStatus('error', errorMessage(error));
      new Notice(`E2EE Sync: rotation failed — ${errorMessage(error)}`, 12000);
    }
  }

  /** Engine callback: verifiers of unknown keys exist — the password changed elsewhere. */
  private async promptForChangedPassword(reason: 'changed' | 'wrong'): Promise<string | null> {
    const app = this.app;
    const title = reason === 'changed'
      ? 'E2EE Sync: the E2EE password was changed on another device'
      : 'E2EE Sync: this E2EE password does not match the vault';
    return new Promise((resolve) => {
      new (class extends Modal {
        constructor() {
          super(app);
        }
        onOpen(): void {
          this.titleEl.setText(title);
          this.contentEl.createEl('p', {
            text:
              'Enter the current E2EE password to unlock sync for this vault. ' +
              'Nothing is uploaded until the password is confirmed against the server verifier.',
          });
          const input = this.contentEl.createEl('input', { type: 'password' });
          input.placeholder = 'Current E2EE password';
          const row = this.contentEl.createEl('div', { cls: 'modal-button-container' });
          const cancel = row.createEl('button', { text: 'Not now' });
          const unlock = row.createEl('button', { text: 'Unlock sync', cls: 'mod-cta' });
          const submit = () => {
            this.close();
            resolve(input.value || null);
          };
          cancel.onclick = () => {
            this.close();
            resolve(null);
          };
          unlock.onclick = submit;
          input.addEventListener('keydown', (evt) => {
            if (evt.key === 'Enter') submit();
          });
          window.setTimeout(() => input.focus(), 50);
        }
        onClose(): void {
          super.onClose();
        }
      })().open();
    });
  }

  // ------------------------------------------------------------- syncing

  requestManualSync(): void {
    if (!this.settings.serverUrl || !this.settings.apiToken) {
      new Notice('E2EE Sync: set the server URL and API token in the plugin settings first.', 6000);
      return;
    }
    if (!this.effectivePassword) {
      this.promptForSessionPassword();
      return;
    }
    // Interactive run: conflict modals are allowed without the batch limit.
    void this.engine.runFullSync(true);
  }

  /** PROB-10: verify every remote entry (hash + decryptability), offer repair. */
  private async runIntegrityCheck(): Promise<void> {
    if (!this.settings.serverUrl || !this.settings.apiToken || !this.effectivePassword) {
      new Notice('E2EE Sync: configure the plugin before verifying integrity.', 6000);
      return;
    }
    this.updateStatus('syncing', 'verifying vault integrity…');
    const report = await this.engine.verifyIntegrity();
    if (!report) {
      this.updateStatus('error', 'integrity verification failed');
      return;
    }

    const issues = [...report.hashMismatch, ...report.decryptFailed];
    if (issues.length === 0 && report.failures.length === 0) {
      this.updateStatus('synced');
      new Notice(
        `✅ E2EE Sync: integrity verified — ${report.checked} file(s) checked, no problems found.`,
        8000,
      );
      return;
    }

    this.updateStatus('error', `${issues.length} integrity problem(s)`);
    new IntegrityReportModal(
      this.app,
      report.hashMismatch,
      report.decryptFailed,
      report.failures.map((f) => `${f.path} — ${f.error}`),
      async (repair) => {
        if (!repair) return;
        this.updateStatus('syncing', 'repairing…');
        const { repaired, skipped } = await this.engine.repairPaths(issues);
        this.updateStatus(repaired.length > 0 ? 'synced' : 'error');
        new Notice(
          `E2EE Sync: repaired ${repaired.length} file(s) from local copies` +
            (skipped.length > 0 ? `; ${skipped.length} skipped (no intact local copy: ${skipped.slice(0, 3).join(', ')}…)` : '.'),
          12000,
        );
      },
    ).open();
  }

  /** Ask for the password when session-only mode has nothing in memory. */
  private promptForSessionPassword(): void {
    if (this.settings.rememberEncryptionPassword || this.sessionPassword) return;
    new PasswordPromptModal(this.app, (password) => {
      if (!password) {
        this.updateStatus('error', 'E2EE password not entered (session-only mode)');
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
  private async runRestoreFromServer(): Promise<void> {
    if (!this.settings.serverUrl || !this.settings.apiToken || !this.effectivePassword) {
      new Notice('E2EE Sync: configure the plugin before restoring.', 6000);
      return;
    }
    this.updateStatus('syncing', 'preparing restore…');
    const result = await this.engine.restoreFromServer(async (liveCount) =>
      confirmDialog(
        this.app,
        'E2EE Sync: restore from server?',
        `The server holds ${liveCount} file(s). This wipes this device's sync journal and re-downloads ` +
          'everything from scratch. Local files are never deleted — files that already exist are ' +
          'overwritten with the server copy, and files the server does not have stay where they are. ' +
          'Use this on a new or broken device.',
        'Restore now',
      ),
    );
    if (!result) return; // cancelled or failed — the engine already notified
    new Notice(
      `E2EE Sync: restore finished — ${result.pulled} file(s) downloaded` +
        (result.failures > 0 ? `, ${result.failures} failed.` : '.'),
      10000,
    );
  }

  /** (Re)install the periodic sync timer; minutes <= 0 disables it. */
  setAutoSync(minutes: number): void {
    if (this.autoSyncTimer !== null) {
      window.clearInterval(this.autoSyncTimer);
      this.autoSyncTimer = null;
    }
    const m = Math.min(Math.max(Math.floor(minutes), 0), 1440);
    if (m <= 0 || !this.isConfigured()) return;
    this.autoSyncTimer = window.setInterval(
      () => this.engine.requestSync(),
      m * 60_000,
    );
  }

  private isConfigured(): boolean {
    const s = this.settings;
    return Boolean(s.serverUrl && s.apiToken && this.effectivePassword);
  }

  private onLayoutReady(): void {
    this.registerEvent(
      this.app.vault.on('create', (file) => {
        if (file instanceof TFile) this.engine.onLocalCreated(file.path);
      }),
    );
    this.registerEvent(
      this.app.vault.on('modify', (file) => {
        if (file instanceof TFile) this.engine.onLocalModified(file.path);
      }),
    );
    this.registerEvent(
      this.app.vault.on('delete', (file) => {
        if (file instanceof TFile) this.engine.onLocalDeleted(file.path);
      }),
    );
    // rename == DELETE oldPath + UPLOAD newPath (handled by the sync rules).
    this.registerEvent(
      this.app.vault.on('rename', (file, oldPath) => {
        if (file instanceof TFile) this.engine.onLocalRenamed(oldPath, file.path);
      }),
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
  private showProgress(progress: ProgressLike): void {
    const text = formatProgress(progress);
    if (this.statusBarEl) this.statusBarEl.setText(`E2EE Sync: ${text}`);
    if (this.ribbonEl) this.ribbonEl.setAttribute('aria-label', `E2EE Sync: ${text}`);
  }

  private updateStatus(status: SyncStatus, message?: string): void {
    const icons: Record<SyncStatus, string> = {
      idle: 'refresh-cw',
      syncing: 'refresh-cw',
      synced: 'check',
      error: 'alert-triangle',
      offline: 'cloud-off',
    };
    const labels: Record<SyncStatus, string> = {
      idle: 'idle',
      syncing: 'syncing…',
      synced: 'synced',
      error: 'error',
      offline: 'offline',
    };

    if (this.ribbonEl) {
      setIcon(this.ribbonEl, icons[status]);
      this.ribbonEl.className = `clickable-icon ribbon-clickable e2ee-ribbon-${status}`;
      this.ribbonEl.setAttribute('aria-label', `E2EE Sync: ${message ?? labels[status]}`);
    }

    if (this.statusBarEl) {
      this.statusBarEl.setText(`E2EE Sync: ${labels[status]}`);
      this.statusBarEl.className = `status-bar-item e2ee-${status}`;
      if (message) this.statusBarEl.setAttribute('aria-label', message);
    }

    if ((status === 'error' || status === 'offline') && message && message !== this.lastErrorNotice) {
      this.lastErrorNotice = message;
      new Notice(`E2EE Sync: ${message}`, 8000);
    }
    if (status === 'syncing') this.lastErrorNotice = '';
  }
}

// Re-export for convenience in dev tools / future tests.
export { errorMessage };
