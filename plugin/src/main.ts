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
import { E2eeSyncSettingTab } from './settings';
import { DEFAULT_SETTINGS } from './types';
import type { PluginData, PluginSettings, SyncRecord, SyncStatus } from './types';
import { errorMessage } from './util';

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

export default class E2eeSyncPlugin extends Plugin {
  settings: PluginSettings = { ...DEFAULT_SETTINGS };
  journal: Record<string, SyncRecord> = {};
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
    this.settings = { ...DEFAULT_SETTINGS, ...(data.settings ?? {}) };
    this.journal = data.journal ?? {};

    // Migrate pre-NFC journal keys so records survive the canonicalization of
    // paths (iOS/macOS NFD spellings now share one canonical key).
    for (const key of Object.keys(this.journal)) {
      const canonical = canonicalPath(key);
      if (canonical !== key) {
        const record = this.journal[key];
        delete this.journal[key];
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
      persist: () => this.saveData({ settings: this.settings, journal: this.journal }),
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

    // Event subscriptions happen only once the vault is fully loaded,
    // otherwise initial indexing would masquerade as thousands of edits.
    this.app.workspace.onLayoutReady(() => this.onLayoutReady());

    this.updateStatus('idle');
  }

  onunload(): void {
    // Persist any journal mutations since the last engine flush (up to 19 ops
    // can otherwise be lost when Obsidian closes mid-sync).
    void this.saveData({ settings: this.settings, journal: this.journal }).catch(() => {});
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
    await this.saveData({ settings, journal: this.journal });
  }

  /**
   * A changed password means every existing journal record is meaningless (the
   * remote ciphertext was produced with a different key). Reset the journal so
   * the next sync re-encrypts and re-uploads everything from this device.
   * (With the password verifier in place, a genuinely wrong password is
   * rejected before any upload; this reset only runs for intentional changes.)
   */
  async onEncryptionPasswordChanged(): Promise<void> {
    this.engine.invalidateCrypto();
    this.journal = {};
    await this.saveSettings();
    new Notice(
      'E2EE password changed. Every file will be re-encrypted and re-uploaded on the next sync — ' +
        'run it first on the device with the most up-to-date vault.',
      12000,
    );
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
    void this.engine.runFullSync();
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
