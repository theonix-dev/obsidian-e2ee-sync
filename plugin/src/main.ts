/**
 * E2EE Vault Sync — plugin entry point.
 *
 * Lifecycle, vault event wiring (deferred until layout is ready so initial
 * vault indexing never looks like user activity), status UI (status bar on
 * desktop, mirrored on the ribbon icon because the status bar is hidden on
 * mobile) and the command palette entry.
 */

import { Notice, Plugin, TFile, setIcon } from 'obsidian';
import { SyncEngine } from './syncEngine';
import { E2eeSyncSettingTab } from './settings';
import { DEFAULT_SETTINGS } from './types';
import type { PluginData, PluginSettings, SyncRecord, SyncStatus } from './types';
import { errorMessage } from './util';

const STARTUP_SYNC_DELAY_MS = 4000;

export default class E2eeSyncPlugin extends Plugin {
  settings: PluginSettings = { ...DEFAULT_SETTINGS };
  journal: Record<string, SyncRecord> = {};
  engine!: SyncEngine;

  private statusBarEl: HTMLElement | null = null;
  private ribbonEl: HTMLElement | null = null;
  private autoSyncTimer: number | null = null;
  private readonly oneShotTimers = new Set<number>();
  private lastErrorNotice = '';

  async onload(): Promise<void> {
    const data: PluginData = (await this.loadData()) ?? {};
    this.settings = { ...DEFAULT_SETTINGS, ...(data.settings ?? {}) };
    this.journal = data.journal ?? {};

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
      notify: (message, timeout) => new Notice(message, timeout ?? 6000),
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

    // Event subscriptions happen only once the vault is fully loaded,
    // otherwise initial indexing would masquerade as thousands of edits.
    this.app.workspace.onLayoutReady(() => this.onLayoutReady());

    this.updateStatus('idle');
  }

  onunload(): void {
    this.engine?.dispose();
    if (this.autoSyncTimer !== null) window.clearInterval(this.autoSyncTimer);
    for (const t of this.oneShotTimers) window.clearTimeout(t);
    this.oneShotTimers.clear();
  }

  // ------------------------------------------------------------- settings

  async saveSettings(): Promise<void> {
    await this.saveData({ settings: this.settings, journal: this.journal });
  }

  /**
   * A changed password means every existing journal record is meaningless (the
   * remote ciphertext was produced with a different key). Reset the journal so
   * the next sync re-encrypts and re-uploads everything from this device.
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
    void this.engine.runFullSync();
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
    return Boolean(s.serverUrl && s.apiToken && s.encryptionPassword);
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
