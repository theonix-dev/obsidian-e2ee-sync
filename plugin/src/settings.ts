/**
 * Settings tab: server URL (HTTPS-validated), API token, E2EE password
 * (masked), auto-sync interval and a connection test button.
 */

import { Notice, PluginSettingTab, Setting } from 'obsidian';
import type { App } from 'obsidian';
import { SyncApi } from './api';
import { deriveKey, saltFromVaultId } from './crypto';
import type E2eeSyncPlugin from './main';
import { errorMessage, validateServerUrl } from './util';

export class E2eeSyncSettingTab extends PluginSettingTab {
  constructor(app: App, private readonly plugin: E2eeSyncPlugin) {
    super(app, plugin);
  }

  display(): void {
    const { containerEl } = this;
    containerEl.empty();

    const s = this.plugin.settings;
    let initialPassword = s.encryptionPassword;

    containerEl.createEl('h2', { text: 'E2EE Vault Sync' });

    const intro = containerEl.createEl('p', {
      cls: 'e2ee-setting-note',
    });
    intro.setText(
      'Files are encrypted on this device (AES-256-GCM, PBKDF2-derived key) before they are uploaded. ' +
        'The server only ever stores ciphertext. File contents never leave this device unencrypted — ' +
        'but note that file paths, sizes and timestamps are visible to the server.',
    );

    // ---------------------------------------------------------- server url
    const urlWarning = containerEl.createEl('div', { cls: 'e2ee-setting-warning' });
    new Setting(containerEl)
      .setName('Server URL')
      .setDesc('Base URL of your sync server, e.g. https://sync.example.com')
      .addText((text) =>
        text
          .setPlaceholder('https://sync.example.com')
          .setValue(s.serverUrl)
          .onChange(async (value) => {
            s.serverUrl = value.trim();
            const problem = validateServerUrl(s.serverUrl);
            urlWarning.setText(problem ?? '');
            await this.plugin.saveSettings();
          }),
      );
    urlWarning.setText(validateServerUrl(s.serverUrl) ?? '');

    // ---------------------------------------------------------- api token
    new Setting(containerEl)
      .setName('API token')
      .setDesc('Bearer token configured on the server (AUTH_TOKEN).')
      .addText((text) => {
        text.inputEl.type = 'password';
        text.setPlaceholder('paste the token');
        return text
          .setValue(s.apiToken)
          .onChange(async (value) => {
            s.apiToken = value.trim();
            await this.plugin.saveSettings();
          });
      });

    // ---------------------------------------------------------- password
    new Setting(containerEl)
      .setName('E2EE password')
      .setDesc(
        'Used to derive the encryption key (PBKDF2, 210 000 iterations). Never sent to the server. ' +
          'All devices syncing this vault must use the same password. Changing it re-encrypts and ' +
          're-uploads every file on the next sync.',
      )
      .addText((text) => {
        text.inputEl.type = 'password';
        return text
          .setValue(s.encryptionPassword)
          .onChange(async (value) => {
            s.encryptionPassword = value;
            await this.plugin.saveSettings();
            if (value !== initialPassword) {
              initialPassword = value;
              await this.plugin.onEncryptionPasswordChanged();
            }
          });
      });

    // ---------------------------------------------------------- auto sync
    new Setting(containerEl)
      .setName('Auto-sync interval (minutes)')
      .setDesc('Sync automatically every N minutes (1–1440). 0 disables periodic sync. Changes also apply immediately.')
      .addText((text) =>
        text
          .setValue(String(s.autoSyncMinutes))
          .onChange(async (value) => {
            const minutes = Math.floor(Number(value));
            s.autoSyncMinutes = Number.isFinite(minutes)
              ? Math.min(Math.max(minutes, 0), 1440)
              : 0;
            await this.plugin.saveSettings();
            this.plugin.setAutoSync(s.autoSyncMinutes);
          }),
      );

    // ---------------------------------------------------------- test conn
    new Setting(containerEl)
      .setName('Connection test')
      .setDesc('Checks reachability, the API token and key derivation (GET /api/index).')
      .addButton((button) =>
        button.setButtonText('Test connection').onClick(async () => {
          const btn = button.buttonEl;
          btn.disabled = true;
          btn.setText('Testing…');
          try {
            if (!s.serverUrl || !s.apiToken) {
              throw new Error('Enter the server URL and API token first.');
            }
            const problem = validateServerUrl(s.serverUrl);
            if (problem) new Notice(`⚠️ ${problem}`, 6000);

            const api = new SyncApi(s.serverUrl, s.apiToken);
            const result = await api.testConnection();

            // Sanity-check that Web Crypto + PBKDF2 work on this device.
            await deriveKey('probe', await saltFromVaultId(result.vaultId), 1000);

            new Notice(
              `✅ Connected — ${result.fileCount} file(s) on the server (vault ${result.vaultId.slice(0, 8)}…).`,
              6000,
            );
          } catch (error) {
            new Notice(`❌ ${errorMessage(error)}`, 10000);
          } finally {
            btn.disabled = false;
            btn.setText('Test connection');
          }
        }),
      );

    // ---------------------------------------------------------- manual sync
    new Setting(containerEl)
      .setName('Sync now')
      .setDesc('Run a full synchronization cycle immediately.')
      .addButton((button) =>
        button
          .setButtonText('Sync now')
          .onClick(() => {
            this.plugin.requestManualSync();
          }),
      );

    const footer = containerEl.createEl('p', { cls: 'e2ee-setting-note' });
    footer.setText(
      'Sync journal: this device remembers the last synced state of every file in its plugin data. ' +
        'Conflicts keep both versions: the remote one keeps the original name, the local one is copied to ' +
        '"<name>_conflict_<timestamp>". The .obsidian/ and .trash/ folders are never synchronized.',
    );
  }
}
