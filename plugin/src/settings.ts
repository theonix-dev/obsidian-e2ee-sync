/**
 * Settings tab — fully declarative (Obsidian 1.13.2+ settings API).
 *
 * getSettingDefinitions() drives rendering AND settings search; value
 * persistence goes through getControlValue/setControlValue, which map control
 * keys onto PluginSettings fields. Side effects (auto-sync timer reinstall,
 * password-change journal reset) are applied in setControlValue.
 */

import { Notice, PluginSettingTab } from 'obsidian';
import type { App, SettingDefinitionItem } from 'obsidian';
import { SyncApi } from './api';
import { deriveKey, saltFromVaultId } from './crypto';
import type E2eeSyncPlugin from './main';
import { errorMessage, validateServerUrl } from './util';

const INTRO_TEXT =
  'Files are encrypted on this device (AES-256-GCM, PBKDF2-derived key) before they are uploaded. ' +
  'The server only ever stores ciphertext. File contents never leave this device unencrypted — ' +
  'but note that file paths, sizes and timestamps are visible to the server.';

export class E2eeSyncSettingTab extends PluginSettingTab {
  constructor(app: App, private readonly plugin: E2eeSyncPlugin) {
    super(app, plugin);
  }

  getSettingDefinitions(): SettingDefinitionItem[] {
    const plugin = this.plugin;
    return [
      {
        type: 'group',
        heading: 'E2EE Vault Sync',
        items: [
          { name: 'How it works', desc: INTRO_TEXT },
          {
            name: 'Server URL',
            desc: 'Base URL of your sync server, e.g. https://sync.example.com. HTTPS is required for remote hosts.',
            control: {
              type: 'text',
              key: 'serverUrl',
              placeholder: 'https://sync.example.com',
              validate: (value) => validateServerUrl(String(value)) ?? undefined,
            },
          },
          {
            name: 'API token',
            desc: 'Bearer token configured on the server (AUTH_TOKEN).',
            control: {
              type: 'secret',
              key: 'apiToken',
            },
          },
          {
            name: 'E2EE password',
            desc:
              'Derives the encryption key (PBKDF2, 210 000 iterations). Never sent to the server. All devices ' +
              'syncing this vault must use the same password — changing it re-encrypts and re-uploads every ' +
              'file on the next sync.',
            control: {
              type: 'secret',
              key: 'encryptionPassword',
            },
          },
          {
            name: 'Auto-sync interval (minutes)',
            desc: 'Sync automatically every N minutes (1–1440). 0 disables periodic sync.',
            control: {
              type: 'number',
              key: 'autoSyncMinutes',
              min: 0,
              max: 1440,
              validate: (value) => {
                const n = Number(value);
                if (!Number.isInteger(n) || n < 0 || n > 1440) {
                  return 'Enter an integer between 0 and 1440.';
                }
                return undefined;
              },
            },
          },
          {
            name: 'Test connection',
            desc: 'Checks reachability, the API token and key derivation (GET /api/index).',
            action: () => {
              void this.runConnectionTest();
            },
          },
          {
            name: 'Sync now',
            desc: 'Run a full synchronization cycle immediately.',
            action: () => {
              this.plugin.requestManualSync();
            },
          },
          {
            name: 'Sync journal',
            desc:
              'This device remembers the last synced state of every file in its plugin data. Conflicts keep both ' +
              `versions: the remote one keeps the original name, the local one is copied to "name_conflict_<timestamp>". ` +
              `The ${this.app.vault.configDir}/ and .trash/ folders are never synchronized.`,
          },
        ],
      },
    ];
  }

  getControlValue(key: string): unknown {
    return (this.plugin.settings as unknown as Record<string, unknown>)[key];
  }

  async setControlValue(key: string, value: unknown): Promise<void> {
    (this.plugin.settings as unknown as Record<string, unknown>)[key] = value;
    await this.plugin.saveSettings();
    if (key === 'autoSyncMinutes') {
      this.plugin.setAutoSync(Number(value) || 0);
    }
    if (key === 'encryptionPassword') {
      await this.plugin.onEncryptionPasswordChanged();
    }
  }

  private async runConnectionTest(): Promise<void> {
    const s = this.plugin.settings;
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
    }
  }
}
