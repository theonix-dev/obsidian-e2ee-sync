# Obsidian E2EE Sync

File-by-file, end-to-end-encrypted synchronization for Obsidian vaults to **your own VPS**.
Works on **desktop, Android and iOS** — no Node.js APIs, no Electron APIs, CORS-safe networking.

```
┌──────────────┐   AES-256-GCM ciphertext    ┌──────────────┐   HTTPS (nginx + Let's Encrypt)
│  Obsidian    │ ──────────────────────────► │  Dumb server │ ◄──────────────────────────────
│  plugin      │   [salt|iv|ct+tag] only     │  (this repo) │   never sees keys or plaintext
└──────────────┘                             └──────────────┘
```

## Security model (be honest with yourself)

**Encrypted (never leaves your devices in the clear):** file contents — notes, images, PDFs, audio.
Every file is encrypted locally with AES-256-GCM, its key derived from your password via
PBKDF2-SHA-256 (210 000 iterations) over a deterministic per-vault salt (SHA-256 of the server's
`vaultId`). A fresh 12-byte IV is generated for every single encryption.

**Visible to the server operator:** file **paths and names**, sizes, timestamps, and the number of
devices/requests. If your threat model requires hiding metadata too, this is not the right tool —
that requires an oblivious store (e.g. a padded, chunked bucket design).

**Stored on each device (in the plugin's `data.json`):** server URL, API token, the E2EE password,
and the sync journal. Protect your devices with full-disk encryption and a strong device passcode.
The password can also be left empty in settings and entered per-session if you prefer — but then
auto-sync will prompt/fail until it is set.

**What the server can do to you:** delete or corrupt ciphertext (detected: SHA-256 hash mismatch →
the plugin refuses the upload/download), refuse service, or roll back to older ciphertext of a file
(the three-way state machine will treat that as a remote modification and merge/conflict it).

## Quick start (one-liner)

```bash
curl -fsSL https://raw.githubusercontent.com/<author>/<repo>/main/install.sh | bash
```

The installer detects how it was invoked: piped from the web it clones the full
repository to a folder of your choice first; run from an existing checkout it
just starts the wizard. Either way you get an interactive menu — run the sync
server, install the plugin into a vault, or both — where every parameter is
asked with a visible default (press Enter to accept it). Windows:
`powershell -ExecutionPolicy Bypass -File setup.ps1` (after cloning).

> After you fork/push this repository, edit `GITHUB_REPO` at the top of
> `install.sh` to point at your `<author>/<repo>`.

## Repository layout

```
plugin/          Obsidian plugin (TypeScript)
  src/main.ts        lifecycle, vault events, ribbon/status bar/commands
  src/settings.ts    settings tab + persistence
  src/crypto.ts      Web Crypto: deriveKey / encryptBuffer / decryptBuffer / CryptoManager
  src/api.ts         requestUrl wrapper: auth, timeouts, typed errors
  src/syncEngine.ts  three-way sync planner, conflict resolution, debouncing
  src/types.ts       shared types
  src/util.ts        helpers (error messages, URL validation)
server/          Zero-dependency Node.js REST API (Node >= 18)
  server.js          the whole server
  test-e2e.mjs       42-assertion integration test (spawns the server, exercises crypto + REST)
  nginx.conf.example reverse proxy with TLS
  obsidian-e2ee-sync.service  systemd unit with hardening
```

## Server deployment (VPS)

```bash
# 1. Copy the server somewhere permanent
sudo mkdir -p /opt/obsidian-sync/server /opt/obsidian-sync/data
sudo cp server/server.js /opt/obsidian-sync/server/
sudo useradd --system --home /opt/obsidian-sync obsidian-sync
sudo chown -R obsidian-sync: /opt/obsidian-sync

# 2. Create a token (keep it secret — it is the only thing standing between the
#    internet and your encrypted blobs)
openssl rand -hex 32
sudo install -m 600 /dev/null /etc/obsidian-e2ee-sync.env
echo "AUTH_TOKEN=<paste>" | sudo tee -a /etc/obsidian-e2ee-sync.env > /dev/null

# 3. systemd
sudo cp server/obsidian-e2ee-sync.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now obsidian-e2ee-sync

# 4. TLS via nginx + Let's Encrypt
sudo apt install nginx certbot python3-certbot-nginx
sudo cp server/nginx.conf.example /etc/nginx/sites-available/obsidian-sync
#    edit server_name, then:
sudo ln -s /etc/nginx/sites-available/obsidian-sync /etc/nginx/sites-enabled/
sudo certbot --nginx -d sync.example.com
sudo nginx -t && sudo systemctl reload nginx

# 5. Firewall
sudo ufw allow 443/tcp && sudo ufw enable   # the Node server stays on 127.0.0.1
```

Run the test suite any time: `node server/test-e2e.mjs` (spins up an isolated instance on
127.0.0.1:18977, exercises auth, upload/download round-trips, tombstones, traversal defenses and
restart persistence — 42 assertions).

### Server configuration (environment variables)

| Variable             | Default        | Meaning                                          |
| -------------------- | -------------- | ------------------------------------------------ |
| `AUTH_TOKEN`         | — (required)   | Bearer token, ≥ 16 chars.                        |
| `PORT` / `HOST`      | 8080 / 127.0.0.1 | Bind address — keep on loopback behind nginx.  |
| `DATA_DIR`           | `./data`       | `index.json`, `meta.json`, `files/…`             |
| `MAX_BODY_BYTES`     | 256 MiB        | Upload cap per request.                          |
| `TOMBSTONE_TTL_DAYS` | 0 (forever)    | Only enable if you accept the GC trade-off below.|

### API

| Method & route                       | Purpose                                                |
| ------------------------------------ | ------------------------------------------------------ |
| `GET /api/meta`                      | `{ vaultId }` — stable salt source                     |
| `GET /api/index`                     | full index incl. tombstones `{files:{path:{mtime,size,hash,deleted}}}` |
| `POST /api/upload`                   | binary body + `X-File-Path` (URL-encoded), `X-Client-Mtime`, `X-Cipher-Hash` headers; atomic tmp+rename |
| `GET /api/download?path=…`           | streams ciphertext (`application/octet-stream`)        |
| `DELETE /api/delete?path=…`          | unlinks the blob, writes a tombstone                   |
| `GET /api/health`                    | unauthenticated liveness probe                         |

All other routes require `Authorization: Bearer <AUTH_TOKEN>` (constant-time comparison).

## Plugin: build & install

```bash
cd plugin
npm install
npm run build        # typecheck + bundle -> main.js
```

Copy `main.js`, `manifest.json`, `styles.css` into
`<vault>/.obsidian/plugins/e2ee-vault-sync/` and enable **E2EE Vault Sync** in
Community plugins. For development: `npm run dev` (watch mode) and reload Obsidian.

### Usage

1. Settings → **E2EE Vault Sync**: server URL (`https://…`), API token, E2EE password.
   Press **Test connection** — it verifies reachability, the token, and that Web Crypto works.
2. Set the same password on **every device**; the first device to sync uploads everything,
   other devices pull.
3. Sync triggers: on startup (after vault indexing), on any create/modify/delete/rename
   (debounced 2.5 s per file), every N minutes (configurable), the ribbon icon, and the
   command palette → **E2EE Vault Sync: Force full sync**.

### How conflicts and deletions behave

For each path the plugin compares Local state vs. its journal (last synced state) vs. Remote
index — never local-vs-server wall clocks, so clock drift cannot corrupt decisions.

| Situation                                              | Result                                        |
| ------------------------------------------------------ | --------------------------------------------- |
| changed locally only                                    | push                                          |
| changed remotely only                                   | pull                                          |
| changed on both sides                                   | **keep both**: local copy → `name_conflict_YYYY-MM-DD_HH-mm-ss.ext` (pushed immediately), remote version → original name, `Notice` shown |
| deleted on another device, untouched here               | moved to system trash locally                 |
| deleted on another device, modified here                | local version wins, re-uploaded (resurrect)   |
| deleted locally, untouched remotely                     | tombstoned on the server                      |
| file exists locally + remotely but never synced here    | newest mtime wins (backup-restore scenario)   |

Notes on deliberate policy choices:

- **Untracked local file + remote tombstone → resurrect, never delete.** On a device where the
  journal has no record, the plugin refuses to destroy data it cannot vouch for (a vault restored
  from a backup would otherwise be mass-deleted by old tombstones).
- **Tombstone GC** (`TOMBSTONE_TTL_DAYS`): default off. If enabled, a device that stays offline
  longer than the TTL and *modified* a file during that window will resurrect it instead of
  honouring the deletion — pick a TTL comfortably larger than your worst offline period.
- `.obsidian/` and `.trash/` are never synchronized. Deletes use the system trash.
- Changing the E2EE password resets the journal and re-encrypts everything on next sync — do it on
  your most up-to-date device first.

## Troubleshooting

- **"Decryption failed — wrong E2EE password"** during pull: another device encrypted with a
  different password. Align passwords, then re-sync from the authoritative device.
- **Status stuck on *offline***: check `systemctl status obsidian-e2ee-sync`, then
  `curl -s https://your-host/api/health`.
- **Status *error* with HTTP 401**: token mismatch between plugin settings and
  `/etc/obsidian-e2ee-sync.env`.
- **Large attachments fail**: raise `client_max_body_size` (nginx) and `MAX_BODY_BYTES` (server)
  together.
- **413/400 mid-sync** and other per-file problems never abort the run — failures are collected,
  shown in a Notice, and retried on the next cycle.

## Compliance with the mobile constraints

The bundled `main.js` contains exactly one external import: `require("obsidian")`. No `fs`, `path`,
`crypto`, `http`, `net` or Electron APIs — verified by the build (grep the bundle if you want to
re-check). All networking goes through `requestUrl()`; all files are handled as `ArrayBuffer`
via `vault.readBinary / createBinary / modifyBinary`, so text notes and binary attachments follow
the identical code path.
