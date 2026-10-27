# Obsidian E2EE Sync

File-by-file, end-to-end-encrypted synchronization for Obsidian vaults against a
self-hosted server. Operates on desktop (Windows, macOS, Linux), Android and iOS.
The plugin uses no Node.js or Electron runtime APIs; all networking is performed
through Obsidian's `requestUrl()` and all cryptography through the Web Crypto API.

```
┌──────────────┐  AES-256-GCM ciphertext    ┌──────────────────┐  HTTPS (nginx + Let's Encrypt)
│  Obsidian    │ ─────────────────────────► │  Storage server  │ ◄──────────────────────────────
│  plugin      │  [v2|salt|iv|ct+tag] only  │  (this repo)     │  receives no keys, no plaintext
└──────────────┘                            └──────────────────┘
```

The server functions as an untrusted ciphertext store: it relays and persists
opaque encrypted packets and maintains a per-path index, but possesses neither
the encryption key nor any mechanism to derive it.

## Security model

**Encrypted (never leaves a client device in plaintext):** file contents — notes,
images, PDFs, audio. Every file is encrypted locally with AES-256-GCM before
upload. The 256-bit key is derived from the user's password via PBKDF2-SHA-256
(210 000 iterations) over a deterministic per-vault salt (the first 16 bytes of
SHA-256 of the server-issued `vaultId`). A fresh uniformly random 12-byte IV is
generated for every single encryption operation; IV reuse under a given key is
structurally precluded by the implementation. Since 0.2.0 every packet is
versioned (v2) and binds the file's canonical path into the ciphertext as
AES-GCM additional data — swapping or replaying a ciphertext under a different
file name fails authentication instead of silently substituting content.

**Malicious-server defenses (0.2.0):**

- *Content substitution / rollback:* every download is SHA-256-verified against
  the server index before decryption or any local write; a mismatch aborts the
  pull with an explicit integrity error.
- *Wrong-password devices:* a reserved verifier entry proves this device derives
  the same key as the vault's original encryptor *before* anything is pushed —
  a misconfigured second device can no longer overwrite the store with
  ciphertext nobody else can decrypt.
- *Forged tombstones / mass wipes:* an unusual volume of remote-reported
  deletions in one cycle requires explicit user confirmation; declining keeps
  the local files and re-uploads them.
- *CPU exhaustion:* packets carrying a salt other than the vault's own are
  rejected before the expensive PBKDF2 pass.
- *Cross-platform path forking:* all paths are canonicalized to Unicode NFC on
  both client and server, so NFD (iOS/macOS) and NFC (Windows/Linux) spellings
  of one file share a single entry instead of forking.

**Visible to the server operator:** file paths and names, ciphertext sizes,
timestamps, and request/device counts. The transport is not metadata-private.
Deployments whose threat model requires metadata protection need an oblivious
or padded storage design; this system does not provide one.

**Stored on each client device (in the plugin's `data.json`):** server URL, API
bearer token, and the synchronization journal. The E2EE password is stored
there too by default, but can be switched to session-only memory ("Keep the
E2EE password on this device" toggle) — it is then never written to disk and
re-asked after each app restart. Client devices must be protected accordingly
(full-disk encryption, device passcode).

**Residual server-side capabilities:** denial of service, and a *full-state*
rollback (serving a consistent old index plus old ciphertexts together), which
is inherent to any unversioned store and is surfaced to the user through the
three-way reconciliation as a remote modification rather than silently
overwriting local state.

## Repository layout

```
plugin/          Obsidian plugin (TypeScript)
  src/main.ts        lifecycle, vault events, ribbon/status bar/commands
  src/settings.ts    settings tab and persistence
  src/crypto.ts      Web Crypto: deriveKey / encryptBuffer / decryptBuffer / CryptoManager
  src/api.ts         requestUrl wrapper: auth, timeouts, typed errors
  src/syncEngine.ts  three-way reconciliation planner, conflict resolution, debouncing
  src/types.ts       shared types
  src/util.ts        helpers (error messages, URL validation)
server/          Zero-dependency Node.js REST API (Node >= 18)
  server.js          storage service implementation
  test-e2e.mjs       51-assertion integration test (spawns the server, exercises crypto + REST)
  Dockerfile         container image (unprivileged node user, healthcheck)
  nginx.conf.example reverse proxy with TLS
  obsidian-e2ee-sync.service  hardened systemd unit
install.sh       curl|bash bootstrap installer (clones the repository, runs the wizard)
setup.sh/.ps1    interactive setup wizards (bash 3.2+ / PowerShell 5.1+)
docker-compose.yml, .env.example   containerized deployment
Makefile         operator conveniences: up/down/logs/backup/restore/test
```

## Quick start (one-liner)

```bash
curl -fsSL https://raw.githubusercontent.com/theonix-dev/obsidian-e2ee-sync/main/install.sh | bash
```

The installer detects its invocation context: piped from the web it clones the
full repository to a directory of the user's choice first; executed from an
existing checkout it starts the wizard directly. Either way an interactive menu
is presented — run the sync server, install the plugin into a vault, or both —
where every parameter is requested with a visible default (Enter accepts it).
Windows: `powershell -ExecutionPolicy Bypass -File setup.ps1` (after cloning).

> If you fork this repository, edit `GITHUB_REPO` at the top of
> `install.sh` to point at your `<author>/<repo>`.

## Server deployment (VPS)

```bash
# 1. Copy the server to a permanent location
sudo mkdir -p /opt/obsidian-sync/server /opt/obsidian-sync/data
sudo cp server/server.js /opt/obsidian-sync/server/
sudo useradd --system --home /opt/obsidian-sync obsidian-sync
sudo chown -R obsidian-sync: /opt/obsidian-sync

# 2. Issue a bearer token (sole credential guarding access to the ciphertext store)
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
sudo ufw allow 443/tcp && sudo ufw enable   # the Node server remains bound to 127.0.0.1
```

### Containerized deployment (Docker Compose)

Requires Docker Engine with the Compose plugin. This is the recommended
deployment model when a systemd unit is not applicable.

```bash
cp .env.example .env          # set AUTH_TOKEN (openssl rand -hex 32)
docker compose up -d --build  # build the image and start the service
docker compose ps             # verify the container reports healthy
```

Equivalent operations through the provided Makefile:

```bash
make up        # validate .env, then docker compose up -d --build
make logs      # follow server logs
make backup    # tar.gz snapshot of the server data into ./backups/
make restore BACKUP=backups/<file>.tar.gz   # interactive, replaces data and restarts
make test      # run the 51-assertion integration suite
make down      # stop; the named volume persists
```

Hardening properties of the containerized configuration: the process runs as
the unprivileged `node` user (uid 1000) with a read-only root filesystem, a
tmpfs at `/tmp`, `no-new-privileges`, an init process, and a `HEALTHCHECK`
probing `/api/health`. The service publishes on the host loopback only
(`127.0.0.1:8080`); terminate TLS with a reverse proxy as in the bare-metal
deployment. All environment variables from the table below apply through
`.env`.

Run the test suite at any time: `node server/test-e2e.mjs` (starts an isolated
instance on 127.0.0.1:18977 and exercises authentication, upload/download
round-trips, tombstone lifecycle, traversal defenses and restart persistence —
42 assertions).

### Server configuration (environment variables)

| Variable             | Default          | Meaning                                            |
| -------------------- | ---------------- | -------------------------------------------------- |
| `AUTH_TOKEN`         | — (required)     | Bearer token, ≥ 16 characters.                     |
| `PORT` / `HOST`      | 8080 / 127.0.0.1 | Bind address — keep on loopback behind nginx.      |
| `DATA_DIR`           | `./data`         | `index.json`, `meta.json`, `files/…`               |
| `MAX_BODY_BYTES`     | 256 MiB          | Upload cap per request.                            |
| `TOMBSTONE_TTL_DAYS` | 0 (indefinite)   | Enable only after reviewing the trade-off below.   |

### API

| Method & route             | Purpose                                                                 |
| -------------------------- | ----------------------------------------------------------------------- |
| `GET /api/meta`            | `{ vaultId }` — stable key-derivation salt source                       |
| `GET /api/index`           | full index including tombstones `{files:{path:{mtime,size,hash,deleted}}}` |
| `POST /api/upload`         | binary body + `X-File-Path` (URL-encoded), `X-Client-Mtime`, `X-Cipher-Hash` headers; atomic temp-file + `rename` publication |
| `GET /api/download?path=…` | streams ciphertext (`application/octet-stream`)                         |
| `DELETE /api/delete?path=…`| unlinks the blob and writes a tombstone                                 |
| `GET /api/health`          | unauthenticated liveness probe                                          |

All routes other than `/api/health` require `Authorization: Bearer <AUTH_TOKEN>`
(constant-time comparison).

## Plugin: build and installation

The setup wizards (`install.sh` one-liner, `setup.sh`, `setup.ps1`) automate
both the build and the file placement described below; the manual procedure is:

```bash
cd plugin
npm install
npm run build        # typecheck + bundle -> main.js
```

Copy `main.js`, `manifest.json` and `styles.css` into
`<vault>/.obsidian/plugins/end-to-end-vault-sync/` and enable **E2EE Vault Sync** in
Community plugins. For development: `npm run dev` (watch mode) and reload
Obsidian.

### Usage

1. Settings → **E2EE Vault Sync**: server URL (`https://…`), API token, E2EE
   password. Press **Test connection** — it verifies reachability, the token,
   and that Web Crypto operates correctly on the device.
2. Configure the identical password on **every device**; the first device to
   synchronize uploads the full vault, other devices pull from it.
3. Synchronization triggers: on startup (after vault indexing completes), on
   any create/modify/delete/rename event (debounced 2.5 s per file), on a fixed
   interval (configurable), via the ribbon icon, and via the command palette →
   **E2EE Vault Sync: Force full sync**.

### Reconciliation and conflict behavior

For each path the plugin compares three states — the local file, its
synchronization journal (the state at the last successful sync of that path),
and the remote index — without comparing wall clocks across devices, so clock
drift cannot corrupt decisions.

| Situation                                              | Result                                        |
| ------------------------------------------------------ | --------------------------------------------- |
| changed locally only                                    | push                                          |
| changed remotely only                                   | pull                                          |
| changed on both sides                                   | **keep both**: local copy → `name_conflict_YYYY-MM-DD_HH-mm-ss.ext` (pushed immediately), remote version → original name, `Notice` shown |
| deleted on another device, unchanged locally            | moved to system trash locally                 |
| deleted on another device, modified locally             | local version retained and re-uploaded        |
| deleted locally, unchanged remotely                     | tombstoned on the server                      |
| file exists locally and remotely but never synced here  | newer mtime wins (backup-restore scenario)    |

Deliberate policy decisions:

- **Untracked local file + remote tombstone → resurrect, never delete.** On a
  device whose journal holds no record for the path, the plugin does not
  destroy data it cannot vouch for (a vault restored from a backup would
  otherwise be mass-deleted by stale tombstones).
- **Tombstone garbage collection** (`TOMBSTONE_TTL_DAYS`): disabled by default.
  When enabled, a device that remains offline longer than the TTL and has
  *modified* a file during that window will resurrect it instead of honoring
  the deletion; select a TTL comfortably larger than the longest expected
  offline period.
- `.obsidian/` and `.trash/` are never synchronized. Deletions use the system
  trash.
- Changing the E2EE password resets the journal and re-encrypts the vault on
  the next synchronization; perform the change on the most up-to-date device
  first.

## Troubleshooting

- **"Decryption failed — wrong E2EE password"** during pull: another device
  encrypted with a different password. Align passwords, then re-synchronize
  from the authoritative device.
- **Status stuck on *offline***: check `systemctl status obsidian-e2ee-sync`,
  then `curl -s https://your-host/api/health`.
- **Status *error* with HTTP 401**: token mismatch between plugin settings and
  `/etc/obsidian-e2ee-sync.env`.
- **Large attachments fail**: raise `client_max_body_size` (nginx) and
  `MAX_BODY_BYTES` (server) together.
- **413/400 mid-sync** and other per-file problems never abort the run —
  failures are collected, reported via `Notice`, and retried on the next cycle.

## Testing

Automated verification:

```bash
node server/test-e2e.mjs    # or: make test
```

The suite replicates the plugin's cryptography byte-for-byte over the real
REST surface of a spawned server instance.

Manual acceptance checklist (desktop Obsidian, against a locally running
server):

1. **Single-device round-trip.** Enable the plugin, enter the server URL,
   token and password, press *Test connection* (a success `Notice` is
   expected). Create a note; after the 2.5 s debounce and sync cycle the
   ribbon icon turns to the *synced* state and the path appears in
   `GET /api/index` while the note text remains absent from server storage.
2. **Two-device convergence.** Configure a second vault with identical
   credentials and run *Force full sync*; notes created in the first vault
   appear in the second, and edits made in either vault converge after sync.
3. **Conflict handling.** Stop the server, edit the same note differently in
   both vaults, restart the server and sync both vaults. Each vault retains
   the remote canonical note plus a `name_conflict_YYYY-MM-DD_HH-mm-ss`
   copy, and a conflict `Notice` is displayed.
4. **Deletion propagation.** Delete the note in one vault and sync; the file
   moves to the system trash in the other vault.
5. **Binary attachments.** Add an image; it follows the identical encrypted
   path (verify its ciphertext size in the server index).
6. **Negative path.** Enter a different password in the second vault: pulls
   produce a decryption-failure `Notice`, never corrupted content.
7. **Zero-plaintext audit.** `grep -r "<distinctive phrase from a note>"
   <DATA_DIR>` must return nothing.

## Publishing to the community plugin directory

Releases are automated: pushing a git tag triggers the release workflow, which
builds the plugin (typecheck + esbuild bundle) and publishes a GitHub release
containing `main.js`, `manifest.json` and `styles.css`. The tag must equal the
`version` field in `plugin/manifest.json`.

```bash
# 1. Bump version in plugin/manifest.json and plugin/package.json,
#    add the entry to versions.json ("<version>": "<minAppVersion>").
# 2. Commit, then:
git tag 0.1.0 && git push origin main 0.1.0
```

Submission to the directory is performed through the web portal
[community.obsidian.md](https://community.obsidian.md): sign in with an
Obsidian account, link the GitHub account that owns the plugin repository,
and add the plugin there. Only the initial version is submitted this way;
subsequent releases are pulled by the directory from this repository's
GitHub releases automatically, matched by tag. The directory reads
`manifest.json` at the HEAD of the default branch, so it must be committed
before submitting.

Pre-submission requirements are covered by this repository: an MIT `LICENSE`
at the repository root, a descriptive `README.md` (excerpted on the public
listing page), a valid `manifest.json` (unique id, no restricted naming,
`x.y.z` semver), a `versions.json` mapping plugin versions to minimum
Obsidian versions (consulted when a release requires a newer app version),
and mobile compatibility with `isDesktopOnly: false`. While awaiting or
instead of directory review, the plugin can be distributed for beta testing
via the [BRAT](https://obsidian.md/plugins?id=obsidian42-brat) plugin.

## Mobile platform compliance

The bundled `main.js` contains exactly one external import:
`require("obsidian")`. No `fs`, `path`, `crypto`, `http`, `net` or Electron
APIs — enforced by the build configuration and verifiable by inspecting the
bundle. All networking goes through `requestUrl()`; all files are handled as
`ArrayBuffer` via `vault.readBinary / createBinary / modifyBinary`, so text
notes and binary attachments follow an identical code path.
