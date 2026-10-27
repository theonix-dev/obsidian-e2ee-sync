# E2EE Vault Sync — Engineering Roadmap

Status: living document, owned by the maintainer. Each item is written to be
implementable without further design debate: files, wire formats, migration
steps and acceptance criteria are fixed here. Estimates: **S** (<1 day),
**M** (2–5 days), **L** (>1 week).

Guiding principles (every item must respect all four):

1. **The server is untrusted.** No feature may move trust into the server.
   Any new server-side state is opaque data the client verifies.
2. **Mobile first.** No Node/Electron APIs; every new transfer path must be
   resumable and memory-bounded (no whole-file-in-RAM above a few MB).
3. **Format versioning.** Packet/index formats carry explicit versions; a
   release keeps decoders for the previous version (pull) and always pushes
   the latest. Decoders are removed only after two minor releases.
4. **Prove, don't hope.** Every protocol change ships with tests that would
   have caught the class of bug it fixes (see the 0.2.0 AAD lesson).

---

## Phase 1 — 0.2.1 (correctness): key rotation + proof infrastructure

### SEC-1 · Password rotation protocol (packet v3) — **L** 🔴 top priority

**Problem.** Since 0.2.0 a legitimate password change bricks sync:
`ensurePasswordVerifier()` decrypts the verifier with the *new* password,
fails, sees a non-empty vault, and aborts with "Wrong E2EE password" forever.
Rotation is currently impossible on a populated server.

**Design.** One change solves rotation *and* the last remaining rollback hole
(full-state rollback documented in the README as "inherent"):

**New packet v3 header** (`plugin/src/crypto.ts`):

```
offset 0      : 0x03 (u8)                      version byte
offset 1..9   : keyId — SHA-256(key)[0..8]     public, routes verifier lookup
offset 9..25  : salt (16)                      deterministic vault salt, unchanged
offset 25..37 : IV (12)                        fresh per encryption
offset 37..45 : version counter, u64 BE        per-file, starts at 1, +1 per push
offset 45..   : ciphertext + tag

AAD = 0x03 || keyId || NFC(path) || versionCounter(8B BE)
MIN_V3_BYTES = 45 + 16 = 61
```

The version counter is *inside* the authenticated data, so a server cannot
forge or downgrade it without the key. Rollback detection becomes exact:
the client compares the packet's authenticated `ver` against
`SyncRecord.remoteVersion` and rejects `remote < journal` regardless of what
the index claims — closing the "consistent old index + old ciphertexts"
attack that hash-verification alone cannot see.

**Wire/server changes** (`server/server.js`, still opaque storage):

- Accept optional headers `X-Key-Id` (16 hex chars) and `X-File-Version`
  (positive integer); echo them into the index entry as `keyId` / `ver`.
  The server does not interpret them — index schema stays additive.
- New optional headers are absent for v2 uploads → index fields default
  `keyId: ""`, `ver: 0`. No migration on the server.

**Client changes:**

- `types.ts`: `SyncRecord` gains `remoteVersion: number` (default `0` for
  pre-v3 records, journal migration in `main.ts onload` sets it without
  touching anything else).
- `syncEngine.ts`:
  - `doPush` sends `X-Key-Id` / `X-File-Version` = `record.remoteVersion + 1`
    and stores the returned values.
  - `doPull` rejects packets whose authenticated version is
    `< record.remoteVersion` with a dedicated `RollbackError` → surfaces as
    an integrity failure (loud, per-file, never silent).
  - `planSync` treats a version regression as `remoteChanged` (pull first,
    then the version check decides).
- **Rotation state machine** (`syncEngine.ts`, new `rotatePassword()`):
  1. confirm dialog (existing `confirmDialog`); refuse if a rotation is in
     progress or the previous run left the flag set without completion;
  2. derive new key, seed `VERIFIER`-v3 at a **per-key reserved path**
     `.e2ee-verifier.<keyId-hex16>` (both verifiers coexist during rotation);
  3. re-encrypt + re-push every live file with the new key (streamed, with
     progress UX), each push bumping its version counter;
  4. completion check: every live index entry has the new `keyId` → delete
     the old verifier path; journal reset not needed (versions carried over).
- **Other devices** on next sync: see a verifier they cannot decrypt plus a
  new one → show *"The E2EE password was changed on another device — enter
  the new password"* prompt (recoverable flow via `PasswordPromptModal`,
  never the fatal 0.2.0 error). Old-key pushes are rejected by the
  rotation-complete check (new `ensurePasswordVerifier` accepts *any* valid
  verifier and refuses pushes carrying a stale `keyId` once only new
  verifiers remain).
- Delete `onEncryptionPasswordChanged`'s journal reset (no longer correct).

**Known trade-off (document, don't fix):** AAD binds the path, so a rename
still costs a full re-encryption + re-upload. Accepted for files < 32 MB;
the chunk format (SYNC-2) re-encrypts per chunk, which bounds the cost.

**Tests / acceptance:**

- Unit: v3 header parse/build vectors; AAD vector test with fixed key.
- Engine: rotation state machine reaches "complete" on a simulated index;
  interrupted rotation (crash after step 2) resumes or fails safe.
- e2e (`server/test-e2e.mjs`): new "rotation" section — client A rotates,
  client B's old-password push is rejected with a specific status, B
  recovers after entering the new password; rollback PoC: serve an older
  authentic v3 packet → client rejects with version-mismatch error.
- **The 0.2.0 "password change bricks sync" scenario must pass.**

### OPS-1 · CI pipeline — **S**

New `.github/workflows/ci.yml`, on push/PR to `main` and `beta`:

- job `server`: matrix Node 18/20/22 → `node server/test-e2e.mjs`.
- job `plugin`: `npm ci && npm run build` in `plugin/`, then a cleanliness
  assertion: fail if the bundle contains `require(` other than `"obsidian"`,
  `process.env`, `__dirname`, or `Buffer`.
- No secrets needed; releases stay tag-triggered (tags only on `main`).

### OPS-2 · CHANGELOG.md — **S**

Seed from the 0.1.0/0.1.1/0.2.0 release notes; maintain per release
(Keep-a-Changelog layout). Community-plugin reviewers and users both read it.

### SYNC-1 · Exhaustive conflict-matrix tests — **M**

`planSync` is pure → enumerate the full decision lattice in
`plugin/test/planSync.spec.mjs` (vitest, WebCrypto not needed):

- states: local {absent, unchanged, changed} × record {absent, present} ×
  remote {absent, live, tombstone} × {hash same, hash different} ×
  {version same, version higher, version lower (post-SEC-1)} — ~70 cells;
- each cell asserts the exact planned action and no others;
- plus cross-platform nasties: NFC/NFD pairs, case-only differences
  (`note.md` vs `Note.md` — must plan a keep-both rename on
  case-insensitive filesystems, not a silent overwrite), dotfiles, and
  `MAX_SYNCABLE_BYTES` exclusion.

**Acceptance:** the matrix test file maps 1:1 to the doc-table at the bottom
of `syncEngine.ts` header comment; any future `planSync` edit fails CI if a
cell's verdict changes unintentionally.

---

## Phase 2 — 0.3.0 (resilience): chunked transport + merge + ops hardening

### SYNC-2 · Chunked, resumable transfer — **L**

**Problem.** 256 MB single-request ceiling; 200+ MB transient RAM on iOS;
mobile upload restarts from byte 0 after a drop.

**Design (server-side assembly, index stays compatible):**

- New endpoints (`server/server.js`):
  - `POST /api/upload/begin` — body: JSON `{path, totalBytes, chunkCount,
    chunkHashes[]}` (client-computed SHA-256 per *ciphertext* chunk);
    creates `data/staging/<uploadId>/` (mode 0700), returns `uploadId`.
  - `PUT /api/upload/chunk?uploadId=&n=` — streams one chunk (≤ 32 MB cap
    each), verifies against the pre-declared hash, writes part file.
  - `GET /api/upload/status?uploadId=` — list of already-accepted chunk
    numbers → this is the resume primitive.
  - `POST /api/upload/commit?uploadId=` — verifies completeness, concatenates
    to `data/files/<path>` via rename dance inside `withPathLock`, indexes
    the entry, deletes staging. Old single-shot `POST /api/upload` remains
    for files ≤ 32 MB.
- `plugin/src/api.ts`: the four calls; per-chunk `requestUrl` with retry +
  exponential backoff (existing `ApiError.isNetworkError` drives retry).
- `plugin/src/syncEngine.ts` `doPush`: read → encrypt → upload in 8 MB
  plaintext chunks (each chunk = v3 packet, AAD = path + chunk index +
  whole-file hash — pre-declared hashes keep the manifest unforgable);
  sequential chunks, one file at a time (memory bound).
- Server: `MAX_BODY_BYTES` becomes per-chunk; `MAX_FILE_BYTES` (default
  2 GiB) caps total; staging dirs swept by `cleanupTmpFiles()` after 24 h.

**Tests:** e2e — 70 MB synthetic upload across 4 chunks with an injected
failure after chunk 2 → resume via `/status` → commit → download equals
original; hash-mismatch chunk rejected; commit with a missing chunk → 400.

### SYNC-3 · Three-way merge for Markdown — **M**

- Opt-in setting `enableMarkdownAutoMerge` (default **off**; when on, the
  journal stores the pulled plaintext as the conflict base — this puts
  *plaintext* in `data.json` and the toggle's description must say so).
- `plugin/src/merge.ts`: dependency-free 3-way line merge
  (base = journal copy, ours = local, theirs = decrypted remote). No
  overlapping hunks → merged result pushed; any overlap → fall back to the
  existing keep-both flow. Trailing-newline and CRLF-safe.
- Wire into `doConflict` before `uniqueConflictPath`.

### SYNC-4 · Interactive conflict resolution — **S**

`doConflict` shows a modal (skip entirely when `running` was triggered by
auto-sync with `>5` conflicts — batch to keep-both): *Keep mine / Keep
remote / Keep both / Skip*. Default (Esc) = keep both (current behaviour).

### SEC-3 · Multiple/rotatable API tokens — **S**

`AUTH_TOKEN` stays valid; add `AUTH_TOKENS` (comma-separated) so each device
gets its own token. Compromised device → drop its token without re-keying
the fleet (tokens gate transport, keys gate content). `isAuthorized` checks
the digest against any listed token. Document in README + nginx rate-limit
note becomes non-optional.

### SEC-4 · "Verify vault integrity" command — **S**

Command palette: for every live index entry — download, hash-check against
the index, decrypt-check; report mismatches; offer repair (re-push from
local if the local copy is intact). This is the incident-response tool for
"my server was compromised, now what?".

### SYNC-5 · Bounded concurrency for small files — **S**

`executePlan` is a sequential loop; add a pool: downloads ×3, uploads ×2,
deletes ×1 (ordering preserved within a path). Cuts wall-clock for initial
sync of thousands of notes; memory stays flat (payloads ≤ 32 MB each).

### OPS-3 · Index ETag (battery/bandwidth) — **S**

`GET /api/index` sets `ETag: <sha256 of body>`; client sends
`If-None-Match`; on `304` the sync run is a no-op before planning. This
makes the 5-minute auto-sync nearly free on mobile.

### OPS-5 · Index-rebuild operator tool — **S**

`tools/rebuild-index.mjs`: scan `data/files/` → rebuild `index.json`
(hash/size from disk, `mtime` from fs stat, `ver: 0`), list orphans. The
missing "server disk survived but index.json didn't" recovery path.

---

## Phase 3 — 0.4.0 (scope): deltas, hidden sync, user control

### SYNC-6 · Content-defined chunking (CDC deltas) — **L**

Replace SYNC-2's fixed 8 MB cut with a rolling-hash (buzhash/Rabin, ~64 KB
avg chunk) computed over **plaintext** before encryption; per-chunk AAD
includes the file's full-content hash + chunk index. Editing one line of a
large note re-uploads only the touched chunks. Journal gains
`baseChunkHashes` for delta planning. Depends on SYNC-2; no server change
(hash-declared staging already supports it).

### SYNC-7 · Hidden-file / configuration sync (opt-in) — **M**

LiveSync's "Hidden File Sync" equivalent:

- Server namespace: paths prefixed `config/` (same jail, same crypto, AAD =
  `"config/" + path`); separate journal section.
- Opt-in toggle; default allowlist only: `appearance.json`, `app.json`,
  `hotkeys.json`, `snippets/`, `themes/`, `plugins/<id>/main.js`,
  `manifest.json`, `styles.css`. `plugins/<id>/data.json` and `workspace.json`
  excluded by default (device-local / dangerous to propagate) with
  per-item checkboxes.
- Mass-deletion guard and version counters apply unchanged.

### SYNC-8 · User ignore patterns — **S**

`.syncignore` in the vault root + settings textarea; tiny glob matcher
(`**`, `*`, `?`), no dependency. Evaluated in `isSyncablePath`; changes to
the file itself re-plan (never delete — remote entries for newly-ignored
paths are left alone and shown in the journal UI as "ignored").

### UX-1 · Progress UI — **S**

Status bar text + ribbon badge during runs: `12/87 … uploading notes/x.md`;
for SYNC-2 chunked uploads show per-file %. Long Notices only for terminal
states (current behaviour preserved).

### UX-2 · "Restore from server" command — **S**

Wipes the local journal, pulls everything live into a fresh state (the
"new device / I broke my vault" path), with the mass-deletion guard
inverted (it pulls, never deletes) and a dry-run count first.

### UX-3 · Connection hygiene on mobile — **M (research)**

Investigate `navigator.connection` availability inside the Obsidian WebView
(iOS WKWebView, Android). If usable: "sync on Wi-Fi only" setting; if not:
document the limitation honestly in the README instead of faking it.

---

## Backlog (not scheduled; revisit after 0.4.0)

| ID | Idea | Why it's parked |
|---|---|---|
| BK-1 | Multiple vaults per server | `vaultId` is per-`DATA_DIR`; clean fix is a vault path segment + token→vault map. Real demand unknown yet. |
| BK-2 | Deletion log + sync cursors (replace tombstone TTL semantics) | Current TTL GC is safe for present designs; becomes interesting at 100k+ files with index delta sync (ETag already covers the small case). |
| BK-3 | Plugin unit tests for `crypto.ts` in vitest (Node WebCrypto) | Partially covered by the smoke harness; formalise when SEC-1 lands. |
| BK-4 | First-run onboarding wizard (single flow: URL → token → password → verify → initial sync) | Settings tab suffices while the audience is technical. |
| BK-5 | Signed release provenance beyond GitHub attestations (minisign) | Attestations already generated; marginal gain. |

## Explicitly rejected (with reasons, so we don't relitigate)

| Idea | Reason |
|---|---|
| CRDT / OT for notes | Out of scope for a single-maintainer plugin; 3-way merge + keep-both covers the real failure modes; Obsidian's editor doesn't expose concurrent-session state needed for CRDT. |
| Metadata privacy (encrypted paths) | Incompatible with server-side per-path index/jail and conflict UX; documented as out of threat model. Requires oblivious storage (a different product). |
| P2P sync (WebRTC) | No reliable rendezvous without infrastructure; the self-hosted server *is* the product's answer. |
| Encrypting file *sizes* (padding) | Cost/benefit catastrophically poor on mobile storage; documented. |
| Background/scheduled sync on iOS | Platform restriction (Obsidian must be foreground); cannot be engineered around — document, don't promise. |

---

## Release etiquette (standing rules)

- Tags **only** on `main` (tag push = release, branch-independent).
- `beta` is the integration branch; feature branches → `beta` → `main`.
- Every release: CHANGELOG entry, `versions.json` row, tag == manifest
  version, bundle-cleanliness grep passes in CI.
- Packet format versions: pull-support window = last 2 minors (v1 already
  read-only-legacy; v2 until 0.4.x; v3 current from 0.2.1).
