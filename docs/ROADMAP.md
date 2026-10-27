# E2EE Vault Sync — Problems & Improvements Register

A living register of everything currently wrong or missing, each entry with:
what exactly is wrong, why it matters (concrete failure scenario), and the
agreed solution path with exact code/wire changes. Solve top-to-bottom:
**Section A (problems in the shipped code) before Section B (new
capabilities)** — an item is "done" only when its verification criteria pass.

Priorities: **P0** blocks correct usage or is a security regression ·
**P1** risks data loss or a major capability gap · **P2** robustness /
efficiency / operations · **P3** polish. Estimates: **S** <1 day, **M** 2–5
days, **L** >1 week.

Standing principles every solution must respect:

1. The server stays untrusted — no solution may move trust server-side.
2. Mobile first — no Node/Electron APIs; every transfer path resumable and
   memory-bounded.
3. Explicit format versioning — packets/index carry a version; the previous
   version stays readable for pulls for two minor releases.
4. Prove, don't hope — every fix ships with the test that would have caught
   its bug class (the 0.2.0 AAD lesson).

---

# Section A — Problems in the current code (fix now, in this order)

## PROB-1 · Changing the password permanently bricks sync — **P0 · L**

**What is wrong.** In 0.2.0 a legitimate password change is fatal. The user
changes the password in settings (`onEncryptionPasswordChanged` resets the
journal), but on the next sync `ensurePasswordVerifier()` downloads the
verifier — which was encrypted with the **old** password — fails to decrypt
it with the new one, counts the live files on the server, and aborts:
*"Wrong E2EE password for this vault"*. Every sync attempt from then on
fails the same way. The verifier (a 0.2.0 security improvement) turned
password rotation into a deadlock. Only an empty server works.

**Why it matters.** Password rotation is a routine operation (suspected
leak, shared vault offboarding, periodic hygiene). Today the only way out
is wiping the server and losing every device's sync — or re-installing the
0.1.x plugin.

**Solution.** One coordinated change, **packet format v3**, which also fixes
PROB-2. Both are implemented together in one release.

*New packet header* (`plugin/src/crypto.ts`):

```
offset 0      : 0x03 (u8)                      version byte
offset 1..9   : keyId = SHA-256(key)[0..8]     public — routes verifier lookup
offset 9..25  : salt (16)                      deterministic vault salt (unchanged)
offset 25..37 : IV (12)                        fresh random per encryption
offset 37..45 : version counter, u64 BE        per-file; 1 on first push, +1 each push
offset 45..   : ciphertext + tag

AAD = 0x03 || keyId || NFC(path) || versionCounter (8 bytes BE)
MIN_V3_BYTES = 45 + 16
```

*Rotation state machine* (`syncEngine.rotatePassword()`):

1. Confirm dialog; refuse if a rotation is already in progress.
2. Derive the new key; seed a second verifier at the per-key reserved path
   `.e2ee-verifier.<keyId-hex16>` (old and new verifiers coexist).
3. Re-encrypt and re-push every live file with the new key (streamed;
   progress UX), each push incrementing that file's version counter.
4. Completion check: every live index entry now carries the new `keyId` →
   delete the old verifier path. Journal survives (version counters carry
   over); the 0.2.0 journal-reset in `onEncryptionPasswordChanged` is deleted.

*Other devices during/after rotation:* they see a verifier they cannot
decrypt plus a new one → **recoverable** prompt: *"The E2EE password was
changed on another device — enter the new password"* (reuses
`PasswordPromptModal`). Pushes with a stale `keyId` are rejected once only
new verifiers remain. No data is touched on rejection.

*Server changes* (`server/server.js` — stays an opaque store): accept and
echo optional headers `X-Key-Id` (16 hex) and `X-File-Version` (int) into
the index as `keyId` / `ver`; default `""` / `0` when absent. Additive only;
older clients unaffected.

**Verification.**
- The exact 0.2.0 bricking scenario passes: change password → sync succeeds
  → second device enters the new password → sync succeeds.
- Unit vectors for v3 header build/parse and AAD.
- Interrupted rotation (crash after step 2) resumes or fails safe; a stale-key
  push is rejected with a dedicated error; no partial-key vault state.

## PROB-2 · Full-state rollback is undetectable — **P1 · (ships with PROB-1)**

**What is wrong.** Hash verification (0.2.0) compares downloaded bytes to the
index entry — but the index itself is served by the untrusted server. A
compromised server can serve a *consistent old snapshot* (old index + old
ciphertexts): every hash matches, every packet authenticates (AAD binds the
path, not the point in time), and the client silently overwrites newer local
state. This is the one residual attack documented in the README as
"inherent".

**Why it matters.** It defeats the entire malicious-server threat model with
a move no harder than the swap attack already fixed in 0.2.0.

**Solution.** The v3 version counter from PROB-1. The counter lives **inside
the authenticated data** and the client journal records the last seen
version per file (`SyncRecord.remoteVersion`). A rollback shows up as
`packet.ver < journal.ver` — the server cannot forge a higher counter
without the key, so the client rejects the pull with `RollbackError`
(loud, per-file) instead of overwriting. This closes the attack for single
files and for whole-snapshot restores alike.

**Verification.** e2e test: capture a v3 packet + index entry, roll the
server back to them, client must refuse with a version-mismatch error.

## PROB-3 · Large files: hard 256 MB ceiling and huge RAM spikes — **P1 · L**

**What is wrong.** Two coupled defects:
1. Files > 256 MB cannot sync at all (`MAX_SYNCABLE_BYTES` refusal; the
   server body cap matches). A note with long-form video simply cannot be
   synchronized — no workaround exists.
2. Even a 50 MB attachment is held ~4–5× in memory simultaneously
   (plaintext + ciphertext + packet + hash copy + requestUrl internals) —
   multi-hundred-MB transient heap on iOS, risking jetsam kills mid-sync.

**Why it matters.** Media-heavy vaults are a primary use case for self-hosted
sync; iOS crashes look like "random sync failures" to the user.

**Solution.** Chunked, resumable transport with server-side assembly. The
index format and old clients stay compatible; small files keep the existing
single-shot path.

*Server endpoints* (`server/server.js`):
- `POST /api/upload/begin` — JSON body `{path, totalBytes, chunkCount,
  chunkHashes[]}` (client-computed SHA-256 per ciphertext chunk); creates
  `data/staging/<uploadId>/` (mode 0700); returns `uploadId`.
- `PUT /api/upload/chunk?uploadId=&n=` — one chunk (≤ 32 MB cap), verified
  against the pre-declared hash, stored as a part file.
- `GET /api/upload/status?uploadId=` — accepted chunk numbers → **the
  resume primitive**.
- `POST /api/upload/commit?uploadId=` — completeness check, concatenate to
  `data/files/<path>` under `withPathLock`, index it, drop staging.
- Caps: `MAX_BODY_BYTES` becomes the per-chunk cap; new `MAX_FILE_BYTES`
  (default 2 GiB) caps the assembled file; `cleanupTmpFiles()` also sweeps
  staging dirs older than 24 h.

*Client* (`api.ts`, `syncEngine.doPush`): read → encrypt → upload in 8 MB
plaintext chunks (each chunk is a v3 packet whose AAD includes path + chunk
index + the whole-file hash — the pre-declared hash manifest keeps staging
unforgeable); sequential chunks, one file at a time; per-chunk retry with
backoff driven by `ApiError.isNetworkError`; resume via `/status` after any
interruption. `MAX_SYNCABLE_BYTES` refusal is replaced by the chunked path.

**Verification.** e2e: 70 MB upload in 4 chunks with an injected failure
after chunk 2 → resume → commit → downloaded bytes equal the original;
wrong-hash chunk rejected 400; commit with a gap → 400; memory assertion:
peak heap stays under ~2× chunk size in the smoke harness.

## PROB-4 · Conflict handling is unproven and can silently misplan — **P1 · M**

**What is wrong.** `planSync` decides push/pull/conflict/delete for every
path, yet nothing enumerates its decision space. Uncovered corners include:
case-only collisions (`note.md` vs `Note.md` — on case-insensitive
filesystems a pull can silently overwrite), NFD/NFC pairs on mixed-OS
vaults, files that change during the run, and interactions between
tombstones and missing journal records. "Correct" is currently a claim, not
a proof.

**Why it matters.** Every data-loss bug class in a sync engine lives in this
decision function; the audit fixed the ones we found, not the ones we
didn't.

**Solution.**
1. **Exhaustive matrix tests** (`plugin/test/planSync.spec.mjs`): enumerate
   local {absent, unchanged, changed} × record {absent, present} × remote
   {absent, live, tombstone} × {hash same/different} × {version
   same/higher/lower} ≈ 70 cells; each asserts the exact planned action.
   The matrix doubles as the executable spec — any future `planSync` edit
   that changes a cell's verdict fails CI unless the test is updated
   deliberately.
2. **Case-collision guard**: when two local files differ only by ASCII case,
   plan keep-both with a rename for the second (never overwrite).
3. **Interactive resolution** (see IMP-2) replaces silent keep-both where a
   UI is available.

**Verification.** The matrix maps 1:1 to the decision table documented in
the `syncEngine.ts` header; CI runs it on every push (PROB-8).

## PROB-5 · One bearer token shared by all devices — **P2 · S**

**What is wrong.** `AUTH_TOKEN` is a single credential on every device.
Losing any one phone (or a misconfigured backup) exposes full read/write
control of the store; the only response is rotating the token on *all*
devices at once.

**Why it matters.** Token theft is a strictly easier attack than server
compromise; containment should not require re-provisioning the fleet.

**Solution.** Add `AUTH_TOKENS` (comma-separated list; `AUTH_TOKEN` remains
valid for compatibility). Each device gets its own token; a compromised
device's token is dropped from the list without touching keys or data.
`isAuthorized()` hashes the presented token and compares against every
listed digest. README: recommend per-device tokens; the nginx rate-limit
block stops being "optional".

**Verification.** e2e: two tokens both authorize; removing one from the
env and restarting → that token gets 401, the other still works.

## PROB-6 · Auto-sync burns battery: full index + full plan every interval — **P2 · S**

**What is wrong.** Every cycle (default every 5 minutes) downloads the whole
index and replans everything, even when nothing changed anywhere. On mobile
this is pure cost: radio wake-ups, battery, server load.

**Why it matters.** It discourages leaving auto-sync enabled — the plugin's
core convenience.

**Solution.** `GET /api/index` sets `ETag: sha256(index body)`; the client
sends `If-None-Match`; a `304` ends the cycle before planning. (A follow-up
in IMP-7 can narrow this further with per-path deltas; the ETag alone makes
idle cycles nearly free.)

**Verification.** e2e: second consecutive GET with the same content returns
304; client-side: a no-change cycle performs exactly one request.

## PROB-7 · Transfers are strictly sequential — initial sync crawls — **P3 · S**

**What is wrong.** `executePlan` processes ops one at a time; a fresh device
with thousands of small notes takes multiples of the necessary wall-clock
time (per-request latency dominates), while each request is tiny.

**Why it matters.** First impression of the plugin on a new device is a
multi-hour initial sync for large vaults.

**Solution.** Small worker pool in `executePlan`: downloads ×3, uploads ×2,
deletes ×1 (deletions stay serialized; per-path ordering unchanged). Memory
stays bounded because payloads are ≤ 32 MB each after PROB-3.

**Verification.** Bench in the e2e harness: N files × latency floor; assert
wall-clock scales with `ceil(N/pool)` not N, and per-path invariants hold.

## PROB-8 · Regressions ship unnoticed: no CI on ordinary pushes — **P0 (process) · S**

**What is wrong.** Tests exist (51 server assertions + crypto smoke) but
nothing runs them automatically; a broken push to `main` or `beta` — or a
bundle that secretly uses Node APIs — reaches users until someone remembers
to test by hand. This is exactly how the corrupted `server.js` working tree
almost shipped.

**Why it matters.** Every other item in this register depends on CI to be
verifiable; it is the cheapest P0 here.

**Solution.** `.github/workflows/ci.yml` on push/PR to `main` and `beta`:
job `server` — Node 18/20/22 matrix, `node server/test-e2e.mjs`; job
`plugin` — `npm ci && npm run build` then a bundle-cleanliness assertion
(fail on any `require(` other than `"obsidian"`, on `process.env`,
`__dirname`, `Buffer`). No secrets; releases remain tag-triggered.

**Verification.** A deliberately broken push to `beta` goes red; a clean PR
goes green.

## PROB-9 · `index.json` is a single point of recovery on the server — **P3 · S**

**What is wrong.** If `index.json` is lost/corrupted (disk partial failure,
bad manual edit) while `data/files/` is intact, the server starts with an
empty index; clients then re-upload everything (workable but expensive), and
tombstone history is gone.

**Why it matters.** Cheap operator insurance; also the tool for audits and
migrations.

**Solution.** `tools/rebuild-index.mjs`: scan `data/files/`, rebuild the
index from disk (`sha256` + size per blob, fs `mtime`, `ver: 0`, `keyId:
""`), print orphan report. Document: run with the server stopped.

**Verification.** Script round-trip in CI: build index → corrupt → rebuild →
equals original modulo `ver`/`keyId` defaults.

## PROB-10 · No incident-response tooling after a suspected compromise — **P2 · S**

**What is wrong.** If a user suspects their server or a device was
compromised, there is no supported way to answer "is my vault state
consistent and intact?" — they would hand-check files one by one.

**Why it matters.** The threat model promises detection; a one-command
integrity audit is the user-visible face of that promise.

**Solution.** Command "Verify vault integrity": for every live index entry —
download, hash-check against the index, decrypt-check with the local key;
report mismatches grouped by failure type; offer repair (re-push the intact
local copy) per file or as a batch. Uses the same pool as PROB-7.

**Verification.** e2e: tamper one blob server-side → the command reports
exactly that path; repair restores parity.

---

# Section B — Improvements (build after Section A, in this order)

## IMP-1 · Three-way merge for Markdown — **M**

**Gap.** Conflicts always duplicate (`_conflict_<ts>` copies). For the
common case — two devices edited different paragraphs of the same note —
keep-both produces noise the user must resolve by hand.

**Design.** Opt-in `enableMarkdownAutoMerge` (default **off** — it stores
the pulled plaintext as the merge base in `data.json`; the toggle
description must state this plaintext-at-rest trade-off).
`plugin/src/merge.ts`: dependency-free 3-way line merge (base = journal
copy, ours = local, theirs = decrypted remote). Non-overlapping hunks →
merged result pushed; any overlap → existing keep-both. CRLF-safe,
trailing-newline preserving. Wired into `doConflict`.

**Verification.** Unit corpus: insertions/deletions/edits in different
regions → clean merge; same-line edits → conflict; mixed line endings.

## IMP-2 · Interactive conflict resolution — **S**

**Gap.** The user learns about conflicts from a Notice after the fact; the
"keep both" default is silent.

**Design.** In `doConflict`, a modal: *Keep mine / Keep remote / Keep both /
Skip* (Esc = keep both, current behaviour). Auto-sync runs with >5 conflicts
skip the modal and batch keep-both to avoid UI storms.

## IMP-3 · Progress UI — **S**

**Gap.** During a run the only signal is a status-bar word; large initial
syncs look hung.

**Design.** Status bar + ribbon badge: `12/87 — uploading notes/x.md`;
per-file % for chunked uploads (PROB-3). Long Notices remain for terminal
states only.

## IMP-4 · "Restore from server" command — **S**

**Gap.** A new/broken device must reverse-engineer that clearing settings
triggers a full pull; there is no explicit fresh-clone path.

**Design.** Command wipes the local journal, shows a dry-run count, then
pulls everything live (never deletes; the mass-deletion guard is
inapplicable by construction).

## IMP-5 · User ignore patterns — **S**

**Gap.** Exclusions are hardcoded (config dir, `.trash/`, OS junk). Users
cannot keep e.g. `private/` or `*.bak` off the server.

**Design.** `.syncignore` at vault root + settings textarea; tiny glob
matcher (`**`, `*`, `?`), no dependency. Evaluated in `isSyncablePath`.
Ignoring never deletes: existing remote entries for newly-ignored paths are
left untouched and marked "ignored" in the journal view.

## IMP-6 · Hidden-file / configuration sync (opt-in) — **M**

**Gap.** `.obsidian/` is excluded outright: themes, snippets, hotkeys and
plugin sets don't follow the user across devices (Self-hosted LiveSync's
"Hidden File Sync" proves the demand).

**Design.** Server namespace prefix `config/` (same jail, same crypto, AAD =
`"config/" + path`, separate journal section). Opt-in toggle; default
allowlist only: `appearance.json`, `app.json`, `hotkeys.json`, `snippets/`,
`themes/`, `plugins/<id>/{main.js,manifest.json,styles.css}`.
`plugins/<id>/data.json` and `workspace.json` excluded by default
(device-local, dangerous to propagate) with per-item checkboxes. Version
counters and the mass-deletion guard apply unchanged.

## IMP-7 · Content-defined chunking (delta sync) — **L · depends on PROB-3**

**Gap.** Even chunked, editing one line of a large note re-uploads all of
it (all ciphertext changes with the same key only if the plaintext changed
everywhere — but a fixed cut shifts at every insert).

**Design.** Replace the fixed 8 MB cut with a rolling-hash (buzhash/Rabin)
computed over **plaintext** (~64 KB average chunk) before encryption;
per-chunk AAD adds the whole-file hash + chunk index. Journal stores
`baseChunkHashes` to plan deltas. No server change — PROB-3's hash-declared
staging already accepts arbitrary chunk layouts.

## IMP-8 · Mobile connection hygiene (research) — **M**

**Gap.** No "Wi-Fi only" option; sync over metered mobile data can be
expensive in some regions.

**Design.** First check whether `navigator.connection` is usable inside the
Obsidian WebView on Android/iOS. If yes: a sync-gate setting. If no:
document the limitation honestly in the README instead of shipping a
heuristic that lies.

---

# Backlog (unscheduled; revisit after Section B)

| ID | Item | Why parked |
|---|---|---|
| BK-1 | Multiple vaults per server | `vaultId` is per-`DATA_DIR`; clean fix = path segment + token→vault map. Demand unproven. |
| BK-2 | Deletion log + sync cursors | Tombstone TTL semantics are safe at current scale; relevant at 100k+ files. |
| BK-3 | Formal unit tests for `crypto.ts` (vitest, Node WebCrypto) | Partially covered by the smoke harness; formalise alongside PROB-1. |
| BK-4 | First-run onboarding wizard | Settings tab suffices while the audience is technical. |
| BK-5 | minisign signatures beyond GitHub attestations | Attestations already generated; marginal gain. |

# Explicitly rejected (recorded so they are not relitigated)

| Idea | Reason |
|---|---|
| CRDT / OT merge | Wrong scale for a single-maintainer plugin; 3-way merge + keep-both covers real failure modes; Obsidian's editor exposes no concurrent-session state. |
| Encrypted file paths (metadata privacy) | Incompatible with the per-path index/jail and conflict UX; documented as outside the threat model; needs oblivious storage — a different product. |
| P2P sync (WebRTC) | No reliable rendezvous without infrastructure; the self-hosted server *is* this product's answer. |
| Padding ciphertext sizes | Catastrophic storage/battery cost on mobile for a marginal metadata leak; documented. |
| Background sync on iOS | Platform restriction (Obsidian must be foreground); cannot be engineered around — document, never promise. |

# Standing rules

- Tags only on `main` (a tag push publishes a release, branch-independent);
  `beta` is the integration branch.
- Packet versions: pulls keep reading the previous version for two minor
  releases; pushes always write the latest (v1 read-only legacy; v2 current
  0.2.x; v3 lands with PROB-1/2).
- Every change lands with: CHANGELOG entry, tests per its "Verification"
  line, and a green CI run (PROB-8).
