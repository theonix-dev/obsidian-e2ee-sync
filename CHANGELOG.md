# Changelog

All notable changes to this project are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/).

## [0.3.0] — 2026-11-06

Whole of the roadmap's Section A (problems register) — see `docs/ROADMAP.md`.

### Fixed

- **PROB-1 · Password changes no longer brick sync.** In 0.2.0, changing the
  E2EE password made every subsequent sync abort at the verifier. Changing the
  password now starts a coordinated key rotation: the new verifier is seeded
  alongside the old one, every live file is re-encrypted and re-uploaded with
  its version counter carried over (+1), and only when the whole store is
  under the new key is the old verifier removed. The sync journal survives
  (the 0.2.0 journal reset on password change is gone). Other devices see a
  recoverable prompt — *"The E2EE password was changed on another device —
  enter the new password"* — instead of a deadlock. Interrupted rotations are
  resumable: re-running with the same new password skips files already
  converted. A wrong "current" password aborts before anything is modified.
- **PROB-2 · Full-state server rollbacks are now detected.** Every packet
  carries an authenticated per-file version counter (inside the AES-GCM AAD —
  the untrusted server cannot forge or strip it). A pull whose counter is
  lower than the last one recorded in the local journal is refused loudly as a
  rollback; a pre-v3 packet arriving after v3 history is refused the same way.
  This closes the last residual malicious-server attack documented in the
  0.2.0 README (a consistent old snapshot of index + ciphertexts).

### Added

- **PROB-3 · Chunked, resumable transport for large files.** Files above
  16 MiB upload as independently encrypted ~8 MiB chunks through a staging
  protocol (`/api/upload/begin|chunk|status|commit`) with per-chunk SHA-256
  verification, network-only retries with backoff, and resume from the
  server-reported accepted-chunk list. The hard ceiling moves from 256 MiB to
  2 GiB (`MAX_FILE_BYTES`), and client memory per transfer drops from ~4–5×
  the file to roughly the file + one chunk. Every chunk is authenticated with
  a file manifest (SHA-256 over the plaintext chunk hashes), so chunks of two
  different uploads can never be spliced into one decryptable file. Abandoned
  staging uploads are swept after 24 h (`STAGING_TTL_HOURS`).
- **PROB-4 · Case-collision guard.** Two local files differing only by ASCII
  case (a real hazard on case-insensitive filesystems) now keep both: the
  later spelling is renamed `_case-collision_<timestamp>`. A remote file whose
  only local counterpart differs by case is pulled to a `_remote-case_` copy
  instead of silently overwriting it.
- **PROB-5 · Per-device tokens.** `AUTH_TOKENS=a,b,c` accepts a
  comma-separated token list next to `AUTH_TOKEN`; a lost device's token can
  be dropped without re-provisioning everything else.
- **PROB-6 · Idle cycles are nearly free.** `GET /api/index` serves an ETag;
  the client sends `If-None-Match` and a `304` ends the sync cycle before any
  planning — one cheap request instead of a full index download + replan.
- **PROB-10 · "Verify vault integrity" command.** Downloads every live entry,
  checks the hash against the index and decryptability with the local key,
  reports problems grouped by cause, and can repair them by re-uploading the
  intact local copies (version counters advance by one).
- **PROB-9 · `tools/rebuild-index.mjs`.** Rebuilds `index.json` from the
  surviving blobs after index loss/corruption (`--dry-run` supported), with an
  orphan report. Run with the server stopped.

### Changed

- **PROB-7 · Parallel transfers.** Sync executes with a bounded worker pool —
  downloads ×3, uploads ×2, deletions serialized — so initial syncs of large
  vaults no longer crawl at one-request-at-a-time.
- **PROB-8 · CI on every push.** `.github/workflows/ci.yml` runs the server
  suite on a Node 18/20/22 matrix, builds the plugin, asserts bundle
  cleanliness (only `require("obsidian")`, no Node APIs) and runs the plugin
  specs.
- Packet format v3 (see `plugin/src/crypto.ts` for the byte layout). Packets
  now carry a public `keyId` (first 8 bytes of SHA-256 of the derived key —
  routes verifier lookups and detects foreign-key files before an expensive
  decrypt), the version counter, a self-delimiting ciphertext length and a
  chunk index. v2 and v1 packets remain readable (read-only compatibility);
  every re-push upgrades the file to v3. Devices still on 0.2.0 cannot read
  v3 packets — upgrade all devices together.
- Server: `MAX_BODY_BYTES` is now the per-request (per-chunk) cap; the
  assembled-file cap is the new `MAX_FILE_BYTES` (default 2 GiB).

### Notes / deviations from the roadmap's wire sketch

The shipped v3 header extends the ROADMAP sketch with two fields —
`ctLen` (u32) and `chunkIndex` (u32) — because concatenated chunk packets
must be self-delimiting to be parseable on download. The chunk `fileManifest`
is computed over the *plaintext* chunk hashes (the ROADMAP text implied
ciphertext hashes, which is circular: the manifest must be known before
encryption to go into the AAD). Per-chunk ciphertext hashes travel with each
`PUT` (`X-Chunk-Hash`) instead of being declared up-front at `begin`, which
keeps the client memory bounded to one chunk. Design intent (unforgeable
staging, splicing resistance, rollback detection) is unchanged and covered by
tests.

## [0.2.0] — security hardening

- Packet v2: AES-GCM AAD binds every ciphertext to its canonical path
  (anti-swap/anti-replay).
- Downloads are SHA-256-verified against the index before decryption or any
  local write.
- Password verifier prevents wrong-password devices from overwriting the
  store.
- Mass remote deletions require explicit user confirmation.
- Packets carrying a foreign salt are rejected before the PBKDF2 pass
  (anti CPU-exhaustion).
- All paths canonicalized to Unicode NFC on both ends (anti path-forking).

## [0.1.0] / [0.1.1] — initial releases

- File-by-file E2EE sync (AES-256-GCM, PBKDF2-SHA-256 210k), three-way
  reconciliation, keep-both conflicts, tombstones, mobile support, one-line
  installer, Docker/systemd/nginx deployment kit.
