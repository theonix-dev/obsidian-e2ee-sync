/**
 * Engine-level integration specs against a fake server + fake vault.
 *
 * Unlike planSync/crypto specs these exercise the REAL SyncEngine executor —
 * journal updates, verifier seeding, keep-both conflicts, merge wiring —
 * with genuine packet-v3 crypto (the WebCrypto of the host Node) and two
 * "devices" sharing one in-memory server. The only substituted parts are the
 * network transport (FakeServer implements the SyncApi surface) and the
 * Obsidian vault (FakeVault, backed by the same TFile/TFolder stub the
 * engine bundle sees — the executor instanceof-checks both).
 */

import { finish, loadModule, ok, equal, deepEqual } from './harness.mjs';

const PASSWORD = 'engine-spec-password-0123456789';
const VAULT_ID = 'engine-spec-vault-id-0123456789abcdef';
const T0 = 1_700_000_000_000;

class FakeVault {
  constructor(configDir = '.obsidian') {
    this.configDir = configDir;
    this.now = T0;
    this.files = new Map(); // path -> TFile
    this.folders = new Set();
    this.binaries = new Map(); // path -> ArrayBuffer
  }

  tick() {
    this.now += 1000;
    return this.now;
  }

  getAbstractFileByPath(p) {
    if (this.files.has(p)) return this.files.get(p);
    if (this.folders.has(p)) return new TFolder(p);
    return null;
  }

  getFiles() {
    return [...this.files.values()];
  }

  async readBinary(file) {
    const data = this.binaries.get(file.path);
    if (data === undefined) throw new Error(`FakeVault: missing binary ${file.path}`);
    return data.slice(0);
  }

  async createBinary(path, data) {
    const file = new TFile(path, this.tick());
    file.stat.size = data.byteLength;
    this.files.set(path, file);
    this.binaries.set(path, data);
    return file;
  }

  async modifyBinary(file, data) {
    this.binaries.set(file.path, data);
    file.stat.mtime = this.tick();
    file.stat.size = data.byteLength;
    return file;
  }

  async rename(file, newPath) {
    this.files.delete(file.path);
    this.binaries.set(newPath, this.binaries.get(file.path));
    this.binaries.delete(file.path);
    const copy = new TFile(newPath, file.stat.mtime);
    copy.stat.size = file.stat.size;
    this.files.set(newPath, copy);
    return copy;
  }

  async trash(file) {
    this.files.delete(file.path);
    this.binaries.delete(file.path);
  }

  async createFolder(p) {
    this.folders.add(p);
  }
}

/** In-memory SyncApi stand-in shared by all devices (one server state). */
class FakeServer {
  constructor(cryptoMod) {
    this.crypto = cryptoMod; // for hashing only
    this.vaultId = VAULT_ID;
    this.files = new Map(); // path -> { entry, bytes }
    this.staging = new Map(); // uploadId -> { path, parts: Map, manifest, chunkCount }
    this.uploadSeq = 0;
  }

  async sha256Hex(bytes) {
    return this.crypto.sha256Hex(bytes);
  }

  async getMeta() {
    return { vaultId: this.vaultId };
  }

  async getIndex() {
    const files = {};
    for (const [p, f] of this.files) files[p] = { ...f.entry };
    return { index: { files }, etag: `etag-${this.files.size}`, notModified: false };
  }

  async upload(path, ciphertext, clientMtime, cipherHash, meta = {}) {
    const bytes = new Uint8Array(ciphertext);
    const hash = await this.sha256Hex(bytes);
    if (cipherHash && cipherHash !== hash) throw new engine.ApiError('FakeServer: hash mismatch.', 400);
    const entry = {
      mtime: clientMtime,
      size: bytes.length,
      hash,
      deleted: false,
      keyId: meta.keyId ?? '',
      ver: meta.fileVersion ?? 0,
      manifest: '',
    };
    this.files.set(path, { entry, bytes: bytes.slice() });
    return { path, ...entry };
  }

  async download(path) {
    const f = this.files.get(path);
    if (!f || f.entry.deleted) throw new engine.ApiError('File not found.', 404);
    return f.bytes.slice().buffer;
  }

  async deleteFile(path) {
    const f = this.files.get(path);
    if (!f) throw new engine.ApiError('Unknown path.', 404);
    if (f.entry.deleted) return { path, ...f.entry };
    const tombstone = {
      mtime: Date.now(), size: 0, hash: '', deleted: true, keyId: '', ver: 0, manifest: '',
    };
    this.files.set(path, { entry: tombstone, bytes: null });
    return { path, ...tombstone };
  }

  async beginUpload(request) {
    const uploadId = `upload-${String(++this.uploadSeq).padStart(6, '0')}`;
    this.staging.set(uploadId, {
      path: request.path,
      chunkCount: request.chunkCount,
      manifest: request.fileManifest,
      parts: new Map(),
    });
    return { uploadId };
  }

  async uploadChunk(uploadId, n, chunk, chunkHash) {
    const st = this.staging.get(uploadId);
    if (!st) throw new engine.ApiError('Unknown uploadId.', 404);
    const bytes = new Uint8Array(chunk);
    if ((await this.sha256Hex(bytes)) !== chunkHash) throw new engine.ApiError('Chunk hash mismatch.', 400);
    st.parts.set(n, bytes.slice());
    return { accepted: [...st.parts.keys()].sort((a, b) => a - b) };
  }

  async uploadStatus(uploadId) {
    const st = this.staging.get(uploadId);
    if (!st) throw new engine.ApiError('Unknown uploadId.', 404);
    return { accepted: [...st.parts.keys()].sort((a, b) => a - b), chunkCount: st.chunkCount };
  }

  async commitUpload(uploadId, meta) {
    const st = this.staging.get(uploadId);
    if (!st) throw new engine.ApiError('Unknown uploadId.', 404);
    if (st.parts.size !== st.chunkCount) throw new engine.ApiError('Upload incomplete.', 400);
    const ordered = [...st.parts.keys()].sort((a, b) => a - b);
    const total = ordered.reduce((n2, k) => n2 + st.parts.get(k).length, 0);
    const blob = new Uint8Array(total);
    let o = 0;
    for (const k of ordered) {
      blob.set(st.parts.get(k), o);
      o += st.parts.get(k).length;
    }
    this.staging.delete(uploadId);
    const entry = {
      mtime: meta.clientMtime,
      size: total,
      hash: await this.sha256Hex(blob),
      deleted: false,
      keyId: meta.keyId,
      ver: meta.fileVersion,
      manifest: st.manifest,
    };
    this.files.set(st.path, { entry, bytes: blob });
    return { path: st.path, ...entry };
  }
}

async function run() {
  // Two module instances: the engine bundle (its own crypto/api inside) and a
  // standalone crypto bundle for the spec's own hashing/sealing.
  const engineMod = await loadModule('src/syncEngine.ts');
  const cryptoMod = await loadModule('src/crypto.ts');
  // The obsidian stub is (re)written by loadModule — import the SAME classes
  // the engine bundle uses, so instanceof checks inside the executor hold.
  ({ TFile, TFolder } = await import('./.build/obsidian-stub.mjs'));
  // engineMod.ApiError is the SAME class the engine throws — required for the
  // FakeServer's 404s to be recognized by the executor's instanceof checks.
  engine = engineMod;
  const { SyncEngine } = engineMod;
  const { sha256Hex, CryptoManager, saltFromVaultId } = cryptoMod;

  const makeDevice = (name, vault, server, opts = {}) => {
    const journal = {};
    const notices = [];
    const statuses = [];
    let persisted = 0;
    const settings = {
      serverUrl: 'https://sync.test',
      apiToken: 'token-token-token',
      encryptionPassword: PASSWORD,
      autoSyncMinutes: 0,
      rememberEncryptionPassword: true,
      enableMarkdownAutoMerge: opts.autoMerge === true,
    };
    const eng = new SyncEngine({
      app: { vault },
      getSettings: () => ({ ...settings }),
      getJournal: () => journal,
      setJournalEntry: (path, record) => {
        if (record) journal[path] = record;
        else delete journal[path];
      },
      persist: async () => {
        persisted++;
      },
      setStatus: (status, message) => statuses.push({ status, message }),
      notify: (message) => notices.push(message),
      confirmMassDeletion: async () => true,
      createApi: () => server, // shared fake server = the network
      resolveConflict: opts.resolveConflict,
      setProgress: opts.setProgress,
    });
    return { name, engine: eng, vault, journal, notices, statuses, settings, getPersisted: () => persisted };
  };

  /** runFullSync + loud diagnostics when it returns null. */
  const sync = async (device, label) => {
    const summary = await device.engine.runFullSync();
    if (summary === null) {
      console.error(`  !! ${device.name} sync returned null (${label})`);
      for (const n of device.notices.slice(-4)) console.error(`     notice: ${n}`);
      for (const s of device.statuses.slice(-4)) console.error(`     status: ${s.status} ${s.message ?? ''}`);
    }
    return summary;
  };

  const utf8 = (s) => new TextEncoder().encode(s).buffer;
  const text = async (device, path) =>
    new TextDecoder().decode(await device.vault.readBinary(device.vault.getAbstractFileByPath(path)));
  /** Server-side stored bytes are ciphertext — decrypt before asserting. */
  const text0 = async (stored, path) => {
    const cm = new CryptoManager(PASSWORD, await saltFromVaultId(VAULT_ID));
    const { plaintext } = await cm.decrypt(stored.bytes.slice().buffer, path);
    return new TextDecoder().decode(plaintext);
  };

  console.log('[1] two-device push/pull round trip (real v3 crypto, verifier seeding)');
  {
    const server = new FakeServer(cryptoMod);
    const a = makeDevice('A', new FakeVault(), server);
    const b = makeDevice('B', new FakeVault(), server);

    await a.vault.createBinary('notes/hello.md', utf8('# Hello\n\nfrom device A\n'));
    const s1 = await sync(a, 'initial push');
    equal(s1?.pushed, 1, 'A pushes the new note');
    equal(s1?.failures.length, 0, 'A has no failures');
    equal(a.journal['notes/hello.md']?.remoteVersion, 1, 'A journals version 1');
    ok(
      [...server.files.keys()].some((p) => p.startsWith('.e2ee-verifier.')),
      'A seeded its per-key verifier on the server',
    );

    const s2 = await sync(b, 'first pull');
    equal(s2?.pulled, 1, 'B pulls the note');
    equal(await text(b, 'notes/hello.md'), '# Hello\n\nfrom device A\n', 'B sees the exact plaintext');
    equal(b.journal['notes/hello.md']?.remoteVersion, 1, 'B journals version 1');

    await a.vault.modifyBinary(a.vault.getAbstractFileByPath('notes/hello.md'), utf8('# Hello\n\nedited on A\n'));
    await sync(a, 'A edit push');
    const s3 = await sync(b, 'B pull edit');
    equal(s3?.pulled, 1, 'B pulls the edit');
    equal(await text(b, 'notes/hello.md'), '# Hello\n\nedited on A\n', 'B sees the edit');

    await b.vault.modifyBinary(b.vault.getAbstractFileByPath('notes/hello.md'), utf8('# Hello\n\nedited on B\n'));
    await sync(b, 'B edit push');
    const s4 = await sync(a, 'A pull edit');
    equal(s4?.pulled, 1, 'A pulls B\u2019s edit');
    equal(await text(a, 'notes/hello.md'), '# Hello\n\nedited on B\n', 'A sees B\u2019s edit');
  }

  console.log('[2] keep-both conflict when auto-merge is off (default)');
  {
    const server = new FakeServer(cryptoMod);
    const a = makeDevice('A', new FakeVault(), server);
    const b = makeDevice('B', new FakeVault(), server);

    await a.vault.createBinary('note.md', utf8('line1\nline2\nline3\n'));
    await sync(a, 'A initial');
    await sync(b, 'B initial pull');

    await a.vault.modifyBinary(a.vault.getAbstractFileByPath('note.md'), utf8('line1\nA-edits line2\nline3\n'));
    await sync(a, 'A push v2');
    await b.vault.modifyBinary(b.vault.getAbstractFileByPath('note.md'), utf8('line1\nB-edits line2\nline3\n'));
    const summary = await sync(b, 'B conflict cycle');

    equal(summary?.conflicts, 1, 'plans exactly one conflict');
    equal(await text(b, 'note.md'), 'line1\nA-edits line2\nline3\n', 'remote wins the original path');
    const copies = b.vault.getFiles().map((f) => f.path).filter((p) => p.includes('_conflict_'));
    equal(copies.length, 1, 'local copy preserved as _conflict_ file');
    equal(await text(b, copies[0]), 'line1\nB-edits line2\nline3\n', 'the conflict copy holds B\u2019s edits');
    equal(server.files.get('note.md')?.entry.ver, 2, 'remote stays at v2');
  }

  console.log('[3] IMP-1: clean Markdown auto-merge resolves the conflict');
  {
    const server = new FakeServer(cryptoMod);
    const a = makeDevice('A', new FakeVault(), server, { autoMerge: true });
    const b = makeDevice('B', new FakeVault(), server, { autoMerge: true });

    const note = 'intro line\n\npara-A\n\npara-B\n\noutro\n';
    await a.vault.createBinary('note.md', utf8(note));
    await sync(a, 'A initial');
    await sync(b, 'B initial pull (stores merge base)');

    ok(
      typeof b.journal['note.md']?.basePlain === 'string' && b.journal['note.md'].basePlain === note,
      'toggle on: journal stores the pulled plaintext as merge base',
    );

    // A edits the intro; B edits para-B — different regions.
    await a.vault.modifyBinary(a.vault.getAbstractFileByPath('note.md'), utf8(note.replace('intro line', 'intro line (A)')));
    await sync(a, 'A push');
    await b.vault.modifyBinary(b.vault.getAbstractFileByPath('note.md'), utf8(note.replace('para-B', 'para-B (B)')));
    const summary = await sync(b, 'B conflict cycle with merge');

    equal(summary?.merged, 1, 'conflict resolved by auto-merge');
    equal(summary?.conflicts, 0, 'no keep-both duplication');
    equal(await text(b, 'note.md'), 'intro line (A)\n\npara-A\n\npara-B (B)\n\noutro\n',
      'local file holds the merged note');
    equal(b.vault.getFiles().filter((f) => f.path.includes('_conflict_')).length, 0,
      'no conflict copy was created');
    equal(server.files.get('note.md')?.entry.ver, 3, 'merged content pushed as v3');

    // Device A converges to the merged version on its next cycle.
    await sync(a, 'A pull merged');
    equal(await text(a, 'note.md'), 'intro line (A)\n\npara-A\n\npara-B (B)\n\noutro\n',
      'A receives the merged note');
  }

  console.log('[4] IMP-1: overlapping edits fall back to keep-both even with the toggle on');
  {
    const server = new FakeServer(cryptoMod);
    const a = makeDevice('A', new FakeVault(), server, { autoMerge: true });
    const b = makeDevice('B', new FakeVault(), server, { autoMerge: true });

    await a.vault.createBinary('note.md', utf8('line1\nline2\nline3\n'));
    await sync(a, 'A initial');
    await sync(b, 'B initial pull');

    await a.vault.modifyBinary(a.vault.getAbstractFileByPath('note.md'), utf8('line1\nA-edits line2\nline3\n'));
    await sync(a, 'A push');
    await b.vault.modifyBinary(b.vault.getAbstractFileByPath('note.md'), utf8('line1\nB-edits line2\nline3\n'));
    const summary = await sync(b, 'B conflict cycle');

    equal(summary?.merged, 0, 'no auto-merge for overlapping edits');
    equal(summary?.conflicts, 1, 'keep-both applied');
    equal(b.vault.getFiles().filter((f) => f.path.includes('_conflict_')).length, 1,
      'conflict copy exists');
  }

  console.log('[5] IMP-1: base hygiene — only eligible .md notes, purged when off');
  {
    const server = new FakeServer(cryptoMod);
    const on = makeDevice('A', new FakeVault(), server, { autoMerge: true });
    const off = makeDevice('B', new FakeVault(), server, { autoMerge: false });

    await on.vault.createBinary('note.md', utf8('md content\n'));
    await on.vault.createBinary('data.txt', utf8('txt content\n'));
    await sync(on, 'A push both');
    ok(typeof on.journal['note.md']?.basePlain === 'string', 'toggle on: .md gets a base');
    ok(on.journal['data.txt']?.basePlain === undefined, 'non-.md never gets a base');

    await sync(off, 'B pull');
    ok(off.journal['note.md']?.basePlain === undefined, 'toggle off: no base stored');

    // Turning the toggle off purges stored bases on the next cycle.
    on.settings.enableMarkdownAutoMerge = false;
    await sync(on, 'A idle cycle with toggle off');
    ok(on.journal['note.md']?.basePlain === undefined, 'bases purged after the toggle goes off');
  }

  console.log('[6] IMP-2: interactive resolution — keep mine');
  {
    const server = new FakeServer(cryptoMod);
    const a = makeDevice('A', new FakeVault(), server);
    const asked = [];
    const b = makeDevice('B', new FakeVault(), server, {
      resolveConflict: async (path) => {
        asked.push(path);
        return 'mine';
      },
    });

    await a.vault.createBinary('note.md', utf8('v1\n'));
    await sync(a, 'A initial');
    await sync(b, 'B initial pull');
    await a.vault.modifyBinary(a.vault.getAbstractFileByPath('note.md'), utf8('server edit\n'));
    await sync(a, 'A push v2');
    await b.vault.modifyBinary(b.vault.getAbstractFileByPath('note.md'), utf8('my edit\n'));

    const summary = await sync(b, 'B keep-mine cycle');
    deepEqual(asked, ['note.md'], 'the modal was asked once for the conflicted path');
    equal(summary?.pushed, 1, 'local version pushed');
    equal(summary?.conflicts, 0, 'no keep-both duplication');
    equal(await text(b, 'note.md'), 'my edit\n', 'local file untouched');
    equal(await text0(server.files.get('note.md'), 'note.md'), 'my edit\n', 'remote now holds the local version');
    equal(server.files.get('note.md')?.entry.ver, 3, 'version advanced to 3');

    // A converges: pulls B's winning version.
    await sync(a, 'A pull');
    equal(await text(a, 'note.md'), 'my edit\n', 'A receives the kept version');
  }

  console.log('[7] IMP-2: interactive resolution — keep remote (local edits discarded)');
  {
    const server = new FakeServer(cryptoMod);
    const a = makeDevice('A', new FakeVault(), server);
    const b = makeDevice('B', new FakeVault(), server, { resolveConflict: async () => 'remote' });

    await a.vault.createBinary('note.md', utf8('v1\n'));
    await sync(a, 'A initial');
    await sync(b, 'B initial pull');
    await a.vault.modifyBinary(a.vault.getAbstractFileByPath('note.md'), utf8('server edit\n'));
    await sync(a, 'A push v2');
    await b.vault.modifyBinary(b.vault.getAbstractFileByPath('note.md'), utf8('my doomed edit\n'));

    const summary = await sync(b, 'B keep-remote cycle');
    equal(summary?.pulled, 1, 'remote version pulled');
    equal(await text(b, 'note.md'), 'server edit\n', 'local file replaced by the server version');
    equal(b.vault.getFiles().filter((f) => f.path.includes('_conflict_')).length, 0, 'no copies kept');
  }

  console.log('[8] IMP-2: skip leaves everything for the next cycle');
  {
    const server = new FakeServer(cryptoMod);
    const a = makeDevice('A', new FakeVault(), server);
    const b = makeDevice('B', new FakeVault(), server, { resolveConflict: async () => 'skip' });

    await a.vault.createBinary('note.md', utf8('v1\n'));
    await sync(a, 'A initial');
    await sync(b, 'B initial pull');
    await a.vault.modifyBinary(a.vault.getAbstractFileByPath('note.md'), utf8('server edit\n'));
    await sync(a, 'A push v2');
    await b.vault.modifyBinary(b.vault.getAbstractFileByPath('note.md'), utf8('my edit\n'));

    const summary = await sync(b, 'B skip cycle');
    equal(summary?.skipped, 1, 'skip counted');
    equal(await text(b, 'note.md'), 'my edit\n', 'local file untouched');
    equal(await text0(server.files.get('note.md'), 'note.md'), 'server edit\n', 'remote untouched');
    // The conflict re-plans on the next cycle (still both sides changed).
    const again = makeDevice('B2', b.vault, server, { resolveConflict: async () => 'both' });
    // Reuse B's journal so the planner sees the same stale record.
    for (const [k, v] of Object.entries(b.journal)) again.journal[k] = v;
    const summary2 = await sync(again, 'next cycle re-plans the conflict');
    equal(summary2?.conflicts, 1, 'conflict offered again and resolved as keep-both');
  }

  console.log('[9] IMP-2: auto-run batches keep-both after 5 prompts');
  {
    const server = new FakeServer(cryptoMod);
    const a = makeDevice('A', new FakeVault(), server);
    let asked = 0;
    const b = makeDevice('B', new FakeVault(), server, {
      resolveConflict: async () => {
        asked++;
        return 'both';
      },
    });

    const N = 8;
    for (let i = 0; i < N; i++) {
      await a.vault.createBinary(`c${i}.md`, utf8(`v1-${i}\n`));
    }
    await sync(a, 'A initial 8 files');
    await sync(b, 'B initial pull');

    for (let i = 0; i < N; i++) {
      await a.vault.modifyBinary(a.vault.getAbstractFileByPath(`c${i}.md`), utf8(`server-${i}\n`));
      await b.vault.modifyBinary(b.vault.getAbstractFileByPath(`c${i}.md`), utf8(`local-${i}\n`));
    }
    await sync(a, 'A push all');
    const summary = await sync(b, 'B auto-run with 8 conflicts');

    equal(asked, 5, 'only the first 5 conflicts prompted (CONFLICT_PROMPT_LIMIT)');
    equal(summary?.conflicts, 8, 'all 8 resolved as keep-both');
    const copies = b.vault.getFiles().filter((f) => f.path.includes('_conflict_')).length;
    equal(copies, 8, '8 conflict copies created');
  }

  console.log('[10] IMP-2: interactive run prompts for every conflict');
  {
    const server = new FakeServer(cryptoMod);
    const a = makeDevice('A', new FakeVault(), server);
    let asked = 0;
    const b = makeDevice('B', new FakeVault(), server, {
      resolveConflict: async () => {
        asked++;
        return 'skip';
      },
    });

    for (let i = 0; i < 7; i++) {
      await a.vault.createBinary(`d${i}.md`, utf8(`v1-${i}\n`));
    }
    await sync(a, 'A initial');
    await sync(b, 'B initial pull');
    for (let i = 0; i < 7; i++) {
      await a.vault.modifyBinary(a.vault.getAbstractFileByPath(`d${i}.md`), utf8(`server-${i}\n`));
      await b.vault.modifyBinary(b.vault.getAbstractFileByPath(`d${i}.md`), utf8(`local-${i}\n`));
    }
    await sync(a, 'A push all');
    const summary = await b.engine.runFullSync(true); // interactive run
    equal(asked, 7, 'interactive run prompts for every conflict');
    equal(summary?.skipped, 7, 'all skipped by the user');
  }

  console.log('[11] IMP-3: progress events per op and per chunk');
  {
    const server = new FakeServer(cryptoMod);
    const events = [];
    const a = makeDevice('A', new FakeVault(), server, {
      setProgress: (p) => events.push(p),
    });

    await a.vault.createBinary('notes/big.bin', utf8('# small start\n'));
    await sync(a, 'small push');
    equal(events.filter((e) => e.total === 1 && e.phase === 'push').length, 2,
      'small file: start + completion events for one push');
    equal(events[0].currentPath, 'notes/big.bin', 'progress carries the current path');
    equal(events[events.length - 1].done, 1, 'completion event counts the op as done');

    // Chunked upload: 17.5 MiB -> 3 chunks of 8 MiB -> per-chunk events.
    events.length = 0;
    const big = new Uint8Array(17.5 * 1024 * 1024);
    for (let i = 0; i < big.length; i += 4096) big[i] = i & 0xff;
    await a.vault.createBinary('media/huge.bin', big.buffer);
    await sync(a, 'chunked push');
    const chunkEvents = events.filter((e) => e.chunk);
    deepEqual(chunkEvents.map((e) => e.chunk.index), [1, 2, 3], 'chunk events 1..3 in order');
    deepEqual(chunkEvents.map((e) => e.chunk.count), [3, 3, 3], 'each chunk event knows the total');
    ok(chunkEvents.every((e) => e.phase === 'push' && e.currentPath === 'media/huge.bin'),
      'chunk events carry phase and path');
  }

  console.log('[12] IMP-4: restore from server (fresh clone, never deletes)');
  {
    const server = new FakeServer(cryptoMod);
    const a = makeDevice('A', new FakeVault(), server);
    for (const p of ['a.md', 'b.md', 'dir/c.md']) {
      await a.vault.createBinary(p, utf8(`content of ${p}\n`));
    }
    await sync(a, 'A pushes 3 files');

    // Fresh device: restore pulls everything onto an empty vault.
    const fresh = makeDevice('F', new FakeVault(), server);
    const freshJournalBefore = Object.keys(fresh.journal).length;
    const r1 = await fresh.engine.restoreFromServer(async (count) => {
      equal(count, 3, 'dry-run count reports 3 live files');
      return true;
    });
    equal(r1?.pulled, 3, 'restore pulled every live file');
    equal(r1?.failures, 0, 'restore had no failures');
    equal(freshJournalBefore, 0, 'journal started empty');
    equal(await text(fresh, 'dir/c.md'), 'content of dir/c.md\n', 'restored content matches (nested path)');

    // Device with stale state: journal wiped, files overwritten, local-only
    // files and the tombstoned remote file are never deleted.
    await a.vault.createBinary('a.md', utf8('stale local a\n'));
    await a.vault.createBinary('local-only.md', utf8('keep me\n'));
    a.journal['a.md'] = { localMtime: 1, remoteHash: 'deadbeef', remoteMtime: 1, remoteVersion: 99 };
    const r2 = await a.engine.restoreFromServer();
    equal(r2?.pulled, 3, 'stale device re-downloaded all 3 files');
    equal(await text(a, 'a.md'), 'content of a.md\n', 'stale local file overwritten from the server');
    equal(await text(a, 'local-only.md'), 'keep me\n', 'local-only file never deleted');
    equal(a.journal['a.md']?.remoteVersion, 1, 'journal re-baselined on the server state');

    // Declined confirmation: nothing is wiped, nothing is pulled.
    const declined = makeDevice('D', new FakeVault(), server);
    const r3 = await declined.engine.restoreFromServer(async () => false);
    equal(r3, null, 'declined restore returns null');
    equal(Object.keys(declined.journal).length, 0, 'declined restore leaves the journal untouched');
    equal(declined.vault.getFiles().length, 0, 'declined restore pulls nothing');
  }

  console.log('[13] IMP-5: .syncignore — no ops, server untouched, journal flagged');
  {
    const server = new FakeServer(cryptoMod);
    const a = makeDevice('A', new FakeVault(), server);
    const b = makeDevice('B', new FakeVault(), server);

    await a.vault.createBinary('private/x.md', utf8('secret\n'));
    await a.vault.createBinary('open.md', utf8('open\n'));
    await sync(a, 'A pushes both');
    await sync(b, 'B pulls both');
    equal(await text(b, 'private/x.md'), 'secret\n', 'B has the file before ignoring it');

    // B adds a .syncignore (device-local) and syncs.
    await b.vault.createBinary('.syncignore', utf8('private/\n'));
    const summary = await sync(b, 'B cycle with .syncignore');
    equal(summary?.pushed, 0, 'nothing pushed');
    equal(summary?.pulled, 0, 'nothing pulled');
    equal([...server.files.keys()].includes('.syncignore'), false,
      'the .syncignore file itself never syncs');
    ok(server.files.get('private/x.md') && !server.files.get('private/x.md').entry.deleted,
      'the server entry for the newly-ignored path is left untouched (never delete)');
    equal(b.journal['private/x.md']?.ignored, true, 'the journal flags the ignored record');
    equal(b.journal['open.md']?.ignored, undefined, 'non-ignored records are not flagged');

    // Removing the policy re-enables the path; the flag clears.
    await b.vault.trash(b.vault.getAbstractFileByPath('.syncignore'));
    await sync(b, 'B cycle without .syncignore');
    equal(b.journal['private/x.md']?.ignored, undefined, 'the flag clears when the path syncs again');
  }

  finish('engine.spec');
}

let engine = null;
let TFile = null;
let TFolder = null;

run().catch((err) => {
  console.error('spec crashed:', err);
  process.exit(1);
});
