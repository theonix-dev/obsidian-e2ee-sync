/**
 * IMP-8 — spec for the connection probe and the auto-sync gate.
 */

import { finish, loadModule, ok, equal, deepEqual } from './harness.mjs';

async function run() {
  const { readConnectionInfo, isAutoSyncAllowed } = await loadModule('src/connection.ts');

  console.log('[1] platform probes');
  deepEqual(readConnectionInfo(undefined), { supported: false, metered: false, source: 'none' },
    'no navigator at all -> unsupported');
  deepEqual(readConnectionInfo(null), { supported: false, metered: false, source: 'none' },
    'null navigator -> unsupported');
  deepEqual(readConnectionInfo({}), { supported: false, metered: false, source: 'none' },
    'navigator without connection (iOS WKWebView) -> unsupported');
  deepEqual(readConnectionInfo({ connection: {} }), { supported: false, metered: false, source: 'none' },
    'empty connection object -> unsupported');

  console.log('[2] trustworthy type values');
  ok(readConnectionInfo({ connection: { type: 'wifi' } }).supported, 'wifi supported');
  equal(readConnectionInfo({ connection: { type: 'wifi' } }).metered, false, 'wifi -> unmetered');
  equal(readConnectionInfo({ connection: { type: 'ethernet' } }).metered, false, 'ethernet -> unmetered');
  equal(readConnectionInfo({ connection: { type: 'cellular' } }).metered, true, 'cellular -> metered');
  equal(readConnectionInfo({ connection: { type: 'CELLULAR' } }).metered, true, 'type matching is case-insensitive');
  ok(readConnectionInfo({ connection: { type: 'cellular', saveData: false } }).metered,
    'cellular stays metered without saveData');

  console.log('[3] saveData is an honest signal on its own');
  {
    const r = readConnectionInfo({ connection: { saveData: true } });
    ok(r.supported && r.metered && r.source === 'saveData', 'saveData -> metered (the user asked)');
  }

  console.log('[4] unknown/none refuse to guess');
  ok(!readConnectionInfo({ connection: { type: 'unknown' } }).supported, "type 'unknown' -> unsupported");
  ok(!readConnectionInfo({ connection: { type: 'none' } }).supported, "type 'none' -> unsupported");
  ok(!readConnectionInfo({ connection: { type: 'wifi', saveData: false } }).metered,
    'wifi+saveData:false -> unmetered');

  console.log('[5] the gate');
  ok(isAutoSyncAllowed(false, readConnectionInfo({ connection: { type: 'cellular' } })),
    'toggle off -> sync allowed even on cellular');
  ok(!isAutoSyncAllowed(true, readConnectionInfo({ connection: { type: 'cellular' } })),
    'toggle on + cellular -> blocked');
  ok(isAutoSyncAllowed(true, readConnectionInfo({ connection: { type: 'wifi' } })),
    'toggle on + wifi -> allowed');
  ok(!isAutoSyncAllowed(true, readConnectionInfo({ connection: { saveData: true } })),
    'toggle on + saveData -> blocked');
  ok(isAutoSyncAllowed(true, readConnectionInfo({})),
    'toggle on + unsupported platform -> NEVER blocked (no heuristic that lies)');

  finish('connection.spec');
}

run().catch((err) => {
  console.error('spec crashed:', err);
  process.exit(1);
});
