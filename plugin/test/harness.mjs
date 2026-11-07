/**
 * Spec harness — loads real TypeScript sources under plain Node without any
 * test-framework dependency.
 *
 * esbuild (already a devDependency) bundles the target module in memory with
 * the `obsidian` import aliased to a minimal stub, the resulting CJS bundle
 * is evaluated, and its exports are handed to the spec. This exercises the
 * PRODUCTION code, not a re-implementation.
 */

import { build } from 'esbuild';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const buildDir = path.join(__dirname, '.build');
fs.mkdirSync(buildDir, { recursive: true });

/** Minimal `obsidian` surface needed by the pure engine/crypto modules. */
const STUB = `
export class TFile {
  constructor(path, mtime) { this.path = path; this.stat = { mtime }; }
}
export class TFolder {
  constructor(path) { this.path = path; }
}
export function normalizePath(p) {
  const cleaned = String(p).replace(/\\\\/g, '/').split('/').filter((s, i) => s !== '' && !(s === '.' && i > 0));
  let out = cleaned.join('/');
  if (out.startsWith('./')) out = out.slice(2);
  return out;
}
export function requestUrl() {
  throw new Error('requestUrl must not be called from pure specs');
}
`;

export async function loadModule(relPath, { stub = true } = {}) {
  // The sources legitimately target the Obsidian WebView runtime, where Web
  // Crypto hangs off `window`. Under plain Node it lives on globalThis.
  if (typeof globalThis.window === 'undefined') globalThis.window = globalThis;

  const entry = path.resolve(__dirname, '..', relPath);
  let stubMod = null;
  const externals = [];
  if (stub) {
    const stubPath = path.join(buildDir, 'obsidian-stub.mjs');
    fs.writeFileSync(stubPath, STUB);
    stubMod = await import(stubPath);
    // Keep "obsidian" external so the bundle does not inline a private copy
    // of the stub classes — specs import the same module file, and executor
    // instanceof checks (TFile/TFolder) must see ONE class identity.
    externals.push('obsidian');
  }
  const result = await build({
    entryPoints: [entry],
    bundle: true,
    format: 'cjs',
    platform: 'neutral',
    target: 'node18',
    write: false,
    logLevel: 'silent',
    external: externals,
  });
  const code = result.outputFiles[0].text;
  const mod = { exports: {} };
  const requireStub = (name) => {
    if (name === 'obsidian' && stubMod) return stubMod;
    throw new Error(`Unexpected require("${name}") in the spec bundle`);
  };
  new Function('module', 'exports', 'require', code)(mod, mod.exports, requireStub);
  return mod.exports;
}

// ----------------------------------------------------------- tiny assert lib

let passed = 0;
let failed = 0;
const failures = [];

export function ok(condition, label, detail = '') {
  if (condition) {
    passed++;
    console.log(`  ✔ ${label}`);
  } else {
    failed++;
    failures.push(label);
    console.log(`  ✘ ${label}${detail ? ` — ${detail}` : ''}`);
  }
}

export function equal(actual, expected, label) {
  ok(
    actual === expected,
    label,
    `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`,
  );
}

export function deepEqual(actual, expected, label) {
  const a = JSON.stringify(actual);
  const e = JSON.stringify(expected);
  ok(a === e, label, `expected ${e}, got ${a}`);
}

export async function throws(fn, label, match = null) {
  let threw = null;
  try {
    await fn();
  } catch (err) {
    threw = err;
  }
  if (!threw) {
    ok(false, label, 'did not throw');
    return;
  }
  if (match && !match.test(threw.message || '')) {
    ok(false, label, `threw unexpected message: ${threw.message}`);
    return;
  }
  ok(true, label);
}

export function finish(specName) {
  console.log(`\n${specName}: ${passed} passed, ${failed} failed`);
  if (failed > 0) {
    for (const f of failures) console.error(`  FAILED: ${f}`);
    process.exit(1);
  }
  process.exit(0);
}
