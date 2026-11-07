/** Small platform-safe helpers (no Node.js APIs — must run on mobile). */

export function errorMessage(error: unknown): string {
  if (error instanceof Error && error.message) return error.message;
  if (typeof error === 'string') return error;
  try {
    return JSON.stringify(error);
  } catch {
    return String(error);
  }
}

// ------------------------------------------------------------ progress (IMP-3)

/** Structural shape of the engine's progress reports (see SyncEngine). */
export interface ProgressLike {
  /** Ops finished in this cycle. */
  done: number;
  /** Ops planned for this cycle. */
  total: number;
  /** What kind of op `currentPath` is right now. */
  phase: string;
  currentPath: string;
  /** Present while a chunked (large-file) transfer is in flight. */
  chunk?: { index: number; count: number };
}

const PHASE_VERBS: Record<string, string> = {
  push: 'uploading',
  pull: 'downloading',
  conflict: 'resolving',
  delete: 'deleting',
  forget: 'cleaning',
};

/**
 * Status-bar/ribbon text for a running sync: "12/87 — uploading notes/x.md",
 * with a per-file percentage while chunked transfers are in flight.
 */
export function formatProgress(p: ProgressLike): string {
  const verb = PHASE_VERBS[p.phase] ?? 'syncing';
  const base = `${p.done}/${p.total} — ${verb} ${p.currentPath}`;
  if (p.chunk && p.chunk.count > 1) {
    const pct = Math.min(100, Math.max(0, Math.round((p.chunk.index / p.chunk.count) * 100)));
    return `${base} (${pct}%)`;
  }
  return base;
}

function isLocalHost(hostname: string): boolean {
  // Loopback only: mDNS ".local" names can be spoofed on hostile networks.
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]';
}

/**
 * Validate the server URL. Returns null when acceptable, otherwise a
 * human-readable problem description.
 *
 * HTTPS is required for remote hosts: without TLS the API bearer token and the
 * (already encrypted) file payloads would travel in cleartext. Plain HTTP is
 * tolerated for loopback / LAN testing.
 */
export function validateServerUrl(url: string): string | null {
  const trimmed = url.trim();
  if (!trimmed) return null;
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return 'This is not a valid URL (did you include https:// ?).';
  }
  if (parsed.protocol !== 'https:' && !isLocalHost(parsed.hostname)) {
    return 'The URL is not HTTPS — your API token would travel in cleartext. Use HTTPS except for local testing.';
  }
  if (parsed.username || parsed.password) {
    return 'The URL must not contain credentials.';
  }
  return null;
}
