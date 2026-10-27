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

function isLocalHost(hostname: string): boolean {
  return (
    hostname === 'localhost' ||
    hostname === '127.0.0.1' ||
    hostname === '[::1]' ||
    hostname.endsWith('.local')
  );
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
