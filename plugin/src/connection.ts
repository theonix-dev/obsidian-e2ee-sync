/**
 * IMP-8 — mobile connection hygiene probe.
 *
 * Research verdict (see README "Wi-Fi only"): the Network Information API
 * (navigator.connection) exists in the Android System WebView (Chromium) but
 * historically misreported values there (crbug 520088) and still reports
 * `type: 'unknown'` in some builds; iOS's WKWebView does not expose it at
 * all. The only HONEST signals are therefore:
 *   - `type` === 'wifi' | 'ethernet'      -> unmetered;
 *   - `type` === 'cellular'                -> metered;
 *   - `saveData` === true                  -> the user's OS-level Data Saver
 *                                             explicitly asked to save data;
 *   - anything else ('unknown', missing)   -> unsupported: no gate, no guess.
 *
 * When unsupported, a Wi-Fi-only setting must never silently block sync —
 * the setting simply has no effect on that device, which the settings tab
 * and README state plainly.
 */

export interface ConnectionInfo {
  /** True when the platform reported a trustworthy connection type. */
  supported: boolean;
  /** True when the current connection is metered (cellular or Data Saver). */
  metered: boolean;
  /** What the decision was based on. */
  source: 'type' | 'saveData' | 'none';
}

interface ConnectionLike {
  type?: string;
  saveData?: boolean;
}

interface NavigatorLike {
  connection?: ConnectionLike;
}

const UNMETERED_TYPES = new Set(['wifi', 'ethernet']);
const METERED_TYPES = new Set(['cellular']);

/** Probe a navigator-like object (injectable for specs). */
export function readConnectionInfo(nav?: NavigatorLike | null): ConnectionInfo {
  const conn = nav?.connection;
  if (!conn) return { supported: false, metered: false, source: 'none' };
  const type = String(conn.type ?? '').toLowerCase();
  if (UNMETERED_TYPES.has(type)) {
    return { supported: true, metered: false, source: 'type' };
  }
  if (METERED_TYPES.has(type)) {
    return { supported: true, metered: true, source: 'type' };
  }
  if (conn.saveData === true) {
    return { supported: true, metered: true, source: 'saveData' };
  }
  // 'unknown', 'none', missing type without saveData: the platform is not
  // telling — refuse to guess.
  return { supported: false, metered: false, source: 'none' };
}

/** The live navigator of this WebView (undefined in non-DOM contexts). */
export function currentConnectionInfo(): ConnectionInfo {
  const nav = (typeof navigator !== 'undefined' ? navigator : undefined) as
    | NavigatorLike
    | undefined;
  return readConnectionInfo(nav);
}

/**
 * IMP-8 gate for NON-manual syncs. With the toggle off everything syncs;
 * with it on, sync is skipped only while the device reports a metered
 * connection. An unsupported device is never blocked — blocking without a
 * signal would be a heuristic that lies.
 */
export function isAutoSyncAllowed(wifiOnly: boolean, info: ConnectionInfo): boolean {
  if (!wifiOnly) return true;
  if (!info.supported) return true;
  return !info.metered;
}
