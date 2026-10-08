export interface ActiveSessionKeys {
  sessionId: string;
  fingerprint: string;
  kEnc: Uint8Array;
  kMac: Uint8Array;
}

let activeKeys: ActiveSessionKeys | null = null;

/**
 * Stores the active derived session keys in module memory.
 * Never stores keys in localStorage, sessionStorage, or React state.
 */
export function setSessionKeys(keys: ActiveSessionKeys): void {
  // Clear any existing keys first
  clearSessionKeys();
  activeKeys = {
    sessionId: keys.sessionId,
    fingerprint: keys.fingerprint,
    kEnc: new Uint8Array(keys.kEnc),
    kMac: new Uint8Array(keys.kMac),
  };
}

/**
 * Retrieves the currently active session keys, or null if no session is active.
 */
export function getSessionKeys(): ActiveSessionKeys | null {
  return activeKeys;
}

/**
 * Returns true if active session keys exist.
 */
export function hasSessionKeys(): boolean {
  return activeKeys !== null;
}

/**
 * Safely wipes key material by zeroing buffers before discarding reference.
 */
export function clearSessionKeys(): void {
  if (activeKeys) {
    activeKeys.kEnc.fill(0);
    activeKeys.kMac.fill(0);
    activeKeys = null;
  }
}

