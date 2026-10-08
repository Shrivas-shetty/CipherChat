import { extract, expand } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "./encoding";
import {
  CONFIRM_PREFIX,
  FINGERPRINT_LEN,
  INFO_ENC,
  INFO_FINGERPRINT,
  INFO_MAC,
  KEY_LEN_ENC,
  KEY_LEN_MAC,
  SALT_PREFIX,
} from "./params";

export interface DerivedSessionKeys {
  kEnc: Uint8Array;
  kMac: Uint8Array;
  fingerprintBytes: Uint8Array;
  fingerprint: string;
}

const encoder = new TextEncoder();

export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const totalLen = arrays.reduce((sum, a) => sum + a.length, 0);
  const out = new Uint8Array(totalLen);
  let offset = 0;
  for (const arr of arrays) {
    out.set(arr, offset);
    offset += arr.length;
  }
  return out;
}

/**
 * Formats 8 fingerprint bytes as uppercase hex in 4 groups of 4 separated by spaces,
 * e.g. "60B3 9698 05E7 205C".
 */
export function fingerprintString(fingerprintBytes: Uint8Array): string {
  if (fingerprintBytes.length !== FINGERPRINT_LEN) {
    throw new Error(`Fingerprint must be ${FINGERPRINT_LEN} bytes`);
  }
  const hex = bytesToHex(fingerprintBytes).toUpperCase();
  return `${hex.slice(0, 4)} ${hex.slice(4, 8)} ${hex.slice(8, 12)} ${hex.slice(12, 16)}`;
}

/**
 * Derives K_enc (32 bytes), K_mac (32 bytes), and fingerprint (8 bytes)
 * via HKDF-SHA256 according to RFC 5869.
 */
export function deriveSessionKeys(
  Z: Uint8Array,
  sessionId: string,
  pubInitiator: Uint8Array,
  pubResponder: Uint8Array
): DerivedSessionKeys {
  const cleanSessionId = encoder.encode(sessionId.trim().toLowerCase());
  const saltMaterial = concatBytes(
    SALT_PREFIX,
    cleanSessionId,
    pubInitiator,
    pubResponder
  );
  const salt = sha256(saltMaterial);

  const prk = extract(sha256, Z, salt);
  const kEnc = expand(sha256, prk, INFO_ENC, KEY_LEN_ENC);
  const kMac = expand(sha256, prk, INFO_MAC, KEY_LEN_MAC);
  const fingerprintBytes = expand(sha256, prk, INFO_FINGERPRINT, FINGERPRINT_LEN);
  const fingerprint = fingerprintString(fingerprintBytes);

  return {
    kEnc,
    kMac,
    fingerprintBytes,
    fingerprint,
  };
}

/**
 * Computes key confirmation tag:
 * HMAC-SHA256(key=K_mac, msg = ASCII "CC1-confirm" || ASCII session_id || ASCII role_char)
 * where role_char is "I" for initiator and "R" for responder.
 */
export function confirmTag(
  kMac: Uint8Array,
  sessionId: string,
  role: "initiator" | "responder" | "I" | "R"
): string {
  const roleChar = role === "initiator" || role === "I" ? "I" : "R";
  const cleanSessionId = encoder.encode(sessionId.trim().toLowerCase());
  const msg = concatBytes(CONFIRM_PREFIX, cleanSessionId, encoder.encode(roleChar));
  const tagBytes = hmac(sha256, kMac, msg);
  return bytesToHex(tagBytes);
}

/**
 * Constant-time comparison between two hex string confirmation tags.
 */
export function constantTimeCompare(a: string, b: string): boolean {
  const strA = a.trim().toLowerCase();
  const strB = b.trim().toLowerCase();
  if (strA.length !== strB.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < strA.length; i++) {
    diff |= strA.charCodeAt(i) ^ strB.charCodeAt(i);
  }
  return diff === 0;
}

/**
 * Verifies a received key confirmation tag against expected tag in constant time.
 */
export function verifyConfirmTag(
  kMac: Uint8Array,
  sessionId: string,
  role: "initiator" | "responder" | "I" | "R",
  receivedTag: string
): boolean {
  const expected = confirmTag(kMac, sessionId, role);
  return constantTimeCompare(expected, receivedTag);
}

