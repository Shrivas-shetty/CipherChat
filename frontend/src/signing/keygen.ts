import { p256 } from "@noble/curves/nist.js";
import { bytesToBase64 } from "../crypto/base64";
import { fingerprintHex } from "./signature";

export type GeneratedPair = {
  privateKey: Uint8Array;
  publicKeyBytes: Uint8Array;
  publicKeyB64: string;
  fingerprint: string;
  keygenMs: number;
};

export function generateSigningKeyPair(): GeneratedPair {
  const start = performance.now();
  // keygen() draws a valid scalar in [1, n-1] via crypto.getRandomValues.
  const { secretKey } = p256.keygen();
  const publicKeyBytes = p256.getPublicKey(secretKey, false);
  const keygenMs = performance.now() - start;
  return {
    privateKey: secretKey,
    publicKeyBytes,
    publicKeyB64: bytesToBase64(publicKeyBytes),
    fingerprint: fingerprintHex(publicKeyBytes),
    keygenMs,
  };
}
