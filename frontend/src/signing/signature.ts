import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "../crypto/encoding";

const encoder = new TextEncoder();

function len4(bytes: Uint8Array): Uint8Array {
  const result = new Uint8Array(bytes.length + 4);
  new DataView(result.buffer).setUint32(0, bytes.length, false);
  result.set(bytes, 4);
  return result;
}

export function buildSignatureInput(macInput: Uint8Array, hmacTag: Uint8Array): Uint8Array {
  const prefix = encoder.encode("CC1-sig"), a = len4(macInput), b = len4(hmacTag);
  const result = new Uint8Array(prefix.length + a.length + b.length);
  result.set(prefix); result.set(a, prefix.length); result.set(b, prefix.length + a.length);
  return result;
}

export function fingerprintHex(publicKeyBytes: Uint8Array): string {
  return bytesToHex(sha256(publicKeyBytes));
}

export function formatFingerprint(hex: string): string {
  return hex.slice(0, 16).match(/.{4}/g)?.join(" ").toUpperCase() ?? "";
}

export function parsePublicKeyBytes(publicKeyBytes: Uint8Array): Uint8Array {
  if (publicKeyBytes.length !== 65 || publicKeyBytes[0] !== 0x04) throw new Error("bad_public_key");
  try {
    p256.Point.fromBytes(publicKeyBytes);
  } catch {
    throw new Error("bad_public_key");
  }
  return new Uint8Array(publicKeyBytes);
}

export function signEcdsa(privateKey: Uint8Array, signatureInput: Uint8Array): Uint8Array {
  if (privateKey.length !== 32) throw new Error("bad_private_key");
  // noble-curves 2.4 hashes by default. Hash explicitly once to match the
  // specified SHA-256 digest, then disable its default prehash.
  return p256.sign(sha256(signatureInput), privateKey, { prehash: false, lowS: true, format: "compact" });
}

export function verifyEcdsa(publicKeyBytes: Uint8Array, signatureInput: Uint8Array, signature: Uint8Array): boolean {
  try {
    if (publicKeyBytes.length !== 65 || publicKeyBytes[0] !== 0x04 || signature.length !== 64) return false;
    return p256.verify(signature, sha256(signatureInput), publicKeyBytes,
      { prehash: false, lowS: false, format: "compact" });
  } catch {
    return false;
  }
}
