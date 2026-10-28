import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";

const encoder = new TextEncoder();
export const sha256 = (bytes: Uint8Array): Uint8Array => nobleSha256(bytes);
export const utf8 = (value: string): Uint8Array => encoder.encode(value);
export const toHex = (bytes: Uint8Array): string => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

export function digestKey(digest: Uint8Array, bits: number): number | string {
  if (bits === 256) return toHex(digest.slice(0, 8));
  if (!Number.isInteger(bits) || bits < 4 || bits > 32 || bits % 4 !== 0) throw new RangeError("bits must be a multiple of 4 from 4 to 32 or 256");
  let value = 0; const bytes = Math.ceil(bits / 8);
  for (let i = 0; i < bytes; i += 1) value = value * 256 + digest[i];
  return (value >>> (bytes * 8 - bits)) >>> 0;
}

export function prefixHex(digest: Uint8Array, bits: number): string {
  if (bits === 256) return toHex(digest);
  if (!Number.isInteger(bits) || bits < 4 || bits > 32 || bits % 4 !== 0) throw new RangeError("bits must be a multiple of 4 from 4 to 32 or 256");
  return toHex(digest).slice(0, bits / 4);
}

export function digestsEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}
