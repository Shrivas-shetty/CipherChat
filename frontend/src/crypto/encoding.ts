import { BYTE_LEN } from "./params";

/**
 * Encodes a Uint8Array to a lowercase hexadecimal string.
 */
export function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return hex.toLowerCase();
}

/**
 * Decodes a lowercase hexadecimal string to a Uint8Array.
 * Throws if string is not even-length or contains non-hexadecimal characters.
 */
export function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== "string") {
    throw new Error("hex must be a string");
  }
  if (hex.length % 2 !== 0) {
    throw new Error("Hex string must have an even length");
  }
  if (!/^[0-9a-f]*$/.test(hex)) {
    throw new Error("Hex string must contain only lowercase hexadecimal characters");
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Encodes a non-negative BigInt to a 256-byte big-endian Uint8Array.
 * Left-pads with zeros if necessary.
 */
export function bigintTo256Bytes(n: bigint): Uint8Array {
  if (n < 0n) {
    throw new Error("Cannot encode negative BigInt");
  }
  let hex = n.toString(16);
  if (hex.length % 2 !== 0) {
    hex = "0" + hex;
  }
  const rawBytes = hexToBytes(hex);
  if (rawBytes.length > BYTE_LEN) {
    throw new Error(`BigInt exceeds fixed length of ${BYTE_LEN} bytes`);
  }
  const out = new Uint8Array(BYTE_LEN);
  out.set(rawBytes, BYTE_LEN - rawBytes.length);
  return out;
}

/**
 * Decodes a big-endian Uint8Array into a BigInt.
 */
export function bytesToBigInt(bytes: Uint8Array): bigint {
  if (bytes.length === 0) {
    return 0n;
  }
  const hex = bytesToHex(bytes);
  return BigInt("0x" + (hex || "0"));
}

