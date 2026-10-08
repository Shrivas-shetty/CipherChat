import { bigintTo256Bytes, bytesToBigInt, bytesToHex, hexToBytes } from "./encoding";
import { modpow } from "./modpow";
import { BYTE_LEN, G, P, PRIVATE_EXP_BYTES } from "./params";

export interface PrivateKey {
  x: bigint;
  bytes: Uint8Array;
}

/**
 * Generates 32 random bytes from CSPRNG, forces top bit to 1 (x >= 2^255).
 */
export function generatePrivate(): PrivateKey {
  const bytes = new Uint8Array(PRIVATE_EXP_BYTES);
  crypto.getRandomValues(bytes);
  bytes[0] |= 0x80;
  const x = bytesToBigInt(bytes);
  return { x, bytes };
}

/**
 * Computes public key y = g^x mod p.
 */
export function publicFromPrivate(x: bigint): bigint {
  return modpow(G, x, P);
}

/**
 * Encodes public key as 512 lowercase hex characters (256 bytes big-endian).
 */
export function encodePublic(y: bigint): string {
  const bytes = bigintTo256Bytes(y);
  return bytesToHex(bytes);
}

/**
 * Decodes 512 lowercase hex characters to a BigInt public key.
 */
export function decodePublic(hexStr: string): bigint {
  if (typeof hexStr !== "string") {
    throw new Error("Public value must be a string");
  }
  if (hexStr.length !== BYTE_LEN * 2) {
    throw new Error(`Public value must be exactly ${BYTE_LEN * 2} characters`);
  }
  const bytes = hexToBytes(hexStr);
  return bytesToBigInt(bytes);
}

/**
 * Peer public validation: 2 <= y <= p - 2.
 * Rejects non-hex, wrong length, or out-of-range values.
 */
export function validatePublic(y: bigint | string): { valid: boolean; reason: string } {
  let val: bigint;
  if (typeof y === "string") {
    try {
      val = decodePublic(y);
    } catch {
      return { valid: false, reason: "bad_public" };
    }
  } else if (typeof y === "bigint") {
    val = y;
  } else {
    return { valid: false, reason: "bad_public" };
  }

  if (val < 2n || val > P - 2n) {
    return { valid: false, reason: "bad_public" };
  }

  return { valid: true, reason: "" };
}

/**
 * Computes shared secret Z = peer_y^x mod p, encoded as 256-byte big-endian Uint8Array.
 */
export function sharedSecret(peerY: bigint, x: bigint): Uint8Array {
  const check = validatePublic(peerY);
  if (!check.valid) {
    throw new Error("Invalid peer public value for Diffie-Hellman");
  }
  const zInt = modpow(peerY, x, P);
  return bigintTo256Bytes(zInt);
}

