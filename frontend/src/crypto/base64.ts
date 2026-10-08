/**
 * Standard base64 encoding and decoding for Uint8Array.
 */

export function bytesToBase64(bytes: Uint8Array): string {
  const chunks: string[] = [];
  for (let offset = 0; offset < bytes.length; offset += 32 * 1024) {
    chunks.push(String.fromCharCode(...bytes.subarray(offset, offset + 32 * 1024)));
  }
  return btoa(chunks.join(""));
}

export function base64ToBytes(b64: string): Uint8Array {
  const normalized = b64.trim();
  const binary = atob(normalized);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

