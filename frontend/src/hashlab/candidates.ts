import { utf8 } from "./hashing";

export function makeNonce(rand: (bytes: Uint8Array) => void = (bytes) => crypto.getRandomValues(bytes)): string {
  const bytes = new Uint8Array(4); rand(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
export const candidate = (nonce: string, i: number): string => `${nonce}-${i}`;
export const candidateBytes = (nonce: string, i: number): Uint8Array => utf8(candidate(nonce, i));
