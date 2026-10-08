export const POPCOUNT = Uint8Array.from({ length: 256 }, (_, n) => {
  let x = n, count = 0;
  while (x) { count += x & 1; x >>>= 1; }
  return count;
});

export function countDiffBits(a: Uint8Array, b: Uint8Array): number {
  if (a.length !== b.length) throw new Error("Byte arrays must have equal lengths");
  let count = 0;
  for (let i = 0; i < a.length; i += 1) count += POPCOUNT[a[i] ^ b[i]];
  return count;
}

export function flipBit(bytes: Uint8Array, index: number): Uint8Array {
  if (!Number.isInteger(index) || index < 0 || index >= bytes.length * 8) throw new RangeError("Bit index out of range");
  const copy = new Uint8Array(bytes);
  copy[index >>> 3] ^= 1 << (7 - (index & 7));
  return copy;
}

export function countDiffBitsInRange(a: Uint8Array, b: Uint8Array, byteStart: number, byteEnd: number): number {
  if (a.length !== b.length) throw new Error("Byte arrays must have equal lengths");
  if (!Number.isInteger(byteStart) || !Number.isInteger(byteEnd) || byteStart < 0 || byteEnd < byteStart || byteEnd > a.length) throw new RangeError("Byte range out of bounds");
  let count = 0;
  for (let i = byteStart; i < byteEnd; i += 1) count += POPCOUNT[a[i] ^ b[i]];
  return count;
}
