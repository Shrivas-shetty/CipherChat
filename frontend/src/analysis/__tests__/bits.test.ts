import { describe, expect, it } from "vitest";
import { countDiffBits, countDiffBitsInRange, flipBit, POPCOUNT } from "../bits";

describe("bit helpers", () => {
  it("has correct popcounts for all byte values", () => { for (let n = 0; n < 256; n += 1) { let ref = 0; for (let i = 0; i < 8; i += 1) ref += (n >> i) & 1; expect(POPCOUNT[n]).toBe(ref); } });
  it("counts differences, flips one bit in a copy, and counts byte ranges", () => {
    const a = new Uint8Array([0, 0xff, 0x10]), b = new Uint8Array([1, 0xf0, 0x11]);
    expect(countDiffBits(a, b)).toBe(6); expect(countDiffBitsInRange(a, b, 1, 2)).toBe(4);
    const flipped = flipBit(a, 0); expect(flipped).not.toBe(a); expect(countDiffBits(a, flipped)).toBe(1); expect(a[0]).toBe(0);
  });
  it("rejects length mismatches and invalid ranges", () => { expect(() => countDiffBits(new Uint8Array(1), new Uint8Array(2))).toThrow(/equal lengths/); expect(() => countDiffBitsInRange(new Uint8Array(1), new Uint8Array(1), 0, 2)).toThrow(); });
});
