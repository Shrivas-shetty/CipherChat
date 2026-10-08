import { describe, expect, it } from "vitest";
import { correlationSet, mse, npcrUaci, pearsonHorizontal, psnr, shannonEntropy } from "../pixelStats";

describe("pixel statistics", () => {
  it("computes per-channel entropy and interleaving", () => {
    expect(shannonEntropy(new Uint8Array(30).fill(9), 0)).toBe(0);
    const values = new Uint8Array(256 * 3);
    for (let i = 0; i < 256; i += 1) values[i * 3] = i;
    expect(shannonEntropy(values, 0)).toBeCloseTo(8, 12);
    expect(shannonEntropy(new Uint8Array([0, 4, 9, 0, 4, 9, 0, 4, 9, 9, 9, 9]), 0)).toBeCloseTo(-(0.75 * Math.log2(.75) + .25 * Math.log2(.25)), 12);
  });
  it("calculates horizontal correlation per channel without crossing rows", () => {
    const gradient = new Uint8Array(4 * 2 * 3);
    for (let i = 0; i < 8; i += 1) for (let c = 0; c < 3; c += 1) gradient[i * 3 + c] = (i % 4) * 20 + c;
    expect(pearsonHorizontal(gradient, 4, 2, 0)).toBeCloseTo(1, 12);
    const rowEdges = new Uint8Array(2 * 2 * 3);
    [0, 100, 100, 0].forEach((v, i) => { rowEdges[i * 3] = v; });
    expect(pearsonHorizontal(rowEdges, 2, 2, 0)).toBe(-1);
    const alternating = new Uint8Array(4 * 3); [0, 1, 0, 1].forEach((v, i) => { for (let c = 0; c < 3; c += 1) alternating[i * 3 + c] = v; });
    expect(pearsonHorizontal(alternating, 4, 1, 0)).toBe(-1);
    expect(pearsonHorizontal(new Uint8Array(12).fill(3), 2, 2, 0)).toBeNull();
    expect(pearsonHorizontal(new Uint8Array(6), 1, 2, 0)).toBeNull();
    expect(correlationSet(new Uint8Array([1, 4, 8, 2, 4, 9, 3, 4, 10]), 3, 1).g).toBeNull();
  });
  it("computes MSE, PSNR and NPCR/UACI", () => {
    const a = new Uint8Array([0, 20, 255]), b = new Uint8Array([0, 20, 255]);
    expect(mse(a, b)).toBe(0); expect(psnr(0)).toBeNull();
    expect(mse(new Uint8Array([0]), new Uint8Array([255]))).toBe(65025); expect(psnr(65025)).toBe(0);
    expect(psnr(1)).toBeCloseTo(48.1308, 4);
    const changed = npcrUaci(a, new Uint8Array([255, 20, 0]));
    expect(changed.changed).toBe(2); expect(changed.npcr).toBeCloseTo(200 / 3); expect(changed.uaci).toBeCloseTo(200 / 3); expect(changed.sumAbsDiff).toBe(510);
    expect(npcrUaci(a, a)).toMatchObject({ changed: 0, npcr: 0, uaci: 0 });
  });
});
