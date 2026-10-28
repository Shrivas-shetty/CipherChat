import { describe, expect, it } from "vitest";
import { correlationSet, mse, npcrUaci, pairCount, pearsonDirectional, pearsonHorizontal, psnr, shannonEntropy } from "../pixelStats";

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
  it("counts directional pixel pairs without crossing row boundaries", () => {
    expect(pairCount(4, 3, "h")).toBe(9); expect(pairCount(4, 3, "v")).toBe(8); expect(pairCount(4, 3, "d")).toBe(6);
    expect(pairCount(1, 16, "h")).toBe(0); expect(pairCount(1, 16, "d")).toBe(0); expect(pairCount(1, 16, "v")).toBe(15);
    expect(pairCount(16, 1, "v")).toBe(0); expect(pairCount(16, 1, "d")).toBe(0); expect(pairCount(16, 1, "h")).toBe(15);
    const rgb = (values: number[]) => Uint8Array.from(values.flatMap((v) => [v, v, v]));
    const rows = rgb([0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255]);
    expect(pearsonDirectional(rows, 4, 4, 0, "h")).toBe(1);
    expect(pearsonDirectional(rows, 4, 4, 0, "v")).toBe(-1);
    const checker = rgb(Array.from({ length: 9 }, (_, i) => ((Math.floor(i / 3) + i % 3) % 2) * 255));
    expect(pearsonDirectional(checker, 3, 3, 0, "h")).toBe(-1);
    expect(pearsonDirectional(checker, 3, 3, 0, "v")).toBe(-1);
    expect(pearsonDirectional(checker, 3, 3, 0, "d")).toBe(1);
    const boundary = rgb([0, 0, 0, 255, 255, 255]);
    expect(pearsonDirectional(boundary, 2, 3, 0, "h")).toBeCloseTo(.5, 12);
    expect(pearsonDirectional(boundary, 2, 3, 0, "d")).toBeNull();
    expect(pearsonDirectional(rgb([0, 10, 20, 30]), 1, 4, 0, "v")).toBe(1);
    expect(pearsonDirectional(rgb([0, 10, 20, 30]), 4, 1, 0, "h")).toBe(1);
    expect(pearsonDirectional(rgb([0, 1, 2, 3]), 1, 4, 0, "h")).toBeNull();
    expect(pearsonDirectional(rgb([0, 1, 2, 3]), 1, 4, 0, "d")).toBeNull();
    expect(pearsonDirectional(rgb([0, 1, 2, 3]), 4, 1, 0, "v")).toBeNull();
    expect(pearsonDirectional(rgb([0, 1, 2, 3]), 4, 1, 0, "d")).toBeNull();
    const channels = Uint8Array.from([0, 3, 9, 255, 3, 8, 255, 3, 7, 0, 3, 6]);
    expect(pearsonDirectional(channels, 2, 2, 0, "v")).toBe(-1);
    expect(pearsonDirectional(channels, 2, 2, 1, "v")).toBeNull();
  });
});
