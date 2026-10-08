import { describe, expect, it } from "vitest";
import { base64ToBytes, nearestNeighborThumbSize } from "../noiseImage";

describe("cipher noise image helpers", () => {
  it("decodes large base64 data without spreading or overflowing the stack", () => {
    const source = new Uint8Array(1024 * 1024); for (let i = 0; i < source.length; i += 1) source[i] = i & 255;
    let binary = ""; const chunk = 0x8000;
    for (let i = 0; i < source.length; i += chunk) binary += String.fromCharCode(...source.subarray(i, i + chunk));
    const decoded = base64ToBytes(btoa(binary));
    expect(decoded).toEqual(source);
  });
  it("sizes pixelated thumbnails without upscaling", () => {
    expect(nearestNeighborThumbSize(512, 512)).toEqual({ w: 96, h: 96 });
    expect(nearestNeighborThumbSize(40, 20)).toEqual({ w: 40, h: 20 });
    expect(nearestNeighborThumbSize(1, 1)).toEqual({ w: 1, h: 1 });
  });
});
