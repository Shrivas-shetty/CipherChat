import { describe, expect, it } from "vitest";
import { bytesToBase64, base64ToBytes } from "../../crypto/base64";
import { ciphertextToNoiseRgb, fitWithin, rgbToRgba, rgbaToRgb, sha256Hex } from "../pipeline";

describe("image pixel pipeline", () => {
  it("fits dimensions without upscaling", () => {
    expect(fitWithin(4000, 3000, 512)).toEqual({ w: 512, h: 384 });
    expect(fitWithin(300, 200, 512)).toEqual({ w: 300, h: 200 });
    expect(fitWithin(1, 1000, 512)).toEqual({ w: 1, h: 512 });
    expect(fitWithin(512, 512, 512)).toEqual({ w: 512, h: 512 });
  });
  it("converts RGB and RGBA and slices ciphertext visualization", () => {
    const rgb = new Uint8Array([10, 20, 30, 40, 50, 60]);
    expect(rgbaToRgb(rgbToRgba(rgb))).toEqual(rgb);
    expect(ciphertextToNoiseRgb(new Uint8Array(32).fill(9), 2, 2)).toHaveLength(12);
  });
  it("hashes bytes and base64 round trips one megabyte", () => {
    expect(sha256Hex(new Uint8Array())).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    const bytes = new Uint8Array(1024 * 1024);
    for (let offset = 0; offset < bytes.length; offset += 65536) crypto.getRandomValues(bytes.subarray(offset, offset + 65536));
    expect(base64ToBytes(bytesToBase64(bytes))).toEqual(bytes);
  });
});
