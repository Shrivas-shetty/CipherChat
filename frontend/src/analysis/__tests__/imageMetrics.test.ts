import { describe, expect, it } from "vitest";
import vectors from "../../../../shared/test_vectors/image_metrics.json";
import { aesCbcDecrypt, aesCbcEncrypt } from "../aes";
import { computeImageMetrics } from "../imageMetrics";
import { correlationSet, mse, npcrUaci, psnr, shannonEntropy } from "../pixelStats";

const bytes = (hex: string) => Uint8Array.from(hex.match(/.{2}/g)?.map((v) => Number.parseInt(v, 16)) ?? []);
const hex = (value: Uint8Array) => Array.from(value, (b) => b.toString(16).padStart(2, "0")).join("");
const close = (actual: number | null, expected: number | null) => expected === null ? expect(actual).toBeNull() : expect(actual).toBeCloseTo(expected, 9);
let clock = 0;
const timingDeps = { now: () => (clock += 10), yieldFn: async () => {} };

describe("image metrics browser implementation", () => {
  it("matches the committed Python oracle ciphertext and image statistics", async () => {
    const key = bytes(vectors.key_hex), iv = bytes(vectors.iv_hex);
    for (const testCase of vectors.cases) {
      const pixels = bytes(testCase.pixels_hex), ct = aesCbcEncrypt(key, iv, pixels), n = pixels.length;
      expect(hex(ct)).toBe(testCase.ct_hex);
      expect(hex(aesCbcDecrypt(key, iv, ct))).toBe(testCase.pixels_hex);
      for (const flip of testCase.flip_trials) {
        const changedPixels = new Uint8Array(pixels); changedPixels[flip.byte_idx] ^= 1;
        const changedCt = aesCbcEncrypt(key, iv, changedPixels), diff = npcrUaci(ct, changedCt, n);
        expect(hex(changedCt)).toBe(flip.ct_hex); expect(diff.changed).toBe(flip.changed_count); expect(diff.sumAbsDiff).toBe(flip.sum_abs_diff);
      }
      [0, 1, 2].forEach((channel) => close(shannonEntropy(ct.slice(0, n), channel as 0 | 1 | 2, n), [testCase.entropy_r, testCase.entropy_g, testCase.entropy_b][channel]));
      const ptCorr = correlationSet(pixels, testCase.w, testCase.h), ctCorr = correlationSet(ct.slice(0, n), testCase.w, testCase.h);
      for (const keyName of ["r", "g", "b", "avg"] as const) { close(ptCorr[keyName], testCase.corr_pt[keyName]); close(ctCorr[keyName], testCase.corr_ct[keyName]); }
      const mseEnc = mse(pixels, ct, n); close(mseEnc, testCase.mse_enc); close(psnr(mseEnc), testCase.psnr_enc);
      const result = await computeImageMetrics({ w: testCase.w, h: testCase.h, key, iv, pixels, ct }, { ...timingDeps, rng: () => 0.41 });
      expect(result.mse_dec).toBe(0); expect(result.psnr_dec).toBeNull();
      expect(result.npcr_trial_pcts).toHaveLength(5); expect(result.uaci_trial_pcts).toHaveLength(5);
      expect(result.flip_byte_idx.every((i) => i >= 0 && i < n)).toBe(true);
      expect([...result.npcr_trial_pcts, ...result.uaci_trial_pcts].every((v) => v >= 0 && v <= 100)).toBe(true);
      ct.fill(0);
    }
  });

  it("preserves CBC forward propagation and the averaged random-region estimates", async () => {
    const w = 64, h = 64, pixels = new Uint8Array(w * h * 3);
    for (let i = 0; i < pixels.length; i += 1) pixels[i] = (i * 73 + (i >>> 3) * 19) & 255;
    const key = new Uint8Array(32).fill(17), iv = new Uint8Array(16).fill(8), ct = aesCbcEncrypt(key, iv, pixels);
    const i = 701, changed = new Uint8Array(pixels); changed[i] ^= 1;
    const changedCt = aesCbcEncrypt(key, iv, changed), start = Math.floor(i / 16) * 16;
    expect(changedCt.slice(0, start)).toEqual(ct.slice(0, start));
    let regionChanged = 0; for (let j = start; j < ct.length; j += 1) if (ct[j] !== changedCt[j]) regionChanged += 1;
    expect(regionChanged / (ct.length - start)).toBeGreaterThanOrEqual(.98);
    let yieldCount = 0; clock = 0;
    const result = await computeImageMetrics({ w, h, key, iv, pixels, ct }, { ...timingDeps, rng: () => .5, yieldFn: async () => { yieldCount += 1; } });
    expect(result.npcr_trials).toBe(5); expect(yieldCount).toBeGreaterThanOrEqual(5);
    expect(Math.abs(result.entropy_avg - (8 - 184 / (w * h)))).toBeLessThan(.03);
    expect(Math.abs(result.corr_ct_avg ?? 1)).toBeLessThan(.05);
    for (let j = 0; j < 5; j += 1) {
      const index = result.flip_byte_idx[j], factor = (pixels.length - 16 * Math.floor(index / 16)) / pixels.length;
      expect(Math.abs(result.npcr_trial_pcts[j] - 99.61 * factor)).toBeLessThan(2.5);
      expect(Math.abs(result.uaci_trial_pcts[j] - 33.46 * factor)).toBeLessThan(2.5);
    }
  });

  it("rejects a baseline mismatch and reports a non-lossless decrypt", async () => {
    const pixels = new Uint8Array([1, 2, 3]), key = new Uint8Array(32), iv = new Uint8Array(16), ct = aesCbcEncrypt(key, iv, pixels);
    await expect(computeImageMetrics({ w: 1, h: 1, pixels, key, iv, ct: new Uint8Array(ct).fill(0) }, timingDeps)).rejects.toMatchObject({ reason: "baseline mismatch" });
    const aes = { encrypt: aesCbcEncrypt, decrypt: (k: Uint8Array, v: Uint8Array, c: Uint8Array) => { const decoded = aesCbcDecrypt(k, v, c); decoded[0] ^= 1; return decoded; } };
    const result = await computeImageMetrics({ w: 1, h: 1, pixels, key, iv, ct }, { ...timingDeps, aes });
    expect(result.mse_dec).toBeGreaterThan(0); expect(result.psnr_dec).not.toBeNull();
    await expect(computeImageMetrics({ w: 1, h: 1, pixels, key, iv, ct }, { ...timingDeps, aes: { encrypt: aesCbcEncrypt, decrypt: () => { throw new Error("bad padding"); } } })).rejects.toMatchObject({ reason: "decrypt error" });
  });

  it("honors aborts between asynchronous steps", async () => {
    const controller = new AbortController(), pixels = new Uint8Array([1, 2, 3]), key = new Uint8Array(32), iv = new Uint8Array(16), ct = aesCbcEncrypt(key, iv, pixels);
    const retained: Uint8Array[] = [];
    const aes = { encrypt: (k: Uint8Array, v: Uint8Array, p: Uint8Array) => { retained.push(k, v, p); return aesCbcEncrypt(k, v, p); }, decrypt: aesCbcDecrypt };
    await expect(computeImageMetrics({ w: 1, h: 1, pixels, key, iv, ct }, { aes, signal: controller.signal, yieldFn: async () => controller.abort() })).rejects.toMatchObject({ name: "MetricsAbort" });
    expect(retained.length).toBeGreaterThan(0); expect(retained.every((buffer) => buffer.every((value) => value === 0))).toBe(true);
  });

  it("finishes a maximum-size image job and yields during its trials", async () => {
    const w = 512, h = 512, pixels = new Uint8Array(w * h * 3);
    for (let i = 0; i < pixels.length; i += 1) pixels[i] = (i * 19 + (i >>> 5) * 7) & 255;
    const key = new Uint8Array(32).fill(41), iv = new Uint8Array(16).fill(7), ct = aesCbcEncrypt(key, iv, pixels);
    let yields = 0; clock = 0; const started = Date.now();
    const result = await computeImageMetrics({ w, h, pixels, key, iv, ct }, { ...timingDeps, rng: () => .37, yieldFn: async () => { yields += 1; } });
    expect(Date.now() - started).toBeLessThan(20_000); expect(yields).toBeGreaterThanOrEqual(5); expect(result.n_pixels).toBe(512 * 512);
  });
});
