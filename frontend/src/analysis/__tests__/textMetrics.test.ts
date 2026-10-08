import { describe, expect, it } from "vitest";
import vectors from "../../../../shared/test_vectors/text_metrics.json";
import { aesCbcDecrypt, aesCbcEncrypt } from "../aes";
import { countDiffBits, countDiffBitsInRange, flipBit } from "../bits";
import { computeTextMetrics, MetricsAbort } from "../textMetrics";

const fromHex = (hex: string) => Uint8Array.from(hex.match(/.{2}/g)?.map((x) => Number.parseInt(x, 16)) ?? []);
function seeded(seed: number) { let state = seed >>> 0; return () => { state = (Math.imul(state, 1664525) + 1013904223) >>> 0; return state / 0x1_0000_0000; }; }
const yieldFn = async () => new Promise<void>((resolve) => setTimeout(resolve, 0));

describe("text security analysis", () => {
  it("matches the Python AES-CBC cross-language oracle", () => {
    const key = fromHex(vectors.key_hex), iv = fromHex(vectors.iv_hex);
    for (const c of vectors.cases) {
      const pt = fromHex(c.pt_hex), ct = aesCbcEncrypt(key, iv, pt);
      expect(Array.from(ct, (x) => x.toString(16).padStart(2, "0")).join("")).toBe(c.ct_hex);
      expect(Array.from(aesCbcDecrypt(key, iv, ct))).toEqual(Array.from(pt));
      for (const t of c.key_flip_trials) expect(countDiffBits(ct, aesCbcEncrypt(flipBit(key, t.bit_idx), iv, pt))).toBe(t.changed_bits);
      for (const t of c.pt_flip_trials) {
        const altered = aesCbcEncrypt(key, iv, flipBit(pt, t.bit_idx));
        const start = Math.floor(Math.floor(t.bit_idx / 8) / 16) * 16;
        expect(countDiffBits(ct, altered)).toBe(t.changed_bits);
        expect(countDiffBitsInRange(ct, altered, start, Math.min(start + 16, ct.length))).toBe(t.block_changed_bits);
      }
    }
  });

  it("computes fixed-count trials and percentages from a valid baseline", async () => {
    const key = new Uint8Array(32).fill(3), iv = new Uint8Array(16).fill(7), pt = new TextEncoder().encode("metrics 🙂"), ct = aesCbcEncrypt(key, iv, pt);
    const result = await computeTextMetrics({ key, iv, pt, ct }, { rng: seeded(7), yieldFn });
    expect(result.key_flip_pcts).toHaveLength(8); expect(result.pt_flip_bit_idx).toHaveLength(8);
    expect(result.key_flip_pcts.every((x) => x >= 0 && x <= 100)).toBe(true);
    expect(result.pt_flip_changed_bits.every((x, i) => x >= result.pt_flip_block_changed_bits[i])).toBe(true);
    expect(key.every((x) => x === 3)).toBe(true);
  });

  it("stops before posting on baseline mismatch and aborts between trials", async () => {
    const key = new Uint8Array(32).fill(1), iv = new Uint8Array(16), pt = new Uint8Array([1, 2, 3]), ct = aesCbcEncrypt(key, iv, pt);
    await expect(computeTextMetrics({ key, iv, pt, ct: new Uint8Array(ct).fill(0) })).rejects.toMatchObject({ reason: "baseline mismatch" });
    const abort = new AbortController(); let yields = 0;
    await expect(computeTextMetrics({ key, iv, pt, ct }, { rng: seeded(2), signal: abort.signal, yieldFn: async () => { yields += 1; abort.abort(); } })).rejects.toBeInstanceOf(MetricsAbort);
    expect(yields).toBe(1);
  });

  it("keeps preceding CBC blocks unchanged and changes downstream blocks", () => {
    const key = new Uint8Array(32).fill(9), iv = new Uint8Array(16).fill(5), pt = new Uint8Array(80).map((_, i) => i);
    const before = aesCbcEncrypt(key, iv, pt), after = aesCbcEncrypt(key, iv, flipBit(pt, 32 * 8));
    expect(before.slice(0, 32)).toEqual(after.slice(0, 32));
    for (let offset = 32; offset < before.length; offset += 16) expect(before.slice(offset, offset + 16)).not.toEqual(after.slice(offset, offset + 16));
  });

  it("has plausible confusion and block-avalanche averages over 64 trials", async () => {
    const key = new Uint8Array(32).fill(0x25), iv = new Uint8Array(16).fill(0x41), pt = new Uint8Array(200).map((_, i) => i & 255), ct = aesCbcEncrypt(key, iv, pt);
    const runs = await Promise.all(Array.from({ length: 8 }, (_, i) => computeTextMetrics({ key, iv, pt, ct }, { rng: seeded(100 + i), yieldFn })));
    const confusion = runs.flatMap((r) => r.key_flip_pcts).reduce((a, b) => a + b, 0) / 64;
    const block = runs.reduce((a, r) => a + r.block_avalanche_pct, 0) / runs.length;
    expect(confusion).toBeGreaterThanOrEqual(46); expect(confusion).toBeLessThanOrEqual(54);
    expect(block).toBeGreaterThanOrEqual(45); expect(block).toBeLessThanOrEqual(55);
  });
});
