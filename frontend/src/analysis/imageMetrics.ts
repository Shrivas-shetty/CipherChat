import { aesCbcDecrypt, aesCbcEncrypt } from "./aes";
import { NPCR_TRIALS } from "./config";
import { correlationSet, mse, npcrUaci, psnr, shannonEntropy } from "./pixelStats";
import { uniformInt } from "./rng";
import { measureMedianUs } from "./timing";
import { MetricsAbort, MetricsFailure } from "./textMetrics";

export type ImageMetricsResult = {
  width: number; height: number; n_pixels: number; pt_len_bytes: number; ct_len_bytes: number;
  npcr_trials: number; npcr_pct: number; npcr_trial_pcts: number[]; npcr_changed_counts: number[];
  uaci_pct: number; uaci_trial_pcts: number[]; flip_byte_idx: number[];
  entropy_r: number; entropy_g: number; entropy_b: number; entropy_avg: number;
  corr_pt_r: number | null; corr_pt_g: number | null; corr_pt_b: number | null; corr_pt_avg: number | null;
  corr_ct_r: number | null; corr_ct_g: number | null; corr_ct_b: number | null; corr_ct_avg: number | null;
  mse_dec: number; psnr_dec: number | null; mse_enc: number; psnr_enc: number | null;
  enc_us: number; dec_us: number; timing_iters: number;
};
export type ImageMetricsInput = { w: number; h: number; key: Uint8Array; iv: Uint8Array; pixels: Uint8Array; ct: Uint8Array };
type Aes = { encrypt: typeof aesCbcEncrypt; decrypt: typeof aesCbcDecrypt };
export type ImageMetricsDeps = { rng?: () => number; now?: () => number; yieldFn?: () => Promise<void>; signal?: AbortSignal; aes?: Aes };
const defaultYield = () => new Promise<void>((resolve) => setTimeout(resolve, 0));
const mean = (v: number[]) => v.reduce((a, x) => a + x, 0) / v.length;
const equal = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((v, i) => v === b[i]);

export async function computeImageMetrics(input: ImageMetricsInput, deps: ImageMetricsDeps = {}): Promise<ImageMetricsResult> {
  const key = new Uint8Array(input.key), iv = new Uint8Array(input.iv), pixels = new Uint8Array(input.pixels), ct = new Uint8Array(input.ct);
  let cipherCopy: Uint8Array | undefined;
  const aes = deps.aes ?? { encrypt: aesCbcEncrypt, decrypt: aesCbcDecrypt };
  const yieldFn = deps.yieldFn ?? defaultYield;
  const check = () => { if (deps.signal?.aborted) throw new MetricsAbort(); };
  const yieldStep = async () => { check(); await yieldFn(); check(); };
  try {
    const n = input.w * input.h * 3;
    if (!Number.isInteger(input.w) || !Number.isInteger(input.h) || input.w < 1 || input.h < 1 || key.length !== 32 || iv.length !== 16 || pixels.length !== n || ct.length < n || ct.length % 16 !== 0) throw new MetricsFailure("bad input");
    check();
    const baseline = aes.encrypt(key, iv, pixels);
    const baselineMatches = equal(baseline, ct);
    baseline.fill(0);
    if (!baselineMatches) throw new MetricsFailure("baseline mismatch");
    await yieldStep();

    const cipher = cipherCopy = ct.slice(0, n);
    const flipByteIdx: number[] = [], changedCounts: number[] = [], npcrPcts: number[] = [], uaciPcts: number[] = [];
    for (let trial = 0; trial < NPCR_TRIALS; trial += 1) {
      check();
      const index = uniformInt(n - 1, deps.rng);
      const modified = new Uint8Array(pixels); modified[index] ^= 1;
      let modifiedCt: Uint8Array | undefined;
      try {
        modifiedCt = aes.encrypt(key, iv, modified);
        const result = npcrUaci(cipher, modifiedCt, n);
        flipByteIdx.push(index); changedCounts.push(result.changed); npcrPcts.push(result.npcr); uaciPcts.push(result.uaci);
      } finally { modified.fill(0); modifiedCt?.fill(0); }
      await yieldStep();
    }

    const entropy = [0, 1, 2].map((c) => shannonEntropy(cipher, c as 0 | 1 | 2, n));
    const cipherCorrelation = correlationSet(cipher, input.w, input.h);
    const plainCorrelation = correlationSet(pixels, input.w, input.h);
    await yieldStep();
    const mseEnc = mse(pixels, cipher, n), psnrEnc = psnr(mseEnc);
    await yieldStep();
    let decoded: Uint8Array;
    try { decoded = aes.decrypt(key, iv, ct); }
    catch { throw new MetricsFailure("decrypt error"); }
    let mseDec: number;
    try { mseDec = mse(pixels, decoded, n); } finally { decoded.fill(0); }
    const psnrDec = psnr(mseDec);
    await yieldStep();

    const timingDeps = { now: deps.now ?? (() => performance.now()), yieldFn, signal: deps.signal };
    const encTiming = await measureMedianUs(() => { const result = aes.encrypt(key, iv, pixels); result.fill(0); }, timingDeps);
    const decTiming = await measureMedianUs(() => { const result = aes.decrypt(key, iv, ct); result.fill(0); }, timingDeps);
    check();
    return {
      width: input.w, height: input.h, n_pixels: input.w * input.h, pt_len_bytes: n, ct_len_bytes: ct.length,
      npcr_trials: NPCR_TRIALS, npcr_pct: mean(npcrPcts), npcr_trial_pcts: npcrPcts, npcr_changed_counts: changedCounts,
      uaci_pct: mean(uaciPcts), uaci_trial_pcts: uaciPcts, flip_byte_idx: flipByteIdx,
      entropy_r: entropy[0], entropy_g: entropy[1], entropy_b: entropy[2], entropy_avg: mean(entropy),
      corr_pt_r: plainCorrelation.r, corr_pt_g: plainCorrelation.g, corr_pt_b: plainCorrelation.b, corr_pt_avg: plainCorrelation.avg,
      corr_ct_r: cipherCorrelation.r, corr_ct_g: cipherCorrelation.g, corr_ct_b: cipherCorrelation.b, corr_ct_avg: cipherCorrelation.avg,
      mse_dec: mseDec, psnr_dec: psnrDec, mse_enc: mseEnc, psnr_enc: psnrEnc,
      enc_us: encTiming.medianUs, dec_us: decTiming.medianUs, timing_iters: encTiming.iters,
    };
  } catch (error) {
    if (deps.signal?.aborted) throw new MetricsAbort();
    throw error;
  } finally { key.fill(0); iv.fill(0); pixels.fill(0); ct.fill(0); cipherCopy?.fill(0); }
}
