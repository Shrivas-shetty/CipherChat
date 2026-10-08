import { countDiffBits, countDiffBitsInRange, flipBit } from "./bits";
import { aesCbcDecrypt, aesCbcEncrypt } from "./aes";
import { KEY_FLIP_TRIALS, PT_FLIP_TRIALS } from "./config";
import { uniformInt } from "./rng";
import { measureMedianUs } from "./timing";

export class MetricsAbort extends Error { constructor() { super("aborted"); this.name = "MetricsAbort"; } }
export class MetricsFailure extends Error {
  reason: string;
  constructor(reason: string) { super(reason); this.reason = reason; this.name = "MetricsFailure"; }
}
export type TextMetricsResult = {
  pt_len_bytes: number; ct_len_bytes: number; total_ct_bits: number; key_trials: number; confusion_pct: number; key_flip_pcts: number[];
  pt_trials: number; diffusion_bits: number; avalanche_pct: number; block_avalanche_pct: number;
  pt_flip_bit_idx: number[]; pt_flip_changed_bits: number[]; pt_flip_block_changed_bits: number[];
  enc_us: number; dec_us: number; timing_iters: number;
};
export type TextMetricsInput = { key: Uint8Array; iv: Uint8Array; pt: Uint8Array; ct: Uint8Array };
export type TextMetricsDeps = { rng?: () => number; now?: () => number; yieldFn?: () => Promise<void>; signal?: AbortSignal };
const defaultYield = () => new Promise<void>((resolve) => setTimeout(resolve, 0));
const mean = (values: number[]) => values.reduce((sum, value) => sum + value, 0) / values.length;
const sameBytes = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((v, i) => v === b[i]);

export async function computeTextMetrics(input: TextMetricsInput, deps: TextMetricsDeps = {}): Promise<TextMetricsResult> {
  const rng = deps.rng ?? (() => crypto.getRandomValues(new Uint32Array(1))[0] / 0x1_0000_0000);
  const now = deps.now ?? (() => performance.now());
  const yieldFn = deps.yieldFn ?? defaultYield;
  const check = () => { if (deps.signal?.aborted) throw new MetricsAbort(); };
  const key = new Uint8Array(input.key), iv = new Uint8Array(input.iv), pt = new Uint8Array(input.pt), ct = new Uint8Array(input.ct);
  try {
    if (key.length !== 32 || iv.length !== 16 || pt.length < 1 || ct.length < 16 || ct.length % 16 !== 0) throw new MetricsFailure("bad input");
    check();
    const baseline = aesCbcEncrypt(key, iv, pt);
    if (!sameBytes(baseline, ct)) throw new MetricsFailure("baseline mismatch");
    baseline.fill(0);
    const totalBits = ct.length * 8;
    const keyPcts: number[] = [];
    for (let trial = 0; trial < KEY_FLIP_TRIALS; trial += 1) {
      check();
      const bitIndex = uniformInt(255, rng);
      const modifiedKey = flipBit(key, bitIndex);
      try { const changed = aesCbcEncrypt(modifiedKey, iv, pt); keyPcts.push(countDiffBits(ct, changed) / totalBits * 100); changed.fill(0); }
      finally { modifiedKey.fill(0); }
      await yieldFn();
    }
    const ptBits: number[] = [], changedBits: number[] = [], blockBits: number[] = [];
    for (let trial = 0; trial < PT_FLIP_TRIALS; trial += 1) {
      check();
      const bitIndex = uniformInt(pt.length * 8 - 1, rng);
      const modifiedPt = flipBit(pt, bitIndex);
      try {
        const changed = aesCbcEncrypt(key, iv, modifiedPt);
        ptBits.push(bitIndex); changedBits.push(countDiffBits(ct, changed));
        const blockStart = Math.floor(Math.floor(bitIndex / 8) / 16) * 16;
        blockBits.push(countDiffBitsInRange(ct, changed, blockStart, Math.min(blockStart + 16, ct.length)));
        changed.fill(0);
      } finally { modifiedPt.fill(0); }
      await yieldFn();
    }
    check();
    const timingDeps = { now, yieldFn, signal: deps.signal };
    const encryptTiming = await measureMedianUs(() => { const result = aesCbcEncrypt(key, iv, pt); result.fill(0); }, timingDeps);
    check();
    const decryptTiming = await measureMedianUs(() => {
      const result = aesCbcDecrypt(key, iv, ct);
      if (!sameBytes(result, pt)) { result.fill(0); throw new MetricsFailure("decrypt mismatch"); }
      result.fill(0);
    }, timingDeps);
    check();
    return {
      pt_len_bytes: pt.length, ct_len_bytes: ct.length, total_ct_bits: totalBits,
      key_trials: keyPcts.length, confusion_pct: mean(keyPcts), key_flip_pcts: keyPcts,
      pt_trials: ptBits.length, diffusion_bits: mean(changedBits), avalanche_pct: mean(changedBits) / totalBits * 100,
      block_avalanche_pct: mean(blockBits) / 128 * 100, pt_flip_bit_idx: ptBits,
      pt_flip_changed_bits: changedBits, pt_flip_block_changed_bits: blockBits,
      enc_us: encryptTiming.medianUs, dec_us: decryptTiming.medianUs, timing_iters: encryptTiming.iters,
    };
  } catch (error) {
    if (deps.signal?.aborted) throw new MetricsAbort();
    throw error;
  } finally { key.fill(0); iv.fill(0); pt.fill(0); ct.fill(0); }
}
