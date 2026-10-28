import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { measureMedianUs } from "../analysis/timing";

export const HMAC_TIMING_MIN_BATCH_MS = 2;
export const HMAC_TIMING_SAMPLES = 3;
export const HMAC_TIMING_MAX_ITERS = 5000;

export async function measureHmacUs(kMac: Uint8Array, macInput: Uint8Array): Promise<number> {
  const measured = await measureMedianUs(() => { hmac(sha256, kMac, macInput); }, {
    now: () => performance.now(), yieldFn: () => new Promise<void>((resolve) => setTimeout(resolve, 0)),
    warmups: 1, minBatchMs: HMAC_TIMING_MIN_BATCH_MS, samples: HMAC_TIMING_SAMPLES, maxIters: HMAC_TIMING_MAX_ITERS,
  });
  return Number.isFinite(measured.medianUs) ? Math.max(0.001, measured.medianUs) : 0.001;
}
