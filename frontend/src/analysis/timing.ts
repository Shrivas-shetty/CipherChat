import { TIMING_MAX_ITERS, TIMING_MIN_BATCH_MS, TIMING_SAMPLES } from "./config";

export type TimingDeps = { now: () => number; yieldFn: () => Promise<void>; minBatchMs?: number; samples?: number; maxIters?: number; signal?: AbortSignal };
const median = (values: number[]) => { const sorted = [...values].sort((a, b) => a - b); return sorted[Math.floor(sorted.length / 2)]; };

export async function measureMedianUs(fn: () => void, deps: TimingDeps): Promise<{ medianUs: number; iters: number }> {
  const check = () => { if (deps.signal?.aborted) throw new Error("aborted"); };
  for (let i = 0; i < 3; i += 1) { check(); fn(); await deps.yieldFn(); }
  const minMs = deps.minBatchMs ?? TIMING_MIN_BATCH_MS;
  const maxIters = deps.maxIters ?? TIMING_MAX_ITERS;
  let iters = 1;
  while (iters < maxIters) {
    check();
    const start = deps.now();
    for (let i = 0; i < iters; i += 1) fn();
    const elapsed = deps.now() - start;
    await deps.yieldFn();
    check();
    if (elapsed >= minMs) break;
    iters = Math.min(maxIters, iters * 2);
  }
  const values: number[] = [];
  for (let sample = 0; sample < (deps.samples ?? TIMING_SAMPLES); sample += 1) {
    check();
    const start = deps.now();
    for (let i = 0; i < iters; i += 1) fn();
    values.push(((deps.now() - start) * 1000) / iters);
    await deps.yieldFn();
    check();
  }
  return { medianUs: median(values), iters };
}
