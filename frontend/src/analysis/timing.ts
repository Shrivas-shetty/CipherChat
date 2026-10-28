import { TIMING_MAX_ITERS, TIMING_MIN_BATCH_MS, TIMING_SAMPLES } from "./config";

export type TimingDeps = { now: () => number; yieldFn: () => Promise<void>; minBatchMs?: number; samples?: number; maxIters?: number; signal?: AbortSignal;
  cooperative?: { count: number; run: (index: number) => void }; onProgress?: (operations: number, elapsedMs: number) => void };
const median = (values: number[]) => { const sorted = [...values].sort((a, b) => a - b); return sorted[Math.floor(sorted.length / 2)]; };

export async function measureMedianUs(fn: () => void, deps: TimingDeps): Promise<{ medianUs: number; iters: number }> {
  if (deps.cooperative) return measureMedianUsAsync(deps.cooperative.count, deps.cooperative.run, deps);
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

/** Cooperative per-operation timer for CPU-heavy browser workloads. */
export async function measureMedianUsAsync(count: number, fn: (index: number) => void, deps: TimingDeps): Promise<{ medianUs: number; iters: number }> {
  const check = () => { if (deps.signal?.aborted) throw new Error("aborted"); };
  const minMs = deps.minBatchMs ?? TIMING_MIN_BATCH_MS;
  const maxRepeats = 4096;
  let repeats = 1;
  const batch = async (repeatCount: number) => {
    const start = deps.now(); let lastYield = start, operations = 0;
    for (let repeat = 0; repeat < repeatCount; repeat += 1) {
      for (let i = 0; i < count; i += 1) {
        check(); fn(i); operations += 1;
        if (operations % 1024 === 0 && deps.now() - lastYield >= 16) {
          deps.onProgress?.(operations, Math.max(0, deps.now() - start));
          await deps.yieldFn(); lastYield = deps.now();
        }
      }
    }
    return { elapsed: Math.max(Number.EPSILON, deps.now() - start), operations };
  };
  for (let i = 0; i < 3; i += 1) { check(); await batch(1); await deps.yieldFn(); }
  let measured = await batch(repeats);
  while (measured.elapsed < minMs && repeats < maxRepeats) {
    await deps.yieldFn(); check(); repeats = Math.min(maxRepeats, repeats * 2); measured = await batch(repeats);
  }
  const values: number[] = [];
  for (let sample = 0; sample < (deps.samples ?? TIMING_SAMPLES); sample += 1) {
    check(); const result = await batch(repeats); values.push(result.elapsed * 1000 / result.operations); await deps.yieldFn();
  }
  return { medianUs: median(values), iters: repeats };
}
