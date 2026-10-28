import { measureMedianUs } from "../analysis/timing";
import { PERF_COUNT_MAX, TRIALS_MAX } from "./config";
import { defaultYield, type RuntimeDeps } from "./runtime";

export type PerformanceRow = { count: number; time_ms: number; us_per_hash: number; hashes_per_second: number; trials: number };
export async function runPerformance({ counts, trials, hash, measureMedianUs: customMeasure, now = () => performance.now(), yieldFn = defaultYield, signal, onProgress }: {
  counts: number[]; trials: number; hash: (message: string) => void; measureMedianUs?: typeof measureMedianUs; now?: () => number; yieldFn?: () => Promise<void>; signal?: AbortSignal; onProgress?: RuntimeDeps["onProgress"];
}): Promise<PerformanceRow[]> {
  if (counts.some((n) => !Number.isInteger(n) || n < 1 || n > PERF_COUNT_MAX) || !Number.isInteger(trials) || trials < 1 || trials > TRIALS_MAX) throw new RangeError("invalid benchmark settings");
  const rows: PerformanceRow[] = [];
  for (const count of counts) {
    if (signal?.aborted) break;
    const result = customMeasure
      ? await customMeasure(() => { for (let i = 0; i < count; i += 1) hash(`bench-${i}`); }, { now, yieldFn, samples: trials, signal })
      : await measureMedianUs(() => {}, { now, yieldFn, samples: trials, signal,
        cooperative: { count, run: (i) => hash(`bench-${i}`) },
        onProgress: (attempts, elapsed_ms) => onProgress?.({ attempts, elapsed_ms, hashesPerSecond: attempts * 1000 / Math.max(.001, elapsed_ms) }) });
    const usPerHash = Math.max(Number.EPSILON, result.medianUs);
    const timeMs = Math.max(Number.EPSILON, usPerHash * count / 1000);
    rows.push({ count, time_ms: timeMs, us_per_hash: usPerHash, hashes_per_second: 1_000_000 / usPerHash, trials });
    onProgress?.({ attempts: count, elapsed_ms: timeMs, hashesPerSecond: count / (timeMs / 1000) });
  }
  return rows;
}
