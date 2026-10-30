import { mean as existingMean, median as existingMedian } from "../analysis/stats";

export { mean as analysisMean, median as analysisMedian } from "../analysis/stats";

export type SummaryStats = {
  n: number; mean: number | null; median: number | null; p95: number | null;
  stddev: number | null; min: number | null; max: number | null;
};

export function mean(values: number[]): number | null {
  return values.length ? existingMean(values) : null;
}

export function median(values: number[]): number | null {
  return values.length ? existingMedian(values) : null;
}

export function percentile(values: number[], p: number): number | null {
  if (!values.length) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const rank = Math.max(1, Math.min(sorted.length, Math.ceil(p * sorted.length)));
  return sorted[rank - 1];
}

export function stddev(values: number[]): number | null {
  if (values.length < 2) return null;
  const average = existingMean(values);
  const sumSquares = values.reduce((sum, value) => sum + (value - average) ** 2, 0);
  return Math.sqrt(sumSquares / (values.length - 1));
}

export function summarize(values: number[]): SummaryStats {
  const sorted = [...values].sort((a, b) => a - b);
  return {
    n: values.length,
    mean: mean(values),
    median: median(values),
    p95: percentile(values, 0.95),
    stddev: stddev(values),
    min: sorted[0] ?? null,
    max: sorted[sorted.length - 1] ?? null,
  };
}
