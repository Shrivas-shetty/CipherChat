export type Point = { x: number; y: number };
export type Regression = { slope: number; intercept: number; r2: number };
export const mean = (values: number[]) => values.length ? values.reduce((sum, value) => sum + value, 0) / values.length : 0;
export function median(values: number[]): number {
  if (!values.length) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}
export function linearRegression(points: Point[]): Regression | null {
  if (points.length < 2) return null;
  const xMean = mean(points.map((p) => p.x)), yMean = mean(points.map((p) => p.y));
  const variance = points.reduce((sum, p) => sum + (p.x - xMean) ** 2, 0);
  if (variance === 0) return null;
  const covariance = points.reduce((sum, p) => sum + (p.x - xMean) * (p.y - yMean), 0);
  const slope = covariance / variance, intercept = yMean - slope * xMean;
  const residual = points.reduce((sum, p) => sum + (p.y - (slope * p.x + intercept)) ** 2, 0);
  const total = points.reduce((sum, p) => sum + (p.y - yMean) ** 2, 0);
  return { slope, intercept, r2: total === 0 ? 1 : 1 - residual / total };
}
export function regressionLineEnds(points: Point[], reg: Regression | null): Point[] {
  if (!reg || points.length < 2) return [];
  const xs = points.map((p) => p.x), minX = Math.min(...xs), maxX = Math.max(...xs);
  return [{ x: minX, y: reg.slope * minX + reg.intercept }, { x: maxX, y: reg.slope * maxX + reg.intercept }];
}
