import { describe, expect, it } from "vitest";
import { linearRegression, mean, median } from "../stats";

describe("statistics helpers", () => {
  it("computes mean and median", () => { expect(mean([1, 2, 3])).toBe(2); expect(median([8, 1, 4, 2])).toBe(3); });
  it("fits exact and noisy data", () => {
    expect(linearRegression([{ x: 0, y: 1 }, { x: 1, y: 3 }, { x: 2, y: 5 }])).toEqual({ slope: 2, intercept: 1, r2: 1 });
    const fit = linearRegression([{ x: 0, y: 1 }, { x: 1, y: 2.9 }, { x: 2, y: 5.1 }, { x: 3, y: 7 }])!;
    expect(fit.slope).toBeCloseTo(2, 1); expect(fit.r2).toBeGreaterThan(0.99);
  });
  it("returns null when regression is undefined", () => { expect(linearRegression([{ x: 2, y: 1 }, { x: 2, y: 5 }])).toBeNull(); expect(linearRegression([{ x: 1, y: 2 }])).toBeNull(); });
});
