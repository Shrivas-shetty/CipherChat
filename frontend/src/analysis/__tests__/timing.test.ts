import { describe, expect, it } from "vitest";
import { measureMedianUs } from "../timing";

describe("AES timing calibration", () => {
  it("doubles batch size to the threshold and returns the sample median", async () => {
    let clock = 0, calls = 0;
    const result = await measureMedianUs(() => { calls += 1; clock += 1; }, { now: () => clock, yieldFn: async () => {}, minBatchMs: 5, samples: 5, maxIters: 64 });
    expect(result.iters).toBe(8); expect(result.medianUs).toBe(1000); expect(calls).toBe(3 + 1 + 2 + 4 + 8 + 40);
  });
  it("caps calibration at the maximum iteration count", async () => {
    let clock = 0;
    const result = await measureMedianUs(() => {}, { now: () => clock, yieldFn: async () => {}, minBatchMs: 5, samples: 5, maxIters: 16 });
    expect(result.iters).toBe(16);
  });
});
