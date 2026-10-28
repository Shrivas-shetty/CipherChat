import { describe, expect, it } from "vitest";
import { runPerformance } from "../performance";
import { sha256, utf8 } from "../hashing";
describe("hash benchmark runner", () => {
  it("validates settings and reports median timing fields", async () => {
    const result = await runPerformance({ counts: [20, 100], trials: 3, hash: () => {}, measureMedianUs: async (fn, deps) => { fn(); await deps.yieldFn(); return { medianUs: 2, iters: 4 }; } });
    expect(result[0]).toMatchObject({ count: 20, time_ms: .04, us_per_hash: 2, hashes_per_second: 500000, trials: 3 });
    await expect(runPerformance({ counts: [0], trials: 1, hash: () => {} })).rejects.toThrow();
    await expect(runPerformance({ counts: [1], trials: 21, hash: () => {} })).rejects.toThrow();
    const guarded = await runPerformance({ counts: [1], trials: 1, hash: () => {}, measureMedianUs: async () => ({ medianUs: 0, iters: 1 }) });
    expect(guarded[0].hashes_per_second).toBeGreaterThan(0);
  });
  it("runs cooperative real-hash smoke samples", async () => {
    const rows = await runPerformance({ counts: [20, 2000], trials: 2, hash: (message) => { sha256(utf8(message)); } });
    expect(rows.every((row) => row.time_ms > 0 && row.hashes_per_second > 0)).toBe(true);
    expect(rows[1].time_ms).toBeGreaterThan(rows[0].time_ms);
  });
});
