import { describe, expect, it } from "vitest";
import { uniformInt } from "../rng";

describe("uniformInt", () => {
  it("stays in bounds and reaches every value", () => { let n = 0; const seen = new Set<number>(); for (let i = 0; i < 10000; i += 1) { n = (n + 0.38196601125) % 1; seen.add(uniformInt(6, () => n)); } expect([...seen].sort()).toEqual([0, 1, 2, 3, 4, 5, 6]); });
  it("is deterministic for an injected generator", () => { const rng = () => 0.375; expect(uniformInt(7, rng)).toBe(0); expect(uniformInt(7, rng)).toBe(0); });
});
