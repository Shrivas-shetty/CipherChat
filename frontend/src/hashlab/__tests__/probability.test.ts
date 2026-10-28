import { describe, expect, it } from "vitest";
import { expectedAttempts, formatPow2, formatSci, successProbability } from "../probability";
describe("hash attack probability", () => {
  it("computes expected work and birthday probability", () => {
    expect(expectedAttempts("preimage", 16)).toBe(65536);
    expect(expectedAttempts("collision", 16)).toBeCloseTo(320.8, 0);
    expect(expectedAttempts("preimage", 256)).toBe(2 ** 256);
    expect(successProbability("preimage", 16, 65536)).toBeCloseTo(.632, 2);
    expect(successProbability("collision", 16, 302)).toBeCloseTo(.5, 2);
    expect(successProbability("preimage", 256, 100000)).toBeGreaterThan(0);
    expect(successProbability("preimage", 256, 100000)).toBeCloseTo(8.6e-73, -1);
    expect(successProbability("collision", 16, 0)).toBe(0);
    expect(formatSci(1.2e-72)).toBe("1.2e-72"); expect(formatPow2(256)).toContain("2^256");
  });
});
