import { describe, expect, it } from "vitest";
import { hashLabStore } from "../store";
describe("hash lab in-memory store", () => {
  it("notifies subscribers and clears entries", () => {
    hashLabStore.clear(); let notified = 0; const stop = hashLabStore.subscribe(() => notified++);
    hashLabStore.add({ attack: "collision", bits: 16, limit: 10, result: { found: false, attempts: 10, elapsed_ms: 1, stopReason: "attempt_limit", nonce: "test" }, expected: 320, mode: "16-BIT DEMO" });
    expect(hashLabStore.getSnapshot().entries).toHaveLength(1); expect(notified).toBe(1);
    hashLabStore.clear(); expect(hashLabStore.getSnapshot().entries).toHaveLength(0); stop();
  });
});
