import { describe, expect, it } from "vitest";
import { runCollision, runPreimage, runSecondPreimage } from "../attacks";
import { candidate, makeNonce } from "../candidates";
import { digestKey, sha256, utf8 } from "../hashing";

describe("educational hash attacks", () => {
  it("finds valid preimages and independent trials vary", async () => {
    const target = digestKey(sha256(utf8("wanted")), 8) as number;
    const result = await runPreimage({ bits: 8, target, maxAttempts: 2000, maxMs: 5000, nonce: "test0001", yieldFn: async () => {} });
    expect(result.found).toBe(true); expect(result.attempts).toBe(Number(result.details!.message.split("-").at(-1)) + 1);
    expect(digestKey(sha256(utf8(result.details!.message)), 8)).toBe(target);
    expect(makeNonce((b) => b.fill(0x12))).toBe("12121212"); expect(candidate("12345678", 2)).toBe("12345678-2");
  });
  it("finds a distinct second preimage and a collision", async () => {
    const second = await runSecondPreimage({ bits: 8, original: "original", maxAttempts: 2000, maxMs: 5000, nonce: "second01", yieldFn: async () => {} });
    expect(second.found).toBe(true); expect(second.details!.message).not.toBe("original");
    expect(digestKey(sha256(utf8(second.details!.message)), 8)).toBe(digestKey(sha256(utf8("original")), 8));
    const collision = await runCollision({ bits: 16, maxAttempts: 2000, maxMs: 5000, nonce: "collide1", yieldFn: async () => {} });
    expect(collision.found).toBe(true); expect(collision.details!.message1).not.toBe(collision.details!.message2);
    expect(digestKey(sha256(utf8(collision.details!.message1)), 16)).toBe(digestKey(sha256(utf8(collision.details!.message2)), 16));
  });
  it("honors attempt and time limits and cancellation", async () => {
    const limited = await runCollision({ bits: 256, maxAttempts: 2000, maxMs: 5000, nonce: "limit001", yieldFn: async () => {} });
    expect(limited).toMatchObject({ found: false, stopReason: "attempt_limit", attempts: 2000 });
    let time = 0;
    const timed = await runCollision({ bits: 256, maxAttempts: 10000, maxMs: 2, nonce: "time0001", now: () => time++, yieldFn: async () => {} });
    expect(timed.stopReason).toBe("time_limit");
    const abort = new AbortController(); abort.abort();
    expect((await runCollision({ bits: 16, maxAttempts: 1000, maxMs: 5000, nonce: "abort001", signal: abort.signal })).stopReason).toBe("cancelled");
    const yielding = new AbortController(); let yields = 0, reports = 0, fakeNow = 0;
    const cooperative = await runCollision({ bits: 256, maxAttempts: 2000, maxMs: 100000, nonce: "yield001", signal: yielding.signal,
      now: () => fakeNow++, yieldFn: async () => { yields += 1; }, onProgress: () => { reports += 1; } });
    expect(cooperative).toMatchObject({ stopReason: "attempt_limit", attempts: 2000 });
    expect(yields).toBeGreaterThan(0); expect(reports).toBeGreaterThan(0);
  });

  it("finds statistical averages in the expected ranges", async () => {
    const target = digestKey(sha256(utf8("statistical target")), 8) as number;
    let preimageTotal = 0, secondTotal = 0;
    for (let i = 0; i < 50; i += 1) {
      preimageTotal += (await runPreimage({ bits: 8, target, maxAttempts: 2000, maxMs: 5000, nonce: `pre-${i}`, yieldFn: async () => {} })).attempts;
      secondTotal += (await runSecondPreimage({ bits: 8, original: "statistical original", maxAttempts: 2000, maxMs: 5000, nonce: `sec-${i}`, yieldFn: async () => {} })).attempts;
    }
    expect(preimageTotal / 50).toBeGreaterThanOrEqual(150); expect(preimageTotal / 50).toBeLessThanOrEqual(400);
    expect(secondTotal / 50).toBeGreaterThanOrEqual(150); expect(secondTotal / 50).toBeLessThanOrEqual(400);
    let collisionTotal = 0;
    for (let i = 0; i < 30; i += 1) collisionTotal += (await runCollision({ bits: 16, maxAttempts: 2000, maxMs: 5000, nonce: `col-${i}`, yieldFn: async () => {} })).attempts;
    expect(collisionTotal / 30).toBeGreaterThanOrEqual(150); expect(collisionTotal / 30).toBeLessThanOrEqual(600);
  });
});
