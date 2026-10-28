import { ATTACK_MAX_ATTEMPTS_CAP, FULL_BITS, SLICE_MS } from "./config";
import { candidate, candidateBytes } from "./candidates";
import { digestKey, digestsEqual, prefixHex, sha256, toHex } from "./hashing";
import { defaultYield, type RuntimeDeps } from "./runtime";
import type { Attack } from "./probability";

export type StopReason = "found" | "attempt_limit" | "time_limit" | "cancelled";
export type AttackOptions = RuntimeDeps & { bits: number; maxAttempts: number; maxMs: number; nonce: string; hash?: (bytes: Uint8Array) => Uint8Array };
export type AttackResult = { found: boolean; attempts: number; elapsed_ms: number; stopReason: StopReason; nonce: string; details?: Record<string, string> };
type Target = { digest?: Uint8Array; key: number | string; original?: string };
const isValidBits = (bits: number) => bits === FULL_BITS || (Number.isInteger(bits) && bits >= 4 && bits <= 32 && bits % 4 === 0);

async function run(attack: Attack, options: AttackOptions, target?: Target): Promise<AttackResult> {
  const { bits, maxAttempts, maxMs, nonce, signal, onProgress } = options;
  if (!isValidBits(bits) || !Number.isInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > ATTACK_MAX_ATTEMPTS_CAP || !Number.isFinite(maxMs) || maxMs <= 0) throw new RangeError("invalid attack settings");
  const now = options.now ?? (() => performance.now()), yieldFn = options.yieldFn ?? defaultYield, hash = options.hash ?? sha256;
  const started = now(); let lastYield = started, attempts = 0, reason: StopReason = "attempt_limit", details: Record<string, string> | undefined;
  const indexByKey = new Map<number | string, number>(); let candidateIndex = 0;
  while (attempts < maxAttempts) {
    if (signal?.aborted) { reason = "cancelled"; break; }
    const elapsed = Math.max(0, now() - started);
    if (elapsed >= maxMs) { reason = "time_limit"; break; }
    const i = candidateIndex++, message = candidate(nonce, i), digest = hash(candidateBytes(nonce, i)); attempts += 1;
    const key = digestKey(digest, bits);
    if (attack === "collision") {
      const earlier = indexByKey.get(key);
      if (earlier !== undefined) {
        if (bits === FULL_BITS && (attempts >= maxAttempts || now() - started >= maxMs)) { reason = attempts >= maxAttempts ? "attempt_limit" : "time_limit"; break; }
        const earlierMessage = candidate(nonce, earlier), earlierDigest = hash(candidateBytes(nonce, earlier));
        if (bits === FULL_BITS) attempts += 1;
        if (bits !== FULL_BITS || digestsEqual(digest, earlierDigest)) {
          details = { message1: earlierMessage, message2: message, hashHex: toHex(earlierDigest), ...(bits === FULL_BITS ? {} : { hashHex2: toHex(digest), sharedPrefix: prefixHex(digest, bits) }) };
          reason = "found"; break;
        }
      } else indexByKey.set(key, i);
    } else if (target && key === target.key && (bits !== FULL_BITS || digestsEqual(digest, target.digest!)) && message !== target.original) {
      details = attack === "preimage"
        ? { message, hashHex: toHex(digest), target: bits === FULL_BITS ? toHex(target.digest!) : target.digest ? prefixHex(target.digest, bits) : Number(target.key).toString(16).padStart(bits / 4, "0") }
        : { original: target.original!, message, originalHashHex: toHex(target.digest!), foundHashHex: toHex(digest) };
      reason = "found"; break;
    }
    const current = now();
    if (attempts % 1024 === 0) onProgress?.({ attempts, elapsed_ms: Math.max(0, current - started), hashesPerSecond: attempts * 1000 / Math.max(0.001, current - started) });
    if (current - lastYield >= SLICE_MS) {
      onProgress?.({ attempts, elapsed_ms: Math.max(0, current - started), hashesPerSecond: attempts * 1000 / Math.max(0.001, current - started) });
      await yieldFn(); lastYield = now();
    }
  }
  if (signal?.aborted) reason = "cancelled";
  const elapsed_ms = Math.max(0, now() - started);
  onProgress?.({ attempts, elapsed_ms, hashesPerSecond: attempts * 1000 / Math.max(0.001, elapsed_ms) });
  const targetText = target ? bits === FULL_BITS ? toHex(target.digest!) : target.digest ? prefixHex(target.digest, bits) : Number(target.key).toString(16).padStart(bits / 4, "0") : undefined;
  if (attack === "preimage" && target) details = { target: targetText!, ...details };
  if (attack === "second_preimage" && target) details = { original: target.original!, originalHashHex: toHex(target.digest!), target: targetText!, ...details };
  return { found: reason === "found", attempts, elapsed_ms, stopReason: reason, nonce, details };
}

export function runPreimage(options: AttackOptions & { target: Uint8Array | number }): Promise<AttackResult> {
  const target = typeof options.target === "number" ? { key: options.target } : { digest: options.target, key: digestKey(options.target, options.bits) };
  return run("preimage", options, target);
}
export function runSecondPreimage(options: AttackOptions & { original: string }): Promise<AttackResult> {
  const digest = (options.hash ?? sha256)(new TextEncoder().encode(options.original));
  return run("second_preimage", options, { digest, key: digestKey(digest, options.bits), original: options.original });
}
export function runCollision(options: AttackOptions): Promise<AttackResult> { return run("collision", options); }
