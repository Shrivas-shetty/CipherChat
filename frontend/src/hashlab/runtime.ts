import { SLICE_MS } from "./config";

export type RuntimeDeps = { now?: () => number; yieldFn?: () => Promise<void>; signal?: AbortSignal; onProgress?: (value: { attempts: number; elapsed_ms: number; hashesPerSecond: number }) => void };
export const defaultYield = () => new Promise<void>((resolve) => setTimeout(resolve, 0));
export function isAborted(signal?: AbortSignal): boolean { return !!signal?.aborted; }
export async function maybeYield(lastYield: number, now: () => number, yieldFn: () => Promise<void>): Promise<number> {
  if (now() - lastYield >= SLICE_MS) { await yieldFn(); return now(); }
  return lastYield;
}
