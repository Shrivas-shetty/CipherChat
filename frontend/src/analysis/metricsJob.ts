import { ApiError } from "../api/http";
import { getSessionKeys, subscribeSessionKeysCleared } from "../crypto/sessionKeys";
import { getCollectMetrics } from "./settings";
import { computeTextMetrics } from "./textMetrics";
import { postTextMetrics, type TextMetricPayload } from "./api";
import { QUEUE_CAP } from "./config";

export type MetricStatus = "queued" | "running" | "recorded" | "skipped" | `failed: ${string}`;
export type TextMetricsJobInput = { messageId: number; sessionId: string; pt: Uint8Array; iv: Uint8Array; ct: Uint8Array };
type Job = TextMetricsJobInput & { controller: AbortController };
type StatusListener = (messageId: number, status: MetricStatus | null) => void;
const queue: Job[] = [];
const controllers = new Map<string, Set<AbortController>>();
const statuses = new Map<number, MetricStatus>();
const listeners = new Set<StatusListener>();
let running = false;

export const getMetricStatus = (messageId: number): MetricStatus | undefined => statuses.get(messageId);
export function subscribeMetricStatus(listener: StatusListener): () => void { listeners.add(listener); return () => listeners.delete(listener); }
function setStatus(messageId: number, status: MetricStatus | null) {
  if (status === null) statuses.delete(messageId); else statuses.set(messageId, status);
  for (const listener of listeners) listener(messageId, status);
}
function wipe(job: Job) { job.pt.fill(0); job.iv.fill(0); job.ct.fill(0); }
function removeController(job: Job) {
  const set = controllers.get(job.sessionId);
  set?.delete(job.controller);
  if (set?.size === 0) controllers.delete(job.sessionId);
}
function wait(ms: number, signal: AbortSignal) {
  return new Promise<void>((resolve, reject) => {
    const onAbort = () => { clearTimeout(timer); reject(new Error("aborted")); };
    const timer = setTimeout(() => { signal.removeEventListener("abort", onAbort); resolve(); }, ms);
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

export function enqueueTextMetrics(input: TextMetricsJobInput): MetricStatus | null {
  if (!getCollectMetrics()) return null;
  if (queue.length + (running ? 1 : 0) >= QUEUE_CAP) { setStatus(input.messageId, "skipped"); return "skipped"; }
  const controller = new AbortController();
  const job: Job = { ...input, pt: new Uint8Array(input.pt), iv: new Uint8Array(input.iv), ct: new Uint8Array(input.ct), controller };
  const set = controllers.get(job.sessionId) ?? new Set<AbortController>();
  set.add(controller); controllers.set(job.sessionId, set);
  queue.push(job);
  setStatus(job.messageId, "queued");
  void drain();
  return "queued";
}

async function submitWithRetry(payload: TextMetricPayload, signal: AbortSignal) {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    if (signal.aborted) return;
    try { await postTextMetrics(payload, signal); return; }
    catch (error) {
      if (signal.aborted) return;
      const retryable = !(error instanceof ApiError) || error.status >= 500;
      if (!retryable || attempt === 1) throw error;
      await wait(2000, signal);
    }
  }
}

async function run(job: Job) {
  const current = getSessionKeys();
  if (!current || current.sessionId.toLowerCase() !== job.sessionId.toLowerCase() || job.controller.signal.aborted) return;
  const keyCopy = new Uint8Array(current.kEnc);
  setStatus(job.messageId, "running");
  try {
    const metrics = await computeTextMetrics({ key: keyCopy, iv: job.iv, pt: job.pt, ct: job.ct }, { signal: job.controller.signal });
    keyCopy.fill(0); job.pt.fill(0); job.iv.fill(0); job.ct.fill(0);
    if (job.controller.signal.aborted) return;
    const payload: TextMetricPayload = { message_id: job.messageId, session_id: job.sessionId, ...metrics };
    await submitWithRetry(payload, job.controller.signal);
    if (!job.controller.signal.aborted) setStatus(job.messageId, "recorded");
  } catch (error) {
    if (job.controller.signal.aborted) return;
    const reason = error instanceof Error ? error.message : "analysis failed";
    setStatus(job.messageId, `failed: ${reason}`);
  } finally { keyCopy.fill(0); wipe(job); removeController(job); }
}

async function drain() {
  if (running) return;
  running = true;
  try {
    while (queue.length) {
      const job = queue.shift()!;
      await run(job);
      await new Promise<void>((resolve) => setTimeout(resolve, 0));
    }
  } finally { running = false; }
}

subscribeSessionKeysCleared((sessionId) => {
  for (const controller of controllers.get(sessionId) ?? []) controller.abort();
  for (let i = queue.length - 1; i >= 0; i -= 1) {
    if (queue[i].sessionId === sessionId) {
      const [job] = queue.splice(i, 1);
      wipe(job); removeController(job); setStatus(job.messageId, null);
    }
  }
});
