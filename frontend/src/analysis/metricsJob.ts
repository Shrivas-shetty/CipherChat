import { ApiError } from "../api/http";
import { getSessionKeys, subscribeSessionKeysCleared } from "../crypto/sessionKeys";
import { getCollectMetrics } from "./settings";
import { computeTextMetrics } from "./textMetrics";
import { computeImageMetrics } from "./imageMetrics";
import { postTextMetrics, postImageMetrics, type TextMetricPayload, type ImageMetricPayload } from "./api";
import { IMAGE_QUEUE_CAP, QUEUE_CAP } from "./config";

export type MetricStatus = "queued" | "running" | "recorded" | "skipped" | `failed: ${string}`;
export type TextMetricsJobInput = { messageId: number; sessionId: string; pt: Uint8Array; iv: Uint8Array; ct: Uint8Array };
export type ImageMetricsJobInput = { messageId: number; sessionId: string; w: number; h: number; pixels: Uint8Array; iv: Uint8Array; ct: Uint8Array };
type BaseJob = { messageId: number; sessionId: string; iv: Uint8Array; ct: Uint8Array; controller: AbortController };
type TextJob = BaseJob & { kind: "text"; pt: Uint8Array };
type ImageJob = BaseJob & { kind: "image"; w: number; h: number; pixels: Uint8Array; key: Uint8Array };
type Job = TextJob | ImageJob;
type StatusListener = (messageId: number, status: MetricStatus | null) => void;
const queue: Job[] = [];
const controllers = new Map<string, Set<AbortController>>();
const statuses = new Map<number, MetricStatus>();
const listeners = new Set<StatusListener>();
let running = false;

export const getMetricStatus = (messageId: number): MetricStatus | undefined => statuses.get(messageId);
export function subscribeMetricStatus(listener: StatusListener): () => void { listeners.add(listener); return () => listeners.delete(listener); }
function setStatus(messageId: number, status: MetricStatus | null) { if (status === null) statuses.delete(messageId); else statuses.set(messageId, status); for (const listener of listeners) listener(messageId, status); }
function wipe(job: Job) { job.iv.fill(0); job.ct.fill(0); if (job.kind === "text") job.pt.fill(0); else { job.pixels.fill(0); job.key.fill(0); } }
function removeController(job: Job) { const set = controllers.get(job.sessionId); set?.delete(job.controller); if (set?.size === 0) controllers.delete(job.sessionId); }
function track(job: Job) { const set = controllers.get(job.sessionId) ?? new Set<AbortController>(); set.add(job.controller); controllers.set(job.sessionId, set); }
function wait(ms: number, signal: AbortSignal) { return new Promise<void>((resolve, reject) => { const onAbort = () => { clearTimeout(timer); reject(new Error("aborted")); }; const timer = setTimeout(() => { signal.removeEventListener("abort", onAbort); resolve(); }, ms); signal.addEventListener("abort", onAbort, { once: true }); }); }

function enqueue(job: Job, image = false): MetricStatus | null {
  if (!getCollectMetrics()) { wipe(job); return null; }
  if (queue.length + (running ? 1 : 0) >= QUEUE_CAP || (image && queue.filter((entry) => entry.kind === "image").length >= IMAGE_QUEUE_CAP)) {
    wipe(job); setStatus(job.messageId, "skipped"); return "skipped";
  }
  track(job); queue.push(job); setStatus(job.messageId, "queued"); void drain(); return "queued";
}

export function enqueueTextMetrics(input: TextMetricsJobInput): MetricStatus | null {
  return enqueue({ ...input, kind: "text", pt: new Uint8Array(input.pt), iv: new Uint8Array(input.iv), ct: new Uint8Array(input.ct), controller: new AbortController() });
}

export function enqueueImageMetrics(input: ImageMetricsJobInput): MetricStatus | null {
  const keys = getSessionKeys();
  if (!keys || keys.sessionId.toLowerCase() !== input.sessionId.toLowerCase()) return null;
  return enqueue({ ...input, kind: "image", pixels: new Uint8Array(input.pixels), iv: new Uint8Array(input.iv), ct: new Uint8Array(input.ct), key: new Uint8Array(keys.kEnc), controller: new AbortController() }, true);
}

export function enqueueMetrics(input: TextMetricsJobInput | ImageMetricsJobInput): MetricStatus | null {
  return "pixels" in input ? enqueueImageMetrics(input) : enqueueTextMetrics(input);
}

async function submitWithRetry(payload: TextMetricPayload | ImageMetricPayload, signal: AbortSignal, kind: Job["kind"]) {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    if (signal.aborted) return;
    try { if (kind === "text") await postTextMetrics(payload as TextMetricPayload, signal); else await postImageMetrics(payload as ImageMetricPayload, signal); return; }
    catch (error) { if (signal.aborted) return; const retryable = !(error instanceof ApiError) || error.status >= 500; if (!retryable || attempt === 1) throw error; await wait(2000, signal); }
  }
}

async function run(job: Job) {
  const current = getSessionKeys();
  if (!current || current.sessionId.toLowerCase() !== job.sessionId.toLowerCase() || job.controller.signal.aborted) { wipe(job); removeController(job); return; }
  const keyCopy = job.kind === "image" ? job.key : new Uint8Array(current.kEnc);
  setStatus(job.messageId, "running");
  try {
    let payload: TextMetricPayload | ImageMetricPayload;
    if (job.kind === "text") {
      const metrics = await computeTextMetrics({ key: keyCopy, iv: job.iv, pt: job.pt, ct: job.ct }, { signal: job.controller.signal });
      payload = { message_id: job.messageId, session_id: job.sessionId, ...metrics };
    } else {
      const metrics = await computeImageMetrics({ w: job.w, h: job.h, key: keyCopy, iv: job.iv, pixels: job.pixels, ct: job.ct }, { signal: job.controller.signal });
      payload = { message_id: job.messageId, session_id: job.sessionId, ...metrics };
    }
    if (job.controller.signal.aborted) return;
    await submitWithRetry(payload, job.controller.signal, job.kind);
    if (!job.controller.signal.aborted) setStatus(job.messageId, "recorded");
  } catch (error) {
    if (job.controller.signal.aborted) return;
    const reason = error instanceof Error ? error.message : "analysis failed";
    setStatus(job.messageId, `failed: ${reason}`);
  } finally { keyCopy.fill(0); wipe(job); removeController(job); }
}

async function drain() { if (running) return; running = true; try { while (queue.length) { const job = queue.shift()!; await run(job); await new Promise<void>((resolve) => setTimeout(resolve, 0)); } } finally { running = false; } }

subscribeSessionKeysCleared((sessionId) => {
  for (const controller of controllers.get(sessionId) ?? []) controller.abort();
  for (let i = queue.length - 1; i >= 0; i -= 1) if (queue[i].sessionId === sessionId) { const [job] = queue.splice(i, 1); wipe(job); removeController(job); setStatus(job.messageId, null); }
});
