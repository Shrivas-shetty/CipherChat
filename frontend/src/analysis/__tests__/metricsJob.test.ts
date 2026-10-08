import { beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "../../api/http";
import { aesCbcEncrypt } from "../aes";
import { clearSessionKeys, setSessionKeys } from "../../crypto/sessionKeys";
import { enqueueImageMetrics, enqueueTextMetrics, getMetricStatus } from "../metricsJob";
import { postImageMetrics, postTextMetrics } from "../api";

vi.mock("../api", () => ({ postTextMetrics: vi.fn(), postImageMetrics: vi.fn() }));
const post = vi.mocked(postTextMetrics);
const postImage = vi.mocked(postImageMetrics);
const sessionId = "11111111-1111-4111-8111-111111111111";
const key = new Uint8Array(32).fill(0x41), iv = new Uint8Array(16).fill(0x27), pt = new TextEncoder().encode("job test"), ct = aesCbcEncrypt(key, iv, pt);
const storage = new Map<string, string>();
function setupKeys() { setSessionKeys({ sessionId, fingerprint: "0000 0000 0000 0000", kEnc: key, kMac: new Uint8Array(32).fill(3) }); }
function enqueue(messageId: number) { return enqueueTextMetrics({ messageId, sessionId, pt, iv, ct }); }
async function waitFor(id: number, wanted: string) { for (let i = 0; i < 400; i += 1) { if (getMetricStatus(id) === wanted) return; await new Promise((resolve) => setTimeout(resolve, 10)); } throw new Error(`Timed out waiting for ${wanted}; got ${getMetricStatus(id)}`); }

describe("metrics job queue", () => {
  beforeEach(() => { Object.defineProperty(globalThis, "localStorage", { configurable: true, value: { getItem: (k: string) => storage.get(k) ?? null, setItem: (k: string, v: string) => storage.set(k, v), removeItem: (k: string) => storage.delete(k) } }); clearSessionKeys(); storage.clear(); post.mockReset(); postImage.mockReset(); setupKeys(); });
  it("processes jobs serially and sends only numeric fields plus session id", async () => {
    const order: number[] = [];
    post.mockImplementation(async (payload) => { order.push(payload.message_id); return { id: payload.message_id }; });
    enqueue(201); enqueue(202);
    await waitFor(201, "recorded"); await waitFor(202, "recorded");
    expect(order).toEqual([201, 202]);
    for (const call of post.mock.calls) {
      const payload = call[0];
      const check = (value: unknown, keyName?: string): void => {
        if (typeof value === "string") expect(keyName).toBe("session_id");
        else if (Array.isArray(value)) value.forEach((v) => check(v));
        else if (value && typeof value === "object") Object.entries(value).forEach(([k, v]) => check(v, k));
        else expect(["number", "undefined"].includes(typeof value)).toBe(true);
      };
      check(payload);
      const serialized = JSON.stringify(payload);
      for (const secret of [new TextDecoder().decode(pt), Array.from(key, (v) => v.toString(16).padStart(2, "0")).join(""), Array.from(iv, (v) => v.toString(16).padStart(2, "0")).join("")]) expect(serialized).not.toContain(secret);
    }
  });
  it("does not retry client errors and retries one server error", async () => {
    post.mockRejectedValueOnce(new ApiError(400, "bad request")); enqueue(203); await waitFor(203, "failed: bad request"); expect(post).toHaveBeenCalledTimes(1);
    post.mockReset().mockRejectedValueOnce(new ApiError(503, "unavailable")).mockResolvedValue({ id: 204 });
    enqueue(204); await waitFor(204, "recorded"); expect(post).toHaveBeenCalledTimes(2);
  });
  it("drops queued work on key clear and skips jobs when collection is disabled or full", async () => {
    post.mockResolvedValue({ id: 0 });
    enqueue(205); enqueue(206); clearSessionKeys();
    await new Promise((resolve) => setTimeout(resolve, 30)); expect(post).not.toHaveBeenCalled(); expect(getMetricStatus(206)).toBeUndefined();
    setupKeys(); storage.set("cc.collectMetrics", "false"); expect(enqueue(207)).toBeNull();
    const imagePixels = new Uint8Array([4, 5, 6]), imageCiphertext = aesCbcEncrypt(key, iv, imagePixels);
    expect(enqueueImageMetrics({ messageId: 2080, sessionId, w: 1, h: 1, pixels: imagePixels, iv, ct: imageCiphertext })).toBeNull();
    storage.set("cc.collectMetrics", "true");
    for (let id = 300; id <= 350; id += 1) enqueue(id);
    expect(getMetricStatus(350)).toBe("skipped"); clearSessionKeys();
  });

  it("runs text and image work in FIFO order and posts no image secrets", async () => {
    const order: string[] = [];
    post.mockImplementation(async (payload) => { order.push(`text-${payload.message_id}`); return { id: payload.message_id }; });
    postImage.mockImplementation(async (payload) => { order.push(`image-${payload.message_id}`); return { id: payload.message_id }; });
    const pixels = new Uint8Array([10, 20, 30]), imageCt = aesCbcEncrypt(key, iv, pixels);
    enqueue(208);
    enqueueImageMetrics({ messageId: 209, sessionId, w: 1, h: 1, pixels, iv, ct: imageCt });
    await waitFor(208, "recorded"); await waitFor(209, "recorded");
    expect(order).toEqual(["text-208", "image-209"]);
    const payload = postImage.mock.calls[0][0];
    const walk = (value: unknown, keyName?: string): void => {
      if (typeof value === "string") expect(keyName).toBe("session_id");
      else if (value === null || typeof value === "number") return;
      else if (Array.isArray(value)) value.forEach((entry) => walk(entry));
      else if (value && typeof value === "object") Object.entries(value).forEach(([key, entry]) => walk(entry, key));
      else throw new Error(`Unexpected metric value: ${typeof value}`);
    };
    walk(payload);
    const serialized = JSON.stringify(payload);
    const hex = (data: Uint8Array) => Array.from(data, (v) => v.toString(16).padStart(2, "0")).join("");
    const b64 = (data: Uint8Array) => btoa(String.fromCharCode(...data));
    for (const secret of [hex(key), hex(iv), hex(pixels), hex(imageCt), b64(pixels), b64(imageCt)]) expect(serialized).not.toContain(secret);
  });

  it("caps queued image jobs at five and aborts queued image work on session end", async () => {
    postImage.mockResolvedValue({ id: 0 });
    const pixels = new Uint8Array([10, 20, 30]), imageCt = aesCbcEncrypt(key, iv, pixels);
    for (let id = 510; id < 517; id += 1) enqueueImageMetrics({ messageId: id, sessionId, w: 1, h: 1, pixels, iv, ct: imageCt });
    expect(getMetricStatus(516)).toBe("skipped");
    clearSessionKeys();
    await new Promise((resolve) => setTimeout(resolve, 30));
    expect(postImage).not.toHaveBeenCalled(); expect(getMetricStatus(511)).toBeUndefined();
  });
});
