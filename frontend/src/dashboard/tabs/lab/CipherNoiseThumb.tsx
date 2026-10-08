import { useEffect, useState } from "react";
import { dashboardApi } from "../../api";
import type { ImageLabRecord } from "../../api";
import { base64ToBytes, noiseToCanvas } from "./noiseImage";

const thumbnailCache = new Map<number, string>();
const waiting: Array<() => void> = [];
let active = 0;
function limited<T>(work: () => Promise<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    const start = () => { active += 1; void work().then(resolve, reject).finally(() => { active -= 1; waiting.shift()?.(); }); };
    if (active < 3) start(); else waiting.push(start);
  });
}
async function loadThumb(messageId: number): Promise<string> {
  const cached = thumbnailCache.get(messageId);
  if (cached) { thumbnailCache.delete(messageId); thumbnailCache.set(messageId, cached); return cached; }
  return limited(async () => {
    const item = await dashboardApi.cipherNoise(messageId);
    const bytes = base64ToBytes(item.noise_rgb_b64);
    try {
      const url = noiseToCanvas(bytes, item.w, item.h, 96).toDataURL("image/png");
      thumbnailCache.set(messageId, url);
      while (thumbnailCache.size > 50) thumbnailCache.delete(thumbnailCache.keys().next().value!);
      return url;
    } finally { bytes.fill(0); }
  });
}

export function CipherNoiseThumb({ record, onOpen }: { record: ImageLabRecord; onOpen: (record: ImageLabRecord) => void }) {
  const [src, setSrc] = useState<string | null>(thumbnailCache.get(record.message_id) ?? null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    let live = true;
    if (!src) void loadThumb(record.message_id).then((url) => { if (live) setSrc(url); }).catch(() => { if (live) setFailed(true); });
    return () => { live = false; };
  }, [record.message_id, src]);
  return <button className="cipher-thumb-button" title={`View encrypted noise for message ${record.message_id}`} onClick={() => onOpen(record)} disabled={!src}>
    {src ? <img className="cipher-thumb" src={src} width={96} height={96} alt={`Encrypted noise, ${record.width} by ${record.height}`} style={{ imageRendering: "pixelated" }} /> : failed ? <span className="cipher-thumb-error" aria-label="Image unavailable">⚠</span> : <span className="cipher-thumb-skeleton" aria-label="Loading encrypted image" />}
  </button>;
}

export async function fetchNoiseCanvas(messageId: number): Promise<{ canvas: HTMLCanvasElement; w: number; h: number }> {
  const item = await dashboardApi.cipherNoise(messageId);
  const bytes = base64ToBytes(item.noise_rgb_b64);
  try { return { canvas: noiseToCanvas(bytes, item.w, item.h), w: item.w, h: item.h }; }
  finally { bytes.fill(0); }
}
