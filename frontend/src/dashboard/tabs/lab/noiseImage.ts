export function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  const out = new Uint8Array(binary.length);
  const chunk = 0x8000;
  for (let start = 0; start < binary.length; start += chunk) {
    const end = Math.min(binary.length, start + chunk);
    for (let i = start; i < end; i += 1) out[i] = binary.charCodeAt(i);
  }
  return out;
}

export function nearestNeighborThumbSize(w: number, h: number, max = 96): { w: number; h: number } {
  if (w < 1 || h < 1 || max < 1) throw new RangeError("dimensions and max must be positive");
  const scale = Math.min(1, max / Math.max(w, h));
  return { w: Math.max(1, Math.floor(w * scale)), h: Math.max(1, Math.floor(h * scale)) };
}

export function noiseToCanvas(bytes: Uint8Array, w: number, h: number, max?: number): HTMLCanvasElement {
  if (bytes.length !== w * h * 3) throw new Error("Invalid cipher-noise buffer length");
  const source = document.createElement("canvas"); source.width = w; source.height = h;
  const sourceCtx = source.getContext("2d");
  if (!sourceCtx) throw new Error("Canvas is unavailable");
  const image = sourceCtx.createImageData(w, h);
  for (let i = 0, p = 0; i < bytes.length; i += 3, p += 4) { image.data[p] = bytes[i]; image.data[p + 1] = bytes[i + 1]; image.data[p + 2] = bytes[i + 2]; image.data[p + 3] = 255; }
  sourceCtx.putImageData(image, 0, 0);
  const size = max ? nearestNeighborThumbSize(w, h, max) : { w, h };
  const canvas = document.createElement("canvas"); canvas.width = size.w; canvas.height = size.h;
  const ctx = canvas.getContext("2d");
  if (!ctx) throw new Error("Canvas is unavailable");
  ctx.imageSmoothingEnabled = false; ctx.drawImage(source, 0, 0, size.w, size.h);
  image.data.fill(0); source.width = 0; source.height = 0;
  return canvas;
}
