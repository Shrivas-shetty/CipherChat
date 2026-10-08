import { rgbToRgba } from "./pipeline";

const urls = new Set<string>();

export async function renderRgbPng(rgb: Uint8Array, w: number, h: number): Promise<string> {
  const canvas = document.createElement("canvas");
  canvas.width = w; canvas.height = h;
  const ctx = canvas.getContext("2d");
  if (!ctx) throw new Error("Image rendering is unavailable.");
  const rgba = new Uint8ClampedArray(new Uint8Array(rgbToRgba(rgb)));
  ctx.putImageData(new ImageData(rgba, w, h), 0, 0);
  const blob = await new Promise<Blob>((resolve, reject) => canvas.toBlob((b) => b ? resolve(b) : reject(new Error("PNG encoding failed.")), "image/png"));
  const url = URL.createObjectURL(blob);
  urls.add(url);
  return url;
}

export function releaseObjectUrl(url?: string): void {
  if (url && urls.delete(url)) URL.revokeObjectURL(url);
}

export function releaseAllImageUrls(): void {
  for (const url of urls) URL.revokeObjectURL(url);
  urls.clear();
}
