import { fitWithin, rgbaToRgb } from "./pipeline";
import { MAX_IMAGE_DIM } from "./constants";

export type DecodedImage = { w: number; h: number; rgb: Uint8Array; decodeMs: number };
const ACCEPTED = new Set(["image/png", "image/jpeg", "image/webp", "image/gif"]);

export async function decodeImage(file: File): Promise<DecodedImage> {
  if (!ACCEPTED.has(file.type)) throw new Error("Choose a PNG, JPEG, WebP, or GIF image.");
  if (file.size > 10 * 1024 * 1024) throw new Error("Images must be 10 MB or smaller.");
  const start = performance.now();
  let source: CanvasImageSource | null = null;
  let sourceWidth = 0;
  let sourceHeight = 0;
  let closeBitmap: (() => void) | null = null;
  let url: string | null = null;
  try {
    if (typeof createImageBitmap === "function") {
      const bitmap = await createImageBitmap(file, { imageOrientation: "from-image" });
      source = bitmap; sourceWidth = bitmap.width; sourceHeight = bitmap.height; closeBitmap = () => bitmap.close();
    }
    else {
      url = URL.createObjectURL(file);
      const img = new Image();
      img.src = url;
      await img.decode();
      source = img; sourceWidth = img.naturalWidth; sourceHeight = img.naturalHeight;
    }
    const size = fitWithin(sourceWidth, sourceHeight, MAX_IMAGE_DIM);
    const canvas = typeof OffscreenCanvas !== "undefined" ? new OffscreenCanvas(size.w, size.h) : document.createElement("canvas");
    canvas.width = size.w; canvas.height = size.h;
    const ctx = canvas.getContext("2d") as CanvasRenderingContext2D | OffscreenCanvasRenderingContext2D | null;
    if (!ctx) throw new Error("Image decoding is unavailable in this browser.");
    ctx.fillStyle = "white"; ctx.fillRect(0, 0, size.w, size.h);
    ctx.imageSmoothingEnabled = true; ctx.imageSmoothingQuality = "high";
    if (!source) throw new Error("Image decoding is unavailable in this browser.");
    ctx.drawImage(source, 0, 0, size.w, size.h);
    const imageData = ctx.getImageData(0, 0, size.w, size.h);
    return { ...size, rgb: rgbaToRgb(imageData.data), decodeMs: Math.round((performance.now() - start) * 100) / 100 };
  } catch (err) {
    if (err instanceof Error && err.message.startsWith("Choose") || err instanceof Error && err.message.startsWith("Images")) throw err;
    throw new Error("Could not decode this image file.");
  } finally {
    closeBitmap?.();
    if (url) URL.revokeObjectURL(url);
  }
}
