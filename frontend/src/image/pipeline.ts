import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "../crypto/encoding";

export function fitWithin(w: number, h: number, max: number): { w: number; h: number } {
  if (w <= max && h <= max) return { w: Math.max(1, Math.round(w)), h: Math.max(1, Math.round(h)) };
  const scale = max / Math.max(w, h);
  return { w: Math.max(1, Math.round(w * scale)), h: Math.max(1, Math.round(h * scale)) };
}

export function rgbaToRgb(rgba: Uint8ClampedArray | Uint8Array): Uint8Array {
  const rgb = new Uint8Array((rgba.length / 4) * 3);
  for (let s = 0, d = 0; s < rgba.length; s += 4, d += 3) {
    rgb[d] = rgba[s]; rgb[d + 1] = rgba[s + 1]; rgb[d + 2] = rgba[s + 2];
  }
  return rgb;
}

export function rgbToRgba(rgb: Uint8Array): Uint8ClampedArray {
  const rgba = new Uint8ClampedArray((rgb.length / 3) * 4);
  for (let s = 0, d = 0; s < rgb.length; s += 3, d += 4) {
    rgba[d] = rgb[s]; rgba[d + 1] = rgb[s + 1]; rgba[d + 2] = rgb[s + 2]; rgba[d + 3] = 255;
  }
  return rgba;
}

export function ciphertextToNoiseRgb(ct: Uint8Array, w: number, h: number): Uint8Array {
  return ct.slice(0, w * h * 3);
}

export function sha256Hex(bytes: Uint8Array): string {
  return bytesToHex(sha256(bytes));
}
