export type CorrelationSet = { r: number | null; g: number | null; b: number | null; avg: number | null };

export function shannonEntropy(bytes: Uint8Array, channel: 0 | 1 | 2, n = bytes.length): number {
  const counts = new Uint32Array(256);
  let size = 0;
  for (let i = channel; i < Math.min(n, bytes.length); i += 3) { counts[bytes[i]] += 1; size += 1; }
  if (!size) return 0;
  let entropy = 0;
  for (const count of counts) if (count) { const p = count / size; entropy -= p * Math.log2(p); }
  return entropy;
}

export type Direction = "h" | "v" | "d";
export function pairCount(w: number, h: number, dir: Direction): number {
  return dir === "h" ? h * Math.max(0, w - 1) : dir === "v" ? w * Math.max(0, h - 1) : Math.max(0, w - 1) * Math.max(0, h - 1);
}

export function pearsonDirectional(buf: Uint8Array, w: number, h: number, channel: 0 | 1 | 2, dir: Direction): number | null {
  const pairs = pairCount(w, h, dir);
  if (!pairs || h <= 0 || w <= 0 || buf.length < w * h * 3) return null;
  const step = dir === "h" ? 3 : dir === "v" ? w * 3 : (w + 1) * 3;
  const visit = (fn: (i: number) => void) => {
    if (dir === "h") { for (let y = 0; y < h; y += 1) for (let x = 0; x < w - 1; x += 1) fn((y * w + x) * 3 + channel); }
    else if (dir === "v") { for (let y = 0; y < h - 1; y += 1) for (let x = 0; x < w; x += 1) fn((y * w + x) * 3 + channel); }
    else { for (let y = 0; y < h - 1; y += 1) for (let x = 0; x < w - 1; x += 1) fn((y * w + x) * 3 + channel); }
  };
  let sx = 0, sy = 0;
  visit((i) => { sx += buf[i]; sy += buf[i + step]; });
  const mx = sx / pairs, my = sy / pairs;
  let cov = 0, vx = 0, vy = 0;
  visit((i) => { const dx = buf[i] - mx, dy = buf[i + step] - my; cov += dx * dy; vx += dx * dx; vy += dy * dy; });
  return vx === 0 || vy === 0 ? null : cov / Math.sqrt(vx * vy);
}

export function pearsonHorizontal(buf: Uint8Array, w: number, h: number, channel: 0 | 1 | 2): number | null {
  return pearsonDirectional(buf, w, h, channel, "h");
}

export function correlationSet(buf: Uint8Array, w: number, h: number, dir: Direction = "h"): CorrelationSet {
  const [r, g, b] = [0, 1, 2].map((c) => pearsonDirectional(buf, w, h, c as 0 | 1 | 2, dir));
  const values = [r, g, b].filter((v): v is number => v !== null);
  return { r, g, b, avg: values.length ? values.reduce((a, v) => a + v, 0) / values.length : null };
}

export function mse(a: Uint8Array, b: Uint8Array, n = Math.min(a.length, b.length)): number {
  if (a.length < n || b.length < n || n <= 0) throw new Error("invalid mse input");
  let sum = 0;
  for (let i = 0; i < n; i += 1) { const d = a[i] - b[i]; sum += d * d; }
  return sum / n;
}

export function psnr(value: number): number | null {
  return value === 0 ? null : 10 * Math.log10(65025 / value);
}

export function npcrUaci(a: Uint8Array, b: Uint8Array, n = Math.min(a.length, b.length)) {
  if (a.length < n || b.length < n || n <= 0) throw new Error("invalid npcr/uaci input");
  let changed = 0, sumAbsDiff = 0;
  for (let i = 0; i < n; i += 1) { const d = Math.abs(a[i] - b[i]); if (d) changed += 1; sumAbsDiff += d; }
  return { changed, npcr: changed / n * 100, uaci: sumAbsDiff / (255 * n) * 100, sumAbsDiff };
}
