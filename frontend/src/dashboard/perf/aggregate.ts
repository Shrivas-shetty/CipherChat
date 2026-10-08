import type { BenchSample } from "../api";

export const mean = (xs: number[]) => xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : null;
export function median(xs: number[]): number | null { if (!xs.length) return null; const a = [...xs].sort((x, y) => x - y); const m = Math.floor(a.length / 2); return a.length % 2 ? a[m] : (a[m - 1] + a[m]) / 2; }
export function percentile(xs: number[], p: number): number | null { if (!xs.length) return null; const a = [...xs].sort((x, y) => x - y); return a[Math.max(0, Math.ceil(p * a.length) - 1)]; }
export function stddev(xs: number[]): number | null { const m = mean(xs); return m === null ? null : Math.sqrt(xs.reduce((s, x) => s + (x - m) ** 2, 0) / xs.length); }
export type Group = { kind: "text" | "image"; size_param: number; mode: "secure" | "plain"; samples: BenchSample[] };
export function groupSamples(samples: BenchSample[]): Group[] {
  const map = new Map<string, Group>();
  for (const sample of samples) { const key = `${sample.kind}/${sample.size_param}/${sample.mode}`; let g = map.get(key); if (!g) { g = { kind: sample.kind, size_param: sample.size_param, mode: sample.mode, samples: [] }; map.set(key, g); } g.samples.push(sample); }
  return [...map.values()].sort((a, b) => a.kind.localeCompare(b.kind) || a.size_param - b.size_param || a.mode.localeCompare(b.mode));
}
const fields = ["e2e_ms", "crypto_send_ms", "to_notify_ms", "fetch_ms", "crypto_recv_ms", "post_ms", "bytes_up", "bytes_down", "ws_notify_bytes"] as const;
export type Summary = Group & { n: number; [key: string]: any };
export function summarize(group: Group): Summary { const out: Record<string, number | null> = { n: group.samples.length }; for (const field of fields) { const values = group.samples.map((s) => s[field]); out[`${field}_mean`] = mean(values); out[`${field}_median`] = median(values); out[`${field}_p95`] = percentile(values, .95); out[`${field}_stddev`] = stddev(values); } return { ...group, ...out } as Summary; }
export function overheadRows(summaries: ReturnType<typeof summarize>[]) {
  const keys = [...new Set(summaries.map((x) => `${x.kind}/${x.size_param}`))];
  return keys.map((key) => { const [kind, size] = key.split("/"); const s = summaries.find((x) => `${x.kind}/${x.size_param}` === key && x.mode === "secure"); const p = summaries.find((x) => `${x.kind}/${x.size_param}` === key && x.mode === "plain"); const secureMean = s?.e2e_ms_mean ?? null; const plainMean = p?.e2e_ms_mean ?? null; const secureBytesUp = s?.bytes_up_mean ?? null; const plainBytesUp = p?.bytes_up_mean ?? null; const plaintext_bytes = s?.samples[0]?.plaintext_bytes ?? p?.samples[0]?.plaintext_bytes ?? null; return { kind, size_param: Number(size), secureMean, plainMean, overheadMs: secureMean !== null && plainMean !== null ? secureMean - plainMean : null, overheadPct: secureMean !== null && plainMean ? (secureMean - plainMean) / plainMean * 100 : null, secureBytesUp, plainBytesUp, byteOverheadPct: secureBytesUp !== null && plainBytesUp ? (secureBytesUp - plainBytesUp) / plainBytesUp * 100 : null, plaintext_bytes, protocolBytesPerPlainByte: secureBytesUp !== null && plaintext_bytes ? secureBytesUp / plaintext_bytes : null }; });
}
