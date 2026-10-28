import type { HmacRecord, SignatureRecord } from "../../api";
import type { PlotPoint } from "./ScatterWithRegression";

export function mean(values: Array<number | null | undefined>): number | null {
  const valid = values.filter((value): value is number => value != null && Number.isFinite(value));
  return valid.length ? valid.reduce((sum, value) => sum + value, 0) / valid.length : null;
}
export function hmacGroups(records: HmacRecord[]) {
  const text = records.filter((row) => row.msg_type === "text");
  const images = records.filter((row) => row.msg_type === "image");
  return {
    textMeanUs: mean(text.map((row) => row.hmac_gen_us)),
    imageMeanUs: mean(images.map((row) => row.hmac_gen_us)),
    textPoints: text.map((row): PlotPoint => ({ x: row.pt_len_bytes, y: row.hmac_gen_us, messageId: row.id })),
    imagePoints: images.filter((row) => row.n_pixels != null).map((row): PlotPoint => ({ x: row.n_pixels!, y: row.hmac_gen_us, messageId: row.id, width: row.w, height: row.h, nPixels: row.n_pixels })),
  };
}
export function signatureGroups(records: SignatureRecord[]) {
  const text = records.filter((row) => row.msg_type === "text");
  const images = records.filter((row) => row.msg_type === "image");
  return {
    meanGenerationMs: mean(records.map((row) => row.sig_gen_ms)),
    meanVerificationMs: mean(records.map((row) => row.sig_verify_ms)),
    textPoints: text.map((row): PlotPoint => ({ x: row.pt_len_bytes, y: row.sig_gen_ms, messageId: row.id })),
    imagePoints: images.map((row): PlotPoint => ({ x: row.pt_len_bytes, y: row.sig_gen_ms, messageId: row.id, width: row.w, height: row.h, nPixels: row.n_pixels })),
  };
}
export function sortRows<T>(rows: T[], field: keyof T, direction: "asc" | "desc"): T[] {
  return [...rows].sort((a, b) => {
    const av = a[field], bv = b[field];
    const order = av == null ? (bv == null ? 0 : -1) : bv == null ? 1 : typeof av === "number" && typeof bv === "number" ? av - bv : String(av).localeCompare(String(bv));
    return direction === "asc" ? order : -order;
  });
}
