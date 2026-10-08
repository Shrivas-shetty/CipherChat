import type { TextLabRecord } from "../../api";
export type RecordSortKey = keyof Pick<TextLabRecord, "created_at" | "sender" | "message_id" | "pt_len_bytes" | "ct_len_bytes" | "ct_preview_hex" | "confusion_pct" | "diffusion_bits" | "avalanche_pct" | "block_avalanche_pct" | "enc_us" | "dec_us">;
export function sortTextRecords(rows: TextLabRecord[], key: RecordSortKey, direction: "asc" | "desc"): TextLabRecord[] {
  const sign = direction === "asc" ? 1 : -1;
  return [...rows].sort((a, b) => {
    const left = a[key] ?? "", right = b[key] ?? "";
    const compared = typeof left === "number" && typeof right === "number" ? left - right : String(left).localeCompare(String(right));
    return compared * sign;
  });
}
