import { requestJson } from "../api/http";

export type TextMetricPayload = {
  message_id: number; session_id: string; pt_len_bytes: number; ct_len_bytes: number; total_ct_bits: number;
  key_trials: number; confusion_pct: number; key_flip_pcts: number[]; pt_trials: number;
  diffusion_bits: number; avalanche_pct: number; block_avalanche_pct: number;
  pt_flip_bit_idx: number[]; pt_flip_changed_bits: number[]; pt_flip_block_changed_bits: number[];
  enc_us: number; dec_us: number; timing_iters: number;
};
export function postTextMetrics(payload: TextMetricPayload, signal?: AbortSignal): Promise<{ id: number }> {
  return requestJson<{ id: number }>("/api/lab/text-metrics", { method: "POST", body: JSON.stringify(payload), signal });
}
