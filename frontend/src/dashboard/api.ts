import { requestJson } from "../api/http";

export type DashboardCategory = "auth" | "session" | "message" | "demo" | "lab" | "other";
export type AuditEvent = { id: number; ts: string; event_type: string; severity: "info" | "warning" | "alert"; user_id: number | null; username: string | null; success: boolean; ip: string | null; session_id: string | null; details: Record<string, unknown> | null; prev_hash: string; row_hash: string };
export type Page<T> = { items: T[]; has_more_older: boolean; latest_id: number | null };
export type DashboardMessage = { id: number; session_id: string; sender: string; recipient: string; sender_role: string; msg_type: "text" | "image"; counter: number; size_bytes: number; w: number | null; h: number | null; created_at: string; delivered_at: string | null; verification_status: "pending" | "verified" | "failed"; verification_reason: string | null; verified_at: string | null };
export type DashboardSession = { id: string; initiator: string; responder: string; status: string; started_at: string; established_at: string | null; ended_at: string | null; end_reason: string | null; duration_seconds: number; handshake_ms: number | null; fingerprint: string | null; message_count: number; failed_verification_count: number };
export type DashboardSummary = { server_time: string; users: { total: number; analysts: number; online: string[] }; active_session: null | { id: string; initiator: string; responder: string; status: string; started_at: string; established_at: string | null; fingerprint: string | null }; sessions: { total: number; established_ever: number; terminated: number; active: number }; messages: { total: number; text: number; image: number; verified: number; failed: number; pending: number }; security: { failed_logins_total: number; failed_logins_24h: number; lockouts_total: number; tamper_detected_total: number; token_rejections_total: number; room_full_total: number }; audit: { rows: number; last_id: number | null }; lab: { text_records: number; image_records: number } };
export type AuditTypes = { categories: Record<"auth" | "session" | "message" | "demo" | "lab", string[]>; severities: string[] };
export type TextLabRecord = { id: number; message_id: number; session_id: string; sender: string | null; message_created_at: string | null; pt_len_bytes: number; ct_len_bytes: number; total_ct_bits: number; key_trials: number; confusion_pct: number; key_flip_pcts: number[]; pt_trials: number; diffusion_bits: number; avalanche_pct: number; block_avalanche_pct: number; pt_flip_bit_idx: number[]; pt_flip_changed_bits: number[]; pt_flip_block_changed_bits: number[]; enc_us: number; dec_us: number; timing_iters: number; created_at: string };
export type TextLabPage = { total: number; items: TextLabRecord[]; has_more_older: boolean; latest_id: number | null };
export type ImageLabRecord = {
  id: number; message_id: number; session_id: string; sender: string | null; message_created_at: string | null; created_at: string;
  width: number; height: number; n_pixels: number; pt_len_bytes: number; ct_len_bytes: number;
  npcr_trials: number; npcr_pct: number; npcr_trial_pcts: number[]; npcr_changed_counts: number[]; uaci_pct: number; uaci_trial_pcts: number[]; flip_byte_idx: number[];
  entropy_r: number; entropy_g: number; entropy_b: number; entropy_avg: number;
  corr_pt_r: number | null; corr_pt_g: number | null; corr_pt_b: number | null; corr_pt_avg: number | null;
  corr_ct_r: number | null; corr_ct_g: number | null; corr_ct_b: number | null; corr_ct_avg: number | null;
  mse_dec: number; psnr_dec: number | null; mse_enc: number; psnr_enc: number | null; enc_us: number; dec_us: number; timing_iters: number;
};
export type ImageLabPage = { total: number; items: ImageLabRecord[]; has_more_older: boolean; latest_id: number | null };
export type CipherNoiseResponse = { message_id: number; w: number; h: number; noise_rgb_b64: string };

function query(params: Record<string, string | number | boolean | null | undefined>): string {
  const search = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => { if (value !== null && value !== undefined && value !== "") search.set(key, String(value)); });
  return search.size ? `?${search.toString()}` : "";
}

export const dashboardApi = {
  logs: (params: Record<string, string | number | boolean | null | undefined>, signal?: AbortSignal) => requestJson<Page<AuditEvent>>(`/api/dashboard/logs${query(params)}`, { signal }),
  logTypes: (signal?: AbortSignal) => requestJson<AuditTypes>("/api/dashboard/logs/types", { signal }),
  messages: (params: Record<string, string | number | boolean | null | undefined>, signal?: AbortSignal) => requestJson<Page<DashboardMessage>>(`/api/dashboard/messages${query(params)}`, { signal }),
  sessions: (limit = 50, signal?: AbortSignal) => requestJson<{ items: DashboardSession[] }>(`/api/dashboard/sessions${query({ limit })}`, { signal }),
  summary: (signal?: AbortSignal) => requestJson<DashboardSummary>("/api/dashboard/summary", { signal }),
  auditIntegrity: (signal?: AbortSignal) => requestJson<{ ok: boolean; first_bad_id: number | null; rows_checked: number; checked_at: string }>("/api/dashboard/audit-integrity", { signal }),
  textLabRecords: (params: { limit?: number; before_id?: number }, signal?: AbortSignal) => requestJson<TextLabPage>(`/api/dashboard/lab/text/records${query(params)}`, { signal }),
  clearTextLab: () => requestJson<{ deleted: number }>("/api/dashboard/lab/text", { method: "DELETE" }),
  imageLabRecords: (params: { limit?: number; before_id?: number }, signal?: AbortSignal) => requestJson<ImageLabPage>(`/api/dashboard/lab/image/records${query(params)}`, { signal }),
  cipherNoise: (messageId: number, signal?: AbortSignal) => requestJson<CipherNoiseResponse>(`/api/dashboard/lab/image/${messageId}/cipher-noise`, { signal }),
  clearImageLab: () => requestJson<{ deleted: number }>("/api/dashboard/lab/image", { method: "DELETE" }),
};
