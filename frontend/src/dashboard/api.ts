import { requestJson } from "../api/http";
import type { CaptureDetail, CaptureSummary, HttpRow, NetworkStatus, PacketRow, PcapFileItem, Scenario, SidecarItem, Timeline } from "./network/types";
import type { CompareExchangesPage, CompareHistoryItem, CompareRunCreate, CompareRunDetail, CompareRunSummary, StoredCompareExchange, TrialMeasurement } from "../compare/types";

export type DashboardCategory = "auth" | "session" | "message" | "keys" | "demo" | "lab" | "network" | "compare" | "other";
export type AuditEvent = { id: number; ts: string; event_type: string; severity: "info" | "warning" | "alert"; user_id: number | null; username: string | null; success: boolean; ip: string | null; session_id: string | null; details: Record<string, unknown> | null; prev_hash: string; row_hash: string };
export type Page<T> = { items: T[]; has_more_older: boolean; latest_id: number | null };
export type DashboardMessage = { id: number; session_id: string; sender: string; recipient: string; sender_role: string; msg_type: "text" | "image"; counter: number; size_bytes: number; w: number | null; h: number | null; created_at: string; delivered_at: string | null; verification_status: "pending" | "verified" | "failed"; verification_reason: string | null; verified_at: string | null; signature_status: "pending" | "valid" | "invalid" | "not_checked" | null; sig_verify_ms: number | null; sig_gen_ms: number | null };
export type DashboardSession = { id: string; initiator: string; responder: string; status: string; started_at: string; established_at: string | null; ended_at: string | null; end_reason: string | null; duration_seconds: number; handshake_ms: number | null; fingerprint: string | null; message_count: number; failed_verification_count: number };
export type DashboardSummary = { server_time: string; users: { total: number; analysts: number; online: string[] }; active_session: null | { id: string; initiator: string; responder: string; status: string; started_at: string; established_at: string | null; fingerprint: string | null }; sessions: { total: number; established_ever: number; terminated: number; active: number }; messages: { total: number; text: number; image: number; verified: number; failed: number; pending: number }; signatures: { signed: number; valid: number; invalid: number; keys_total: number; keys_active: number }; security: { failed_logins_total: number; failed_logins_24h: number; lockouts_total: number; tamper_detected_total: number; token_rejections_total: number; room_full_total: number }; audit: { rows: number; last_id: number | null }; lab: { text_records: number; image_records: number; bench_runs: number }; network: { captures: number }; compare: { runs: number } };
export type AuditTypes = { categories: Record<"auth" | "session" | "message" | "keys" | "demo" | "lab" | "network" | "compare", string[]>; severities: string[] };
export type HmacRecord = { id: number; created_at: string; msg_type: "text" | "image"; pt_len_bytes: number; w: number | null; h: number | null; n_pixels: number | null; ct_len_bytes: number; hmac_gen_us: number };
export type SignatureRecord = { id: number; created_at: string; sender: string; recipient: string; msg_type: "text" | "image"; pt_len_bytes: number; w: number | null; h: number | null; n_pixels: number | null; signer_key_id: number; key_fingerprint: string; signature_len: number; signature_preview_hex: string; sig_gen_ms: number; sig_verify_ms: number | null; signature_status: "pending" | "valid" | "invalid" | "not_checked" };
export type SigningKeyRecord = { id: number; username: string; fingerprint: string; created_at: string; retired_at: string | null; retire_reason: "logout" | "replaced" | "legacy_algorithm" | null; active: boolean; keygen_ms: number | null; signed_count: number };
export type TextLabRecord = { id: number; message_id: number; session_id: string; sender: string | null; message_created_at: string | null; pt_len_bytes: number; ct_len_bytes: number; total_ct_bits: number; key_trials: number; confusion_pct: number; key_flip_pcts: number[]; pt_trials: number; diffusion_bits: number; avalanche_pct: number; block_avalanche_pct: number; pt_flip_bit_idx: number[]; pt_flip_changed_bits: number[]; pt_flip_block_changed_bits: number[]; enc_us: number; dec_us: number; timing_iters: number; created_at: string };
export type TextLabPage = { total: number; items: TextLabRecord[]; has_more_older: boolean; latest_id: number | null };
export type ImageLabRecord = {
  id: number; message_id: number; session_id: string; sender: string | null; message_created_at: string | null; created_at: string;
  width: number; height: number; n_pixels: number; pt_len_bytes: number; ct_len_bytes: number;
  npcr_trials: number; npcr_pct: number; npcr_trial_pcts: number[]; npcr_changed_counts: number[]; uaci_pct: number; uaci_trial_pcts: number[]; flip_byte_idx: number[];
  entropy_r: number; entropy_g: number; entropy_b: number; entropy_avg: number;
  corr_pt_r: number | null; corr_pt_g: number | null; corr_pt_b: number | null; corr_pt_avg: number | null;
  corr_ct_r: number | null; corr_ct_g: number | null; corr_ct_b: number | null; corr_ct_avg: number | null;
  corr_v_pt_r: number | null; corr_v_pt_g: number | null; corr_v_pt_b: number | null; corr_v_pt_avg: number | null;
  corr_v_ct_r: number | null; corr_v_ct_g: number | null; corr_v_ct_b: number | null; corr_v_ct_avg: number | null;
  corr_d_pt_r: number | null; corr_d_pt_g: number | null; corr_d_pt_b: number | null; corr_d_pt_avg: number | null;
  corr_d_ct_r: number | null; corr_d_ct_g: number | null; corr_d_ct_b: number | null; corr_d_ct_avg: number | null;
  mse_dec: number; psnr_dec: number | null; mse_enc: number; psnr_enc: number | null; enc_us: number; dec_us: number; timing_iters: number;
};
export type ImageLabPage = { total: number; items: ImageLabRecord[]; has_more_older: boolean; latest_id: number | null };
export type CipherNoiseResponse = { message_id: number; w: number; h: number; noise_rgb_b64: string };
export type BenchSample = { id: number; seq: number; mode: "secure" | "plain"; kind: "text" | "image"; size_param: number; plaintext_bytes: number; crypto_send_ms: number; to_notify_ms: number; fetch_ms: number; crypto_recv_ms: number; e2e_ms: number; post_ms: number; verify_post_ms: number | null; bytes_up: number; bytes_down: number; ws_notify_bytes: number };
export type BenchRun = { id: number; created_at: string; label: string; repeats: number; warmup: number; text_lengths: number[]; image_sides: number[]; handshake_ms: number[]; note: string | null; sample_count: number };
export type BenchRunDetail = BenchRun & { samples: BenchSample[] };
export type BrowserHandshake = { id: number; ts: string; session_id: string | null; handshake_ms: number | null; initiator: string | null; responder: string | null; initiator_keygen_ms: number | null; initiator_derive_ms: number | null; responder_keygen_ms: number | null; responder_derive_ms: number | null };

function query(params: Record<string, string | number | boolean | null | undefined>): string {
  const search = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => { if (value !== null && value !== undefined && value !== "") search.set(key, String(value)); });
  return search.size ? `?${search.toString()}` : "";
}

export const dashboardApi = {
  networkStatus: (signal?: AbortSignal) => requestJson<NetworkStatus>("/api/dashboard/network/status", {signal}),
  networkFiles: (signal?: AbortSignal) => requestJson<{pcaps:PcapFileItem[];sidecars:SidecarItem[]}>("/api/dashboard/network/files", {signal}),
  ingestPcap: (body:{filename:string;label:string;scenario:Scenario;marker?:string;sidecar?:string;server_port?:number;replace?:boolean}) => requestJson<{id:number}>("/api/dashboard/network/ingest",{method:"POST",body:JSON.stringify(body)}),
  captures: (limit=50,signal?:AbortSignal) => requestJson<{items:CaptureSummary[]}>(`/api/dashboard/network/captures?limit=${limit}`,{signal}),
  capture: (id:number,signal?:AbortSignal) => requestJson<CaptureDetail>(`/api/dashboard/network/captures/${id}`,{signal}),
  timeline: (id:number,bucket?:number,signal?:AbortSignal) => requestJson<Timeline>(`/api/dashboard/network/captures/${id}/timeline${bucket?`?bucket_ms=${bucket}`:""}`,{signal}),
  packets: (id:number,params:Record<string,string|number|undefined>,signal?:AbortSignal) => requestJson<{items:PacketRow[];next_after_frame:number|null}>(`/api/dashboard/network/captures/${id}/packets?${new URLSearchParams(Object.entries(params).filter(([,v])=>v!==undefined).map(([k,v])=>[k,String(v)]))}`,{signal}),
  httpTransactions: (id:number,params:Record<string,string|number|undefined>,signal?:AbortSignal) => requestJson<{items:HttpRow[];next_after_frame:number|null}>(`/api/dashboard/network/captures/${id}/http?${new URLSearchParams(Object.entries(params).filter(([,v])=>v!==undefined).map(([k,v])=>[k,String(v)]))}`,{signal}),
  deleteCapture: (id:number) => requestJson<void>(`/api/dashboard/network/captures/${id}`,{method:"DELETE"}),
  logs: (params: Record<string, string | number | boolean | null | undefined>, signal?: AbortSignal) => requestJson<Page<AuditEvent>>(`/api/dashboard/logs${query(params)}`, { signal }),
  logTypes: (signal?: AbortSignal) => requestJson<AuditTypes>("/api/dashboard/logs/types", { signal }),
  messages: (params: Record<string, string | number | boolean | null | undefined>, signal?: AbortSignal) => requestJson<Page<DashboardMessage>>(`/api/dashboard/messages${query(params)}`, { signal }),
  sessions: (limit = 50, signal?: AbortSignal) => requestJson<{ items: DashboardSession[] }>(`/api/dashboard/sessions${query({ limit })}`, { signal }),
  summary: (signal?: AbortSignal) => requestJson<DashboardSummary>("/api/dashboard/summary", { signal }),
  hmacRecords: (params: { limit?: number; before_id?: number; msg_type?: string }, signal?: AbortSignal) => requestJson<{total:number;items:HmacRecord[];has_more_older:boolean;latest_id:number|null}>(`/api/dashboard/hmac/records${query(params)}`, { signal }),
  signatureRecords: (params: { limit?: number; before_id?: number; msg_type?: string }, signal?: AbortSignal) => requestJson<{total:number;items:SignatureRecord[];has_more_older:boolean;latest_id:number|null}>(`/api/dashboard/signatures/records${query(params)}`, { signal }),
  signingKeys: (limit = 200, signal?: AbortSignal) => requestJson<{total:number;items:SigningKeyRecord[]}>(`/api/dashboard/signatures/keys${query({limit})}`, { signal }),
  auditIntegrity: (signal?: AbortSignal) => requestJson<{ ok: boolean; first_bad_id: number | null; rows_checked: number; checked_at: string }>("/api/dashboard/audit-integrity", { signal }),
  textLabRecords: (params: { limit?: number; before_id?: number }, signal?: AbortSignal) => requestJson<TextLabPage>(`/api/dashboard/lab/text/records${query(params)}`, { signal }),
  clearTextLab: () => requestJson<{ deleted: number }>("/api/dashboard/lab/text", { method: "DELETE" }),
  imageLabRecords: (params: { limit?: number; before_id?: number }, signal?: AbortSignal) => requestJson<ImageLabPage>(`/api/dashboard/lab/image/records${query(params)}`, { signal }),
  cipherNoise: (messageId: number, signal?: AbortSignal) => requestJson<CipherNoiseResponse>(`/api/dashboard/lab/image/${messageId}/cipher-noise`, { signal }),
  clearImageLab: () => requestJson<{ deleted: number }>("/api/dashboard/lab/image", { method: "DELETE" }),
  benchRuns: (limit = 50, signal?: AbortSignal) => requestJson<{ items: BenchRun[] }>(`/api/dashboard/bench/runs${query({ limit })}`, { signal }),
  benchRun: (id: number, signal?: AbortSignal) => requestJson<BenchRunDetail>(`/api/dashboard/bench/runs/${id}`, { signal }),
  handshakes: (limit = 200, signal?: AbortSignal) => requestJson<{ items: BrowserHandshake[] }>(`/api/dashboard/perf/handshakes${query({ limit })}`, { signal }),
  clearBench: () => requestJson<{ deleted: number }>("/api/dashboard/bench/runs", { method: "DELETE" }),
  compareRuns: (limit = 50, signal?: AbortSignal) => requestJson<{items: CompareRunSummary[]}>(`/api/dashboard/compare/runs${query({limit})}`, {signal}),
  compareRun: (id: number, signal?: AbortSignal) => requestJson<CompareRunDetail>(`/api/dashboard/compare/runs/${id}`, {signal}),
  createCompareRun: (body: CompareRunCreate) => requestJson<{id:number}>("/api/dashboard/compare/runs", {method:"POST",body:JSON.stringify(body)}),
  createCompareExchange: (runId: number, body: Record<string, unknown>) => requestJson<{id:number}>(`/api/dashboard/compare/runs/${runId}/exchanges`, {method:"POST",body:JSON.stringify(body)}),
  finalizeCompareRun: (runId: number, status: "complete" | "stopped", trials: TrialMeasurement[]) => requestJson<{id:number;status:string}>(`/api/dashboard/compare/runs/${runId}/finalize`, {method:"POST",body:JSON.stringify({status,trials})}),
  abortCompareRun: (runId: number) => requestJson<{id:number;status:string}>(`/api/dashboard/compare/runs/${runId}/abort`, {method:"POST"}),
  compareExchanges: (runId: number, params: {limit?:number;after_id?:number}, signal?: AbortSignal) => requestJson<CompareExchangesPage>(`/api/dashboard/compare/runs/${runId}/exchanges${query(params)}`, {signal}),
  compareExchange: (runId: number, exchangeId: number, signal?: AbortSignal) => requestJson<StoredCompareExchange>(`/api/dashboard/compare/runs/${runId}/exchanges/${exchangeId}`, {signal}),
  compareHistory: (limit = 50, signal?: AbortSignal) => requestJson<{items:CompareHistoryItem[]}>(`/api/dashboard/compare/history${query({limit})}`, {signal}),
  deleteCompareRun: (id: number) => requestJson<void>(`/api/dashboard/compare/runs/${id}`, {method:"DELETE"}),
  deleteAllCompareRuns: () => requestJson<void>("/api/dashboard/compare/runs", {method:"DELETE"}),
};
