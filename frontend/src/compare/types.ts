export type CompareMode = "secured" | "unsecured";
export type SetupTimings = { setup_keygen_ms: number; setup_dh_ms: number; setup_hkdf_ms: number };

export type CompareRunCreate = SetupTimings & {
  label: string;
  input_text: string;
  trials: number;
  warmup: number;
  sig_public_key_b64: string;
};

export type TrialMeasurement = {
  trial_no: number;
  mode: CompareMode;
  warmup: boolean;
  exchange_id: number;
  total_ms: number;
  prep_ms: number;
  post_ms: number;
  get_ms: number;
  finish_ms: number;
  seal_ms: number | null;
  sign_ms: number | null;
  verify_hmac_ms: number | null;
  verify_sig_ms: number | null;
  decrypt_ms: number | null;
  post_req_bytes: number;
  post_resp_bytes: number;
  get_resp_bytes: number;
  plaintext_bytes: number;
  ciphertext_bytes: number | null;
  integrity_ok: boolean | null;
  signature_ok: boolean | null;
  roundtrip_ok: boolean;
};

export type CompareRunSummary = {
  id: number; created_at: string; finished_at: string | null;
  status: "running" | "complete" | "stopped" | "aborted";
  label: string; input_preview: string; input_bytes: number;
  trials: number; warmup: number; trial_rows: number;
};

export type CompareRun = {
  id: number; created_at: string; finished_at: string | null;
  status: "running" | "complete" | "stopped" | "aborted";
  analyst_id: number; label: string; input_text: string; input_bytes: number;
  trials: number; warmup: number; setup_keygen_ms: number; setup_dh_ms: number;
  setup_hkdf_ms: number; sig_public_key_b64: string; sig_fingerprint: string;
};

export type CompareTrial = TrialMeasurement & { id: number; run_id: number };
export type CompareRunDetail = { run: CompareRun; trials: CompareTrial[] };
export type CompareExchangePreview = {
  id: number; created_at: string; mode: CompareMode; warmup: boolean;
  text: string | null; session_id: string | null; sender_role: "I" | null;
  counter: number | null; msg_type: string | null; meta_json: string | null;
  iv_hex: string | null; ct_len: number | null; ct_preview_hex: string | null;
  hmac_hex: string | null; signature_preview_hex: string | null;
};
export type CompareExchangesPage = { items: CompareExchangePreview[]; next_after_id: number | null };
export type StoredCompareExchange = { id: number; mode: CompareMode; text?: string } & {
  session_id?: string; sender_role?: "I"; counter?: number; msg_type?: "text";
  meta_json?: "{}"; iv?: string; ct?: string; hmac?: string; signature?: string;
};
export type CompareHistoryItem = {
  id: number; created_at: string; label: string; input_bytes: number; trials: number;
  status: "complete" | "stopped"; secured_totals: number[]; unsecured_totals: number[];
};

export type ScheduleEntry = { pair: number; warmup: boolean; order: [CompareMode, CompareMode] };
