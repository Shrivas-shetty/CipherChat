import { requestJson } from "../api/http";

export type DashboardCategory = "auth" | "session" | "message" | "demo" | "other";
export type AuditEvent = { id: number; ts: string; event_type: string; severity: "info" | "warning" | "alert"; user_id: number | null; username: string | null; success: boolean; ip: string | null; session_id: string | null; details: Record<string, unknown> | null; prev_hash: string; row_hash: string };
export type Page<T> = { items: T[]; has_more_older: boolean; latest_id: number | null };
export type DashboardMessage = { id: number; session_id: string; sender: string; recipient: string; sender_role: string; msg_type: "text" | "image"; counter: number; size_bytes: number; w: number | null; h: number | null; created_at: string; delivered_at: string | null; verification_status: "pending" | "verified" | "failed"; verification_reason: string | null; verified_at: string | null };
export type DashboardSession = { id: string; initiator: string; responder: string; status: string; started_at: string; established_at: string | null; ended_at: string | null; end_reason: string | null; duration_seconds: number; handshake_ms: number | null; fingerprint: string | null; message_count: number; failed_verification_count: number };
export type DashboardSummary = { server_time: string; users: { total: number; analysts: number; online: string[] }; active_session: null | { id: string; initiator: string; responder: string; status: string; started_at: string; established_at: string | null; fingerprint: string | null }; sessions: { total: number; established_ever: number; terminated: number; active: number }; messages: { total: number; text: number; image: number; verified: number; failed: number; pending: number }; security: { failed_logins_total: number; failed_logins_24h: number; lockouts_total: number; tamper_detected_total: number; token_rejections_total: number; room_full_total: number }; audit: { rows: number; last_id: number | null } };
export type AuditTypes = { categories: Record<"auth" | "session" | "message" | "demo", string[]>; severities: string[] };

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
};
