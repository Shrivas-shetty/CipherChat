import { requestJson } from "../api/http";

export type RegisterSigningKeyPayload = { public_key_b64: string; keygen_ms: number };
export function registerSigningKey(payload: RegisterSigningKeyPayload) {
  return requestJson<{id: number; fingerprint: string; created_at: string}>("/api/keys", { method: "POST", body: JSON.stringify(payload) });
}
export type PeerKeyResponse = { id: number; user_id: number; username: string; fingerprint: string; public_key_b64: string; created_at: string; retired_at: string | null; retire_reason: string | null };
export function fetchKey(id: number) { return requestJson<PeerKeyResponse>(`/api/keys/${id}`); }
