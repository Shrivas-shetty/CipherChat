import { useCallback } from "react";
import { dashboardApi } from "../api";
import { usePolling } from "../hooks/usePolling";
import { formatTs } from "../labels";

const REASONS: Record<string, string> = { logout: "Logout", disconnect: "Disconnect", superseded: "Superseded", handshake_timeout: "Handshake timeout", key_confirm_failed: "Key confirmation failed", bad_public: "Invalid DH public value", fingerprint_mismatch: "Fingerprint mismatch", server_restart: "Server restart" };
export function SessionsView({ onOpenSession }: { onOpenSession: (id: string) => void }) {
  const fetcher = useCallback((signal: AbortSignal) => dashboardApi.sessions(200, signal), []);
  const { data, error, loading, refresh } = usePolling(fetcher, 5000);
  const rows = data?.items ?? [];
  return <div className="dash-view">
    {error && <div className="dash-error">Could not load sessions: {error} <button onClick={() => void refresh()}>Retry</button></div>}
    {loading && !data && <div className="dash-empty">Loading sessions…</div>}
    {!loading && !error && rows.length === 0 && <div className="dash-empty">No sessions recorded</div>}
    {rows.length > 0 && <div className="dash-table-wrap"><table className="dash-table"><thead><tr><th>Started</th><th>Initiator → Responder</th><th>Status</th><th>Handshake</th><th>Duration</th><th>End reason</th><th>Fingerprint</th><th>Messages</th><th>Failed checks</th></tr></thead><tbody>{rows.map((s) => <tr key={s.id} onClick={() => onOpenSession(s.id)} className="clickable-row"><td title={s.started_at}>{formatTs(s.started_at)}</td><td>{s.initiator} → {s.responder}</td><td><span className={`status-pill ${s.status === "established" ? "integrity-ok" : s.status === "terminated" ? "dash-muted" : "severity-warning"}`}>{s.status}</span></td><td>{s.handshake_ms === null ? "—" : `${s.handshake_ms.toFixed(1)} ms`}</td><td>{s.duration_seconds.toFixed(1)} s</td><td>{s.end_reason ? REASONS[s.end_reason] ?? s.end_reason : "—"}</td><td><code>{s.fingerprint ?? "—"}</code></td><td>{s.message_count}</td><td className={s.failed_verification_count ? "integrity-failed" : ""}>{s.failed_verification_count}</td></tr>)}</tbody></table></div>}
  </div>;
}
