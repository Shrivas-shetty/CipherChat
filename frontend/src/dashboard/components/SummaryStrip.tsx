import { useCallback } from "react";
import { dashboardApi } from "../api";
import { usePolling } from "../hooks/usePolling";
import { formatTs } from "../labels";

export function SummaryStrip() {
  const fetcher = useCallback((signal: AbortSignal) => dashboardApi.summary(signal), []);
  const { data, error, loading, refresh } = usePolling(fetcher, 5000);
  return <section className="dash-summary">
    {error && <div className="dash-error">Summary unavailable: {error} <button onClick={() => void refresh()}>Retry</button></div>}
    <div className="dash-summary-top"><div><b>Online</b> {data?.users.online.length ? data.users.online.map((u) => <span className="online-chip" key={u}>{u}</span>) : <span className="dash-muted">No chat users online</span>}</div>
      <div><b>Active session</b> {data?.active_session ? <span>{data.active_session.status === "established" ? `Established: ${data.active_session.initiator} ↔ ${data.active_session.responder}` : "Negotiating…"}{data.active_session.fingerprint && <> · <code>{data.active_session.fingerprint}</code></>}</span> : <span>No active session</span>}</div>
      <span className="dash-muted">{loading && !data ? "Loading…" : data ? `Last updated ${formatTs(data.server_time)}` : ""}</span>
    </div>
    {data && <div className="dash-cards">
      <div><small>Messages</small><b>{data.messages.total}</b><span>{data.messages.text} text · {data.messages.image} image</span></div>
      <div><small>Verified</small><b>{data.messages.verified}</b></div>
      <div className={data.messages.failed ? "failed-card" : ""}><small>Failed checks</small><b>{data.messages.failed}</b></div>
      <div><small>Failed logins (24h)</small><b>{data.security.failed_logins_24h}</b></div>
      <div><small>Tamper detections</small><b>{data.security.tamper_detected_total}</b></div>
      <div><small>Sessions</small><b>{data.sessions.total}</b></div>
      <div><small>Text metrics</small><b>{data.lab.text_records}</b></div>
      <div><small>Image metrics</small><b>{data.lab.image_records}</b></div>
    </div>}
  </section>;
}
