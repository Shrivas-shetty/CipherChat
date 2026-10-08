import { useCallback, useEffect, useState } from "react";
import { dashboardApi, type DashboardMessage } from "../api";
import { usePolling } from "../hooks/usePolling";
import { formatTs } from "../labels";

function bytes(n: number): string { return n < 1024 ? `${n} B` : `${(n / 1024).toFixed(1)} KB`; }
type Props = { sessionFilter: string; onSessionFilter: (id: string) => void };
export function MessagesView({ sessionFilter, onSessionFilter }: Props) {
  const [type, setType] = useState("");
  const [status, setStatus] = useState("");
  const [session, setSession] = useState(sessionFilter);
  const [items, setItems] = useState<DashboardMessage[]>([]);
  const [older, setOlder] = useState(false);
  const [olderError, setOlderError] = useState(false);
  useEffect(() => setSession(sessionFilter), [sessionFilter]);
  const key = `${type}|${status}|${session}`;
  const fetcher = useCallback((signal: AbortSignal) => dashboardApi.messages({ limit: 100, msg_type: type || undefined, verification_status: status || undefined, session_id: session || undefined }, signal), [type, status, session]);
  const { data, error, loading, refresh } = usePolling(fetcher, 5000, false, key);
  useEffect(() => { setItems([]); setOlder(false); }, [key]);
  useEffect(() => { if (data) { setItems((current) => [...data.items, ...current.filter((row) => !data.items.some((newRow) => newRow.id === row.id))].sort((a, b) => b.id - a.id)); setOlder(data.has_more_older); } }, [data]);
  async function loadOlder() {
    if (!items.length) return;
    setOlderError(false);
    try { const result = await dashboardApi.messages({ limit: 100, before_id: items[items.length - 1].id, msg_type: type || undefined, verification_status: status || undefined, session_id: session || undefined }); setItems((prev) => [...prev, ...result.items.filter((row) => !prev.some((x) => x.id === row.id))]); setOlder(result.has_more_older); }
    catch { setOlderError(true); }
  }
  return <div className="dash-view">
    <p className="dash-note">The server only stores ciphertext; message contents are not available to the dashboard.</p>
    <div className="dash-filterbar"><label>Type <select value={type} onChange={(e) => setType(e.target.value)}><option value="">Any</option><option value="text">Text</option><option value="image">Image</option></select></label><label>Integrity <select value={status} onChange={(e) => setStatus(e.target.value)}><option value="">Any</option><option value="pending">Pending</option><option value="verified">Verified</option><option value="failed">Failed</option></select></label><input value={session} onChange={(e) => { setSession(e.target.value); onSessionFilter(e.target.value); }} placeholder="Session ID" /><button onClick={() => void refresh()}>Refresh</button></div>
    {error && <div className="dash-error">Could not load messages: {error} <button onClick={() => void refresh()}>Retry</button></div>}
    {olderError && <div className="dash-error">Could not load older messages. <button onClick={() => void loadOlder()}>Retry</button></div>}
    {loading && items.length === 0 && <div className="dash-empty">Loading messages…</div>}
    {!loading && !error && items.length === 0 && <div className="dash-empty">No messages match these filters</div>}
    {items.length > 0 && <div className="dash-table-wrap"><table className="dash-table"><thead><tr><th>Time</th><th>Sender → Recipient</th><th>Type</th><th>Counter</th><th>Size</th><th>Dimensions</th><th>Delivered</th><th>Integrity</th><th>Session</th></tr></thead><tbody>{items.map((m) => <tr key={m.id} className={m.verification_status === "failed" ? "row-alert" : ""}><td title={m.created_at}>{formatTs(m.created_at)}</td><td>{m.sender} → {m.recipient}</td><td>{m.msg_type}</td><td>{m.counter}</td><td>{bytes(m.size_bytes)}</td><td>{m.msg_type === "image" && m.w && m.h ? `${m.w}×${m.h}` : "—"}</td><td>{m.delivered_at ? formatTs(m.delivered_at) : "—"}</td><td>{m.verification_status === "verified" ? <span className="integrity-ok">Verified</span> : m.verification_status === "failed" ? <span className="integrity-failed">FAILED ({m.verification_reason ?? "unknown"})</span> : <span className="dash-muted">Pending</span>}</td><td><button className="session-chip" title={m.session_id} onClick={() => { setSession(m.session_id); onSessionFilter(m.session_id); }}>{m.session_id.slice(0, 8)}</button></td></tr>)}</tbody></table></div>}
    {older && items.length > 0 && <button className="load-older" onClick={() => void loadOlder()}>Load older</button>}
  </div>;
}
