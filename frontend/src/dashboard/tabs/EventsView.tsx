import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { dashboardApi, type AuditEvent } from "../api";
import { usePolling } from "../hooks/usePolling";
import { DASHBOARD_CATEGORIES, eventLabel, formatTs, severityClass } from "../labels";

type Props = { sessionFilter: string; onSessionFilter: (id: string) => void };
export function EventsView({ sessionFilter, onSessionFilter }: Props) {
  const [category, setCategory] = useState("all");
  const [severity, setSeverity] = useState("");
  const [success, setSuccess] = useState("");
  const [usernameInput, setUsernameInput] = useState("");
  const [username, setUsername] = useState("");
  const [session, setSession] = useState(sessionFilter);
  const [live, setLive] = useState(true);
  const [items, setItems] = useState<AuditEvent[]>([]);
  const [older, setOlder] = useState(true);
  const [olderError, setOlderError] = useState(false);
  const [expanded, setExpanded] = useState<number[]>([]);
  const [newRows, setNewRows] = useState<number[]>([]);
  const latestId = useRef<number | null>(null);
  const filterKey = useMemo(() => JSON.stringify([category, severity, success, username, session]), [category, severity, success, username, session]);
  const previousFilter = useRef(filterKey);
  if (previousFilter.current !== filterKey) { latestId.current = null; previousFilter.current = filterKey; }
  const fetcher = useCallback((signal: AbortSignal) => dashboardApi.logs({ limit: 100, after_id: latestId.current, category: category === "all" ? undefined : category, severity_min: severity || undefined, success: success === "" ? undefined : success === "true", username, session_id: session || undefined }, signal), [category, severity, success, username, session]);
  const { data, error, loading, refresh } = usePolling(fetcher, 3000, !live, filterKey);

  useEffect(() => { const timer = window.setTimeout(() => setUsername(usernameInput.trim()), 300); return () => clearTimeout(timer); }, [usernameInput]);
  useEffect(() => { setSession(sessionFilter); }, [sessionFilter]);
  useEffect(() => { setItems([]); setOlder(true); latestId.current = null; }, [filterKey]);
  useEffect(() => {
    if (!data) return;
    if (data.latest_id !== null) latestId.current = data.latest_id;
    setOlder(data.has_more_older);
    const known = new Set(items.map((row) => row.id));
    const added = data.items.filter((row) => !known.has(row.id));
    if (added.length > 0 && items.length > 0) {
      const ids = added.map((row) => row.id);
      setNewRows((old) => [...old, ...ids]);
      window.setTimeout(() => setNewRows((old) => old.filter((id) => !ids.includes(id))), 1800);
    }
    setItems((current) => {
      const known = new Set(current.map((row) => row.id));
      const added = data.items.filter((row) => !known.has(row.id));
      return [...added, ...current].slice(0, 1000);
    });
  }, [data]);

  async function loadOlder() {
    if (!items.length) return;
    setOlderError(false);
    try {
      const page = await dashboardApi.logs({ limit: 100, before_id: items[items.length - 1].id, category: category === "all" ? undefined : category, severity_min: severity || undefined, success: success === "" ? undefined : success === "true", username, session_id: session || undefined });
      setItems((current) => [...current, ...page.items.filter((r) => !current.some((x) => x.id === r.id))].slice(-1000)); setOlder(page.has_more_older);
    } catch { setOlderError(true); }
  }
  function setCategoryFilter(value: string) { setCategory(value); }
  return <div className="dash-view">
    <div className="dash-filterbar"><div className="dash-chips">{DASHBOARD_CATEGORIES.map((value) => <button className={category === value ? "selected" : ""} key={value} onClick={() => setCategoryFilter(value)}>{value === "all" ? "All" : value[0].toUpperCase() + value.slice(1)}</button>)}<button className={severity === "warning" ? "selected" : ""} onClick={() => setSeverity(severity === "warning" ? "" : "warning")}>Security alerts only</button></div>
      <label>Severity <select value={severity} onChange={(e) => setSeverity(e.target.value)}><option value="">Any</option><option value="info">Info+</option><option value="warning">Warning+</option><option value="alert">Alert</option></select></label>
      <label>Success <select value={success} onChange={(e) => setSuccess(e.target.value)}><option value="">Any</option><option value="true">Success</option><option value="false">Failed</option></select></label>
      <input value={usernameInput} onChange={(e) => setUsernameInput(e.target.value)} placeholder="Filter username" />
      <input value={session} onChange={(e) => { setSession(e.target.value); onSessionFilter(e.target.value); }} placeholder="Session ID" />
      <label className="live-toggle"><input type="checkbox" checked={live} onChange={(e) => setLive(e.target.checked)} /> Live</label>
    </div>
    {error && <div className="dash-error">Could not load events: {error} <button onClick={() => void refresh()}>Retry</button></div>}
    {olderError && <div className="dash-error">Could not load older events. <button onClick={() => void loadOlder()}>Retry</button></div>}
    {loading && items.length === 0 && <div className="dash-empty">Loading events…</div>}
    {!loading && !error && items.length === 0 && <div className="dash-empty">No events match these filters</div>}
    {items.length > 0 && <div className="dash-table-wrap"><table className="dash-table"><thead><tr><th>Time</th><th>Severity</th><th>Event</th><th>User</th><th>Success</th><th>IP</th><th>Session</th><th>Details</th></tr></thead><tbody>{items.map((row) => <tr key={row.id} className={`${row.severity === "alert" ? "row-alert" : ""} ${newRows.includes(row.id) ? "row-new" : ""}`}>
      <td title={row.ts}>{formatTs(row.ts)}</td><td><span className={`severity-badge ${severityClass(row.severity)}`}>{row.severity}</span></td><td>{eventLabel(row.event_type, row.details)}</td><td>{row.username ?? "—"}</td><td>{row.success ? "✓" : "✕"}</td><td>{row.ip ?? "—"}</td>
      <td>{row.session_id ? <button className="session-chip" title={`${row.session_id} (click to copy)`} onClick={() => { void navigator.clipboard?.writeText(row.session_id!); setSession(row.session_id!); onSessionFilter(row.session_id!); }}>{row.session_id.slice(0, 8)}</button> : "—"}</td>
      <td><span className="details-compact">{row.details ? JSON.stringify(row.details) : "—"}</span>{row.details && <button className="details-toggle" onClick={() => setExpanded((v) => v.includes(row.id) ? v.filter((id) => id !== row.id) : [...v, row.id])}>{expanded.includes(row.id) ? "Hide" : "Expand"}</button>}{expanded.includes(row.id) && <pre className="details-json">{JSON.stringify(row.details, null, 2)}</pre>}</td>
    </tr>)}</tbody></table></div>}
    {older && items.length > 0 && <button className="load-older" onClick={() => void loadOlder()}>Load older</button>}
  </div>;
}
