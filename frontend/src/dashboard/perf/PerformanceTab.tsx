import { useCallback, useEffect, useState } from "react";
import { Bar, BarChart, CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { dashboardApi, type BenchRun, type BenchRunDetail } from "../api";
import { usePolling } from "../hooks/usePolling";
import { groupSamples, overheadRows, summarize } from "./aggregate";

export function PerformanceTab() {
  const fetchRuns = useCallback((signal: AbortSignal) => dashboardApi.benchRuns(200, signal), []);
  const { data, error, refresh } = usePolling(fetchRuns, 15000);
  const [selected, setSelected] = useState<number | null>(null);
  const [detail, setDetail] = useState<BenchRunDetail | null>(null);
  const [handshakes, setHandshakes] = useState<{items: Awaited<ReturnType<typeof dashboardApi.handshakes>>["items"]} | null>(null);
  const runs = data?.items ?? [];
  useEffect(() => { if (selected === null && runs.length) setSelected(runs[0].id); }, [selected, runs]);
  useEffect(() => { if (selected !== null) void dashboardApi.benchRun(selected).then(setDetail).catch(() => setDetail(null)); }, [selected]);
  useEffect(() => { void dashboardApi.handshakes().then(setHandshakes).catch(() => setHandshakes(null)); }, []);
  const groups = detail ? groupSamples(detail.samples).map(summarize) : [];
  const rows = overheadRows(groups);
  const clear = async () => { if (window.confirm("Clear all benchmark runs and samples?")) { await dashboardApi.clearBench(); setDetail(null); setSelected(null); await refresh(); } };
  const chartData = (kind: string) => [...new Set(groups.filter(x => x.kind === kind).map(x => x.size_param))].map(size => { const s = groups.find(x => x.kind === kind && x.size_param === size && x.mode === "secure"); const p = groups.find(x => x.kind === kind && x.size_param === size && x.mode === "plain"); return { size, secure: s?.e2e_ms_mean, plain: p?.e2e_ms_mean }; });
  return <section className="dash-panel">
    <h2>Performance analysis</h2><p>Performance numbers are measured by a headless benchmark client over the real server. The secure path uses the Python reference crypto, which is faster than the browser's JavaScript AES shown in the Text/Image Labs. The plaintext baseline exists only for comparison and is disabled by default.</p>
    <div className="dash-tools"><select value={selected ?? ""} onChange={e => setSelected(Number(e.target.value))}><option value="">Select run</option>{runs.map((r: BenchRun) => <option key={r.id} value={r.id}>{r.label} · {new Date(r.created_at).toLocaleString()} · {r.repeats} repeats</option>)}</select><button onClick={() => void refresh()}>Refresh</button></div>
    {error && <p className="dash-error">{error}</p>}
    {!runs.length && <p>No benchmark data. Run <code>python -m app.bench.run --server http://HOST:8000 --quick</code>. To compare plaintext, enable <code>ALLOW_PLAINTEXT_BASELINE=true</code> on the server.</p>}
    {detail && <><h3>Headless handshake measurements</h3><p>n={detail.handshake_ms.length}; mean {avg(detail.handshake_ms).toFixed(2)} ms; median {median(detail.handshake_ms).toFixed(2)} ms; p95 {pct(detail.handshake_ms).toFixed(2)} ms. DH group 14's 2048-bit modular exponentiation is the dominant cost.</p><h3>Browser handshakes</h3><table><thead><tr><th>Date</th><th>Users</th><th>Handshake ms</th><th>Initiator keygen / derive</th><th>Responder keygen / derive</th></tr></thead><tbody>{handshakes?.items.slice(0,20).map(h => <tr key={h.id}><td>{h.ts}</td><td>{h.initiator} / {h.responder}</td><td>{h.handshake_ms}</td><td>{h.initiator_keygen_ms} / {h.initiator_derive_ms}</td><td>{h.responder_keygen_ms} / {h.responder_derive_ms}</td></tr>)}</tbody></table>
    {groups.some(x => x.mode === "plain") ? null : <p className="dash-notice">This run has no plaintext baseline samples; showing secure measurements only.</p>}
    {(["text", "image"] as const).map(kind => <div key={kind}><h3>{kind === "text" ? "Text latency (characters)" : "Image latency (side pixels)"}</h3><ResponsiveContainer width="100%" height={280}><LineChart data={chartData(kind)}><CartesianGrid strokeDasharray="3 3"/><XAxis dataKey="size"/><YAxis label={{ value: "Mean end-to-end ms", angle: -90, position: "insideLeft" }}/><Tooltip/><Legend/><Line dataKey="secure" stroke="#c0392b"/><Line dataKey="plain" stroke="#2980b9"/></LineChart></ResponsiveContainer></div>)}
    <h3>Request byte overhead</h3><ResponsiveContainer width="100%" height={280}><BarChart data={rows}><CartesianGrid strokeDasharray="3 3"/><XAxis dataKey="size_param"/><YAxis/><Tooltip/><Legend/><Bar dataKey="secureBytesUp" name="Secure bytes up" fill="#c0392b"/><Bar dataKey="plainBytesUp" name="Plain bytes up" fill="#2980b9"/></BarChart></ResponsiveContainer><p>Fixed IV, HMAC, JSON, and padding costs dominate short text. Base64 encoding contributes to both modes for images.</p>
    <table><thead><tr><th>Kind / size</th><th>Plain bytes</th><th>Secure upload</th><th>Plain upload</th><th>Latency overhead ms / %</th><th>Protocol bytes / plain byte</th></tr></thead><tbody>{rows.map((r, i) => <tr key={i}><td>{r.kind} {r.size_param}</td><td>{r.plaintext_bytes}</td><td>{fmt(r.secureBytesUp)}</td><td>{fmt(r.plainBytesUp)}</td><td>{fmt(r.overheadMs)} / {fmt(r.overheadPct)}%</td><td>{fmt(r.protocolBytesPerPlainByte)}</td></tr>)}</tbody></table>
    <h3>Raw samples</h3><table><thead><tr><th>Mode</th><th>Kind</th><th>Size</th><th>n</th><th>Mean / median / p95 e2e ms</th><th>Mean bytes up</th></tr></thead><tbody>{groups.map((g,i)=><tr key={i}><td>{g.mode}</td><td>{g.kind}</td><td>{g.size_param}</td><td>{g.n}</td><td>{fmt(g.e2e_ms_mean)} / {fmt(g.e2e_ms_median)} / {fmt(g.e2e_ms_p95)}</td><td>{fmt(g.bytes_up_mean)}</td></tr>)}</tbody></table></>}
    <h3>Runs</h3><table><thead><tr><th>Label</th><th>Date</th><th>Repeats</th><th>Samples</th><th>Handshake count</th></tr></thead><tbody>{runs.map(r=><tr key={r.id}><td>{r.label}</td><td>{r.created_at}</td><td>{r.repeats}</td><td>{r.sample_count}</td><td>{r.handshake_ms.length}</td></tr>)}</tbody></table><button className="btn danger" onClick={() => void clear()}>Clear benchmark data</button>
  </section>;
}
function avg(a:number[]){return a.length?a.reduce((x,y)=>x+y,0)/a.length:0} function median(a:number[]){const s=[...a].sort((x,y)=>x-y); return s.length?s[Math.floor(s.length/2)]:0} function pct(a:number[]){const s=[...a].sort((x,y)=>x-y);return s.length?s[Math.ceil(.95*s.length)-1]:0} function fmt(x:number|null){return x===null?"—":x.toFixed(2)}
