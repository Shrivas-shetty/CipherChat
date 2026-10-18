import { useEffect, useMemo, useState } from "react";
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { dashboardApi } from "../api";
import type { CaptureDetail, CaptureSummary } from "./types";
import { comparisonVerdict, deltaPercent, messageRequestBytes, messageResponseBytes, perMessage } from "./compare";

type Metric = { name: string; a: number | null; b: number | null; unit?: string };

export function CompareView({ captures }: { captures: CaptureSummary[] }) {
  const [aid, setA] = useState<number | null>(null);
  const [bid, setB] = useState<number | null>(null);
  const [a, setDetailA] = useState<CaptureDetail | null>(null);
  const [b, setDetailB] = useState<CaptureDetail | null>(null);

  useEffect(() => {
    if (captures.length) {
      if (aid === null) setA(captures[0].id);
      if (bid === null) setB(captures[1]?.id ?? captures[0].id);
    }
  }, [captures, aid, bid]);
  useEffect(() => { if (aid !== null) void dashboardApi.capture(aid).then(setDetailA).catch(() => setDetailA(null)); }, [aid]);
  useEffect(() => { if (bid !== null) void dashboardApi.capture(bid).then(setDetailB).catch(() => setDetailB(null)); }, [bid]);

  const metrics = useMemo<Metric[]>(() => {
    if (!a || !b) return [];
    const ar = messageRequestBytes(a), br = messageRequestBytes(b);
    const as = messageResponseBytes(a), bs = messageResponseBytes(b);
    const am = a.sidecar_info?.messages ?? null, bm = b.sidecar_info?.messages ?? null;
    return [
      ["Packets", a.capture.packet_count, b.capture.packet_count],
      ["Frame bytes", a.capture.total_frame_bytes, b.capture.total_frame_bytes],
      ["TCP payload bytes", a.capture.total_tcp_payload_bytes, b.capture.total_tcp_payload_bytes],
      ["Duration (s)", a.capture.duration_s, b.capture.duration_s],
      ["TCP streams", a.capture.tcp_streams, b.capture.tcp_streams],
      ["SYN count", a.capture.syn_count, b.capture.syn_count],
      ["HTTP requests", a.capture.http_requests, b.capture.http_requests],
      ["WebSocket frames", a.capture.ws_frames, b.capture.ws_frames],
      ["Message request bytes", ar, br], ["Message response bytes", as, bs],
      ["Request bytes per message", perMessage(ar, am), perMessage(br, bm)],
      ["Packets per message", perMessage(a.capture.packet_count, am), perMessage(b.capture.packet_count, bm)],
    ].map(([name, x, y]) => ({ name: String(name), a: Number.isFinite(x as number) ? x as number : null, b: Number.isFinite(y as number) ? y as number : null }));
  }, [a, b]);

  const chart = a && b ? [
    { name: "Capture A", packets: a.capture.packet_count, bytes: a.capture.total_frame_bytes },
    { name: "Capture B", packets: b.capture.packet_count, bytes: b.capture.total_frame_bytes },
  ] : [];

  return <div className="dash-view">
    <label>Capture A <select value={aid ?? ""} onChange={e => setA(Number(e.target.value))}>{captures.map(x => <option key={x.id} value={x.id}>{x.label} · {x.scenario}</option>)}</select></label>{" "}
    <label>Capture B <select value={bid ?? ""} onChange={e => setB(Number(e.target.value))}>{captures.map(x => <option key={x.id} value={x.id}>{x.label} · {x.scenario}</option>)}</select></label>
    {a && b && <>
      <p>{comparisonVerdict(a, b)}</p>
      <p>For fair comparison capture each scenario in its own file with the same number of messages. Packet totals include login, handshake and WebSocket traffic.</p>
      <table className="dash-table"><thead><tr><th>Metric</th><th>A</th><th>B</th><th>Delta (B − A)</th><th>%</th></tr></thead><tbody>
        {metrics.map(m => { const d = deltaPercent(m.a, m.b); return <tr key={m.name}><td>{m.name}</td><td>{m.a ?? "—"}</td><td>{m.b ?? "—"}</td><td>{d.delta?.toFixed(2) ?? "—"}</td><td>{d.percent?.toFixed(2) ?? "—"}</td></tr>; })}
        <tr><td>Marker visible</td><td>{(a.exposures.find(x => x.kind === "marker")?.count ?? 0) > 0 ? "Yes" : "No"}</td><td>{(b.exposures.find(x => x.kind === "marker")?.count ?? 0) > 0 ? "Yes" : "No"}</td><td>—</td><td>—</td></tr>
      </tbody></table>
      <h3>Packets by capture</h3>
      <ResponsiveContainer width="100%" height={250}><BarChart data={chart}><CartesianGrid strokeDasharray="3 3"/><XAxis dataKey="name"/><YAxis allowDecimals={false} label={{ value: "Packet count", angle: -90, position: "insideLeft" }}/><Tooltip/><Legend/><Bar dataKey="packets" name="Packets" fill="#8e44ad"/></BarChart></ResponsiveContainer>
      <h3>Frame bytes by capture</h3>
      <ResponsiveContainer width="100%" height={250}><BarChart data={chart}><CartesianGrid strokeDasharray="3 3"/><XAxis dataKey="name"/><YAxis label={{ value: "Bytes", angle: -90, position: "insideLeft" }}/><Tooltip/><Legend/><Bar dataKey="bytes" name="Frame bytes" fill="#2980b9"/></BarChart></ResponsiveContainer>
    </>}
  </div>;
}
