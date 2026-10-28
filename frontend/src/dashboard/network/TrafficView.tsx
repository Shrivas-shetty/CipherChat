import { useEffect, useState } from "react";
import { Area, AreaChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { dashboardApi } from "../api";
import { timelineBucket } from "./compare";
import type { Timeline } from "./types";

export function TrafficView({ id }: { id: number }) {
  const [choice, setChoice] = useState("auto");
  const [data, setData] = useState<Timeline | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    const ctrl = new AbortController();
    dashboardApi.timeline(id, timelineBucket(choice), ctrl.signal)
      .then(setData)
      .catch((e) => { if (!ctrl.signal.aborted) setError(String(e)); });
    return () => ctrl.abort();
  }, [id, choice]);

  return <div className="dash-view">
    <label>Bucket size <select value={choice} onChange={(e) => setChoice(e.target.value)}>
      <option value="auto">Auto</option><option value="100">100 ms</option><option value="500">500 ms</option><option value="1000">1 s</option><option value="5000">5 s</option>
    </select></label>
    {error && <p className="dash-error">{error}</p>}
    <p>Bucket: {data?.bucket_ms} ms</p>
    <h3>Traffic bytes by direction</h3>
    <ResponsiveContainer width="100%" height={300}>
      <AreaChart data={data?.buckets ?? []}>
        <CartesianGrid strokeDasharray="3 3"/><XAxis dataKey="t" unit="s"/><YAxis/><Tooltip/>
        <Area dataKey="c2s_bytes" stackId="1" name="Client to server bytes" fill="#2980b9"/>
        <Area dataKey="s2c_bytes" stackId="1" name="Server to client bytes" fill="#e67e22"/>
      </AreaChart>
    </ResponsiveContainer>
    <div className="dash-chips" aria-label="Traffic chart color key">
      <span><i aria-hidden="true" style={{ display: "inline-block", width: 12, height: 12, backgroundColor: "#2980b9", marginRight: 6 }} />Blue: Client → server</span>
      <span><i aria-hidden="true" style={{ display: "inline-block", width: 12, height: 12, backgroundColor: "#e67e22", marginRight: 6 }} />Orange: Server → client</span>
    </div>
    <h3>Packets per bucket</h3>
    <ResponsiveContainer width="100%" height={260}>
      <LineChart data={data?.buckets ?? []}>
        <CartesianGrid strokeDasharray="3 3"/><XAxis dataKey="t" unit="s"/><YAxis/><Tooltip/>
        <Line dataKey="packets" name="Packets" stroke="#8e44ad"/>
      </LineChart>
    </ResponsiveContainer>
  </div>;
}
