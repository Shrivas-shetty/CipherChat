import { useCallback, useState } from "react";
import { dashboardApi, type TextLabRecord } from "../../api";
import { usePolling } from "../../hooks/usePolling";
import { formatTs } from "../../labels";
import { ScatterWithRegression, type PlotSeries } from "./ScatterWithRegression";
import { TextRecordsTable } from "./TextRecordsTable";
import { TextSummaryCards } from "./TextSummaryCards";

type LabSnapshot = { total: number; records: TextLabRecord[]; updatedAt: string };
const PAGE_CAP = 5000;
async function fetchAllTextRecords(signal: AbortSignal): Promise<LabSnapshot> {
  const records: TextLabRecord[] = [];
  let beforeId: number | undefined, total = 0, more = true;
  while (more && records.length < PAGE_CAP) {
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");
    const page = await dashboardApi.textLabRecords({ limit: 2000, before_id: beforeId }, signal);
    total = page.total;
    records.push(...page.items);
    more = page.has_more_older && page.items.length > 0;
    beforeId = page.items.at(-1)?.id;
  }
  return { total, records: records.slice(0, PAGE_CAP), updatedAt: new Date().toISOString() };
}
const points = (records: TextLabRecord[], field: "confusion_pct" | "avalanche_pct" | "block_avalanche_pct" | "diffusion_bits" | "enc_us" | "dec_us") => records.map((r) => ({ x: r.pt_len_bytes, y: r[field], messageId: r.message_id }));

export function TextLab() {
  const [section, setSection] = useState<"overview" | "confusion" | "diffusion" | "time" | "records">("overview");
  const [showWholeFit, setShowWholeFit] = useState(true), [showBlockFit, setShowBlockFit] = useState(true);
  const [actionError, setActionError] = useState<string | null>(null);
  const fetcher = useCallback((signal: AbortSignal) => fetchAllTextRecords(signal), []);
  const { data, error, loading, refresh } = usePolling(fetcher, 10000);
  const records = data?.records ?? [];

  async function clearData() {
    if (!window.confirm("Clear all text lab metric records? This cannot be undone.")) return;
    setActionError(null);
    try { await dashboardApi.clearTextLab(); await refresh(); }
    catch (error) { setActionError(error instanceof Error ? error.message : "Could not clear text lab data"); }
  }

  const avalancheSeries: PlotSeries[] = [
    { name: "Whole-message avalanche", color: "#56a7ff", points: points(records, "avalanche_pct") },
    { name: "Block avalanche", color: "#43c59e", points: points(records, "block_avalanche_pct") },
  ];
  return <div className="text-lab">
    <header className="text-lab-header"><div><b>{data?.total ?? 0}</b> total records {data && <span className="dash-muted">· Last updated {formatTs(data.updatedAt)}</span>}</div><div><button onClick={() => void refresh()}>Refresh</button> <button className="danger-button" disabled={!data?.total} onClick={() => void clearData()}>Clear text lab data</button></div></header>
    {error && <div className="dash-error">Could not load text metrics: {error} <button onClick={() => void refresh()}>Retry</button></div>}
    {actionError && <div className="dash-error">{actionError}</div>}
    {loading && !data && <div className="dash-empty">Loading text metrics…</div>}
    {!loading && !error && records.length === 0 ? <div className="dash-empty"><b>No text metrics yet.</b><p>Log in as two users, enable “Collect security metrics”, and send text messages of different lengths.</p></div> : records.length > 0 && <>
      <p className="lab-blind-note">All values are computed in the senders' browsers and reported to the server as numbers. The server never sees plaintext or keys, so this dashboard cannot display message contents.</p>
      <nav className="dash-subtabs">{([["overview", "Overview"], ["confusion", "Confusion"], ["diffusion", "Diffusion / Avalanche"], ["time", "Time tests"], ["records", "Records"]] as const).map(([value, label]) => <button key={value} className={section === value ? "selected" : ""} onClick={() => setSection(value)}>{label}</button>)}</nav>
      {section === "overview" && <TextSummaryCards records={records} total={data?.total ?? records.length} />}
      {section === "confusion" && <ScatterWithRegression title="Key-bit confusion" subtitle="Mean of 8 random single-key-bit flips per message" xLabel="Plaintext length (bytes)" yLabel="Ciphertext bits changed (%)" series={[{ name: "Confusion", color: "#a879ff", points: points(records, "confusion_pct") }]} referenceY={50} referenceLabel="50%" />}
      {section === "diffusion" && <>
        <div className="lab-toggles"><label><input type="checkbox" checked={showWholeFit} onChange={(e) => setShowWholeFit(e.target.checked)} /> Whole-message regression</label><label><input type="checkbox" checked={showBlockFit} onChange={(e) => setShowBlockFit(e.target.checked)} /> Block regression</label></div>
        <ScatterWithRegression title="Plaintext-bit avalanche" xLabel="Plaintext length (bytes)" yLabel="Ciphertext bits changed (%)" series={avalancheSeries.map((s, i) => ({ ...s, regression: i === 0 ? showWholeFit : showBlockFit }))} referenceY={50} referenceLabel="50%" />
        <ScatterWithRegression title="Diffusion" xLabel="Plaintext length (bytes)" yLabel="Mean changed ciphertext bits" series={[{ name: "Diffusion bits", color: "#43c59e", points: points(records, "diffusion_bits") }]} />
        <p className="dash-note">CBC encryption propagates a plaintext change to every ciphertext block from the changed block onward, so whole-message avalanche depends on where the bit is flipped (~50% in the first block, lower for later bits); block avalanche stays ~50%.</p>
        {(showWholeFit || showBlockFit) && <div className="lab-fit-summary">{avalancheSeries.map((s, i) => { const vals = s.points; const xMean = vals.reduce((n, p) => n + p.x, 0) / (vals.length || 1); const yMean = vals.reduce((n, p) => n + p.y, 0) / (vals.length || 1); const denom = vals.reduce((n, p) => n + (p.x - xMean) ** 2, 0); const slope = denom ? vals.reduce((n, p) => n + (p.x - xMean) * (p.y - yMean), 0) / denom : 0; return (i === 0 ? showWholeFit : showBlockFit) && <span key={s.name}>{s.name} slope: {slope.toPrecision(4)} · </span>; })}</div>}
      </>}
      {section === "time" && <><ScatterWithRegression title="AES encryption time" xLabel="Plaintext length (bytes)" yLabel="Microseconds per operation" subtitle="Browser (JavaScript) timings, AES only." series={[{ name: "Encrypt μs", color: "#56a7ff", points: points(records, "enc_us") }]} /><ScatterWithRegression title="AES decryption time" xLabel="Plaintext length (bytes)" yLabel="Microseconds per operation" subtitle="Browser (JavaScript) timings, AES only." series={[{ name: "Decrypt μs", color: "#ffb454", points: points(records, "dec_us") }]} /></>}
      {section === "records" && <TextRecordsTable records={records} />}
    </>}
  </div>;
}
