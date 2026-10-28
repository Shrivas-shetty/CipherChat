import { useCallback, useState } from "react";
import type { ImageLabRecord } from "../../api";
import { dashboardApi } from "../../api";
import { mean } from "../../../analysis/stats";
import { usePolling } from "../../hooks/usePolling";
import { formatTs } from "../../labels";
import { ScatterWithRegression } from "./ScatterWithRegression";
import { ImageRecordsTable } from "./ImageRecordsTable";
import { ImageSummaryCards } from "./ImageSummaryCards";
import { correlationAverages, directionFields, prePhaseRecords, type CorrelationDirection } from "./correlationView";

type Snapshot = { total: number; records: ImageLabRecord[]; updatedAt: string };
const PAGE_CAP = 5000;
async function fetchAll(signal: AbortSignal): Promise<Snapshot> {
  const records: ImageLabRecord[] = [];
  let before_id: number | undefined, total = 0, more = true;
  while (more && records.length < PAGE_CAP) {
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");
    const page = await dashboardApi.imageLabRecords({ limit: 2000, before_id }, signal);
    total = page.total; records.push(...page.items); more = page.has_more_older && page.items.length > 0;
    before_id = page.items.at(-1)?.id;
  }
  return { total, records: records.slice(0, PAGE_CAP), updatedAt: new Date().toISOString() };
}
const pts = (records: ImageLabRecord[], value: (row: ImageLabRecord) => number) => records.map((row) => ({ x: row.n_pixels, y: value(row), messageId: row.message_id }));
const fixed = (value: number | null) => value === null ? "n/a" : value.toFixed(4);

function EntropyTable({ records }: { records: ImageLabRecord[] }) {
  return <section className="dash-panel"><h3>Cipher-image entropy</h3><div className="dash-table-wrap"><table className="dash-table image-analysis-table"><thead><tr><th>Message id</th><th>Dimensions</th><th>Entropy R</th><th>Entropy G</th><th>Entropy B</th><th>Average</th><th>Expected for n pixels: 8 − 184/n</th></tr></thead><tbody>
    {records.map((r) => <tr key={r.id}><td>{r.message_id}</td><td>{r.width} × {r.height}</td><td>{r.entropy_r.toFixed(4)}</td><td>{r.entropy_g.toFixed(4)}</td><td>{r.entropy_b.toFixed(4)}</td><td>{r.entropy_avg.toFixed(4)}</td><td>{Math.max(0, 8 - 184 / r.n_pixels).toFixed(4)}</td></tr>)}
    <tr className="image-average-row"><th colSpan={2}>Average</th><td>{mean(records.map((r) => r.entropy_r)).toFixed(4)}</td><td>{mean(records.map((r) => r.entropy_g)).toFixed(4)}</td><td>{mean(records.map((r) => r.entropy_b)).toFixed(4)}</td><td>{mean(records.map((r) => r.entropy_avg)).toFixed(4)}</td><td>—</td></tr>
  </tbody></table></div></section>;
}

function CorrelationTable({ records, direction }: { records: ImageLabRecord[]; direction: CorrelationDirection }) {
  const cols = directionFields(direction);
  const averages = correlationAverages(records, direction);
  const title = direction === "h" ? "Horizontal" : direction === "v" ? "Vertical" : "Diagonal";
  const explanation = direction === "h" ? "Pairs are adjacent pixels in each row: (r,k) with (r,k+1)."
    : direction === "v" ? "Pairs are adjacent pixels in each column: (r,k) with (r+1,k)."
      : "Pairs are down-right diagonal pixels: (r,k) with (r+1,k+1).";
  const oldCount = direction === "h" ? 0 : prePhaseRecords(records, direction);
  return <section className="dash-panel"><h3>{title} pixel correlation</h3><p className="dash-note">{explanation} Pearson r uses every valid pair per RGB channel.</p>
    {oldCount > 0 && <div className="hash-warning">{oldCount} records were captured before {direction === "v" ? "vertical" : "diagonal"} analysis existed (shown as n/a). Clear the Image Lab data and send images again to fill them.</div>}
    <div className="dash-cards image-lab-cards"><div><small>Mean plaintext r</small><b>{fixed(averages[3])}</b></div><div><small>Mean cipher r</small><b>{fixed(averages[7])}</b></div></div>
    <div className="dash-table-wrap"><table className="dash-table image-analysis-table"><thead><tr><th rowSpan={2}>Message id</th><th rowSpan={2}>Dimensions</th><th colSpan={4}>Plaintext r</th><th colSpan={4}>Cipher r</th></tr><tr>{["R", "G", "B", "Avg", "R", "G", "B", "Avg"].map((x, i) => <th key={`${x}${i}`}>{x}</th>)}</tr></thead><tbody>
    {records.map((r) => <tr key={r.id}><td>{r.message_id}</td><td>{r.width} × {r.height}</td>{cols.map((k) => <td key={k}>{fixed(r[k] as number | null)}</td>)}</tr>)}
    <tr className="image-average-row"><th colSpan={2}>Average</th>{averages.map((value, i) => <td key={i}>{fixed(value)}</td>)}</tr>
  </tbody></table></div></section>;
}

function MseTable({ records }: { records: ImageLabRecord[] }) {
  return <section className="dash-panel"><h3>MSE / PSNR</h3><p className="dash-note">PSNR is infinite when MSE is 0.</p><div className="dash-table-wrap"><table className="dash-table image-analysis-table"><thead><tr><th>Message id</th><th>Dimensions</th><th>MSE (original vs decrypted)</th><th>PSNR (original vs decrypted)</th><th>MSE (original vs encrypted)</th><th>PSNR (original vs encrypted)</th></tr></thead><tbody>
    {records.map((r) => <tr className={r.mse_dec !== 0 ? "image-lossy-row" : ""} key={r.id}><td>{r.message_id}</td><td>{r.width} × {r.height}</td><td>{r.mse_dec.toFixed(4)}</td><td>{r.psnr_dec === null ? "∞ (identical)" : `${r.psnr_dec.toFixed(2)} dB`}</td><td>{r.mse_enc.toFixed(4)}</td><td>{r.psnr_enc === null ? "∞" : `${r.psnr_enc.toFixed(2)} dB`}</td></tr>)}
  </tbody></table></div></section>;
}

export function ImageLab() {
  const [section, setSection] = useState<"overview" | "images" | "performance" | "npcr" | "entropy" | "correlation" | "mse">("overview");
  const [actionError, setActionError] = useState("");
  const [correlationDirection, setCorrelationDirection] = useState<CorrelationDirection>("h");
  const fetcher = useCallback((signal: AbortSignal) => fetchAll(signal), []);
  const { data, error, loading, refresh } = usePolling(fetcher, 10000);
  const records = data?.records ?? [];
  async function clearData() {
    if (!window.confirm("Clear all image lab metric records? This cannot be undone.")) return;
    setActionError("");
    try { await dashboardApi.clearImageLab(); await refresh(); }
    catch (err) { setActionError(err instanceof Error ? err.message : "Could not clear image lab data"); }
  }
  const meanNpcr = mean(records.map((r) => r.npcr_pct)), meanUaci = mean(records.map((r) => r.uaci_pct));
  return <div className="text-lab image-lab">
    <header className="text-lab-header"><div><b>{data?.total ?? 0}</b> total records {data && <span className="dash-muted">· Last updated {formatTs(data.updatedAt)}</span>}</div><div><button onClick={() => void refresh()}>Refresh</button> <button className="danger-button" disabled={!data?.total} onClick={() => void clearData()}>Clear image lab data</button></div></header>
    {error && <div className="dash-error">Could not load image metrics: {error} <button onClick={() => void refresh()}>Retry</button></div>}
    {actionError && <div className="dash-error">{actionError}</div>}
    {loading && !data && <div className="dash-empty">Loading image metrics…</div>}
    {!loading && !error && records.length === 0 ? <div className="dash-empty"><b>No image metrics yet.</b><p>Log in as two users, enable 'Collect security metrics', and send images of different sizes.</p></div> : records.length > 0 && <>
      <p className="lab-blind-note">All values are computed in the senders' browsers and reported to the server as numbers. The server is blind to original and decrypted images, so this dashboard can show only the ENCRYPTED images.</p>
      <nav className="dash-subtabs">{([ ["overview", "Overview"], ["images", "Images"], ["performance", "Performance"], ["npcr", "NPCR / UACI"], ["entropy", "Entropy"], ["correlation", "Correlation"], ["mse", "MSE / PSNR"] ] as const).map(([value, label]) => <button key={value} className={section === value ? "selected" : ""} onClick={() => setSection(value)}>{label}</button>)}</nav>
      {section === "overview" && <ImageSummaryCards records={records} total={data?.total ?? records.length} />}
      {section === "images" && <ImageRecordsTable records={records} />}
      {section === "performance" && <><p className="dash-note">Browser (JavaScript) timings, AES only.</p><ScatterWithRegression title="AES encryption time" xLabel="Image pixels" yLabel="Milliseconds per operation" series={[{ name: "Encrypt ms", color: "#56a7ff", points: pts(records, (r) => r.enc_us / 1000) }]} /><ScatterWithRegression title="AES decryption time" xLabel="Image pixels" yLabel="Milliseconds per operation" series={[{ name: "Decrypt ms", color: "#ffb454", points: pts(records, (r) => r.dec_us / 1000) }]} /></>}
      {section === "npcr" && <><div className="dash-cards image-lab-cards"><div><small>Average NPCR</small><b>{meanNpcr.toFixed(2)}%</b></div><div><small>Average UACI</small><b>{meanUaci.toFixed(2)}%</b></div></div>
        <ScatterWithRegression title="NPCR" xLabel="Image pixels" yLabel="Changed ciphertext pixels (%)" series={[{ name: "NPCR", color: "#a879ff", points: pts(records, (r) => r.npcr_pct) }]} referenceY={meanNpcr} referenceLabel={`Average NPCR: ${meanNpcr.toFixed(2)}%`} referenceDashed={false} referenceY2={99.61} referenceLabel2="Ideal for a random cipher" yDomain={[0, 105]} />
        <ScatterWithRegression title="UACI" xLabel="Image pixels" yLabel="Mean intensity change (%)" series={[{ name: "UACI", color: "#43c59e", points: pts(records, (r) => r.uaci_pct) }]} referenceY={meanUaci} referenceLabel={`Average UACI: ${meanUaci.toFixed(2)}%`} referenceDashed={false} referenceY2={33.46} referenceLabel2="Ideal for a random cipher" yDomain={[0, 36]} />
        <p className="dash-note">AES-CBC propagates a one-pixel change only forward from its block to the end of the image, so averaged over random pixel positions NPCR is about 50% and UACI about 16.7%, about half the ideal values. Dedicated image ciphers add a permutation/diffusion layer to approach the ideal.</p>
      </>}
      {section === "entropy" && <EntropyTable records={records} />}
      {section === "correlation" && <><nav className="dash-subtabs">{([["h", "Horizontal"], ["v", "Vertical"], ["d", "Diagonal"]] as const).map(([value, label]) => <button key={value} className={correlationDirection === value ? "selected" : ""} onClick={() => setCorrelationDirection(value)}>{label}</button>)}</nav><CorrelationTable records={records} direction={correlationDirection} /></>}
      {section === "mse" && <MseTable records={records} />}
    </>}
  </div>;
}
