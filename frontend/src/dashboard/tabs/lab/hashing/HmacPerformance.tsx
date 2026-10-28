import { useCallback, useMemo, useState } from "react";
import type { HmacRecord } from "../../../api";
import { dashboardApi } from "../../../api";
import { usePolling } from "../../../hooks/usePolling";
import { formatTs } from "../../../labels";
import { ScatterWithRegression } from "../ScatterWithRegression";
import { hmacGroups, sortRows } from "../phase12Aggregation";

const PAGE_SIZE = 2000;
const MAX_ROWS = 5000;
const PAGE_ROWS = 50;
type SortKey = keyof HmacRecord;

export function HmacPerformance() {
  const [sort, setSort] = useState<{key:SortKey;direction:"asc"|"desc"}>({key:"id",direction:"desc"});
  const [page, setPage] = useState(0);
  const fetcher = useCallback(async (signal: AbortSignal) => {
    const all: HmacRecord[] = [];
    let before: number | undefined;
    let total = 0;
    while (all.length < MAX_ROWS) {
      const data = await dashboardApi.hmacRecords({limit:PAGE_SIZE,before_id:before},signal);
      total = data.total;
      all.push(...data.items);
      if (!data.has_more_older || !data.items.length) break;
      before = data.items[data.items.length - 1].id;
    }
    return {records:all.slice(0,MAX_ROWS),total};
  }, []);
  const {data,error,loading,refresh} = usePolling(fetcher,10000);
  const records = data?.records ?? [];
  const stats = useMemo(() => hmacGroups(records),[records]);
  const sorted = useMemo(() => sortRows(records,sort.key,sort.direction),[records,sort]);
  const visible = sorted.slice(page*PAGE_ROWS,(page+1)*PAGE_ROWS);
  function toggle(key:SortKey) { setSort((old) => ({key,direction:old.key===key&&old.direction==="asc"?"desc":"asc"})); }
  return <div className="dash-view">
    <div className="dash-filterbar"><button onClick={() => void refresh()}>Refresh</button><span className="dash-muted">Loaded {records.length} of the newest {MAX_ROWS} messages</span></div>
    {error && <div className="dash-error">Could not load HMAC timings: {error}<button onClick={() => void refresh()}>Retry</button></div>}
    {loading && !data && <p className="dash-empty">Loading HMAC timing records…</p>}
    {!loading && !error && records.length===0 && <p className="dash-empty">Send messages with two logged-in users; only messages sent after Phase 12 are included</p>}
    {records.length>0 && <>
      <div className="dash-cards"><div><small>Records</small><b>{data?.total ?? records.length}</b></div><div><small>Mean text HMAC time</small><b>{stats.textMeanUs?.toFixed(3) ?? "—"} µs</b></div><div><small>Mean image HMAC time</small><b>{stats.imageMeanUs?.toFixed(3) ?? "—"} µs</b></div></div>
      <ScatterWithRegression title="Text HMAC time" xLabel="Plaintext length (bytes)" yLabel="HMAC generation time (µs)" series={[{name:"Text",color:"#43c59e",points:stats.textPoints}]} />
      <ScatterWithRegression title="Image HMAC time" xLabel="Total pixels (width × height)" yLabel="HMAC generation time (µs)" series={[{name:"Images",color:"#56a7ff",points:stats.imagePoints}]} />
      <section className="dash-panel"><h3>HMAC records</h3><div className="dash-table-wrap"><table className="dash-table"><thead><tr>{([ ["created_at","Time"],["id","Message ID"],["msg_type","Type"],["pt_len_bytes","Plaintext bytes"],["w","Dimensions"],["n_pixels","Pixels"],["hmac_gen_us","HMAC time (µs)"] ] as [SortKey,string][]).map(([key,label])=><th key={key}><button className="sort-button" onClick={()=>toggle(key)}>{label}{sort.key===key?(sort.direction==="asc"?" ↑":" ↓"):""}</button></th>)}</tr></thead><tbody>{visible.map(row=><tr key={row.id}><td>{formatTs(row.created_at)}</td><td>#{row.id}</td><td>{row.msg_type}</td><td>{row.pt_len_bytes.toLocaleString()}</td><td>{row.w&&row.h?`${row.w}×${row.h}`:"—"}</td><td>{row.n_pixels == null?"—":row.n_pixels.toLocaleString()}</td><td>{row.hmac_gen_us.toFixed(3)}</td></tr>)}</tbody></table></div><div className="dash-filterbar"><button disabled={page===0} onClick={()=>setPage(Math.max(0,page-1))}>Previous</button><span>Page {page+1} of {Math.max(1,Math.ceil(sorted.length/PAGE_ROWS))}</span><button disabled={(page+1)*PAGE_ROWS>=sorted.length} onClick={()=>setPage(page+1)}>Next</button></div></section>
      <p className="dash-note">HMAC-SHA256 processes the whole message, so time grows linearly with its size. Values are measured in the sender's browser (calibrated batches, median) and stored with each message.</p>
    </>}
  </div>;
}
