import { useCallback, useMemo, useState } from "react";
import type { SignatureRecord, SigningKeyRecord } from "../../../api";
import { dashboardApi } from "../../../api";
import { usePolling } from "../../../hooks/usePolling";
import { formatTs } from "../../../labels";
import { ScatterWithRegression } from "../ScatterWithRegression";
import { signatureGroups, sortRows } from "../phase12Aggregation";

type Tab="Overview"|"Text"|"Images"|"Records"|"Keys";
type RowSort=keyof SignatureRecord;
const PAGE_SIZE=2000, MAX_ROWS=5000, TABLE_PAGE=40;
const grouped=(hex:string)=>hex.slice(0,16).match(/.{4}/g)?.join(" ").toUpperCase()??hex;

export function SignatureLab() {
  const [tab,setTab]=useState<Tab>("Overview");
  const [page,setPage]=useState(0);
  const [sort,setSort]=useState<{key:RowSort;direction:"asc"|"desc"}>({key:"id",direction:"desc"});
  const fetcher=useCallback(async(signal:AbortSignal)=>{
    const records:SignatureRecord[]=[]; let before:number|undefined; let total=0;
    while(records.length<MAX_ROWS){const part=await dashboardApi.signatureRecords({limit:PAGE_SIZE,before_id:before},signal);total=part.total;records.push(...part.items);if(!part.has_more_older||!part.items.length)break;before=part.items[part.items.length-1].id;}
    const keys=await dashboardApi.signingKeys(1000,signal);
    return {records:records.slice(0,MAX_ROWS),recordTotal:total,keys:keys.items,keyTotal:keys.total};
  },[]);
  const {data,error,loading,refresh}=usePolling(fetcher,10000);
  const records=data?.records??[], keys=data?.keys??[];
  const stats=useMemo(()=>signatureGroups(records),[records]);
  const sorted=useMemo(()=>sortRows(records,sort.key,sort.direction),[records,sort]);
  const visible=sorted.slice(page*TABLE_PAGE,(page+1)*TABLE_PAGE);
  function toggleSort(key:RowSort){setSort((old)=>({key,direction:old.key===key&&old.direction==="asc"?"desc":"asc"}));}
  const charts=(isImage:boolean)=> <ScatterWithRegression title="PT Length vs ECDSA Signature Generation Time" xLabel="Plaintext length (bytes)" yLabel="ECDSA P-256 signature generation time (ms)" series={[{name:isImage?"Images":"Text",color:isImage?"#56a7ff":"#43c59e",points:isImage?stats.imagePoints:stats.textPoints}]} />;
  return <div className="dash-view">
    <div className="dash-filterbar"><button onClick={()=>void refresh()}>Refresh</button><span className="dash-muted">Loaded up to {MAX_ROWS} newest signed messages</span></div>
    {error&&<div className="dash-error">Could not load signature data: {error}<button onClick={()=>void refresh()}>Retry</button></div>}
    {loading&&!data&&<div className="dash-empty">Loading signature data…</div>}
    {!loading&&!error&&records.length===0&&<div className="dash-empty">Send messages with two logged-in users; only messages sent after Phase 12 are included</div>}
    <nav className="dash-subtabs">{(["Overview","Text","Images","Records","Keys"] as Tab[]).map(value=><button key={value} className={tab===value?"selected":""} onClick={()=>setTab(value)}>{value}</button>)}</nav>
    {tab==="Overview"&&<>
      <div className="dash-cards"><div><small>Signed messages</small><b>{data?.recordTotal??0}</b></div><div><small>VALID</small><b>{records.filter(row=>row.signature_status==="valid").length}</b></div><div><small>Mean signature generation</small><b>{stats.meanGenerationMs?.toFixed(3)??"—"} ms</b></div><div><small>Mean verification</small><b>{stats.meanVerificationMs?.toFixed(3)??"—"} ms</b></div><div><small>Keys total / active</small><b>{data?.keyTotal??0} / {keys.filter(key=>key.active).length}</b></div></div>
      <section className="dash-panel"><h3>How signatures work</h3><p>ECDSA (P-256, SHA-256) signs the 32-byte SHA-256 digest of the message (the encrypted envelope plus HMAC tag) with one elliptic-curve scalar multiplication, so signing time is nearly independent of message length. The private key exists only in the sender's browser; the server stores public keys and verifies uploads.</p></section>
    </>}
    {tab==="Text"&&<>{charts(false)}<p className="dash-note">ECDSA signs a fixed 32-byte digest using P-256, so signing time is nearly independent of plaintext length.</p></>}
    {tab==="Images"&&<>{charts(true)}<p className="dash-note">ECDSA signs a fixed 32-byte digest using P-256, so signing time is nearly independent of plaintext length.</p></>}
    {tab==="Records"&&<section className="dash-panel"><h3>Signature records</h3><div className="dash-table-wrap"><table className="dash-table"><thead><tr>{([["created_at","Time"],["id","Message"],["sender","Sender → recipient"],["msg_type","Type"],["pt_len_bytes","Plaintext"],["signer_key_id","Key ID"],["signature_preview_hex","Signature preview"],["sig_gen_ms","Generated (ms)"],["sig_verify_ms","Verified (ms)"],["signature_status","Status"]] as [RowSort,string][]).map(([key,label])=><th key={key}><button className="sort-button" onClick={()=>toggleSort(key)}>{label}{sort.key===key?(sort.direction==="asc"?" ↑":" ↓"):""}</button></th>)}</tr></thead><tbody>{visible.map(row=><tr key={row.id}><td>{formatTs(row.created_at)}</td><td>#{row.id}</td><td>{row.sender} → {row.recipient}</td><td>{row.msg_type}{row.msg_type==="image"&&row.w&&row.h?` ${row.w}×${row.h}`:""}</td><td>{row.pt_len_bytes.toLocaleString()} B</td><td title={row.key_fingerprint}>{row.signer_key_id} · {grouped(row.key_fingerprint)}</td><td><code>{row.signature_preview_hex}…</code></td><td>{row.sig_gen_ms.toFixed(3)}</td><td>{row.sig_verify_ms==null?"—":row.sig_verify_ms.toFixed(3)}</td><td><span className={row.signature_status==="valid"?"integrity-ok":row.signature_status==="invalid"?"integrity-failed":"dash-muted"}>{row.signature_status.toUpperCase()}</span></td></tr>)}</tbody></table></div><div className="dash-filterbar"><button disabled={!page} onClick={()=>setPage(page-1)}>Previous</button><span>Page {page+1} of {Math.max(1,Math.ceil(sorted.length/TABLE_PAGE))}</span><button disabled={(page+1)*TABLE_PAGE>=sorted.length} onClick={()=>setPage(page+1)}>Next</button></div></section>}
    {tab==="Keys"&&<section className="dash-panel"><h3>Signing key registry ({data?.keyTotal??0})</h3><div className="dash-table-wrap"><table className="dash-table"><thead><tr><th>ID</th><th>User</th><th>Fingerprint</th><th>Created</th><th>Retired</th><th>Reason</th><th>State</th><th>Keygen (ms)</th><th>Signed messages</th></tr></thead><tbody>{keys.map((key:SigningKeyRecord)=><tr key={key.id}><td>{key.id}</td><td>{key.username}</td><td><code>{grouped(key.fingerprint)}</code></td><td>{formatTs(key.created_at)}</td><td>{key.retired_at?formatTs(key.retired_at):"—"}</td><td>{key.retire_reason??"—"}</td><td><span className={key.active?"integrity-ok":"dash-muted"}>{key.active?"ACTIVE":"RETIRED"}</span></td><td>{key.keygen_ms==null?"—":key.keygen_ms.toFixed(2)}</td><td>{key.signed_count}</td></tr>)}</tbody></table></div></section>}
  </div>;
}
