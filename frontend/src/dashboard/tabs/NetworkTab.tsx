import {useCallback,useEffect,useState} from "react";
import {dashboardApi} from "../api";
import type {CaptureDetail,CaptureSummary,NetworkStatus,PcapFileItem,SidecarItem} from "../network/types";
import {CapturesView} from "../network/CapturesView";import {OverviewView} from "../network/OverviewView";import {TrafficView} from "../network/TrafficView";import {PacketsView} from "../network/PacketsView";import {HttpView} from "../network/HttpView";import {CompareView} from "../network/CompareView";
type View="Captures"|"Overview"|"Traffic"|"Packets"|"HTTP"|"Compare";
export function NetworkTab(){const [view,setView]=useState<View>("Captures"),[status,setStatus]=useState<NetworkStatus|null>(null),[files,setFiles]=useState<{pcaps:PcapFileItem[];sidecars:SidecarItem[]}|null>(null),[captures,setCaptures]=useState<CaptureSummary[]>([]),[detail,setDetail]=useState<CaptureDetail|null>(null),[selected,setSelected]=useState<number|null>(null),[error,setError]=useState("");
 const refresh=useCallback(async()=>{try{const [f,c]=await Promise.all([dashboardApi.networkFiles(),dashboardApi.captures()]);setFiles(f);setCaptures(c.items);setError("");}catch(e){setError(e instanceof Error?e.message:String(e));}},[]);
 useEffect(()=>{void dashboardApi.networkStatus().then(setStatus).catch(e=>setError(String(e)));void refresh();},[refresh]);
 const busy=captures.some(x=>x.status==="queued"||x.status==="running");
 useEffect(()=>{const tick=()=>{if(document.visibilityState==="visible")void refresh();};const id=window.setInterval(tick,busy?2000:15000);document.addEventListener("visibilitychange",tick);return()=>{window.clearInterval(id);document.removeEventListener("visibilitychange",tick);};},[refresh,busy]);
 useEffect(()=>{if(selected!==null){const c=captures.find(x=>x.id===selected);if(!c){setDetail(null);return;}void dashboardApi.capture(selected).then(setDetail).catch(e=>{setDetail(null);setError(String(e));});}},[selected,captures]);
 const select=(id:number)=>{setSelected(id);};
 const views:View[]=["Captures","Overview","Traffic","Packets","HTTP","Compare"];
 return <section className="dash-panel"><h2>Network traffic analysis</h2>{error&&<p className="dash-error">{error}</p>}<div className="dash-tools"><label>Selected capture <select value={selected??""} onChange={e=>setSelected(e.target.value?Number(e.target.value):null)}><option value="">Choose capture</option>{captures.map(c=><option key={c.id} value={c.id}>{c.label} · {c.filename} ({c.status})</option>)}</select></label><button onClick={()=>void refresh()}>Refresh</button></div><nav className="dash-chips">{views.map(x=><button key={x} className={view===x?"selected":""} onClick={()=>setView(x)}>{x}</button>)}</nav>
 {view==="Captures"?<CapturesView status={status} files={files} captures={captures} onSelect={select} onRefresh={()=>{void refresh();}}/>:view==="Compare"?<CompareView captures={captures}/>:!selected||!detail?<p>Select a completed capture to view its analysis.</p>:view==="Overview"?<OverviewView detail={detail}/>:view==="Traffic"?<TrafficView id={selected}/>:view==="Packets"?<PacketsView id={selected}/>:<HttpView id={selected}/>}</section>;
}
