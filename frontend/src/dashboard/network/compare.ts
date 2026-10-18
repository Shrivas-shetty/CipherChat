import type { CaptureDetail } from "./types";

export function deltaPercent(a:number|null,b:number|null){
  if(a===null||b===null)return {delta:null as number|null,percent:null as number|null};
  const delta=b-a;return {delta,percent:a===0?(delta===0?0:null):delta/a*100};
}
export function perMessage(value:number|null,messages:number|null){return value===null||messages===null||messages<=0?null:value/messages;}
export function messageRequestBytes(d:CaptureDetail){return d.http_by_class.filter(x=>["message_send","baseline_send"].includes(x.endpoint_class)).reduce((n,x)=>n+x.request_body_bytes_total,0);}
export function messageResponseBytes(d:CaptureDetail){return d.http_by_class.filter(x=>["message_fetch","baseline_fetch"].includes(x.endpoint_class)).reduce((n,x)=>n+x.response_body_bytes_total,0);}
export function comparisonVerdict(a:CaptureDetail,b:CaptureDetail){
  const markerA=a.capture.marker,markerB=b.capture.marker;
  const hitsA=a.exposures.find(x=>x.kind==="marker")?.count??0,hitsB=b.exposures.find(x=>x.kind==="marker")?.count??0;
  return markerA&&markerA===markerB&&hitsA>0&&hitsB===0?"Marker visible in A, hidden in B: payload confidentiality demonstrated":"No matching marker visibility contrast to report.";
}
export function interpretScenario(scenario:string,markerFound:number,credentialsFound:number){
  if(scenario==="plain_baseline"&&markerFound>0)return "EXPECTED: the plaintext baseline marker is visible.";
  if(scenario==="secure_traffic"&&markerFound>0)return "FAILURE: a marker appeared in the secure message traffic.";
  if(scenario==="login_attempt"&&credentialsFound>0)return "EXPECTED: login credentials are visible in plain HTTP traffic.";
  if(scenario==="secure_traffic")return "No marker exposure found in the captured traffic.";
  return "Interpretation depends on the scenario and capture completeness.";
}
export function formatBytes(n:number|null){if(n===null)return "—";if(n<1024)return `${n} B`;const units=["KiB","MiB","GiB"];let x=n/1024,i=0;while(x>=1024&&i<units.length-1){x/=1024;i++;}return `${x.toFixed(2)} ${units[i]}`;}
export function formatDuration(s:number|null){if(s===null)return "—";if(s<1)return `${(s*1000).toFixed(1)} ms`;if(s<60)return `${s.toFixed(2)} s`;return `${Math.floor(s/60)}m ${(s%60).toFixed(1)}s`;}
export function timelineBucket(value:string):number|undefined{return value==="auto"?undefined:Number(value);}
