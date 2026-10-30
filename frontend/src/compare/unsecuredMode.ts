import type { TrialMeasurement } from "./types";
import { exchange, type TimedExchangeResult } from "./transport";
import type { TrialDeps } from "./securedMode";

export async function runUnsecuredTrial(text: string, deps: TrialDeps): Promise<TrialMeasurement> {
  const send = deps.exchange ?? exchange;
  const now = deps.now ?? (() => performance.now());
  const t0 = now();
  const plaintextBytes = new TextEncoder().encode(text).byteLength;
  let postStart = t0, getStart = t0, getParsed = t0;
  const post: TimedExchangeResult<{id:number}> = await send("POST", `/api/dashboard/compare/runs/${deps.runId}/exchanges`,
    {mode:"unsecured", warmup:deps.warmup, text}, {signal:deps.signal, onFetchStart:()=>{postStart=now();}});
  const get = await send<any>("GET", `/api/dashboard/compare/runs/${deps.runId}/exchanges/${post.json.id}`, undefined,
    {signal:deps.signal,onFetchStart:()=>{getStart=now();},onResponseParsed:()=>{getParsed=now();}});
  const recovered = get.json.mode === "unsecured" && typeof get.json.text === "string" ? get.json.text : null;
  const roundtripOk = recovered === text;
  // Include the client-side response/mode check in finish, then apply the
  // timer-resolution floor required by the backend's positive timing schema.
  const tEnd = now();
  const prep= Math.max(0.001,postStart-t0);
  const postMs=Math.max(0.001,getStart-postStart);
  const getMs=Math.max(0.001,getParsed-getStart);
  const finishMs=Math.max(0.001,tEnd-getParsed);
  const total=prep+postMs+getMs+finishMs;
  return {trial_no:deps.trialNo,mode:"unsecured",warmup:deps.warmup,exchange_id:post.json.id,total_ms:total,
    prep_ms:prep,post_ms:postMs,get_ms:getMs,finish_ms:finishMs,seal_ms:null,sign_ms:null,
    verify_hmac_ms:null,verify_sig_ms:null,decrypt_ms:null,post_req_bytes:post.reqBytes,post_resp_bytes:post.respBytes,
    get_resp_bytes:get.respBytes,plaintext_bytes:plaintextBytes,ciphertext_bytes:null,integrity_ok:null,signature_ok:null,roundtrip_ok:roundtripOk};
}
