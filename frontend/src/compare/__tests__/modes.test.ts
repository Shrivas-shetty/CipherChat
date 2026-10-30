import { describe, expect, it, vi } from "vitest";
import { setupBenchmark } from "../benchContext";
import { runSecuredTrial } from "../securedMode";
import { runUnsecuredTrial } from "../unsecuredMode";
import type { TimedExchangeResult } from "../transport";

describe("comparison client modes",()=>{
  it("round-trips a signed encrypted trial without posting key material",async()=>{
    const context=await setupBenchmark();
    let posted:any=null, tick=0;
    const fake=vi.fn(async <T,>(method:string,_path:string,body?:unknown,options?:any):Promise<TimedExchangeResult<T>>=>{
      options?.onFetchStart?.();
      if(method==="POST") posted=body;
      const json=(method==="POST"?{id:7}:{...posted,id:7,mode:"secured"}) as T;
      tick+=2; options?.onResponseParsed?.();
      return {status:method==="POST"?201:200,json,reqBytes:123,respBytes:45};
    });
    try {
      const result=await runSecuredTrial(context,"synthetic 🔐",{trialNo:1,runId:4,warmup:false,exchange:fake as any,now:()=>++tick});
      expect(result.roundtrip_ok).toBe(true); expect(result.integrity_ok).toBe(true); expect(result.signature_ok).toBe(true);
      expect(result.verify_hmac_ms).toBeGreaterThan(0); expect(result.verify_sig_ms).toBeGreaterThan(0); expect(result.decrypt_ms).toBeGreaterThan(0);
      expect(posted.mode).toBe("secured"); expect(posted.sender_role).toBe("I");
      expect(Object.keys(posted)).not.toContain("kEnc"); expect(Object.keys(posted)).not.toContain("privateKey");
    } finally {context.dispose();}
  });

  it("sends and retrieves exactly the selected plaintext for the unsecured path",async()=>{
    const text="plain 🔓"; let posted:any=null;
    const fake=async <T,>(method:string,_path:string,body?:unknown,options?:any):Promise<TimedExchangeResult<T>>=>{
      options?.onFetchStart?.(); if(method==="POST")posted=body;
      const json=(method==="POST"?{id:9}:{id:9,mode:"unsecured",text:posted.text}) as T;
      options?.onResponseParsed?.();return {status:method==="POST"?201:200,json,reqBytes:42,respBytes:19};
    };
    const result=await runUnsecuredTrial(text,{trialNo:1,runId:2,warmup:false,exchange:fake as any,now:()=>0});
    expect(posted).toEqual({mode:"unsecured",warmup:false,text}); expect(result.roundtrip_ok).toBe(true);
    expect(result.plaintext_bytes).toBe(new TextEncoder().encode(text).byteLength); expect(result.seal_ms).toBeNull();
    expect([result.prep_ms,result.post_ms,result.get_ms,result.finish_ms].every(value=>value>0)).toBe(true);
    expect(result.total_ms).toBe(result.prep_ms+result.post_ms+result.get_ms+result.finish_ms);
  });
});
