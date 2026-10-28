import { describe,it,expect } from "vitest";
import { hmacGroups, mean, signatureGroups, sortRows } from "../phase12Aggregation";
import type { HmacRecord, SignatureRecord } from "../../../api";

const hmac=(id:number,type:"text"|"image",pt:number,time:number,n_pixels:number|null):HmacRecord=>({id,created_at:"2026-01-01T00:00:00Z",msg_type:type,pt_len_bytes:pt,w:type==="image"?2:null,h:type==="image"?3:null,n_pixels,ct_len_bytes:16,hmac_gen_us:time});
describe("Phase 12 dashboard aggregation",()=>{
  it("ignores null/non-finite samples and separates HMAC data series",()=>{
    expect(mean([2,null,4,Number.NaN])).toBe(3);
    const grouped=hmacGroups([hmac(1,"text",10,2,null),hmac(2,"image",18,6,6)]);
    expect(grouped.textMeanUs).toBe(2);expect(grouped.imageMeanUs).toBe(6);
    expect(grouped.textPoints[0].x).toBe(10);expect(grouped.imagePoints[0].x).toBe(6);
  });
  it("groups signature records and sorts nullable values",()=>{
    const base={created_at:"2026-01-01",sender:"a",recipient:"b",pt_len_bytes:8,w:null,h:null,n_pixels:null,signer_key_id:1,key_fingerprint:"a".repeat(64),signature_len:64,signature_preview_hex:"a".repeat(64),signature_status:"valid" as const};
    const rows:SignatureRecord[]=[{...base,id:1,msg_type:"text",sig_gen_ms:2,sig_verify_ms:null},{...base,id:2,msg_type:"image",sig_gen_ms:4,sig_verify_ms:3}];
    const grouped=signatureGroups(rows);expect(grouped.meanGenerationMs).toBe(3);expect(grouped.meanVerificationMs).toBe(3);
    expect(grouped.textPoints).toHaveLength(1);expect(grouped.imagePoints).toHaveLength(1);
    expect(sortRows([{v:null},{v:3},{v:1}],"v","asc").map(row=>row.v)).toEqual([null,1,3]);
  });
});
