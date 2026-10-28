import { describe, expect, it } from "vitest";
import { measureMedianUs } from "../../analysis/timing";
import { measureHmacUs } from "../hmacTiming";

describe("HMAC generation timing",()=>{
  it("uses calibrated median samples and returns a finite positive result",async()=>{
    let clock=0, work=0;
    const result=await measureMedianUs(()=>{work+=1;clock+=0.25;},{now:()=>clock,yieldFn:async()=>{},warmups:1,minBatchMs:1,samples:3,maxIters:16});
    expect(work).toBeGreaterThan(0);expect(result.medianUs).toBeGreaterThan(0);expect(Number.isFinite(result.medianUs)).toBe(true);
  });
  it("clamps very fast workloads and measures large inputs longer",async()=>{
    const key=Uint8Array.from({length:32},(_,i)=>i);
    const small=await measureHmacUs(key,new Uint8Array(100));
    const large=await measureHmacUs(key,new Uint8Array(100_000));
    expect(small).toBeGreaterThanOrEqual(0.001);expect(Number.isFinite(small)).toBe(true);
    expect(large).toBeGreaterThan(small*0.25);
  });
});
