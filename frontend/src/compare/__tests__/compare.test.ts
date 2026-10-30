import { describe, expect, it } from "vitest";
import { buildSchedule } from "../schedule";
import { mean, median, percentile, stddev, summarize } from "../stats";
import { historyMedians, measuredRows, selectedLatestRun } from "../analysis";
import type { CompareHistoryItem, CompareTrial } from "../types";

describe("comparison benchmark pure helpers",()=>{
  it("alternates order and marks warmups",()=>{
    expect(buildSchedule(2,3)).toEqual([
      {pair:0,warmup:true,order:["secured","unsecured"]},
      {pair:1,warmup:true,order:["unsecured","secured"]},
      {pair:2,warmup:false,order:["secured","unsecured"]},
      {pair:3,warmup:false,order:["unsecured","secured"]},
      {pair:4,warmup:false,order:["secured","unsecured"]},
    ]);
  });
  it("computes empty, odd, even, percentile and sample deviation summaries",()=>{
    expect(summarize([])).toEqual({n:0,mean:null,median:null,p95:null,stddev:null,min:null,max:null});
    expect(mean([1,2,3,4])).toBe(2.5); expect(median([4,1,3,2])).toBe(2.5);
    expect(percentile([9,1,4,2],.75)).toBe(4); expect(stddev([1,3])).toBeCloseTo(Math.sqrt(2));
  });
  it("excludes warmups and calculates browser history medians",()=>{
    const rows=[{warmup:true,total_ms:1},{warmup:false,total_ms:2}] as CompareTrial[];
    expect(measuredRows(rows)).toHaveLength(1);
    const history=[{id:3,label:"run",created_at:"now",secured_totals:[1,3],unsecured_totals:[4,6]}] as CompareHistoryItem[];
    expect(historyMedians(history)[0]).toMatchObject({secured:2,unsecured:5});
    expect(selectedLatestRun([{id:1,status:"running"},{id:2,status:"complete"}])?.id).toBe(2);
  });
});
