import {describe,expect,it} from "vitest";
import {comparisonVerdict,deltaPercent,formatBytes,formatDuration,interpretScenario,perMessage,timelineBucket} from "../compare";
import type {CaptureDetail} from "../types";

const capture=(marker:string|null,hits:number):CaptureDetail=>({
 capture:{id:1,filename:"x.pcap",size_bytes:0,label:"x",scenario:"other",marker,server_port:8000,status:"done",error:null,created_at:"",ingested_at:null,tshark_version:null,packet_count:1,first_ts:null,last_ts:null,duration_s:1,total_frame_bytes:100,total_tcp_payload_bytes:0,tcp_streams:1,syn_count:0,retransmissions:0,http_requests:0,http_responses:0,ws_frames:0,ws_payload_bytes:0,truncated:false,client_ips:[],server_ips:[]},sidecar_info:null,exposures:hits?[{kind:"marker",count:hits,frames:[1],snippet:""}]:[],http_by_class:[],protocols:[],conversations:[],size_histogram:[],packet_size_stats:{min:null,max:null,mean:null,median:null}
});

describe("network comparison helpers",()=>{
 it("computes signed deltas and handles null and zero baselines",()=>{
  expect(deltaPercent(10,15)).toEqual({delta:5,percent:50});
  expect(deltaPercent(0,0)).toEqual({delta:0,percent:0});
  expect(deltaPercent(0,3)).toEqual({delta:3,percent:null});
  expect(deltaPercent(null,3)).toEqual({delta:null,percent:null});
 });
 it("calculates per-message values safely",()=>{expect(perMessage(40,4)).toBe(10);expect(perMessage(40,0)).toBeNull();expect(perMessage(null,4)).toBeNull();});
 it("reports matching marker exposure contrasts only",()=>{
  expect(comparisonVerdict(capture("SECRETWORD123",1),capture("SECRETWORD123",0))).toContain("confidentiality demonstrated");
  expect(comparisonVerdict(capture("SECRETWORD123",0),capture("SECRETWORD123",0))).toContain("No matching");
  expect(comparisonVerdict(capture("A_MARKER",1),capture("B_MARKER",0))).toContain("No matching");
 });
 it("formats bytes and durations and maps bucket choices",()=>{
  expect(formatBytes(512)).toBe("512 B");expect(formatBytes(2048)).toBe("2.00 KiB");expect(formatBytes(null)).toBe("—");
  expect(formatDuration(.25)).toBe("250.0 ms");expect(formatDuration(2)).toBe("2.00 s");expect(timelineBucket("auto")).toBeUndefined();expect(timelineBucket("500")).toBe(500);
 });
 it("interprets marker findings by scenario",()=>{
  expect(interpretScenario("plain_baseline",1,0)).toContain("EXPECTED");expect(interpretScenario("secure_traffic",1,0)).toContain("FAILURE");expect(interpretScenario("login_attempt",0,1)).toContain("EXPECTED");
 });
});
