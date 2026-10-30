import { median } from "./stats";
import type { CompareHistoryItem, CompareTrial } from "./types";

export function measuredRows(rows: CompareTrial[]) { return rows.filter(row=>!row.warmup); }
export function historyMedians(items: CompareHistoryItem[]) { return items.map(item=>({id:item.id,label:item.label,created_at:item.created_at,
  secured:median(item.secured_totals),unsecured:median(item.unsecured_totals)})); }
export function selectedLatestRun<T extends {id:number;status:string}>(items:T[]):T|null {
  return items.find(item=>item.status==="complete"||item.status==="stopped")??items[0]??null;
}
