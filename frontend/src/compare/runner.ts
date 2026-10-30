import { DEFAULT_TEXT } from "./config";
import { setupBenchmark, type BenchmarkContext } from "./benchContext";
import { buildSchedule } from "./schedule";
import { runSecuredTrial } from "./securedMode";
import { runUnsecuredTrial } from "./unsecuredMode";
import { dashboardApi } from "../dashboard/api";
import type { TrialMeasurement } from "./types";

export type RunOptions = { label: string; text: string; trials: number; warmup: number };
export type RunProgress = { phase:"setup"|"running"|"saving"; current:number; total:number; completed:TrialMeasurement[] };
export type RunResult = { id:number; status:"complete"|"stopped"; trials:TrialMeasurement[] };

export async function runCompare(options: RunOptions, signal: AbortSignal, onProgress: (p:RunProgress)=>void, shouldStop:()=>boolean=()=>false): Promise<RunResult> {
  let context: BenchmarkContext | null = null;
  let runId: number | null = null;
  const completed: TrialMeasurement[] = [];
  let pendingPair: TrialMeasurement[] = [];
  try {
    onProgress({phase:"setup",current:0,total:options.trials,completed});
    context = await setupBenchmark();
    const created = await dashboardApi.createCompareRun({label:options.label,input_text:options.text,trials:options.trials,warmup:options.warmup,
      ...context.setupTimings,sig_public_key_b64:context.publicKeyB64});
    runId = created.id;
    const schedule = buildSchedule(options.warmup, options.trials);
    let measuredPair = 0;
    for (const pair of schedule) {
      if (signal.aborted || shouldStop()) break;
      pendingPair = [];
      for (const mode of pair.order) {
        if (signal.aborted) break;
        const deps = {trialNo:pair.warmup?pair.pair+1:pair.pair-options.warmup+1,runId,warmup:pair.warmup,signal};
        const measurement = mode === "secured"
          ? await runSecuredTrial(context,options.text,deps)
          : await runUnsecuredTrial(options.text,deps);
        pendingPair.push(measurement);
      }
      if (pendingPair.length === 2) {
        if (!pair.warmup) { completed.push(...pendingPair); measuredPair += 1; }
        onProgress({phase:"running",current:measuredPair,total:options.trials,completed:[...completed]});
      }
      await new Promise<void>((resolve)=>setTimeout(resolve,0));
    }
    const status = signal.aborted || shouldStop() || measuredPair < options.trials ? "stopped" : "complete";
    if (signal.aborted) {
      await dashboardApi.abortCompareRun(runId);
      return {id:runId,status:"stopped",trials:completed};
    }
    onProgress({phase:"saving",current:measuredPair,total:options.trials,completed:[...completed]});
    if (completed.length) await dashboardApi.finalizeCompareRun(runId,status,completed);
    else await dashboardApi.abortCompareRun(runId);
    return {id:runId,status:completed.length?status:"stopped",trials:completed};
  } catch (error) {
    if (runId !== null) { try { await dashboardApi.abortCompareRun(runId); } catch { /* preserve original failure */ } }
    throw error;
  } finally { context?.dispose(); }
}

export const defaultRunOptions: RunOptions = {label:"",text:DEFAULT_TEXT,trials:20,warmup:3};
