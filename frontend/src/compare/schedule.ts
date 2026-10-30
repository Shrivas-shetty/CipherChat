import type { ScheduleEntry } from "./types";

export function buildSchedule(warmup: number, trials: number): ScheduleEntry[] {
  const result: ScheduleEntry[] = [];
  const total = warmup + trials;
  for (let pair = 0; pair < total; pair += 1) {
    const securedFirst = pair % 2 === 0;
    result.push({
      pair,
      warmup: pair < warmup,
      order: securedFirst ? ["secured", "unsecured"] : ["unsecured", "secured"],
    });
  }
  return result;
}
