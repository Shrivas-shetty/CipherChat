import type { AttackResult } from "./attacks";
import type { PerformanceRow } from "./performance";
export type HashLabEntry = { id: number; attack: "performance" | "preimage" | "second_preimage" | "collision"; bits: number; limit: number; result: AttackResult | PerformanceRow[]; expected: number; mode: "FULL" | "16-BIT DEMO" };
type State = { entries: HashLabEntry[] };
let state: State = { entries: [] }; let serial = 0;
const listeners = new Set<() => void>();
const notify = () => listeners.forEach((listener) => listener());
export const hashLabStore = {
  getSnapshot: (): State => state,
  subscribe: (listener: () => void) => { listeners.add(listener); return () => listeners.delete(listener); },
  add: (entry: Omit<HashLabEntry, "id">) => { state = { entries: [{ ...entry, id: ++serial }, ...state.entries] }; notify(); },
  clear: () => { state = { entries: [] }; notify(); },
};
