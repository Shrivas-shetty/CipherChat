const KEY = "cc.collectMetrics";
export function getCollectMetrics(): boolean {
  try { return localStorage.getItem(KEY) !== "false"; } catch { return true; }
}
export function setCollectMetrics(enabled: boolean): void {
  try { localStorage.setItem(KEY, String(enabled)); } catch { /* storage may be disabled */ }
}
