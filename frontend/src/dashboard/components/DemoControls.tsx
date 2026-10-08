import { useEffect, useState } from "react";
import { requestJson } from "../../api/http";

export function DemoControls() {
  const [armed, setArmed] = useState(false);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let alive = true;
    void requestJson<{ armed: boolean }>("/api/admin/tamper").then((r) => { if (alive) setArmed(r.armed); }).catch((e: unknown) => { if (alive) setError(e instanceof Error ? e.message : "Could not load demo status"); }).finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, []);
  async function setState(next: boolean) {
    setBusy(true); setError(null);
    try { const result = await requestJson<{ armed: boolean }>("/api/admin/tamper", { method: "POST", body: JSON.stringify({ armed: next }) }); setArmed(result.armed); }
    catch (e) { setError(e instanceof Error ? e.message : "Could not change demo state"); }
    finally { setBusy(false); }
  }
  return <details className="dash-panel dash-demo"><summary>Demo Controls <span className={armed ? "severity-alert" : "dash-muted"}>{loading ? "Checking…" : armed ? "ARMED" : "DISARMED"}</span></summary>
    <p>Arms the Phase 4 one-shot tamper simulation: the next fetched message copy has one ciphertext bit flipped. Stored ciphertext is unchanged.</p>
    {error && <p className="dash-error">{error}</p>}
    <button disabled={loading || busy || armed} onClick={() => void setState(true)}>Arm tamper for next message</button> <button disabled={loading || busy || !armed} onClick={() => void setState(false)}>Disarm</button>
  </details>;
}
