import { useState } from "react";
import { dashboardApi } from "../api";

export function AuditIntegrity() {
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; first_bad_id: number | null; rows_checked: number; checked_at: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  async function verify() { setBusy(true); setError(null); try { setResult(await dashboardApi.auditIntegrity()); } catch (e) { setError(e instanceof Error ? e.message : "Verification failed"); } finally { setBusy(false); } }
  return <section className="dash-panel audit-integrity"><button disabled={busy} onClick={() => void verify()}>{busy ? "Verifying…" : "Verify audit log integrity"}</button>
    {result && <strong className={result.ok ? "integrity-ok" : "integrity-failed"}>{result.ok ? `Chain intact (${result.rows_checked} rows)` : `TAMPERING DETECTED at row #${result.first_bad_id}`}</strong>}
    {error && <span className="dash-error">{error}</span>}
  </section>;
}
