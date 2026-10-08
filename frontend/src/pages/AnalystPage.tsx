import { useEffect, useState } from "react";
import { requestJson } from "../api/http";
import { useAuth } from "../auth/AuthContext";

export function AnalystPage() {
  const { user, logout } = useAuth();
  const [armed, setArmed] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(true);
  const [actionLoading, setActionLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function fetchState() {
      try {
        const res = await requestJson<{ armed: boolean }>("/api/admin/tamper");
        if (!cancelled) {
          setArmed(res.armed);
        }
      } catch (err: unknown) {
        if (!cancelled) {
          setError(
            err instanceof Error ? err.message : "Failed to load tamper status"
          );
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }
    void fetchState();
    return () => {
      cancelled = true;
    };
  }, []);

  async function handleToggleTamper(targetArmed: boolean) {
    setActionLoading(true);
    setError(null);
    try {
      const res = await requestJson<{ armed: boolean }>("/api/admin/tamper", {
        method: "POST",
        body: JSON.stringify({ armed: targetArmed }),
      });
      setArmed(res.armed);
    } catch (err: unknown) {
      setError(
        err instanceof Error ? err.message : "Failed to change tamper status"
      );
    } finally {
      setActionLoading(false);
    }
  }

  return (
    <div className="page analyst-page">
      <header className="chat-header">
        <div>
          <h1>CipherChat</h1>
          <p className="you-are">
            Logged in as {user?.username} ({user?.role})
          </p>
        </div>
        <button
          type="button"
          className="btn secondary logout-btn"
          onClick={() => void logout()}
        >
          Logout
        </button>
      </header>

      {/* Analyst overview panel */}
      <div className="panel analyst-panel">
        <div className="analyst-icon">🛡️</div>
        <h2>Analyst Portal</h2>
        <p className="analyst-notice">Security dashboard, coming in Phase 6</p>
        <p className="analyst-desc">
          Analyst accounts cannot join live chat sessions. Audit logs and traffic
          inspection capabilities will be enabled here in future phases.
        </p>
      </div>

      {/* Tamper simulation panel (Phase 4 demo) */}
      <div className="panel tamper-panel">
        <div className="tamper-header">
          <h3>Tamper Simulation (Demo Only)</h3>
          <span
            className={`tamper-badge ${
              loading ? "loading" : armed ? "armed" : "disarmed"
            }`}
          >
            {loading ? "Checking…" : armed ? "⚠️ ARMED" : "DISARMED"}
          </span>
        </div>

        <p className="tamper-desc">
          Simulates an active Man-in-the-Middle altering encrypted packets in
          transit. When armed, the server will flip 1 bit in the ciphertext of
          the <strong>next</strong> message fetched by the recipient.
        </p>

        {error && <p className="msg err">{error}</p>}

        <div className="btn-row">
          <button
            type="button"
            className="btn danger-btn"
            disabled={actionLoading || loading || armed}
            onClick={() => void handleToggleTamper(true)}
          >
            {actionLoading && !armed
              ? "Arming…"
              : "Arm tamper for the next message"}
          </button>
          <button
            type="button"
            className="btn secondary"
            disabled={actionLoading || loading || !armed}
            onClick={() => void handleToggleTamper(false)}
          >
            {actionLoading && armed ? "Disarming…" : "Disarm"}
          </button>
        </div>

        <div className="tamper-info-callout">
          <strong>Expected behavior:</strong>
          <ul>
            <li>
              The receiver validates HMAC-SHA256 over canonical fields{" "}
              <em>before</em> attempting decryption.
            </li>
            <li>
              Because the ciphertext was altered by 1 bit, verification fails (
              <code>hmac_mismatch</code>).
            </li>
            <li>
              The message is <strong>never decrypted</strong>, a red warning badge
              is shown to both peers, and a <code>TAMPER_DETECTED</code> alert is
              committed to the SHA-256 audit hash-chain.
            </li>
          </ul>
        </div>
      </div>
    </div>
  );
}
