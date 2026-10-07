import { useAuth } from "../auth/AuthContext";

export function AnalystPage() {
  const { user, logout } = useAuth();

  return (
    <div className="page analyst-page">
      <header className="chat-header">
        <div>
          <h1>CipherChat</h1>
          <p className="you-are">Logged in as {user?.username} ({user?.role})</p>
        </div>
        <button
          type="button"
          className="btn secondary logout-btn"
          onClick={() => void logout()}
        >
          Logout
        </button>
      </header>

      <div className="panel analyst-panel">
        <div className="analyst-icon">🛡️</div>
        <h2>Analyst Portal</h2>
        <p className="analyst-notice">
          Security dashboard, coming in Phase 6
        </p>
        <p className="analyst-desc">
          Analyst accounts cannot join live chat sessions. Audit logs and traffic inspection capabilities will be enabled here in future phases.
        </p>
      </div>
    </div>
  );
}

