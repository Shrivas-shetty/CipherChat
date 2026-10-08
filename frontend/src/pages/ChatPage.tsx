import { useEffect, useRef, useState, type FormEvent } from "react";
import type { HandshakeStatus, HandshakeTimings } from "../crypto/handshake";

export type ChatMessage = {
  id: string;
  text: string;
  ts: string;
  sender: { user_id: string; username: string };
  mine: boolean;
};

type RoomState = "waiting" | "paired";

type Props = {
  username: string;
  roomState: RoomState;
  peerName: string | null;
  peerLeftNotice: boolean;
  messages: ChatMessage[];
  disconnected: boolean;
  wsError: string | null;
  sessionStatus: HandshakeStatus;
  sessionId: string | null;
  role: "initiator" | "responder" | null;
  fingerprint: string | null;
  timings: HandshakeTimings;
  failureReason: string | null;
  terminationReason: string | null;
  onRequestSession: () => void;
  onSend: (text: string) => void;
  onLogout: () => void;
  onReconnect: () => void;
};

export function ChatPage({
  username,
  roomState,
  peerName,
  peerLeftNotice,
  messages,
  disconnected,
  wsError,
  sessionStatus,
  sessionId,
  role,
  fingerprint,
  timings,
  failureReason,
  terminationReason,
  onRequestSession,
  onSend,
  onLogout,
  onReconnect,
}: Props) {
  const [draft, setDraft] = useState("");
  const listRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = listRef.current;
    if (el) {
      el.scrollTop = el.scrollHeight;
    }
  }, [messages]);

  function getBanner(): { text: string; statusClass: string } {
    if (wsError) return { text: wsError, statusClass: "disconnected" };
    if (disconnected) return { text: "Disconnected", statusClass: "disconnected" };
    if (roomState === "waiting") {
      return {
        text: peerLeftNotice ? "Peer left · Waiting for peer…" : "Waiting for peer…",
        statusClass: "waiting",
      };
    }
    if (sessionStatus === "negotiating") {
      return {
        text: `Negotiating key exchange with ${peerName ?? "peer"}…`,
        statusClass: "negotiating",
      };
    }
    if (sessionStatus === "established") {
      return {
        text: `Secure session with ${peerName ?? "peer"}`,
        statusClass: "established",
      };
    }
    if (sessionStatus === "failed") {
      return {
        text: `Key exchange failed (${failureReason ?? "error"})`,
        statusClass: "failed",
      };
    }
    if (sessionStatus === "terminated") {
      return {
        text: `Session ended (${terminationReason ?? "disconnected"})`,
        statusClass: "terminated",
      };
    }
    return { text: "Connected", statusClass: "paired" };
  }

  function handleSend(e: FormEvent) {
    e.preventDefault();
    const text = draft.trim();
    if (!text || !isChatAllowed) return;
    onSend(text);
    setDraft("");
  }

  const isConnectionDown = disconnected || Boolean(wsError);
  const isChatAllowed =
    sessionStatus === "established" && !isConnectionDown && roomState === "paired";

  const { text: bannerText, statusClass } = getBanner();

  return (
    <div className="page chat-page">
      <header className="chat-header">
        <div>
          <h1>CipherChat</h1>
          <p className="you-are">Logged in as {username}</p>
        </div>
        <div className="header-actions">
          <div className={`status-banner ${statusClass}`} role="status">
            {bannerText}
          </div>
          <button
            type="button"
            className="btn secondary logout-btn"
            onClick={onLogout}
          >
            Logout
          </button>
        </div>
      </header>

      {/* Session established details bar */}
      {sessionStatus === "established" && fingerprint && (
        <div className="session-info-bar">
          <div className="session-banner-row">
            <div className="fingerprint-display">
              <span className="fingerprint-label">Key Fingerprint:</span>
              <code className="fingerprint-code">{fingerprint}</code>
            </div>
          </div>
          <details className="key-details-toggle">
            <summary>Key details (demo only)</summary>
            <div className="key-details-content">
              <div className="detail-item">
                <span className="detail-label">Session ID:</span>
                <code className="detail-val">{sessionId}</code>
              </div>
              <div className="detail-item">
                <span className="detail-label">Role:</span>
                <span className="detail-val">{role}</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Peer:</span>
                <span className="detail-val">{peerName}</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Keygen:</span>
                <span className="detail-val">{timings.keygen_ms} ms</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Derive:</span>
                <span className="detail-val">{timings.derive_ms} ms</span>
              </div>
              <p className="crypto-explainer">
                Diffie-Hellman RFC 3526 Group 14 (2048-bit MODP safe prime) + HKDF-SHA256 (RFC 5869).
                Private exponents and shared secrets never leave your browser. Server acts solely as a blind relay.
              </p>
            </div>
          </details>
        </div>
      )}

      {/* Re-negotiation banner if session ended or failed while peer still in room */}
      {!isConnectionDown &&
        roomState === "paired" &&
        (sessionStatus === "failed" || sessionStatus === "terminated") && (
          <div className={`session-alert ${sessionStatus}`}>
            <div>
              <strong>
                {sessionStatus === "failed"
                  ? "Handshake failed: " + (failureReason ?? "unknown")
                  : "Session terminated: " + (terminationReason ?? "disconnected")}
              </strong>
              <p style={{ margin: "0.25rem 0 0", fontSize: "0.85rem" }}>
                Both users are still in the room. You can initiate a new secure session.
              </p>
            </div>
            <button
              type="button"
              className="btn primary"
              onClick={onRequestSession}
            >
              Start New Session
            </button>
          </div>
        )}

      {isConnectionDown ? (
        <div className="disconnected-panel">
          <p>{wsError ?? "Connection closed unexpectedly."}</p>
          <div className="btn-row">
            <button type="button" className="btn primary" onClick={onReconnect}>
              Reconnect
            </button>
            <button type="button" className="btn secondary" onClick={onLogout}>
              Log Out
            </button>
          </div>
        </div>
      ) : (
        <>
          <div className="message-list" ref={listRef}>
            {messages.length === 0 ? (
              <p className="empty-hint">
                {sessionStatus === "negotiating"
                  ? "Negotiating Diffie-Hellman keys…"
                  : sessionStatus === "established"
                  ? "No messages yet. Chat is secure."
                  : "Waiting for secure session…"}
              </p>
            ) : (
              messages.map((m) => (
                <div
                  key={m.id}
                  className={`bubble-row ${m.mine ? "mine" : "theirs"}`}
                >
                  <div className="bubble">
                    <span className="bubble-meta">
                      {m.mine ? "You" : m.sender.username}
                    </span>
                    <p className="bubble-text">{m.text}</p>
                  </div>
                </div>
              ))
            )}
          </div>

          <form className="composer" onSubmit={handleSend}>
            <input
              className="text-input"
              type="text"
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              placeholder={
                sessionStatus === "negotiating"
                  ? "Negotiating keys with peer…"
                  : isChatAllowed
                  ? "Type a message…"
                  : "Waiting for secure session…"
              }
              maxLength={2000}
              disabled={!isChatAllowed}
              autoComplete="off"
            />
            <button
              type="submit"
              className="btn primary"
              disabled={!isChatAllowed || !draft.trim()}
            >
              Send
            </button>
          </form>
        </>
      )}
    </div>
  );
}
