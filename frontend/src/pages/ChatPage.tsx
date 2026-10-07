import { useEffect, useRef, useState, type FormEvent } from "react";

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

  function bannerText(): string {
    if (wsError) return wsError;
    if (disconnected) return "Disconnected";
    if (roomState === "paired" && peerName) {
      return `Connected to ${peerName}`;
    }
    if (peerLeftNotice && roomState === "waiting") {
      return "Peer left · Waiting for User B…";
    }
    if (roomState === "waiting") return "Waiting for User B…";
    return "Connected";
  }

  function handleSend(e: FormEvent) {
    e.preventDefault();
    const text = draft.trim();
    if (!text || disconnected || wsError) return;
    onSend(text);
    setDraft("");
  }

  const isBlocked = disconnected || Boolean(wsError);

  return (
    <div className="page chat-page">
      <header className="chat-header">
        <div>
          <h1>CipherChat</h1>
          <p className="you-are">Logged in as {username}</p>
        </div>
        <div className="header-actions">
          <div
            className={`status-banner ${isBlocked ? "disconnected" : roomState}`}
            role="status"
          >
            {bannerText()}
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

      {isBlocked ? (
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
              <p className="empty-hint">No messages yet.</p>
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
              placeholder="Type a message…"
              maxLength={2000}
              disabled={isBlocked}
              autoComplete="off"
            />
            <button
              type="submit"
              className="btn primary"
              disabled={isBlocked || !draft.trim()}
            >
              Send
            </button>
          </form>
        </>
      )}
    </div>
  );
}
