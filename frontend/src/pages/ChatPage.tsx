import { useEffect, useRef, useState, type FormEvent } from "react";

export type ChatMessage = {
  id: string;
  text: string;
  ts: string;
  sender: { user_id: string; display_name: string };
  mine: boolean;
};

type RoomState = "waiting" | "paired";

type Props = {
  displayName: string;
  roomState: RoomState;
  peerName: string | null;
  peerLeftNotice: boolean;
  messages: ChatMessage[];
  disconnected: boolean;
  onSend: (text: string) => void;
  onReconnect: () => void;
};

export function ChatPage({
  displayName,
  roomState,
  peerName,
  peerLeftNotice,
  messages,
  disconnected,
  onSend,
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
    if (!text || disconnected) return;
    onSend(text);
    setDraft("");
  }

  return (
    <div className="page chat-page">
      <header className="chat-header">
        <div>
          <h1>CipherChat</h1>
          <p className="you-are">You are {displayName}</p>
        </div>
        <div
          className={`status-banner ${disconnected ? "disconnected" : roomState}`}
          role="status"
        >
          {bannerText()}
        </div>
      </header>

      {disconnected ? (
        <div className="disconnected-panel">
          <p>Connection closed unexpectedly.</p>
          <button type="button" className="btn primary" onClick={onReconnect}>
            Reconnect
          </button>
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
                      {m.mine ? "You" : m.sender.display_name}
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
              disabled={disconnected}
              autoComplete="off"
            />
            <button
              type="submit"
              className="btn primary"
              disabled={disconnected || !draft.trim()}
            >
              Send
            </button>
          </form>
        </>
      )}
    </div>
  );
}
