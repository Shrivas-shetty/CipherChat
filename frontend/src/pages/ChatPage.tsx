import { useEffect, useRef, useState, type FormEvent } from "react";
import type { ChatMessage } from "../chat/types";
import { messageService } from "../chat/messageService";
import type { HandshakeStatus, HandshakeTimings } from "../crypto/handshake";
import { decodeImage, type DecodedImage } from "../image/decode";
import { releaseObjectUrl, renderRgbPng } from "../image/render";

export type { ChatMessage };

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
  onSend: (text: string) => Promise<void> | void;
  onSendImage: (file: File, prepared?: DecodedImage) => Promise<void>;
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
  onSendImage,
  onLogout,
  onReconnect,
}: Props) {
  const [draft, setDraft] = useState("");
  const [sendError, setSendError] = useState<string | null>(null);
  const [isSending, setIsSending] = useState(false);
  const [selectedImage, setSelectedImage] = useState<File | null>(null);
  const [preparedImage, setPreparedImage] = useState<DecodedImage | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [imageError, setImageError] = useState<string | null>(null);
  const [showNoise, setShowNoise] = useState<Record<string, boolean>>({});
  const [lightbox, setLightbox] = useState<string | null>(null);
  const imageInput = useRef<HTMLInputElement>(null);
  const preparedRef = useRef<DecodedImage | null>(null);

  useEffect(() => () => {
    preparedRef.current?.rgb.fill(0);
    preparedRef.current = null;
    messageService.reset();
  }, []);

  useEffect(() => {
    if (sessionStatus === "terminated" || sessionStatus === "failed") {
      preparedRef.current?.rgb.fill(0);
      preparedRef.current = null;
      setPreparedImage(null); setPreviewUrl(null); setSelectedImage(null);
    }
  }, [sessionStatus]);

  function clearImagePreview() {
    preparedRef.current?.rgb.fill(0);
    preparedRef.current = null;
    releaseObjectUrl(previewUrl ?? undefined);
    setPreparedImage(null); setPreviewUrl(null); setSelectedImage(null); setImageError(null);
  }

  async function chooseImage(file: File | undefined) {
    clearImagePreview();
    if (!file) return;
    setSelectedImage(file); setImageError(null);
    try {
      const decoded = await decodeImage(file);
      preparedRef.current = decoded;
      setPreparedImage(decoded);
      setPreviewUrl(await renderRgbPng(decoded.rgb, decoded.w, decoded.h));
    } catch (err) {
      setImageError(err instanceof Error ? err.message : "Could not decode this image.");
    }
  }
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

  async function handleSend(e: FormEvent) {
    e.preventDefault();
    const text = draft.trim();
    if (!text || !isChatAllowed || isSending) return;
    setSendError(null);
    setIsSending(true);
    try {
      await onSend(text);
      setDraft("");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to send message";
      setSendError(msg);
    } finally {
      setIsSending(false);
    }
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
                End-to-end encrypted with AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC).
                Keys and plaintexts never touch server disk or network.
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
                  ? "No messages yet. Chat is end-to-end encrypted."
                  : "Waiting for secure session…"}
              </p>
            ) : (
              messages.map((m) => {
                const isMine = m.mine;
                const isFailed =
                  m.status === "received_failed" || m.status === "failed_at_peer";

                return (
                  <div
                    key={`${m.id}-${m.counter}`}
                    className={`bubble-row ${isMine ? "mine" : "theirs"}`}
                  >
                    <div
                      className={`bubble ${
                        m.status === "received_failed" ? "bubble-tampered" : ""
                      }`}
                    >
                      <div className="bubble-header">
                        <span className="bubble-meta">
                          {isMine ? "You" : m.senderUsername}
                        </span>
                        {m.ts && (
                          <span className="bubble-time">
                            {new Date(m.ts).toLocaleTimeString([], {
                              hour: "2-digit",
                              minute: "2-digit",
                            })}
                          </span>
                        )}
                      </div>

                      {m.image && !m.image.placeholder && m.image.url ? (
                        <div className="image-message">
                          <img className="chat-image" src={showNoise[m.id] ? m.image.noiseUrl : m.image.url} onClick={() => setLightbox(m.image?.url ?? null)} />
                          <div>{m.image.w} × {m.image.h}</div>
                          <button type="button" onClick={() => setShowNoise((v) => ({ ...v, [m.id]: !v[m.id] }))}>{showNoise[m.id] ? "Show decrypted image" : "Show encrypted view"}</button>
                          {!isMine && <a href={m.image.url} download="cipherchat-image.png">Save PNG</a>}
                        </div>
                      ) : m.image?.placeholder ? <p className="tampered-text">[image could not be verified, not decrypted]</p> : (
                      m.status === "received_failed" ? (
                        <p className="bubble-text tampered-text">
                          ⚠️ [message could not be verified, not decrypted]
                        </p>
                      ) : (
                        <p className="bubble-text">{m.text}</p>
                      ))}

                      {/* Status Badge */}
                      <div className="bubble-footer">
                        {isMine ? (
                          <span className={`msg-status ${m.status}`}>
                            {m.status === "sending" && "Sending…"}
                            {m.status === "sent" && "Sent"}
                            {m.status === "verified_by_peer" && "✓ Verified by peer"}
                            {m.status === "failed_at_peer" &&
                              `✗ Integrity failed at peer (${
                                m.failureReason || "error"
                              })`}
                          </span>
                        ) : (
                          <span className={`msg-status ${m.status}`}>
                            {m.status === "received_verified" &&
                              "🛡️ Integrity verified"}
                            {m.status === "received_failed" &&
                              `⚠️ Integrity FAILED (${
                                m.failureReason || "error"
                              })`}
                          </span>
                        )}
                      </div>

                      {/* Collapsible Wire View (Demo Only) */}
                      {m.wire && (
                        <details className="wire-details">
                          <summary>Wire view (demo only)</summary>
                          <div className="wire-content">
                            <div className="wire-header-label">
                              What the server and Wireshark see
                            </div>
                            {m.image && <div className="wire-image-info">{m.image.w} × {m.image.h}, {m.image.plaintextBytes} plaintext bytes, {m.wire.ctLength} ciphertext bytes, {m.image.overheadBytes} bytes overhead<br/>Decode: {m.image.decodeMs ?? "—"} ms · Encrypt/verify: {m.image.cryptoMs ?? "—"} ms<br/>PIXEL HASH: {m.image.pixelHash || "unavailable"}</div>}
                            <div className="wire-table">
                              <div className="wire-row">
                                <span className="wire-key">Counter:</span>
                                <code className="wire-val">{m.wire.counter}</code>
                              </div>
                              <div className="wire-row">
                                <span className="wire-key">IV (16B):</span>
                                <code className="wire-val wire-mono">
                                  {m.wire.ivHex}
                                </code>
                              </div>
                              <div className="wire-row">
                                <span className="wire-key">Ciphertext:</span>
                                <code
                                  className="wire-val wire-mono"
                                  title={m.wire.ctHex}
                                >
                                  {m.wire.ctHex.length > 64
                                    ? `${m.wire.ctHex.slice(0, 64)}…`
                                    : m.wire.ctHex}{" "}
                                  ({m.wire.ctLength} bytes)
                                </code>
                              </div>
                              <div className="wire-row">
                                <span className="wire-key">HMAC (32B):</span>
                                <code className="wire-val wire-mono">
                                  {m.wire.hmacHex}
                                </code>
                              </div>
                              <div className="wire-row">
                                <span className="wire-key">Latency:</span>
                                <span className="wire-val">
                                  {m.wire.latencyMs} ms
                                </span>
                              </div>
                              <div className="wire-row">
                                <span className="wire-key">Verification:</span>
                                <span
                                  className={`wire-val ${
                                    m.wire.verified
                                      ? "verified-text"
                                      : isFailed
                                      ? "failed-text"
                                      : ""
                                  }`}
                                >
                                  {m.wire.verified
                                    ? "Verified (HMAC valid)"
                                    : m.wire.reason
                                    ? `Failed (${m.wire.reason})`
                                    : isMine
                                    ? m.status === "verified_by_peer"
                                      ? "Verified by peer"
                                      : m.status === "failed_at_peer"
                                      ? `Failed at peer (${m.failureReason})`
                                      : "Awaiting peer confirmation"
                                    : "Pending"}
                                </span>
                              </div>
                            </div>
                          </div>
                        </details>
                      )}
                    </div>
                  </div>
                );
              })
            )}
          </div>

          {sendError && (
            <div className="send-error-bar" role="alert">
              <span>⚠️ {sendError}</span>
              <button
                type="button"
                className="btn-dismiss"
                onClick={() => setSendError(null)}
                aria-label="Dismiss error"
              >
                ×
              </button>
            </div>
          )}

          {imageError && <p className="msg err">{imageError}</p>}
          {selectedImage && <div className="image-preview-strip">{previewUrl && <img width="96" height="72" src={previewUrl} alt="Processed image preview" />}<span>{preparedImage ? `${preparedImage.w} × ${preparedImage.h} · ${preparedImage.rgb.length} bytes` : selectedImage.name}</span><button type="button" onClick={clearImagePreview}>Cancel</button><button type="button" disabled={!isChatAllowed || isSending || !preparedImage} onClick={async () => { setIsSending(true); await new Promise<void>((resolve) => requestAnimationFrame(() => resolve())); try { await onSendImage(selectedImage, preparedImage ?? undefined); clearImagePreview(); } catch (err) { setSendError(err instanceof Error ? err.message : "Image send failed"); } finally { setIsSending(false); } }}>{isSending ? "Encrypting…" : "Send"}</button></div>}
          <form className="composer" onSubmit={handleSend}>
            <input
              className="text-input"
              type="text"
              value={draft}
              onChange={(e) => {
                setDraft(e.target.value);
                if (sendError) setSendError(null);
              }}
              placeholder={
                sessionStatus === "negotiating"
                  ? "Negotiating keys with peer…"
                  : isChatAllowed
                  ? "Type an encrypted message…"
                  : "Waiting for secure session…"
              }
              maxLength={2000}
              disabled={!isChatAllowed || isSending}
              autoComplete="off"
            />
            <button
              type="submit"
              className="btn primary"
              disabled={!isChatAllowed || !draft.trim() || isSending}
            >
              {isSending ? "Sending…" : "Send"}
            </button>
            <input ref={imageInput} type="file" hidden accept="image/png,image/jpeg,image/webp,image/gif" onChange={(e) => { void chooseImage(e.target.files?.[0]); e.currentTarget.value = ""; }} />
            <button type="button" disabled={!isChatAllowed || isSending} onClick={() => imageInput.current?.click()}>Attach image</button>
          </form>
          {lightbox && <div className="image-lightbox" onClick={() => setLightbox(null)}><button type="button" onClick={() => setLightbox(null)}>Close</button><img src={lightbox} /></div>}
        </>
      )}
    </div>
  );
}
