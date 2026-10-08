import { useEffect, useRef, useState } from "react";
import { AuthProvider, useAuth } from "./auth/AuthContext";
import { messageService } from "./chat/messageService";
import type { ChatMessage } from "./chat/types";
import {
  loadServerAddress,
  saveServerAddress,
  type ServerAddress,
} from "./config/serverAddress";
import {
  HandshakeRunner,
  type HandshakeStatus,
  type HandshakeTimings,
} from "./crypto/handshake";
import { clearSessionKeys } from "./crypto/sessionKeys";
import { AnalystPage } from "./pages/AnalystPage";
import { AuthPage } from "./pages/AuthPage";
import { ChatPage } from "./pages/ChatPage";
import { ChatSocket, type IncomingFrame } from "./ws/chatSocket";

function MainApp() {
  const { user, token, loading, logout, setAuthError } = useAuth();
  const [serverAddress, setServerAddress] = useState<ServerAddress>(() =>
    loadServerAddress()
  );

  const [roomState, setRoomState] = useState<"waiting" | "paired">("waiting");
  const [peerName, setPeerName] = useState<string | null>(null);
  const [peerLeftNotice, setPeerLeftNotice] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [disconnected, setDisconnected] = useState(false);
  const [wsError, setWsError] = useState<string | null>(null);

  // Phase 3 Session & Crypto State
  const [sessionStatus, setSessionStatus] = useState<HandshakeStatus>("idle");
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [sessionRole, setSessionRole] = useState<
    "initiator" | "responder" | null
  >(null);
  const [fingerprint, setFingerprint] = useState<string | null>(null);
  const [timings, setTimings] = useState<HandshakeTimings>({
    keygen_ms: 0,
    derive_ms: 0,
  });
  const [failureReason, setFailureReason] = useState<string | null>(null);
  const [terminationReason, setTerminationReason] = useState<string | null>(
    null
  );

  const socketRef = useRef<ChatSocket | null>(null);
  const handshakeRef = useRef<HandshakeRunner | null>(null);
  const intentionalCloseRef = useRef(false);
  const peerNameRef = useRef<string | null>(null);
  const sessionRoleRef = useRef<"initiator" | "responder" | null>(null);

  // Subscribe to messageService updates
  useEffect(() => {
    const unsub = messageService.subscribe((msgs) => {
      setMessages(msgs);
    });
    return () => unsub();
  }, []);

  function handleServerAddressChange(addr: ServerAddress) {
    setServerAddress(addr);
    saveServerAddress(addr);
  }

  function resetChatState() {
    setRoomState("waiting");
    setPeerName(null);
    peerNameRef.current = null;
    setPeerLeftNotice(false);
    setDisconnected(false);
    setWsError(null);

    // Reset messages and crypto & session state
    messageService.reset();
    handshakeRef.current?.reset();
    clearSessionKeys();
    setSessionStatus("idle");
    setSessionId(null);
    setSessionRole(null);
    sessionRoleRef.current = null;
    setFingerprint(null);
    setFailureReason(null);
    setTerminationReason(null);
    setTimings({ keygen_ms: 0, derive_ms: 0 });
  }

  // Initialize or keep HandshakeRunner callback reference updated
  useEffect(() => {
    if (!handshakeRef.current) {
      handshakeRef.current = new HandshakeRunner({
        sendFrame: (frame) => {
          try {
            socketRef.current?.send(frame);
          } catch {
            // Socket may have disconnected
          }
        },
        onStatusChange: (status) => {
          setSessionStatus(status);
          const hr = handshakeRef.current;
          if (hr) {
            setFingerprint(hr.fingerprint);
            setTimings({ ...hr.timings });
            setFailureReason(hr.failureReason);
            setTerminationReason(hr.terminationReason);
            setSessionRole(hr.role);
            sessionRoleRef.current = hr.role;
            setSessionId(hr.sessionId);
          }
        },
        onEstablished: (fp) => {
          setFingerprint(fp);
        },
        onFailed: (reason) => {
          setFailureReason(reason);
        },
        onTerminated: (reason) => {
          setTerminationReason(reason);
        },
      });
    }
  }, []);

  useEffect(() => {
    if (!token || user?.role !== "user") {
      intentionalCloseRef.current = true;
      socketRef.current?.close();
      socketRef.current = null;
      resetChatState();
      return;
    }

    const socket = new ChatSocket();
    socketRef.current = socket;
    intentionalCloseRef.current = false;
    resetChatState();

    socket.setHandlers({
      onOpen: () => {
        setDisconnected(false);
      },
      onClose: () => {
        if (intentionalCloseRef.current) {
          intentionalCloseRef.current = false;
          return;
        }
        setDisconnected(true);
        handshakeRef.current?.handleSessionTerminated("", "disconnect");
        clearSessionKeys();
      },
      onFrame: (frame: IncomingFrame) => {
        switch (frame.type) {
          case "joined":
            setDisconnected(false);
            setWsError(null);
            break;
          case "status":
            setRoomState(frame.state);
            {
              const name = frame.peer?.username ?? null;
              setPeerName(name);
              peerNameRef.current = name;
            }
            if (frame.state === "paired") {
              setPeerLeftNotice(false);
            }
            break;
          case "session_start":
            messageService.reset();
            peerNameRef.current = frame.peer.username;
            setPeerName(frame.peer.username);
            sessionRoleRef.current = frame.role;
            setSessionRole(frame.role);
            handshakeRef.current?.startSession(
              frame.session_id,
              frame.role,
              frame.peer
            );
            break;
          case "dh_public":
            handshakeRef.current?.handleDhPublic(
              frame.session_id,
              frame.public
            );
            break;
          case "key_confirm":
            handshakeRef.current?.handleKeyConfirm(
              frame.session_id,
              frame.tag
            );
            break;
          case "session_established":
            handshakeRef.current?.handleSessionEstablished(
              frame.session_id,
              frame.fingerprint
            );
            break;
          case "session_terminated":
            handshakeRef.current?.handleSessionTerminated(
              frame.session_id,
              frame.reason
            );
            clearSessionKeys();
            break;
          case "message_available":
            messageService.enqueueIncoming(
              frame.session_id,
              frame.message_id,
              frame.from_role,
              frame.counter,
              peerNameRef.current ?? "Peer"
            );
            break;
          case "message_status":
            messageService.handleMessageStatus(
              frame.message_id,
              frame.counter,
              frame.status,
              frame.reason
            );
            break;
          case "peer_left":
            handshakeRef.current?.handleSessionTerminated("", "disconnect");
            clearSessionKeys();
            messageService.reset();
            setPeerLeftNotice(true);
            setPeerName(null);
            peerNameRef.current = null;
            break;
          case "error":
            if (frame.code === "UNAUTHORIZED") {
              intentionalCloseRef.current = true;
              socket.close();
              void logout();
              setAuthError("Session expired, please log in again");
            } else if (frame.code === "ROOM_FULL") {
              intentionalCloseRef.current = true;
              setWsError("Chat room is full, only 2 users allowed");
            } else if (frame.code === "SUPERSEDED") {
              intentionalCloseRef.current = true;
              setWsError("You were signed in from another tab or device");
            } else if (frame.code === "FORBIDDEN_ROLE") {
              intentionalCloseRef.current = true;
              setWsError("Analysts cannot join the chat");
            } else if (frame.code === "NO_SESSION") {
              setWsError("No secure session established yet");
            } else {
              setWsError(`${frame.code}: ${frame.message}`);
            }
            break;
        }
      },
    });

    socket.connect(serverAddress, token);

    return () => {
      intentionalCloseRef.current = true;
      socket.close();
      socketRef.current = null;
      handshakeRef.current?.reset();
      clearSessionKeys();
      messageService.reset();
    };
  }, [token, user?.id, user?.role, serverAddress, logout, setAuthError]);

  async function onSend(text: string) {
    if (!user || !sessionRoleRef.current) {
      throw new Error("No active secure session");
    }
    const roleCode = sessionRoleRef.current === "initiator" ? "I" : "R";
    await messageService.sendText(text, user.username, roleCode);
  }

  function handleRequestSession() {
    try {
      socketRef.current?.requestSession();
    } catch {
      setDisconnected(true);
    }
  }

  function handleLogout() {
    intentionalCloseRef.current = true;
    socketRef.current?.close();
    handshakeRef.current?.reset();
    clearSessionKeys();
    messageService.reset();
    void logout();
  }

  function handleReconnect() {
    if (!token) return;
    setWsError(null);
    setDisconnected(false);
    intentionalCloseRef.current = false;
    socketRef.current?.connect(serverAddress, token);
  }

  if (loading) {
    return (
      <div className="page connect-page">
        <p className="loading-text">Loading session…</p>
      </div>
    );
  }

  if (!user || !token) {
    return (
      <AuthPage
        serverAddress={serverAddress}
        onServerAddressChange={handleServerAddressChange}
      />
    );
  }

  if (user.role === "analyst") {
    return <AnalystPage />;
  }

  return (
    <ChatPage
      username={user.username}
      roomState={roomState}
      peerName={peerName}
      peerLeftNotice={peerLeftNotice}
      messages={messages}
      disconnected={disconnected}
      wsError={wsError}
      sessionStatus={sessionStatus}
      sessionId={sessionId}
      role={sessionRole}
      fingerprint={fingerprint}
      timings={timings}
      failureReason={failureReason}
      terminationReason={terminationReason}
      onRequestSession={handleRequestSession}
      onSend={onSend}
      onLogout={handleLogout}
      onReconnect={handleReconnect}
    />
  );
}

export default function App() {
  return (
    <AuthProvider>
      <MainApp />
    </AuthProvider>
  );
}
