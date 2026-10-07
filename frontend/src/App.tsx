import { useEffect, useRef, useState } from "react";
import { AuthProvider, useAuth } from "./auth/AuthContext";
import {
  loadServerAddress,
  saveServerAddress,
  type ServerAddress,
} from "./config/serverAddress";
import { AnalystPage } from "./pages/AnalystPage";
import { AuthPage } from "./pages/AuthPage";
import { ChatPage, type ChatMessage } from "./pages/ChatPage";
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

  const socketRef = useRef<ChatSocket | null>(null);
  const intentionalCloseRef = useRef(false);

  function handleServerAddressChange(addr: ServerAddress) {
    setServerAddress(addr);
    saveServerAddress(addr);
  }

  function resetChatState() {
    setRoomState("waiting");
    setPeerName(null);
    setPeerLeftNotice(false);
    setMessages([]);
    setDisconnected(false);
    setWsError(null);
  }

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
      },
      onFrame: (frame: IncomingFrame) => {
        switch (frame.type) {
          case "joined":
            setDisconnected(false);
            setWsError(null);
            break;
          case "status":
            setRoomState(frame.state);
            setPeerName(frame.peer?.username ?? null);
            if (frame.state === "paired") {
              setPeerLeftNotice(false);
            }
            break;
          case "chat":
            setMessages((prev) => [
              ...prev,
              {
                id: frame.id,
                text: frame.text,
                ts: frame.ts,
                sender: frame.sender,
                mine: frame.sender.user_id === user.id.toString(),
              },
            ]);
            break;
          case "peer_left":
            setPeerLeftNotice(true);
            setPeerName(null);
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
    };
  }, [token, user?.id, user?.role, serverAddress, logout, setAuthError]);

  function onSend(text: string) {
    try {
      socketRef.current?.chat(text);
    } catch {
      setDisconnected(true);
    }
  }

  function handleLogout() {
    intentionalCloseRef.current = true;
    socketRef.current?.close();
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
