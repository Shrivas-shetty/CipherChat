import { useEffect, useRef, useState } from "react";
import {
  loadServerAddress,
  saveServerAddress,
  type ServerAddress,
} from "./config/serverAddress";
import { ChatPage, type ChatMessage } from "./pages/ChatPage";
import { ConnectPage } from "./pages/ConnectPage";
import { ChatSocket, type IncomingFrame } from "./ws/chatSocket";

type Screen = "connect" | "chat";

export default function App() {
  const [screen, setScreen] = useState<Screen>("connect");
  const [serverAddress, setServerAddress] = useState<ServerAddress>(() =>
    loadServerAddress()
  );
  const [joining, setJoining] = useState(false);
  const [connectError, setConnectError] = useState<string | null>(null);

  const [displayName, setDisplayName] = useState("");
  const [userId, setUserId] = useState("");
  const [roomState, setRoomState] = useState<"waiting" | "paired">("waiting");
  const [peerName, setPeerName] = useState<string | null>(null);
  const [peerLeftNotice, setPeerLeftNotice] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [disconnected, setDisconnected] = useState(false);

  const socketRef = useRef<ChatSocket | null>(null);
  const intentionalCloseRef = useRef(false);
  const pendingNameRef = useRef<string | null>(null);
  const screenRef = useRef<Screen>(screen);
  const userIdRef = useRef(userId);

  useEffect(() => {
    screenRef.current = screen;
  }, [screen]);

  useEffect(() => {
    userIdRef.current = userId;
  }, [userId]);

  useEffect(() => {
    const socket = new ChatSocket();
    socketRef.current = socket;

    socket.setHandlers({
      onOpen: () => {
        const name = pendingNameRef.current;
        if (name) {
          socket.join(name);
        }
      },
      onClose: () => {
        setJoining(false);
        if (intentionalCloseRef.current) {
          intentionalCloseRef.current = false;
          return;
        }
        if (screenRef.current === "chat" || pendingNameRef.current) {
          setDisconnected(true);
          setScreen("chat");
        } else {
          setConnectError((prev) => prev ?? "Could not connect to server.");
        }
      },
      onFrame: (frame: IncomingFrame) => {
        switch (frame.type) {
          case "joined":
            setDisplayName(frame.display_name);
            setUserId(frame.user_id);
            userIdRef.current = frame.user_id;
            setJoining(false);
            setConnectError(null);
            setDisconnected(false);
            setScreen("chat");
            break;
          case "status":
            setRoomState(frame.state);
            setPeerName(frame.peer?.display_name ?? null);
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
                mine: frame.sender.user_id === userIdRef.current,
              },
            ]);
            break;
          case "peer_left":
            setPeerLeftNotice(true);
            setPeerName(null);
            break;
          case "error":
            if (frame.code === "ROOM_FULL" || frame.code === "NAME_TAKEN") {
              setJoining(false);
              setConnectError(`${frame.code}: ${frame.message}`);
              setScreen("connect");
              intentionalCloseRef.current = true;
              socket.close();
            } else if (frame.code === "NOT_JOINED") {
              setJoining(false);
              setConnectError(`${frame.code}: ${frame.message}`);
              setScreen("connect");
            }
            break;
          default:
            break;
        }
      },
    });

    return () => {
      intentionalCloseRef.current = true;
      socket.close();
      socketRef.current = null;
    };
  }, []);

  function handleServerAddressChange(addr: ServerAddress) {
    setServerAddress(addr);
    saveServerAddress(addr);
  }

  function resetChatState() {
    setUserId("");
    userIdRef.current = "";
    setRoomState("waiting");
    setPeerName(null);
    setPeerLeftNotice(false);
    setMessages([]);
    setDisconnected(false);
  }

  function onJoin(name: string) {
    setConnectError(null);
    setJoining(true);
    resetChatState();
    setDisplayName(name);
    pendingNameRef.current = name;
    intentionalCloseRef.current = false;

    const socket = socketRef.current;
    if (!socket) {
      setJoining(false);
      setConnectError("Socket not available");
      return;
    }
    socket.connect(serverAddress);
  }

  function onSend(text: string) {
    try {
      socketRef.current?.chat(text);
    } catch {
      setDisconnected(true);
    }
  }

  function onReconnect() {
    intentionalCloseRef.current = true;
    socketRef.current?.close();
    resetChatState();
    setScreen("connect");
    setJoining(false);
    setConnectError(null);
    pendingNameRef.current = null;
  }

  if (screen === "chat" && (userId || disconnected)) {
    return (
      <ChatPage
        displayName={displayName}
        roomState={roomState}
        peerName={peerName}
        peerLeftNotice={peerLeftNotice}
        messages={messages}
        disconnected={disconnected}
        onSend={onSend}
        onReconnect={onReconnect}
      />
    );
  }

  return (
    <ConnectPage
      serverAddress={serverAddress}
      onServerAddressChange={handleServerAddressChange}
      onJoin={onJoin}
      joining={joining}
      error={connectError}
    />
  );
}
