import { wsUrl, type ServerAddress } from "../config/serverAddress";

export const PROTOCOL_VERSION = 1;

export type OutgoingAuth = {
  v: 1;
  type: "auth";
  token: string;
};

export type OutgoingChat = {
  v: 1;
  type: "chat";
  text: string;
};

export type OutgoingFrame = OutgoingAuth | OutgoingChat;

export type IncomingJoined = {
  v: 1;
  type: "joined";
  user_id: string;
  username: string;
};

export type IncomingStatus = {
  v: 1;
  type: "status";
  state: "waiting" | "paired";
  peer: { username: string } | null;
};

export type IncomingChat = {
  v: 1;
  type: "chat";
  id: string;
  sender: { user_id: string; username: string };
  text: string;
  ts: string;
};

export type IncomingPeerLeft = {
  v: 1;
  type: "peer_left";
  username: string;
};

export type IncomingError = {
  v: 1;
  type: "error";
  code:
    | "UNAUTHORIZED"
    | "FORBIDDEN_ROLE"
    | "ROOM_FULL"
    | "SUPERSEDED"
    | "BAD_FRAME"
    | string;
  message: string;
};

export type IncomingFrame =
  | IncomingJoined
  | IncomingStatus
  | IncomingChat
  | IncomingPeerLeft
  | IncomingError;

export type ChatSocketHandlers = {
  onOpen?: () => void;
  onClose?: (event: CloseEvent) => void;
  onError?: (event: Event) => void;
  onFrame?: (frame: IncomingFrame) => void;
};

export class ChatSocket {
  private socket: WebSocket | null = null;
  private handlers: ChatSocketHandlers = {};

  setHandlers(handlers: ChatSocketHandlers): void {
    this.handlers = handlers;
  }

  get readyState(): number {
    return this.socket?.readyState ?? WebSocket.CLOSED;
  }

  connect(addr: ServerAddress, token: string): void {
    this.close();
    const socket = new WebSocket(wsUrl(addr));
    this.socket = socket;

    socket.onopen = () => {
      // Immediately authenticate upon connection opening
      try {
        socket.send(
          JSON.stringify({
            v: PROTOCOL_VERSION,
            type: "auth",
            token,
          })
        );
      } catch {
        // Socket may have closed immediately
      }
      this.handlers.onOpen?.();
    };

    socket.onclose = (event) => {
      this.handlers.onClose?.(event);
    };

    socket.onerror = (event) => {
      this.handlers.onError?.(event);
    };

    socket.onmessage = (event) => {
      try {
        const data = JSON.parse(String(event.data)) as IncomingFrame;
        if (
          data &&
          typeof data === "object" &&
          data.v === PROTOCOL_VERSION &&
          typeof data.type === "string"
        ) {
          this.handlers.onFrame?.(data);
        }
      } catch {
        // ignore non-JSON or unsupported frames
      }
    };
  }

  send(frame: OutgoingFrame): void {
    if (!this.socket || this.socket.readyState !== WebSocket.OPEN) {
      throw new Error("WebSocket is not open");
    }
    this.socket.send(JSON.stringify(frame));
  }

  chat(text: string): void {
    this.send({
      v: PROTOCOL_VERSION,
      type: "chat",
      text,
    });
  }

  close(): void {
    if (this.socket) {
      this.socket.onopen = null;
      this.socket.onclose = null;
      this.socket.onerror = null;
      this.socket.onmessage = null;
      if (
        this.socket.readyState === WebSocket.OPEN ||
        this.socket.readyState === WebSocket.CONNECTING
      ) {
        this.socket.close();
      }
      this.socket = null;
    }
  }
}
