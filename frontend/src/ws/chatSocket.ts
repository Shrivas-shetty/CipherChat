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

export type OutgoingDhPublic = {
  v: 1;
  type: "dh_public";
  session_id: string;
  public: string;
};

export type OutgoingKeyConfirm = {
  v: 1;
  type: "key_confirm";
  session_id: string;
  tag: string;
};

export type OutgoingKeyVerified = {
  v: 1;
  type: "key_verified";
  session_id: string;
  fingerprint: string;
  timings?: { keygen_ms: number; derive_ms: number };
};

export type OutgoingKeyFailed = {
  v: 1;
  type: "key_failed";
  session_id: string;
  reason: "bad_public" | "key_confirm_failed" | string;
};

export type OutgoingRequestSession = {
  v: 1;
  type: "request_session";
};

export type OutgoingFrame =
  | OutgoingAuth
  | OutgoingChat
  | OutgoingDhPublic
  | OutgoingKeyConfirm
  | OutgoingKeyVerified
  | OutgoingKeyFailed
  | OutgoingRequestSession;

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

export type IncomingSessionStart = {
  v: 1;
  type: "session_start";
  session_id: string;
  role: "initiator" | "responder";
  peer: { user_id: string; username: string };
  dh: { group: string; g: number };
};

export type IncomingDhPublic = {
  v: 1;
  type: "dh_public";
  session_id: string;
  from_role: "initiator" | "responder";
  public: string;
};

export type IncomingKeyConfirm = {
  v: 1;
  type: "key_confirm";
  session_id: string;
  from_role: "initiator" | "responder";
  tag: string;
};

export type IncomingSessionEstablished = {
  v: 1;
  type: "session_established";
  session_id: string;
  fingerprint: string;
};

export type IncomingSessionTerminated = {
  v: 1;
  type: "session_terminated";
  session_id: string;
  reason: string;
};

export type IncomingMessageAvailable = {
  v: 1;
  type: "message_available";
  session_id: string;
  message_id: number;
  from_role: "I" | "R";
  counter: number;
  msg_type?: "text" | "image";
};

export type IncomingMessageStatus = {
  v: 1;
  type: "message_status";
  session_id: string;
  message_id: number;
  counter: number;
  status: "verified" | "failed";
  reason?: string;
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
    | "NO_SESSION"
    | "BAD_SESSION"
    | string;
  message: string;
};

export type IncomingFrame =
  | IncomingJoined
  | IncomingStatus
  | IncomingSessionStart
  | IncomingDhPublic
  | IncomingKeyConfirm
  | IncomingSessionEstablished
  | IncomingSessionTerminated
  | IncomingMessageAvailable
  | IncomingMessageStatus
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

  requestSession(): void {
    this.send({
      v: PROTOCOL_VERSION,
      type: "request_session",
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
