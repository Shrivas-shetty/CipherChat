export interface WireDetails {
  counter: number;
  ivHex: string;
  ctHex: string;
  ctLength: number;
  hmacHex: string;
  latencyMs: number;
  verified: boolean;
  reason?: string;
}

export type MessageStatus =
  | "sending"
  | "sent"
  | "verified_by_peer"
  | "failed_at_peer"
  | "received_verified"
  | "received_failed";

export interface ChatMessage {
  id: string; // server ID or local temp ID
  counter: number;
  senderRole: "I" | "R";
  mine: boolean;
  senderUsername: string;
  text: string;
  status: MessageStatus;
  failureReason?: string;
  ts: string;
  wire?: WireDetails;
}

