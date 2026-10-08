import { requestJson } from "../api/http";
import { base64ToBytes } from "../crypto/base64";
import { bytesToHex } from "../crypto/encoding";
import {
  EnvelopeError,
  encryptText,
  envelopeToWire,
  verifyAndDecrypt,
} from "../crypto/envelope";
import { ReplayGuard } from "../crypto/replayGuard";
import { getSessionKeys } from "../crypto/sessionKeys";
import type { ChatMessage, WireDetails } from "./types";

interface GetMessageResponse {
  id: number;
  session_id: string;
  from_role: "I" | "R";
  msg_type: string;
  counter: number;
  meta_json: string;
  iv: string;
  ct: string;
  hmac: string;
  created_at: string;
}

interface QueueItem {
  sessionId: string;
  messageId: number;
  fromRole: "I" | "R";
  counter: number;
  peerUsername: string;
}

export type MessagesListener = (messages: ChatMessage[]) => void;

export class MessageService {
  private messages: ChatMessage[] = [];
  private sendCounter: number = 0;
  private replayGuard: ReplayGuard = new ReplayGuard();
  private queue: QueueItem[] = [];
  private isProcessingQueue: boolean = false;
  private listeners: Set<MessagesListener> = new Set();

  public subscribe(listener: MessagesListener): () => void {
    this.listeners.add(listener);
    listener([...this.messages]);
    return () => {
      this.listeners.delete(listener);
    };
  }

  private notify(): void {
    const copy = [...this.messages];
    for (const l of this.listeners) {
      l(copy);
    }
  }

  public getMessages(): ChatMessage[] {
    return [...this.messages];
  }

  public reset(): void {
    this.messages = [];
    this.sendCounter = 0;
    this.replayGuard.reset();
    this.queue = [];
    this.isProcessingQueue = false;
    this.notify();
  }

  /**
   * Encrypts and sends a plaintext message via POST /api/messages.
   * Throws if no secure session is established or if request fails.
   */
  public async sendText(
    text: string,
    currentUsername: string,
    senderRole: "I" | "R"
  ): Promise<ChatMessage> {
    const keys = getSessionKeys();
    if (!keys) {
      throw new Error("No established secure session");
    }

    this.sendCounter += 1;
    const counter = this.sendCounter;

    const t0 = performance.now();
    const env = encryptText(
      keys.kEnc,
      keys.kMac,
      keys.sessionId,
      senderRole,
      counter,
      text
    );
    const latencyMs = Math.round((performance.now() - t0) * 100) / 100;

    const wireBody = envelopeToWire(env);
    const res = await requestJson<{ id: number; created_at: string }>(
      "/api/messages",
      {
        method: "POST",
        body: JSON.stringify(wireBody),
      }
    );

    const wire: WireDetails = {
      counter,
      ivHex: bytesToHex(env.iv),
      ctHex: bytesToHex(env.ct),
      ctLength: env.ct.length,
      hmacHex: bytesToHex(env.hmac),
      latencyMs,
      verified: false,
    };

    const myMsg: ChatMessage = {
      id: String(res.id),
      counter,
      senderRole,
      mine: true,
      senderUsername: currentUsername,
      text,
      status: "sent",
      ts: res.created_at,
      wire,
    };

    this.messages.push(myMsg);
    this.notify();
    return myMsg;
  }

  /**
   * Enqueues a notification to fetch and verify an incoming message.
   * Messages are processed strictly one at a time via a serial queue.
   */
  public enqueueIncoming(
    sessionId: string,
    messageId: number,
    fromRole: "I" | "R",
    counter: number,
    peerUsername: string
  ): void {
    this.queue.push({
      sessionId,
      messageId,
      fromRole,
      counter,
      peerUsername,
    });
    void this.processQueue();
  }

  private async processQueue(): Promise<void> {
    if (this.isProcessingQueue) {
      return;
    }
    this.isProcessingQueue = true;

    while (this.queue.length > 0) {
      const item = this.queue.shift()!;
      try {
        await this.handleSingleIncoming(item);
      } catch (err) {
        console.error("Error processing incoming message queue item", err);
      }
    }

    this.isProcessingQueue = false;
  }

  private async handleSingleIncoming(item: QueueItem): Promise<void> {
    const keys = getSessionKeys();
    if (!keys || keys.sessionId.toLowerCase() !== item.sessionId.toLowerCase()) {
      return;
    }

    // 1. Fetch message envelope from server
    const res = await requestJson<GetMessageResponse>(
      `/api/messages/${item.messageId}`
    );

    // 2. Strict pipeline: format -> replay -> HMAC -> decrypt
    let iv: Uint8Array = new Uint8Array();
    let ct: Uint8Array = new Uint8Array();
    let hmac: Uint8Array = new Uint8Array();
    let verified = false;
    let failureReason: string | undefined = undefined;
    let decryptedText = "";
    let latencyMs = 0;

    const t0 = performance.now();
    try {
      iv = base64ToBytes(res.iv);
      ct = base64ToBytes(res.ct);
      hmac = base64ToBytes(res.hmac);

      decryptedText = verifyAndDecrypt(
        keys.kEnc,
        keys.kMac,
        item.sessionId,
        item.fromRole,
        {
          session_id: res.session_id,
          sender_role: res.from_role,
          counter: res.counter,
          msg_type: res.msg_type,
          meta_json: res.meta_json,
          iv,
          ct,
          hmac,
        },
        this.replayGuard.getLast(item.fromRole)
      );

      this.replayGuard.commit(item.fromRole, res.counter);
      verified = true;
    } catch (err) {
      if (err instanceof EnvelopeError) {
        failureReason = err.reason;
      } else {
        failureReason = "decrypt_error";
      }
    }
    latencyMs = Math.round((performance.now() - t0) * 100) / 100;

    // 3. Report verification result to server
    try {
      await requestJson(`/api/messages/${item.messageId}/verification`, {
        method: "POST",
        body: JSON.stringify({
          status: verified ? "verified" : "failed",
          reason: verified ? undefined : failureReason,
        }),
      });
    } catch (reportErr) {
      console.warn("Failed to report message verification to server", reportErr);
    }

    // 4. Construct local ChatMessage and update state
    const wire: WireDetails = {
      counter: res.counter,
      ivHex: bytesToHex(iv),
      ctHex: bytesToHex(ct),
      ctLength: ct.length,
      hmacHex: bytesToHex(hmac),
      latencyMs,
      verified,
      reason: failureReason,
    };

    const newMsg: ChatMessage = {
      id: String(res.id),
      counter: res.counter,
      senderRole: item.fromRole,
      mine: false,
      senderUsername: item.peerUsername,
      text: verified
        ? decryptedText
        : "[message could not be verified, not decrypted]",
      status: verified ? "received_verified" : "received_failed",
      failureReason,
      ts: res.created_at,
      wire,
    };

    this.messages.push(newMsg);
    this.notify();
  }

  /**
   * Updates verification status for a sent message upon receiving message_status frame.
   */
  public handleMessageStatus(
    messageId: number,
    counter: number,
    status: "verified" | "failed",
    reason?: string
  ): void {
    const msg = this.messages.find(
      (m) => m.mine && (m.id === String(messageId) || m.counter === counter)
    );
    if (msg) {
      msg.status = status === "verified" ? "verified_by_peer" : "failed_at_peer";
      if (reason) {
        msg.failureReason = reason;
      }
      if (msg.wire) {
        msg.wire.verified = status === "verified";
        msg.wire.reason = reason;
      }
      this.notify();
    }
  }
}

export const messageService = new MessageService();

