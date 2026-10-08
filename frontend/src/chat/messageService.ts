import { requestJson } from "../api/http";
import { base64ToBytes } from "../crypto/base64";
import { bytesToHex } from "../crypto/encoding";
import {
  EnvelopeError,
  encryptText,
  encryptImage,
  parseImageMeta,
  envelopeToWire,
  verifyAndDecrypt,
} from "../crypto/envelope";
import { ReplayGuard } from "../crypto/replayGuard";
import { getSessionKeys } from "../crypto/sessionKeys";
import type { ChatMessage, WireDetails } from "./types";
import { decodeImage, type DecodedImage } from "../image/decode";
import { ciphertextToNoiseRgb, sha256Hex } from "../image/pipeline";
import { releaseAllImageUrls, releaseObjectUrl, renderRgbPng } from "../image/render";
import type { ImageMetricsJobInput, TextMetricsJobInput } from "../analysis/metricsJob";

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
  msgType: "text" | "image";
  generation: number;
}

export type MessagesListener = (messages: ChatMessage[]) => void;

export class MessageService {
  private messages: ChatMessage[] = [];
  private sendCounter: number = 0;
  private replayGuard: ReplayGuard = new ReplayGuard();
  private queue: QueueItem[] = [];
  private isProcessingQueue: boolean = false;
  private listeners: Set<MessagesListener> = new Set();
  private generation = 0;
  private metricsEnqueuer: ((input: TextMetricsJobInput | ImageMetricsJobInput) => string | null) | null = null;

  public setMetricsEnqueuer(enqueuer: typeof this.metricsEnqueuer): void { this.metricsEnqueuer = enqueuer; }

  public handleTextMetricsStatus(messageId: number, status: string | null): void {
    const message = this.messages.find((item) => item.mine && item.id === String(messageId));
    if (message) { message.metricsStatus = status ?? undefined; this.notify(); }
  }

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
    this.generation += 1;
    for (const msg of this.messages) { if (msg.image) { msg.image.rgb?.fill(0); msg.image.url = undefined; msg.image.noiseUrl = undefined; } }
    releaseAllImageUrls();
    this.messages = [];
    this.sendCounter = 0;
    this.replayGuard.reset();
    this.queue = [];
    this.isProcessingQueue = false;
    this.notify();
  }

  public async sendImage(file: File, currentUsername: string, senderRole: "I" | "R", prepared?: DecodedImage): Promise<ChatMessage> {
    const generation = this.generation;
    const keys = getSessionKeys();
    if (!keys) throw new Error("No established secure session");
    const decoded = prepared ?? await decodeImage(file);
    if (generation !== this.generation) { decoded.rgb.fill(0); throw new Error("Session ended"); }
    await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
    const counter = ++this.sendCounter;
    const t0 = performance.now();
    const env = encryptImage(keys.kEnc, keys.kMac, keys.sessionId, senderRole, counter, decoded.w, decoded.h, decoded.rgb);
    const cryptoMs = Math.round((performance.now() - t0) * 100) / 100;
    const url = await renderRgbPng(decoded.rgb, decoded.w, decoded.h);
    if (generation !== this.generation) { releaseObjectUrl(url); decoded.rgb.fill(0); throw new Error("Session ended"); }
    const noiseUrl = await renderRgbPng(ciphertextToNoiseRgb(env.ct, decoded.w, decoded.h), decoded.w, decoded.h);
    if (generation !== this.generation) { releaseObjectUrl(url); releaseObjectUrl(noiseUrl); decoded.rgb.fill(0); throw new Error("Session ended"); }
    let res: { id: number; created_at: string };
    try {
      res = await requestJson<{ id: number; created_at: string }>("/api/messages", {
        method: "POST", body: JSON.stringify(envelopeToWire(env)),
      });
    } catch (err) {
      releaseObjectUrl(url); releaseObjectUrl(noiseUrl);
      if (!prepared) decoded.rgb.fill(0);
      throw err;
    }
    if (generation !== this.generation) { releaseObjectUrl(url); releaseObjectUrl(noiseUrl); decoded.rgb.fill(0); throw new Error("Session ended"); }
    const pixelHash = sha256Hex(decoded.rgb).slice(0, 16);
    const wire: WireDetails = { counter, ivHex: bytesToHex(env.iv), ctHex: bytesToHex(env.ct), ctLength: env.ct.length, hmacHex: bytesToHex(env.hmac), latencyMs: decoded.decodeMs + cryptoMs, verified: false, image: { w: decoded.w, h: decoded.h, plaintextBytes: decoded.rgb.length, overheadBytes: env.ct.length + 48 - decoded.rgb.length, decodeMs: decoded.decodeMs, cryptoMs, pixelHash } };
    const msg: ChatMessage = { id: String(res.id), counter, senderRole, mine: true, senderUsername: currentUsername, text: "", status: "sent", ts: res.created_at, wire, image: { w: decoded.w, h: decoded.h, plaintextBytes: decoded.rgb.length, overheadBytes: env.ct.length + 48 - decoded.rgb.length, pixelHash, url, noiseUrl, decodeMs: decoded.decodeMs, cryptoMs } };
    msg.image!.rgb = new Uint8Array(decoded.rgb);
    if (this.metricsEnqueuer) {
      const pixels = new Uint8Array(decoded.rgb), iv = new Uint8Array(env.iv), ct = new Uint8Array(env.ct);
      try { msg.metricsStatus = this.metricsEnqueuer({ messageId: res.id, sessionId: env.session_id, w: decoded.w, h: decoded.h, pixels, iv, ct }) ?? undefined; }
      finally { pixels.fill(0); iv.fill(0); ct.fill(0); }
    }
    this.messages.push(msg); this.notify(); return msg;
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
    const generation = this.generation;
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
    if (generation !== this.generation) throw new Error("Session ended");

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

    if (this.metricsEnqueuer) {
      const pt = new TextEncoder().encode(text);
      const ivCopy = new Uint8Array(env.iv), ctCopy = new Uint8Array(env.ct);
      try { myMsg.metricsStatus = this.metricsEnqueuer({ messageId: res.id, sessionId: env.session_id, pt, iv: ivCopy, ct: ctCopy }) ?? undefined; }
      finally { pt.fill(0); ivCopy.fill(0); ctCopy.fill(0); }
    }

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
    peerUsername: string,
    msgType: "text" | "image" = "text"
  ): void {
    this.queue.push({
      sessionId,
      messageId,
      fromRole,
      counter,
      msgType,
      peerUsername,
      generation: this.generation,
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
      await new Promise<void>((resolve) => setTimeout(resolve, 0));
    }

    this.isProcessingQueue = false;
  }

  private async handleSingleIncoming(item: QueueItem): Promise<void> {
    if (item.generation !== this.generation) return;
    const keys = getSessionKeys();
    if (!keys || keys.sessionId.toLowerCase() !== item.sessionId.toLowerCase()) {
      return;
    }

    // 1. Fetch message envelope from server
    const res = await requestJson<GetMessageResponse>(
      `/api/messages/${item.messageId}`
    );
    if (item.generation !== this.generation) return;
    const activeKeys = getSessionKeys();
    if (!activeKeys || activeKeys.sessionId.toLowerCase() !== item.sessionId.toLowerCase()) return;

    // 2. Strict pipeline: format -> replay -> HMAC -> decrypt
    let iv: Uint8Array = new Uint8Array();
    let ct: Uint8Array = new Uint8Array();
    let hmac: Uint8Array = new Uint8Array();
    let verified = false;
    let failureReason: string | undefined = undefined;
    let decryptedText = "";
    let latencyMs = 0;
    let receivedImage: { w: number; h: number; rgb: Uint8Array } | undefined;

    const t0 = performance.now();
    try {
      if (res.msg_type !== item.msgType || res.from_role !== item.fromRole || res.counter !== item.counter) {
        throw new EnvelopeError("bad_format");
      }
      try {
        iv = base64ToBytes(res.iv);
        ct = base64ToBytes(res.ct);
        hmac = base64ToBytes(res.hmac);
      } catch {
        throw new EnvelopeError("bad_format");
      }

      const decrypted = verifyAndDecrypt(
        activeKeys.kEnc,
        activeKeys.kMac,
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

      if (item.msgType === "image") {
        const { w, h } = parseImageMeta(res.meta_json);
        const rgb = decrypted as unknown as Uint8Array;
        decryptedText = "";
        receivedImage = { w, h, rgb: new Uint8Array(rgb) };
      } else decryptedText = decrypted as unknown as string;

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

    let renderedUrl: string | undefined;
    let noiseUrl: string | undefined;
    let imageInfo: ChatMessage["image"];
    if (verified && item.msgType === "image" && receivedImage) {
      renderedUrl = await renderRgbPng(receivedImage.rgb, receivedImage.w, receivedImage.h);
      noiseUrl = await renderRgbPng(ciphertextToNoiseRgb(ct, receivedImage.w, receivedImage.h), receivedImage.w, receivedImage.h);
      const pixelHash = sha256Hex(receivedImage.rgb).slice(0, 16);
      imageInfo = { w: receivedImage.w, h: receivedImage.h, plaintextBytes: receivedImage.rgb.length, overheadBytes: ct.length + 48 - receivedImage.rgb.length, pixelHash, url: renderedUrl, noiseUrl, rgb: receivedImage.rgb, cryptoMs: latencyMs };
    } else if (item.msgType === "image") {
      let w = 0, h = 0;
      try { ({ w, h } = parseImageMeta(res.meta_json)); } catch { /* invalid metadata remains a failed placeholder */ }
      imageInfo = { w, h, plaintextBytes: w * h * 3, overheadBytes: ct.length + 48 - w * h * 3, pixelHash: "", placeholder: true };
    }

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
      image: imageInfo ? { w: imageInfo.w, h: imageInfo.h, plaintextBytes: imageInfo.plaintextBytes, overheadBytes: imageInfo.overheadBytes, decodeMs: imageInfo.decodeMs, cryptoMs: imageInfo.cryptoMs, pixelHash: imageInfo.pixelHash } : undefined,
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
      image: imageInfo,
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

