import { hexToBytes } from "./encoding";
import {
  decodePublic,
  encodePublic,
  generatePrivate,
  type PrivateKey,
  publicFromPrivate,
  sharedSecret,
  validatePublic,
} from "./dh";
import {
  confirmTag,
  deriveSessionKeys,
  verifyConfirmTag,
} from "./kdf";
import {
  clearSessionKeys,
  getSessionKeys,
  setSessionKeys,
} from "./sessionKeys";

export type HandshakeStatus =
  | "idle"
  | "negotiating"
  | "established"
  | "failed"
  | "terminated";

export interface SessionPeer {
  user_id: string;
  username: string;
}

export interface HandshakeTimings {
  keygen_ms: number;
  derive_ms: number;
}

export interface HandshakeCallbacks {
  sendFrame: (frame: any) => void;
  onStatusChange?: (status: HandshakeStatus) => void;
  onEstablished?: (fingerprint: string) => void;
  onFailed?: (reason: string) => void;
  onTerminated?: (reason: string) => void;
}

export class HandshakeRunner {
  public status: HandshakeStatus = "idle";
  public role: "initiator" | "responder" | null = null;
  public sessionId: string | null = null;
  public peer: SessionPeer | null = null;
  public fingerprint: string | null = null;
  public timings: HandshakeTimings = { keygen_ms: 0, derive_ms: 0 };
  public failureReason: string | null = null;
  public terminationReason: string | null = null;
  public myPubHex: string | null = null;
  public peerPubHex: string | null = null;
  public earlyPeerTag: string | null = null;

  private myPriv: PrivateKey | null = null;
  private callbacks: HandshakeCallbacks;

  constructor(callbacks: HandshakeCallbacks) {
    this.callbacks = callbacks;
  }

  public setCallbacks(callbacks: HandshakeCallbacks): void {
    this.callbacks = callbacks;
  }

  private setStatus(status: HandshakeStatus): void {
    this.status = status;
    this.callbacks.onStatusChange?.(status);
  }

  public startSession(
    sessionId: string,
    role: "initiator" | "responder",
    peer: SessionPeer
  ): void {
    this.reset();
    this.sessionId = sessionId;
    this.role = role;
    this.peer = peer;
    this.setStatus("negotiating");

    // 1. Generate DH keypair
    const t0 = performance.now();
    this.myPriv = generatePrivate();
    const myPubInt = publicFromPrivate(this.myPriv.x);
    this.myPubHex = encodePublic(myPubInt);
    this.timings.keygen_ms = Math.round((performance.now() - t0) * 100) / 100;

    // 2. Send dh_public frame
    this.callbacks.sendFrame({
      v: 1,
      type: "dh_public",
      session_id: sessionId,
      public: this.myPubHex,
    });
  }

  public handleDhPublic(sessionId: string, peerPubHex: string): void {
    if (this.sessionId !== sessionId || !this.myPriv || !this.myPubHex || !this.role) {
      return;
    }

    // 1. Validate peer's public key
    const check = validatePublic(peerPubHex);
    if (!check.valid) {
      this.failureReason = "bad_public";
      this.setStatus("failed");
      this.callbacks.sendFrame({
        v: 1,
        type: "key_failed",
        session_id: sessionId,
        reason: "bad_public",
      });
      this.callbacks.onFailed?.("bad_public");
      return;
    }

    this.peerPubHex = peerPubHex;

    // 2. Compute shared secret and session keys
    const t0 = performance.now();
    const peerPubInt = decodePublic(peerPubHex);
    const Z = sharedSecret(peerPubInt, this.myPriv.x);

    const pubInitiator = hexToBytes(
      this.role === "initiator" ? this.myPubHex : peerPubHex
    );
    const pubResponder = hexToBytes(
      this.role === "responder" ? this.myPubHex : peerPubHex
    );

    const keys = deriveSessionKeys(Z, sessionId, pubInitiator, pubResponder);
    this.timings.derive_ms = Math.round((performance.now() - t0) * 100) / 100;

    // 3. Store keys securely in module memory
    setSessionKeys({
      sessionId,
      fingerprint: keys.fingerprint,
      kEnc: keys.kEnc,
      kMac: keys.kMac,
    });
    this.fingerprint = keys.fingerprint;

    // 4. Send key_confirm frame
    const myTag = confirmTag(keys.kMac, sessionId, this.role);
    this.callbacks.sendFrame({
      v: 1,
      type: "key_confirm",
      session_id: sessionId,
      tag: myTag,
    });

    // 5. If peer's tag arrived earlier, verify it now
    if (this.earlyPeerTag) {
      const tag = this.earlyPeerTag;
      this.earlyPeerTag = null;
      this.verifyPeerConfirmTag(tag);
    }
  }

  public handleKeyConfirm(sessionId: string, peerTag: string): void {
    if (this.sessionId !== sessionId) {
      return;
    }

    const keys = getSessionKeys();
    if (!keys || keys.sessionId !== sessionId) {
      // Keys not derived yet; buffer tag
      this.earlyPeerTag = peerTag;
      return;
    }

    this.verifyPeerConfirmTag(peerTag);
  }

  private verifyPeerConfirmTag(peerTag: string): void {
    if (!this.sessionId || !this.role || !this.fingerprint) {
      return;
    }
    const keys = getSessionKeys();
    if (!keys) {
      return;
    }

    const peerRole = this.role === "initiator" ? "responder" : "initiator";
    const ok = verifyConfirmTag(keys.kMac, this.sessionId, peerRole, peerTag);

    if (!ok) {
      this.failureReason = "key_confirm_failed";
      this.setStatus("failed");
      clearSessionKeys();
      this.callbacks.sendFrame({
        v: 1,
        type: "key_failed",
        session_id: this.sessionId,
        reason: "key_confirm_failed",
      });
      this.callbacks.onFailed?.("key_confirm_failed");
      return;
    }

    // Confirmation verified!
    this.callbacks.sendFrame({
      v: 1,
      type: "key_verified",
      session_id: this.sessionId,
      fingerprint: this.fingerprint,
      timings: this.timings,
    });
  }

  public handleSessionEstablished(sessionId: string, fingerprint: string): void {
    if (this.sessionId !== sessionId) {
      return;
    }
    this.fingerprint = fingerprint;
    this.setStatus("established");
    this.callbacks.onEstablished?.(fingerprint);
  }

  public handleSessionTerminated(sessionId: string, reason: string): void {
    if (this.sessionId && this.sessionId !== sessionId) {
      return;
    }
    this.terminationReason = reason;
    this.setStatus("terminated");
    clearSessionKeys();
    this.callbacks.onTerminated?.(reason);
  }

  public reset(): void {
    if (this.myPriv) {
      this.myPriv.bytes.fill(0);
      this.myPriv = null;
    }
    this.myPubHex = null;
    this.peerPubHex = null;
    this.earlyPeerTag = null;
    this.failureReason = null;
    this.terminationReason = null;
    this.fingerprint = null;
    this.sessionId = null;
    this.role = null;
    this.peer = null;
    this.timings = { keygen_ms: 0, derive_ms: 0 };
    clearSessionKeys();
    this.setStatus("idle");
  }
}
