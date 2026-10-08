import { cbc } from "@noble/ciphers/aes.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToBase64, base64ToBytes } from "./base64";
import { bytesToHex } from "./encoding";
import { constantTimeCompare } from "./kdf";

export type EnvelopeFailureReason =
  | "bad_format"
  | "replay"
  | "hmac_mismatch"
  | "decrypt_error";

export class EnvelopeError extends Error {
  public reason: EnvelopeFailureReason;
  constructor(reason: EnvelopeFailureReason) {
    super(reason);
    this.reason = reason;
    this.name = "EnvelopeError";
  }
}

export interface Envelope {
  session_id: string;
  sender_role: "I" | "R";
  counter: number;
  msg_type: string;
  meta_json: string;
  iv: Uint8Array;
  ct: Uint8Array;
  hmac: Uint8Array;
}

export interface WireEnvelope {
  session_id: string;
  sender_role: "I" | "R";
  counter: number;
  msg_type: string;
  meta_json: string;
  iv: string;
  ct: string;
  hmac: string;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8");

function encodeField(bytes: Uint8Array): Uint8Array {
  const len = bytes.length;
  const out = new Uint8Array(4 + len);
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength);
  view.setUint32(0, len, false); // big-endian
  out.set(bytes, 4);
  return out;
}

export function buildMacInput(
  sessionId: string,
  senderRole: "I" | "R",
  counter: number,
  msgType: string,
  metaJson: string,
  iv: Uint8Array,
  ct: Uint8Array
): Uint8Array {
  const prefix = encoder.encode("CC1-msg");
  const sBytes = encoder.encode(sessionId.trim().toLowerCase());
  const rBytes = encoder.encode(senderRole);

  const cBytes = new Uint8Array(8);
  new DataView(cBytes.buffer).setBigUint64(0, BigInt(counter), false);

  const tBytes = encoder.encode(msgType);
  const mBytes = encoder.encode(metaJson);

  const fSession = encodeField(sBytes);
  const fRole = encodeField(rBytes);
  const fCounter = encodeField(cBytes);
  const fType = encodeField(tBytes);
  const fMeta = encodeField(mBytes);
  const fIv = encodeField(iv);
  const fCt = encodeField(ct);

  const totalLen =
    prefix.length +
    fSession.length +
    fRole.length +
    fCounter.length +
    fType.length +
    fMeta.length +
    fIv.length +
    fCt.length;

  const out = new Uint8Array(totalLen);
  let offset = 0;
  for (const part of [
    prefix,
    fSession,
    fRole,
    fCounter,
    fType,
    fMeta,
    fIv,
    fCt,
  ]) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function encryptText(
  kEnc: Uint8Array,
  kMac: Uint8Array,
  sessionId: string,
  senderRole: "I" | "R",
  counter: number,
  text: string,
  injectedIv?: Uint8Array
): Envelope {
  if (kEnc.length !== 32 || kMac.length !== 32) {
    throw new Error("kEnc and kMac must be 32 bytes");
  }
  if (senderRole !== "I" && senderRole !== "R") {
    throw new Error("senderRole must be 'I' or 'R'");
  }
  if (counter < 1) {
    throw new Error("counter must be >= 1");
  }
  const ptBytes = encoder.encode(text);
  if (ptBytes.length < 1 || ptBytes.length > 8000 || text.length > 2000) {
    throw new Error("Plaintext must be 1-2000 characters and <= 8000 bytes");
  }

  let iv: Uint8Array;
  if (injectedIv) {
    if (injectedIv.length !== 16) {
      throw new Error("Injected IV must be 16 bytes");
    }
    iv = injectedIv;
  } else {
    iv = new Uint8Array(16);
    crypto.getRandomValues(iv);
  }

  // AES-256-CBC with PKCS7 padding enabled by default in @noble/ciphers
  const cipher = cbc(kEnc, iv);
  const ct = cipher.encrypt(ptBytes);

  const macIn = buildMacInput(
    sessionId,
    senderRole,
    counter,
    "text",
    "{}",
    iv,
    ct
  );
  const tag = hmac(sha256, kMac, macIn);

  return {
    session_id: sessionId.trim().toLowerCase(),
    sender_role: senderRole,
    counter,
    msg_type: "text",
    meta_json: "{}",
    iv,
    ct,
    hmac: tag,
  };
}

export function verifyAndDecrypt(
  kEnc: Uint8Array,
  kMac: Uint8Array,
  sessionId: string,
  senderRole: "I" | "R",
  envelope: Envelope,
  lastCounter: number
): string {
  // 1. Format checks
  if (
    !envelope.iv ||
    envelope.iv.length !== 16 ||
    !envelope.hmac ||
    envelope.hmac.length !== 32 ||
    !envelope.ct ||
    envelope.ct.length < 16 ||
    envelope.ct.length > 8192 ||
    envelope.ct.length % 16 !== 0 ||
    typeof envelope.counter !== "number" ||
    envelope.counter < 1 ||
    envelope.sender_role !== senderRole ||
    envelope.session_id.trim().toLowerCase() !== sessionId.trim().toLowerCase() ||
    envelope.msg_type !== "text" ||
    envelope.meta_json !== "{}"
  ) {
    throw new EnvelopeError("bad_format");
  }

  // 2. Replay check
  if (envelope.counter <= lastCounter) {
    throw new EnvelopeError("replay");
  }

  // 3. HMAC verification (MUST verify before decrypting)
  const macIn = buildMacInput(
    sessionId,
    senderRole,
    envelope.counter,
    envelope.msg_type,
    envelope.meta_json,
    envelope.iv,
    envelope.ct
  );
  const expectedTag = hmac(sha256, kMac, macIn);
  const expectedHex = bytesToHex(expectedTag);
  const actualHex = bytesToHex(envelope.hmac);

  if (!constantTimeCompare(expectedHex, actualHex)) {
    throw new EnvelopeError("hmac_mismatch");
  }

  // 4. Decrypt + PKCS7 unpad + UTF-8 decode
  try {
    const cipher = cbc(kEnc, envelope.iv);
    const ptBytes = cipher.decrypt(envelope.ct);
    const text = decoder.decode(ptBytes);
    if (text.length < 1 || text.length > 2000 || ptBytes.length > 8000) {
      throw new EnvelopeError("decrypt_error");
    }
    return text;
  } catch (err) {
    if (err instanceof EnvelopeError) {
      throw err;
    }
    throw new EnvelopeError("decrypt_error");
  }
}

export function envelopeToWire(env: Envelope): WireEnvelope {
  return {
    session_id: env.session_id,
    sender_role: env.sender_role,
    counter: env.counter,
    msg_type: env.msg_type,
    meta_json: env.meta_json,
    iv: bytesToBase64(env.iv),
    ct: bytesToBase64(env.ct),
    hmac: bytesToBase64(env.hmac),
  };
}

export function wireToEnvelope(wire: WireEnvelope): Envelope {
  return {
    session_id: wire.session_id,
    sender_role: wire.sender_role,
    counter: wire.counter,
    msg_type: wire.msg_type,
    meta_json: wire.meta_json,
    iv: base64ToBytes(wire.iv),
    ct: base64ToBytes(wire.ct),
    hmac: base64ToBytes(wire.hmac),
  };
}

