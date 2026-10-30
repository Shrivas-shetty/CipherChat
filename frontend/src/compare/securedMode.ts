import { base64ToBytes, bytesToBase64 } from "../crypto/base64";
import { buildMacInput, decryptVerifiedWithKey, encryptText, envelopeToWire, validateEnvelopeFormat, verifyEnvelopeMac, wireToEnvelope, type Envelope, type WireEnvelope } from "../crypto/envelope";
import { buildSignatureInput, signEcdsa, verifyEcdsa } from "../signing/signature";
import type { BenchmarkContext } from "./benchContext";
import { exchange, type TimedExchangeResult } from "./transport";
import type { TrialMeasurement } from "./types";

export type TrialDeps = {
  exchange?: typeof exchange;
  now?: () => number;
  signal?: AbortSignal;
  trialNo: number;
  runId: number;
  warmup: boolean;
};

const positiveDuration = (start: number, end: number) => Math.max(0.001, end - start);

export async function runSecuredTrial(
  ctx: BenchmarkContext,
  text: string,
  deps: TrialDeps,
): Promise<TrialMeasurement> {
  const send = deps.exchange ?? exchange;
  const now = deps.now ?? (() => performance.now());
  const t0 = now();
  const plaintextBytes = new TextEncoder().encode(text).byteLength;
  const counter = ctx.nextCounter();
  const sealStart = now();
  const envelope = encryptText(ctx.kEnc, ctx.kMac, ctx.sessionId, "I", counter, text);
  const sealMs = positiveDuration(sealStart, now());
  const signatureInput = buildSignatureInput(
    buildMacInput(ctx.sessionId, "I", counter, "text", "{}", envelope.iv, envelope.ct),
    envelope.hmac,
  );
  const signStart = now();
  const signature = signEcdsa(ctx.privateKey, signatureInput);
  const signMs = positiveDuration(signStart, now());
  const requestBody = {
    mode: "secured", warmup: deps.warmup,
    ...envelopeToWire(envelope),
    sender_role: "I",
    signature: bytesToBase64(signature),
  };
  let postStart = t0;
  let getStart = t0;
  let getParsed = t0;
  let verifyHmacMs: number | null = null;
  let verifySigMs: number | null = null;
  let decryptMs: number | null = null;
  let integrityOk = false;
  let signatureOk = false;
  let recovered = "";
  let getResponse: TimedExchangeResult<any>;
  const postResponse = await send<{ id: number }>("POST", `/api/dashboard/compare/runs/${deps.runId}/exchanges`, requestBody, {
    signal: deps.signal,
    onFetchStart: () => { postStart = now(); },
  });
  const exchangeId = postResponse.json.id;
  getResponse = await send<any>("GET", `/api/dashboard/compare/runs/${deps.runId}/exchanges/${exchangeId}`, undefined, {
    signal: deps.signal,
    onFetchStart: () => { getStart = now(); },
    onResponseParsed: () => { getParsed = now(); },
  });

  const receiveCheckStart = now();
  try {
    if (getResponse.json.mode !== "secured") throw new Error("mode_mismatch");
    const wire = { ...getResponse.json, sender_role: "I" } as WireEnvelope & { signature: string };
    const received: Envelope = wireToEnvelope(wire);
    const hmacStart = now();
    let macInput: Uint8Array;
    try {
      validateEnvelopeFormat(ctx.sessionId, "I", received);
      if (!ctx.replayGuard.check("I", received.counter)) throw new Error("replay");
      macInput = verifyEnvelopeMac(ctx.kMac, ctx.sessionId, "I", received);
      integrityOk = true;
    } finally {
      verifyHmacMs = positiveDuration(hmacStart, now());
    }
    const verifyStart = now();
    try {
      const receivedSignature = base64ToBytes(wire.signature);
      const receivedSignatureInput = buildSignatureInput(macInput!, received.hmac);
      signatureOk = verifyEcdsa(ctx.publicKeyBytes, receivedSignatureInput, receivedSignature);
    }
    catch { signatureOk = false; }
    finally { verifySigMs = positiveDuration(verifyStart, now()); }
    if (!signatureOk) throw new Error("bad_signature");
    const decryptStart = now();
    let plaintext: string;
    try { plaintext = decryptVerifiedWithKey(ctx.kEnc, received) as string; }
    finally { decryptMs = positiveDuration(decryptStart, now()); }
    if (typeof plaintext !== "string") throw new Error("unexpected_plaintext_type");
    recovered = plaintext;
    ctx.replayGuard.commit("I", received.counter);
  } catch {
    // A failed HMAC skips signature verification; a bad signature skips decryption.
  } finally {
    // Include malformed-response parsing in the integrity-check stage so a
    // rejected secured response still carries a measured failure duration.
    if (verifyHmacMs === null) verifyHmacMs = positiveDuration(receiveCheckStart, now());
  }
  const tEnd = now();
  const prepMs = positiveDuration(t0, postStart);
  const postMs = positiveDuration(postStart, getStart);
  const getMs = positiveDuration(getStart, getParsed);
  const finishMs = positiveDuration(getParsed, tEnd);
  const totalMs = prepMs + postMs + getMs + finishMs;
  const roundtripOk = integrityOk && signatureOk && recovered === text;
  return {
    trial_no: deps.trialNo, mode: "secured", warmup: deps.warmup,
    exchange_id: exchangeId, total_ms: totalMs, prep_ms: prepMs,
    post_ms: postMs, get_ms: getMs, finish_ms: finishMs,
    seal_ms: sealMs, sign_ms: signMs, verify_hmac_ms: verifyHmacMs,
    verify_sig_ms: verifySigMs, decrypt_ms: decryptMs,
    post_req_bytes: postResponse.reqBytes, post_resp_bytes: postResponse.respBytes,
    get_resp_bytes: getResponse.respBytes, plaintext_bytes: plaintextBytes,
    ciphertext_bytes: envelope.ct.length, integrity_ok: integrityOk,
    signature_ok: signatureOk, roundtrip_ok: roundtripOk,
  };
}
