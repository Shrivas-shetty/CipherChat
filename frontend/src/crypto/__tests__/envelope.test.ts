import { describe, expect, it } from "vitest";
import { cbc } from "@noble/ciphers/aes.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import vectorJson from "../../../../shared/test_vectors/envelope.json";
import { bytesToBase64 } from "../base64";
import { bytesToHex, hexToBytes } from "../encoding";
import {
  buildMacInput,
  encryptText,
  encryptImage,
  EnvelopeError,
  verifyAndDecrypt,
} from "../envelope";
import { ReplayGuard } from "../replayGuard";

describe("Phase 4 AES-256-CBC + HMAC-SHA256 Message Envelope", () => {
  it("verifies NIST SP 800-38A F.2.5 first-block known answer", () => {
    const key = hexToBytes(
      "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
    );
    const iv = hexToBytes("000102030405060708090a0b0c0d0e0f");
    const pt = hexToBytes("6bc1bee22e409f96e93d7e117393172a");

    const cipher = cbc(key, iv);
    const ct = cipher.encrypt(pt);

    const firstBlockHex = bytesToHex(ct.slice(0, 16));
    expect(firstBlockHex).toBe("f58c4c04d6e5f1ba779eabfb5f7bfbd6");
  });

  it("matches shared test vectors envelope.json exactly", () => {
    const kEnc = hexToBytes(vectorJson.k_enc_hex);
    const kMac = hexToBytes(vectorJson.k_mac_hex);

    for (const testCase of vectorJson.cases) {
      const iv = hexToBytes(testCase.iv_hex);
      const env = testCase.msg_type === "image"
        ? encryptImage(kEnc, kMac, testCase.session_id, testCase.sender_role as "I" | "R", testCase.counter, testCase.w!, testCase.h!, hexToBytes(testCase.pixel_hex!), iv)
        : encryptText(
        kEnc,
        kMac,
        testCase.session_id,
        testCase.sender_role as "I" | "R",
        testCase.counter,
        testCase.plaintext!,
        iv
      );

      const macIn = buildMacInput(
        testCase.session_id,
        testCase.sender_role as "I" | "R",
        testCase.counter,
        testCase.msg_type,
        testCase.meta_json,
        iv,
        env.ct
      );

      expect(bytesToHex(macIn)).toBe(testCase.mac_input_hex);
      expect(bytesToHex(env.ct)).toBe(testCase.ct_hex);
      expect(bytesToBase64(env.ct)).toBe(testCase.ct_b64);
      expect(bytesToHex(env.hmac)).toBe(testCase.hmac_hex);
      expect(bytesToBase64(env.hmac)).toBe(testCase.hmac_b64);

      // Verify and decrypt Python-generated envelope in TypeScript
      const decrypted = verifyAndDecrypt(
        kEnc,
        kMac,
        testCase.session_id,
        testCase.sender_role as "I" | "R",
        {
          session_id: testCase.session_id,
          sender_role: testCase.sender_role as "I" | "R",
          counter: testCase.counter,
          msg_type: testCase.msg_type,
          meta_json: testCase.meta_json,
          iv: hexToBytes(testCase.iv_hex),
          ct: hexToBytes(testCase.ct_hex),
          hmac: hexToBytes(testCase.hmac_hex),
        },
        0
      );
      expect(testCase.msg_type === "image" ? bytesToHex(decrypted as Uint8Array) : decrypted).toBe(testCase.msg_type === "image" ? testCase.pixel_hex : testCase.plaintext);
    }
  });

  it("verifies round-trip for various payloads", () => {
    const kEnc = new Uint8Array(32).fill(0x11);
    const kMac = new Uint8Array(32).fill(0x22);
    const sessionId = "session-1234";

    const messages = [
      "Plain ASCII message",
      "Unicode: Café, crème brûlée, Übermensch, naïve",
      "Emoji: 🛡️🔐🚀💻🔒✨🎉",
      "A".repeat(16), // Padding boundary
      "B".repeat(2000), // Maximum length
    ];

    let lastCounter = 0;
    let counter = 1;

    for (const msg of messages) {
      const env = encryptText(kEnc, kMac, sessionId, "I", counter, msg);
      const dec = verifyAndDecrypt(kEnc, kMac, sessionId, "I", env, lastCounter);
      expect(dec).toBe(msg);
      lastCounter = counter;
      counter++;
    }
  });

  it("authenticates image envelopes before metadata and decrypt validation", () => {
    const kEnc = new Uint8Array(32).fill(7), kMac = new Uint8Array(32).fill(8);
    const rgb = new Uint8Array(36).map((_, i) => (i * 37 + 11) & 255);
    const image = encryptImage(kEnc, kMac, "img-session", "I", 1, 4, 3, rgb);
    expect(verifyAndDecrypt(kEnc, kMac, "img-session", "I", image, 0) as Uint8Array).toEqual(rgb);
    expect(() => verifyAndDecrypt(kEnc, kMac, "img-session", "I", { ...image, msg_type: "text" }, 0)).toThrowError(new EnvelopeError("hmac_mismatch"));
  });

  it("verifies mutation matrix errors", () => {
    const kEnc = new Uint8Array(32).fill(0x33);
    const kMac = new Uint8Array(32).fill(0x44);
    const sessionId = "session-test";
    const env = encryptText(kEnc, kMac, sessionId, "I", 10, "Tamper test");

    // 1. Bit flip in ciphertext -> hmac_mismatch
    const ctCorrupt = new Uint8Array(env.ct);
    ctCorrupt[0] ^= 0x01;
    expect(() =>
      verifyAndDecrypt(kEnc, kMac, sessionId, "I", { ...env, ct: ctCorrupt }, 0)
    ).toThrowError(new EnvelopeError("hmac_mismatch"));

    // 2. Bit flip in IV -> hmac_mismatch
    const ivCorrupt = new Uint8Array(env.iv);
    ivCorrupt[0] ^= 0x01;
    expect(() =>
      verifyAndDecrypt(kEnc, kMac, sessionId, "I", { ...env, iv: ivCorrupt }, 0)
    ).toThrowError(new EnvelopeError("hmac_mismatch"));

    // 3. Bit flip in HMAC -> hmac_mismatch
    const hmacCorrupt = new Uint8Array(env.hmac);
    hmacCorrupt[0] ^= 0x01;
    expect(() =>
      verifyAndDecrypt(kEnc, kMac, sessionId, "I", { ...env, hmac: hmacCorrupt }, 0)
    ).toThrowError(new EnvelopeError("hmac_mismatch"));

    // 4. Counter mutation -> hmac_mismatch
    expect(() =>
      verifyAndDecrypt(kEnc, kMac, sessionId, "I", { ...env, counter: 11 }, 0)
    ).toThrowError(new EnvelopeError("hmac_mismatch"));

    // 5. Replay: counter <= lastCounter -> replay
    expect(() =>
      verifyAndDecrypt(kEnc, kMac, sessionId, "I", env, 10)
    ).toThrowError(new EnvelopeError("replay"));
    expect(() =>
      verifyAndDecrypt(kEnc, kMac, sessionId, "I", env, 15)
    ).toThrowError(new EnvelopeError("replay"));

    // 6. Bad format: wrong lengths -> bad_format
    expect(() =>
      verifyAndDecrypt(
        kEnc,
        kMac,
        sessionId,
        "I",
        { ...env, iv: new Uint8Array(10) },
        0
      )
    ).toThrowError(new EnvelopeError("bad_format"));

    expect(() =>
      verifyAndDecrypt(
        kEnc,
        kMac,
        sessionId,
        "I",
        { ...env, ct: new Uint8Array(15) },
        0
      )
    ).toThrowError(new EnvelopeError("bad_format"));

    // 7. Decrypt error with valid HMAC over forged ciphertext
    const garbageCt = new Uint8Array(32);
    crypto.getRandomValues(garbageCt);
    // Compute valid HMAC with kMac
    const forgedTag = hmac(
      sha256,
      kMac,
      buildMacInput(sessionId, "I", 1, "text", "{}", env.iv, garbageCt)
    );

    expect(() =>
      verifyAndDecrypt(
        kEnc,
        kMac,
        sessionId,
        "I",
        {
          session_id: sessionId,
          sender_role: "I",
          counter: 1,
          msg_type: "text",
          meta_json: "{}",
          iv: env.iv,
          ct: garbageCt,
          hmac: forgedTag,
        },
        0
      )
    ).toThrowError(new EnvelopeError("decrypt_error"));
  });

  it("verifies ReplayGuard strictly allows counter > last", () => {
    const guard = new ReplayGuard();
    expect(guard.getLast("I")).toBe(0);
    expect(guard.getLast("R")).toBe(0);

    // Initial counter 1 is valid
    expect(guard.check("I", 1)).toBe(true);
    guard.commit("I", 1);
    expect(guard.getLast("I")).toBe(1);

    // Counter 1 again rejected (duplicate)
    expect(guard.check("I", 1)).toBe(false);

    // Counter 0 rejected (decreased)
    expect(guard.check("I", 0)).toBe(false);

    // Counter 5 accepted (gap allowed)
    expect(guard.check("I", 5)).toBe(true);
    guard.commit("I", 5);
    expect(guard.getLast("I")).toBe(5);

    // Counter 3 rejected
    expect(guard.check("I", 3)).toBe(false);

    // Independent role R
    expect(guard.check("R", 1)).toBe(true);
    guard.commit("R", 1);
    expect(guard.getLast("R")).toBe(1);

    // Reset clears counters
    guard.reset();
    expect(guard.getLast("I")).toBe(0);
    expect(guard.getLast("R")).toBe(0);
  });
});
