import { describe, expect, it } from "vitest";
import vectorJson from "../../../../shared/test_vectors/dh_hkdf.json";
import {
  decodePublic,
  encodePublic,
  generatePrivate,
  publicFromPrivate,
  sharedSecret,
  validatePublic,
} from "../dh";
import { bytesToHex, hexToBytes } from "../encoding";
import {
  confirmTag,
  deriveSessionKeys,
  fingerprintString,
  verifyConfirmTag,
} from "../kdf";
import { modpow } from "../modpow";
import { P, P_HEX } from "../params";
import {
  clearSessionKeys,
  getSessionKeys,
  hasSessionKeys,
  setSessionKeys,
} from "../sessionKeys";

describe("Diffie-Hellman & HKDF Cryptographic Verification", () => {
  it("verifies RFC 3526 Group 14 prime parameters", () => {
    expect(P_HEX.length).toBe(512);
    expect(P.toString(16).toLowerCase()).toBe(P_HEX);
    // 2048-bit prime
    const bitLen = P.toString(2).length;
    expect(bitLen).toBe(2048);
  });

  it("verifies modpow correctness", () => {
    // 2^10 mod 1000 = 1024 mod 1000 = 24
    expect(modpow(2n, 10n, 1000n)).toBe(24n);
    // 3^7 mod 13 = 2187 mod 13 = 3
    expect(modpow(3n, 7n, 13n)).toBe(3n);
  });

  it("verifies public key decoding and fingerprint string formatting", () => {
    const rawVal = 12345678901234567890n;
    const enc = encodePublic(rawVal);
    expect(decodePublic(enc)).toBe(rawVal);

    const fpBytes = new Uint8Array([0x60, 0xb3, 0x96, 0x98, 0x05, 0xe7, 0x20, 0x5c]);
    expect(fingerprintString(fpBytes)).toBe("60B3 9698 05E7 205C");
  });

  it("verifies CSPRNG private key generation top bit forced to 1", () => {
    for (let i = 0; i < 10; i++) {
      const priv = generatePrivate();
      expect(priv.x >= 2n ** 255n).toBe(true);
      expect(priv.x < 2n ** 256n).toBe(true);
      expect((priv.bytes[0] & 0x80) === 0x80).toBe(true);
      expect(priv.bytes.length).toBe(32);
    }
  });

  it("verifies public key validation", () => {
    const validPub = modpow(2n, 12345n, P);
    expect(validatePublic(validPub).valid).toBe(true);
    const validHex = encodePublic(validPub);
    expect(validatePublic(validHex).valid).toBe(true);

    // Range checks
    expect(validatePublic(0n).valid).toBe(false);
    expect(validatePublic(1n).valid).toBe(false);
    expect(validatePublic(P - 1n).valid).toBe(false);
    expect(validatePublic(P).valid).toBe(false);
    expect(validatePublic(P + 1n).valid).toBe(false);

    // Format checks
    expect(validatePublic("bad").valid).toBe(false);
    expect(validatePublic("00".repeat(256)).valid).toBe(false);
    expect(validatePublic(validHex.toUpperCase()).valid).toBe(false);
  });

  it("matches shared test vector dh_hkdf.json exactly", () => {
    const sessionId = vectorJson.session_id;
    const alicePriv = BigInt("0x" + vectorJson.initiator.x_hex);
    const bobPriv = BigInt("0x" + vectorJson.responder.x_hex);

    // 1. Verify public keys match
    const alicePubInt = publicFromPrivate(alicePriv);
    const alicePubHex = encodePublic(alicePubInt);
    expect(alicePubHex).toBe(vectorJson.initiator.pub_hex);

    const bobPubInt = publicFromPrivate(bobPriv);
    const bobPubHex = encodePublic(bobPubInt);
    expect(bobPubHex).toBe(vectorJson.responder.pub_hex);

    // 2. Verify shared secret Z
    const zAlice = sharedSecret(bobPubInt, alicePriv);
    const zBob = sharedSecret(alicePubInt, bobPriv);
    expect(bytesToHex(zAlice)).toBe(bytesToHex(zBob));
    expect(bytesToHex(zAlice)).toBe(vectorJson.shared_secret_z_hex);

    // 3. Verify HKDF session key derivations
    const pubInitiator = hexToBytes(vectorJson.initiator.pub_hex);
    const pubResponder = hexToBytes(vectorJson.responder.pub_hex);

    const keys = deriveSessionKeys(
      zAlice,
      sessionId,
      pubInitiator,
      pubResponder
    );

    expect(bytesToHex(keys.kEnc)).toBe(vectorJson.k_enc_hex);
    expect(bytesToHex(keys.kMac)).toBe(vectorJson.k_mac_hex);
    expect(keys.fingerprint).toBe(vectorJson.fingerprint_str);
    expect(keys.fingerprint).toBe("60B3 9698 05E7 205C");

    // 4. Verify confirmation tags
    const tagInit = confirmTag(keys.kMac, sessionId, "initiator");
    const tagResp = confirmTag(keys.kMac, sessionId, "responder");
    expect(tagInit).toBe(vectorJson.initiator.confirm_tag);
    expect(tagResp).toBe(vectorJson.responder.confirm_tag);

    // 5. Verify constant-time confirmation tag check
    expect(verifyConfirmTag(keys.kMac, sessionId, "initiator", tagInit)).toBe(true);
    expect(verifyConfirmTag(keys.kMac, sessionId, "responder", tagResp)).toBe(true);
    // Swapped roles or tampered tag fail
    expect(verifyConfirmTag(keys.kMac, sessionId, "initiator", tagResp)).toBe(false);
    expect(
      verifyConfirmTag(
        keys.kMac,
        sessionId,
        "initiator",
        tagInit.slice(0, -1) + "0"
      )
    ).toBe(false);
  });

  it("verifies sessionKeys module zeroes out memory buffers on clear", () => {
    const kEnc = new Uint8Array([1, 2, 3, 4]);
    const kMac = new Uint8Array([5, 6, 7, 8]);
    setSessionKeys({
      sessionId: "test-session",
      fingerprint: "1111 2222 3333 4444",
      kEnc,
      kMac,
    });

    expect(hasSessionKeys()).toBe(true);
    const stored = getSessionKeys();
    expect(stored?.sessionId).toBe("test-session");

    // Clear session keys
    clearSessionKeys();
    expect(hasSessionKeys()).toBe(false);
    expect(getSessionKeys()).toBe(null);
    // Stored references should be zeroed
    expect(stored?.kEnc.every((b) => b === 0)).toBe(true);
    expect(stored?.kMac.every((b) => b === 0)).toBe(true);
  });
});
