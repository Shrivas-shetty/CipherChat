import { describe, expect, it } from "vitest";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { buildSignatureInput, fingerprintHex, formatFingerprint, parsePublicKeyBytes, signEcdsa, verifyEcdsa } from "../signature";
import { generateSigningKeyPair } from "../keygen";

const vectorPath = resolve(process.cwd(), "../shared/test_vectors/signature.json");
type Fixture = { private_key_hex_test_only: string; public_key_hex: string; public_key_b64: string;
  fingerprint_hex: string; mac_input_hex: string; hmac_tag_hex: string; signature_input_hex: string;
  python_signature_hex: string; typescript_signature_hex: string };
const fixture = JSON.parse(readFileSync(vectorPath, "utf8")) as Fixture;
const fromHex = (value: string) => Uint8Array.from(value.match(/.{2}/g) ?? [], (byte) => parseInt(byte, 16));
const toHex = (bytes: Uint8Array) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
const publicKey = fromHex(fixture.public_key_hex);
const privateKey = fromHex(fixture.private_key_hex_test_only);
const input = fromHex(fixture.signature_input_hex);

describe("Phase 12 ECDSA P-256 signatures", () => {
  it("verifies the Python and TypeScript shared vectors and matches the input/fingerprint fixture", () => {
    if (process.env.CC_WRITE_VECTORS === "1" && !fixture.typescript_signature_hex) {
      const generated = toHex(signEcdsa(privateKey, input));
      fixture.typescript_signature_hex = generated;
      const raw = JSON.parse(readFileSync(vectorPath, "utf8")) as Fixture;
      raw.typescript_signature_hex = generated;
      writeFileSync(vectorPath, `${JSON.stringify(raw, null, 2)}\n`, "utf8");
    }
    expect(fixture.public_key_hex).toHaveLength(130);
    expect(fixture.public_key_hex.startsWith("04")).toBe(true);
    expect(Buffer.from(fixture.public_key_b64, "base64").toString("hex")).toBe(fixture.public_key_hex);
    expect(verifyEcdsa(publicKey, input, fromHex(fixture.python_signature_hex))).toBe(true);
    expect(verifyEcdsa(publicKey, input, fromHex(fixture.typescript_signature_hex))).toBe(true);
    expect(toHex(buildSignatureInput(fromHex(fixture.mac_input_hex), fromHex(fixture.hmac_tag_hex)))).toBe(fixture.signature_input_hex);
    expect(fingerprintHex(publicKey)).toBe(fixture.fingerprint_hex);
    expect(formatFingerprint(fixture.fingerprint_hex)).toBe(fixture.fingerprint_hex.slice(0, 16).match(/.{4}/g)!.join(" ").toUpperCase());

  });

  it("rejects bit changes to signature, input, or public key", () => {
    const signature = fromHex(fixture.python_signature_hex), changedSignature = new Uint8Array(signature);
    changedSignature[0] ^= 1;
    const changedInput = new Uint8Array(input); changedInput[0] ^= 1;
    const changedPublic = new Uint8Array(publicKey); changedPublic[1] ^= 1;
    expect(verifyEcdsa(publicKey, input, changedSignature)).toBe(false);
    expect(verifyEcdsa(publicKey, changedInput, signature)).toBe(false);
    expect(verifyEcdsa(changedPublic, input, signature)).toBe(false);
    const order = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    const s = BigInt(`0x${toHex(signature.slice(32))}`);
    const highSValue = s > order / 2n ? s : order - s;
    const highS = new Uint8Array(signature);
    highS.set(fromHex(highSValue.toString(16).padStart(64, "0")), 32);
    expect(verifyEcdsa(publicKey, input, highS)).toBe(true);
  });

  it("returns false for malformed signatures and points without throwing", () => {
    const signature = fromHex(fixture.python_signature_hex);
    for (const malformed of [new Uint8Array(), new Uint8Array(63), new Uint8Array(65), new Uint8Array(64).fill(0xff)]) {
      expect(() => verifyEcdsa(publicKey, input, malformed)).not.toThrow();
      expect(verifyEcdsa(publicKey, input, malformed)).toBe(false);
    }
    expect(verifyEcdsa(new Uint8Array(), input, signature)).toBe(false);
    expect(verifyEcdsa(new Uint8Array(64), input, signature)).toBe(false);
    expect(verifyEcdsa(new Uint8Array(65).fill(0), input, signature)).toBe(false);
    expect(verifyEcdsa(Uint8Array.from([4, ...new Uint8Array(64)]), input, signature)).toBe(false);
    expect(() => parsePublicKeyBytes(Uint8Array.from([4, ...new Uint8Array(64)]))).toThrow("bad_public_key");
  });

  it("generates a fast 32-byte private and uncompressed 65-byte public key pair", () => {
    const pair = generateSigningKeyPair();
    expect(pair.privateKey).toBeInstanceOf(Uint8Array);
    expect(pair.privateKey).toHaveLength(32);
    expect(pair.publicKeyBytes).toHaveLength(65);
    expect(pair.publicKeyBytes[0]).toBe(0x04);
    expect(Number.isFinite(pair.keygenMs)).toBe(true);
    expect(pair.keygenMs).toBeLessThan(100);
    expect(pair.fingerprint).toBe(fingerprintHex(pair.publicKeyBytes));
    const generatedSignature = signEcdsa(pair.privateKey, input);
    expect(generatedSignature).toHaveLength(64);
    expect(verifyEcdsa(pair.publicKeyBytes, input, generatedSignature)).toBe(true);
  });

  it("contains no forge, WebCrypto subtle, or Worker usage under signing", () => {
    const files = ["signature.ts", "keygen.ts", "keyStore.ts", "peerKeys.ts", "api.ts"];
    const contents = files.map((file) => readFileSync(resolve(process.cwd(), `src/signing/${file}`), "utf8")).join("\n");
    expect(contents).not.toMatch(/node-forge|\bforge\b|crypto\.subtle|\bWorker\b/);
  });
});
