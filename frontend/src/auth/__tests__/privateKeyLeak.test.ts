import { afterEach, describe, expect, it, vi } from "vitest";
import { generateSigningKeyPair } from "../../signing/keygen";
import { keyStore } from "../../signing/keyStore";
import { registerSigningKey } from "../../signing/api";
import { MessageService } from "../../chat/messageService";
import { requestJson } from "../../api/http";
import { saveSession } from "../session";
import { setSessionKeys, clearSessionKeys } from "../../crypto/sessionKeys";

afterEach(() => { keyStore.clear(); clearSessionKeys(); vi.unstubAllGlobals(); });

describe("signing private-key request boundary", () => {
  it("sends only public signing material during registration, messaging, and logout", async () => {
    const storage = new Map<string, string>();
    const sessionStorage = {
      getItem: (key: string) => storage.get(key) ?? null,
      setItem: (key: string, value: string) => { storage.set(key, value); },
      removeItem: (key: string) => { storage.delete(key); },
    };
    vi.stubGlobal("sessionStorage", sessionStorage);
    vi.stubGlobal("localStorage", sessionStorage);
    saveSession({ token: "test-token", user: { id: 1, username: "alice", role: "user" }, expires_at: "2099-01-01T00:00:00Z" });

    const pair = generateSigningKeyPair();
    const privateForms = [Buffer.from(pair.privateKey).toString("hex"), Buffer.from(pair.privateKey).toString("base64"),
      Buffer.from(pair.privateKey).toString("base64url")];
    const bodies: string[] = [];
    vi.stubGlobal("fetch", vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      bodies.push(typeof init?.body === "string" ? init.body : "");
      if (bodies.length === 1) return new Response(JSON.stringify({ id: 4, fingerprint: pair.fingerprint, created_at: "2026-01-01T00:00:00Z" }), { status: 201 });
      if (bodies.length === 2) return new Response(JSON.stringify({ id: 8, created_at: "2026-01-01T00:00:01Z" }), { status: 201 });
      return new Response(null, { status: 204 });
    }));

    const registration = await registerSigningKey({ public_key_b64: pair.publicKeyB64, keygen_ms: pair.keygenMs });
    keyStore.set({ privateKey: pair.privateKey, publicKeyB64: pair.publicKeyB64, fingerprint: registration.fingerprint, keyId: registration.id, keygenMs: pair.keygenMs });
    setSessionKeys({ sessionId: "00000000-0000-4000-8000-000000000001", fingerprint: "test", kEnc: new Uint8Array(32).fill(1), kMac: new Uint8Array(32).fill(2) });
    await new MessageService().sendText("hello", "alice", "I");
    await requestJson("/api/auth/logout", { method: "POST" });

    const registrationBody = JSON.parse(bodies[0]) as Record<string, unknown>;
    expect(Object.keys(registrationBody).sort()).toEqual(["keygen_ms", "public_key_b64"]);
    expect(bodies).toHaveLength(3);
    for (const body of bodies) {
      expect(body).not.toContain("PRIVATE KEY");
      expect(body).not.toContain("privateKey");
      expect(body).not.toContain("private_key");
      for (const form of privateForms) expect(body).not.toContain(form);
    }
    keyStore.clear();
    expect(pair.privateKey.every((byte) => byte === 0)).toBe(true);
  });
});
