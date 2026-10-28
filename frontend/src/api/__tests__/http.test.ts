import { afterEach, describe, expect, it, vi } from "vitest";
import { requestJson, setOnUnauthorized } from "../http";

describe("requestJson authentication errors", () => {
  afterEach(() => {
    setOnUnauthorized(null);
    vi.unstubAllGlobals();
  });

  it("preserves invalid-credential details for login requests", async () => {
    vi.stubGlobal("localStorage", { getItem: () => null });
    vi.stubGlobal("sessionStorage", { getItem: () => null, removeItem: vi.fn() });
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      json: async () => ({ detail: "Invalid username or password" }),
    }));
    const onUnauthorized = vi.fn();
    setOnUnauthorized(onUnauthorized);

    await expect(requestJson("/api/auth/login", {
      method: "POST",
      skipAuth: true,
      skipUnauthorizedHandling: true,
      body: JSON.stringify({ username: "unknown", password: "incorrect" }),
    })).rejects.toMatchObject({
      name: "ApiError",
      status: 401,
      detail: "Invalid username or password",
    });
    expect(onUnauthorized).not.toHaveBeenCalled();
  });

  it("still treats other unauthorized responses as an expired session", async () => {
    vi.stubGlobal("localStorage", { getItem: () => null });
    vi.stubGlobal("sessionStorage", { getItem: () => null, removeItem: vi.fn() });
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      json: async () => ({ detail: "Not authenticated" }),
    }));
    const onUnauthorized = vi.fn();
    setOnUnauthorized(onUnauthorized);

    await expect(requestJson("/api/auth/me")).rejects.toMatchObject({
      name: "ApiError",
      status: 401,
      detail: "Session expired, please log in again",
    });
    expect(onUnauthorized).toHaveBeenCalledOnce();
  });
});
