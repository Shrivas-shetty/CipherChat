const SESSION_KEY = "cipherchat.session";

export type AuthUser = {
  id: number;
  username: string;
  role: "user" | "analyst";
};

export type AuthSessionData = {
  token: string;
  user: AuthUser;
  expires_at: string;
};

export function loadSession(): AuthSessionData | null {
  try {
    const raw = sessionStorage.getItem(SESSION_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    const token =
      typeof parsed.token === "string"
        ? parsed.token
        : typeof parsed.access_token === "string"
        ? parsed.access_token
        : null;

    if (
      token &&
      parsed.user &&
      typeof parsed.user === "object" &&
      typeof (parsed.user as AuthUser).id === "number" &&
      typeof (parsed.user as AuthUser).username === "string" &&
      ((parsed.user as AuthUser).role === "user" ||
        (parsed.user as AuthUser).role === "analyst") &&
      typeof parsed.expires_at === "string"
    ) {
      return {
        token,
        user: parsed.user as AuthUser,
        expires_at: parsed.expires_at,
      };
    }
  } catch {
    sessionStorage.removeItem(SESSION_KEY);
  }
  return null;
}

export function saveSession(data: AuthSessionData): void {
  sessionStorage.setItem(SESSION_KEY, JSON.stringify(data));
}

export function clearSession(): void {
  sessionStorage.removeItem(SESSION_KEY);
}
