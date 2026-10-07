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
    const parsed = JSON.parse(raw) as Partial<AuthSessionData>;
    if (
      typeof parsed.token === "string" &&
      parsed.user &&
      typeof parsed.user.id === "number" &&
      typeof parsed.user.username === "string" &&
      (parsed.user.role === "user" || parsed.user.role === "analyst") &&
      typeof parsed.expires_at === "string"
    ) {
      return {
        token: parsed.token,
        user: parsed.user,
        expires_at: parsed.expires_at,
      };
    }
  } catch {
    // ignore parse error and clear corrupt data
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

