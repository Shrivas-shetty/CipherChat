import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import { requestJson, setOnUnauthorized } from "../api/http";
import {
  clearSession,
  loadSession,
  saveSession,
  type AuthSessionData,
  type AuthUser,
} from "./session";

type AuthContextType = {
  user: AuthUser | null;
  token: string | null;
  loading: boolean;
  authError: string | null;
  setAuthError: (err: string | null) => void;
  loginSuccess: (session: AuthSessionData) => void;
  logout: () => Promise<void>;
};

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<AuthSessionData | null>(() => loadSession());
  const [loading, setLoading] = useState(true);
  const [authError, setAuthError] = useState<string | null>(null);

  const handleUnauthorized = useCallback((message: string) => {
    setSession(null);
    clearSession();
    setAuthError(message);
  }, []);

  useEffect(() => {
    setOnUnauthorized(handleUnauthorized);
    return () => {
      setOnUnauthorized(null);
    };
  }, [handleUnauthorized]);

  useEffect(() => {
    async function verifyInitialSession() {
      const stored = loadSession();
      if (!stored?.token) {
        setLoading(false);
        return;
      }

      try {
        const me = await requestJson<AuthUser>("/api/auth/me");
        setSession({
          token: stored.token,
          user: me,
          expires_at: stored.expires_at,
        });
      } catch {
        clearSession();
        setSession(null);
        setAuthError("Session expired, please log in again");
      } finally {
        setLoading(false);
      }
    }

    void verifyInitialSession();
  }, []);

  const loginSuccess = useCallback((newSession: AuthSessionData) => {
    saveSession(newSession);
    setSession(newSession);
    setAuthError(null);
  }, []);

  const logout = useCallback(async () => {
    try {
      if (session?.token) {
        await requestJson("/api/auth/logout", {
          method: "POST",
        });
      }
    } catch {
      // ignore network errors on logout
    } finally {
      clearSession();
      setSession(null);
      setAuthError(null);
    }
  }, [session]);

  return (
    <AuthContext.Provider
      value={{
        user: session?.user ?? null,
        token: session?.token ?? null,
        loading,
        authError,
        setAuthError,
        loginSuccess,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextType {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return ctx;
}

