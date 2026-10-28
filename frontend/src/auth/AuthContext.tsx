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
import { generateSigningKeyPair } from "../signing/keygen";
import { keyStore } from "../signing/keyStore";
import { registerSigningKey } from "../signing/api";
import { clearPeerKeys } from "../signing/peerKeys";

type SigningStatus = "idle" | "generating" | "ready" | "error";
let pendingKeyGeneration: Promise<void> | null = null;

type AuthContextType = {
  user: AuthUser | null;
  token: string | null;
  loading: boolean;
  authError: string | null;
  setAuthError: (err: string | null) => void;
  loginSuccess: (session: AuthSessionData) => void;
  logout: () => Promise<void>;
  signingStatus: SigningStatus;
  retrySigningKeys: () => void;
};

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<AuthSessionData | null>(() => loadSession());
  const [loading, setLoading] = useState(true);
  const [authError, setAuthError] = useState<string | null>(null);
  const [signingStatus, setSigningStatus] = useState<SigningStatus>("idle");
  const [signingAttempt, setSigningAttempt] = useState(0);

  const handleUnauthorized = useCallback((message: string) => {
    keyStore.clear(); clearPeerKeys(); pendingKeyGeneration = null; setSigningStatus("idle");
    setSession(null);
    clearSession();
    setAuthError(message);
  }, []);

  useEffect(() => {
    if (loading) return;
    if (!session || session.user.role !== "user") {
      keyStore.clear(); clearPeerKeys(); setSigningStatus("idle"); pendingKeyGeneration = null;
      return;
    }
    let active = true;
    setSigningStatus("generating");
    if (!pendingKeyGeneration) {
      pendingKeyGeneration = (async () => {
        const pair = await generateSigningKeyPair();
        try {
          const registered = await registerSigningKey({ public_key_b64: pair.publicKeyB64, keygen_ms: pair.keygenMs });
          keyStore.set({ privateKey: pair.privateKey, publicKeyB64: pair.publicKeyB64, fingerprint: registered.fingerprint, keyId: registered.id, keygenMs: pair.keygenMs });
        } catch (error) {
          pair.privateKey.fill(0);
          throw error;
        }
      })().finally(() => { pendingKeyGeneration = null; });
    }
    pendingKeyGeneration.then(() => { if (active) setSigningStatus("ready"); }).catch(() => { if (active) setSigningStatus("error"); });
    return () => { active = false; };
  }, [loading, session?.token, session?.user.role, signingAttempt]);

  useEffect(() => () => { keyStore.clear(); clearPeerKeys(); pendingKeyGeneration = null; }, []);

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
      keyStore.clear(); clearPeerKeys(); pendingKeyGeneration = null; setSigningStatus("idle");
      clearSession();
      setSession(null);
      setAuthError(null);
    }
  }, [session]);

  const retrySigningKeys = useCallback(() => { keyStore.clear(); clearPeerKeys(); pendingKeyGeneration = null; setSigningAttempt((value) => value + 1); }, []);

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
        signingStatus,
        retrySigningKeys,
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

