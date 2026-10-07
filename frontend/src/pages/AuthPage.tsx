import { useEffect, useState, type FormEvent } from "react";
import { ApiError, requestJson } from "../api/http";
import { useAuth } from "../auth/AuthContext";
import type { AuthUser } from "../auth/session";
import { ServerAddressInput } from "../components/ServerAddressInput";
import type { ServerAddress } from "../config/serverAddress";

type Props = {
  serverAddress: ServerAddress;
  onServerAddressChange: (addr: ServerAddress) => void;
};

type Mode = "login" | "register";

function getByteLength(str: string): number {
  return new TextEncoder().encode(str).length;
}

export function AuthPage({ serverAddress, onServerAddressChange }: Props) {
  const { authError, setAuthError, loginSuccess } = useAuth();
  const [mode, setMode] = useState<Mode>("login");

  // Form fields
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  // UI state
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [lockoutSeconds, setLockoutSeconds] = useState<number | null>(null);

  // Field validation errors
  const [usernameError, setUsernameError] = useState<string | null>(null);
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [confirmError, setConfirmError] = useState<string | null>(null);

  // Countdown timer for 429 lockout
  useEffect(() => {
    if (lockoutSeconds === null || lockoutSeconds <= 0) return;
    const interval = window.setInterval(() => {
      setLockoutSeconds((prev) => {
        if (prev === null || prev <= 1) return null;
        return prev - 1;
      });
    }, 1000);
    return () => window.clearInterval(interval);
  }, [lockoutSeconds]);

  function switchMode(newMode: Mode) {
    setMode(newMode);
    setFormError(null);
    setAuthError(null);
    setUsernameError(null);
    setPasswordError(null);
    setConfirmError(null);
  }

  function validateRegisterFields(): boolean {
    let valid = true;
    const u = username.trim();
    if (!/^[A-Za-z0-9_]{3,20}$/.test(u)) {
      setUsernameError("Username must be 3–20 characters (letters, numbers, underscores).");
      valid = false;
    } else {
      setUsernameError(null);
    }

    const byteLen = getByteLength(password);
    if (byteLen < 8 || byteLen > 72) {
      setPasswordError("Password must be 8–72 bytes.");
      valid = false;
    } else if (!/[A-Za-z]/.test(password)) {
      setPasswordError("Password must contain at least one letter.");
      valid = false;
    } else if (!/\d/.test(password)) {
      setPasswordError("Password must contain at least one digit.");
      valid = false;
    } else {
      setPasswordError(null);
    }

    if (password !== confirmPassword) {
      setConfirmError("Passwords do not match.");
      valid = false;
    } else {
      setConfirmError(null);
    }

    return valid;
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setFormError(null);
    setAuthError(null);

    const trimmedUser = username.trim();
    if (!trimmedUser || !password) {
      setFormError("Please fill in all required fields.");
      return;
    }

    if (mode === "register") {
      if (!validateRegisterFields()) {
        return;
      }
    }

    setSubmitting(true);
    try {
      if (mode === "register") {
        // 1. Call register
        await requestJson<AuthUser>("/api/auth/register", {
          method: "POST",
          body: JSON.stringify({
            username: trimmedUser,
            password,
          }),
        });

        // 2. Automatically log in after registration
        const loginData = await requestJson<{
          access_token?: string;
          token?: string;
          user: AuthUser;
          expires_at: string;
        }>("/api/auth/login", {
          method: "POST",
          body: JSON.stringify({
            username: trimmedUser,
            password,
          }),
        });
        const token = loginData.token || loginData.access_token;
        if (!token) {
          throw new Error("Missing token in login response");
        }
        loginSuccess({
          token,
          user: loginData.user,
          expires_at: loginData.expires_at,
        });
      } else {
        // Login mode
        const loginData = await requestJson<{
          access_token?: string;
          token?: string;
          user: AuthUser;
          expires_at: string;
        }>("/api/auth/login", {
          method: "POST",
          body: JSON.stringify({
            username: trimmedUser,
            password,
          }),
        });
        const token = loginData.token || loginData.access_token;
        if (!token) {
          throw new Error("Missing token in login response");
        }
        loginSuccess({
          token,
          user: loginData.user,
          expires_at: loginData.expires_at,
        });
      }
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        if (err.status === 429 && typeof err.retryAfterSeconds === "number") {
          setLockoutSeconds(err.retryAfterSeconds);
        } else {
          setFormError(err.detail);
        }
      } else {
        setFormError("Could not connect to server. Check IP and port.");
      }
    } finally {
      setSubmitting(false);
    }
  }

  const activeError =
    lockoutSeconds !== null && lockoutSeconds > 0
      ? `Too many attempts, try again in ${lockoutSeconds} seconds`
      : formError || authError;

  return (
    <div className="page connect-page">
      <header className="brand">
        <h1>CipherChat</h1>
        <p className="subtitle">Secure Local Messaging — Phase 2</p>
      </header>

      <div className="panel auth-panel">
        <ServerAddressInput
          value={serverAddress}
          onChange={onServerAddressChange}
        />

        <div className="auth-tabs" role="tablist">
          <button
            type="button"
            className={`tab-btn ${mode === "login" ? "active" : ""}`}
            onClick={() => switchMode("login")}
            role="tab"
            aria-selected={mode === "login"}
          >
            Log In
          </button>
          <button
            type="button"
            className={`tab-btn ${mode === "register" ? "active" : ""}`}
            onClick={() => switchMode("register")}
            role="tab"
            aria-selected={mode === "register"}
          >
            Register
          </button>
        </div>

        <form onSubmit={handleSubmit} className="auth-form" noValidate>
          <div className="field-group">
            <label className="field-label" htmlFor="auth-username">
              Username
            </label>
            <input
              id="auth-username"
              className={`text-input ${usernameError ? "input-err" : ""}`}
              type="text"
              maxLength={20}
              value={username}
              onChange={(e) => {
                setUsername(e.target.value);
                if (usernameError) setUsernameError(null);
              }}
              placeholder="3–20 characters"
              autoComplete="username"
              required
            />
            {usernameError ? <p className="field-err">{usernameError}</p> : null}
          </div>

          <div className="field-group">
            <label className="field-label" htmlFor="auth-password">
              Password
            </label>
            <input
              id="auth-password"
              className={`text-input ${passwordError ? "input-err" : ""}`}
              type="password"
              maxLength={72}
              value={password}
              onChange={(e) => {
                setPassword(e.target.value);
                if (passwordError) setPasswordError(null);
              }}
              placeholder="At least 8 chars, 1 letter, 1 digit"
              autoComplete={mode === "login" ? "current-password" : "new-password"}
              required
            />
            {passwordError ? <p className="field-err">{passwordError}</p> : null}
          </div>

          {mode === "register" ? (
            <div className="field-group">
              <label className="field-label" htmlFor="auth-confirm">
                Confirm Password
              </label>
              <input
                id="auth-confirm"
                className={`text-input ${confirmError ? "input-err" : ""}`}
                type="password"
                maxLength={72}
                value={confirmPassword}
                onChange={(e) => {
                  setConfirmPassword(e.target.value);
                  if (confirmError) setConfirmError(null);
                }}
                placeholder="Re-enter your password"
                autoComplete="new-password"
                required
              />
              {confirmError ? <p className="field-err">{confirmError}</p> : null}
            </div>
          ) : null}

          {activeError ? (
            <p className="msg err" role="alert">
              {activeError}
            </p>
          ) : null}

          <button
            type="submit"
            className="btn primary"
            disabled={submitting || (lockoutSeconds !== null && lockoutSeconds > 0)}
          >
            {submitting
              ? mode === "register"
                ? "Registering…"
                : "Signing in…"
              : mode === "register"
              ? "Create Account"
              : "Sign In"}
          </button>
        </form>
      </div>
    </div>
  );
}

