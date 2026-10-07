import { useState, type FormEvent } from "react";
import { ServerAddressInput } from "../components/ServerAddressInput";
import type { ServerAddress } from "../config/serverAddress";

type Props = {
  serverAddress: ServerAddress;
  onServerAddressChange: (addr: ServerAddress) => void;
  onJoin: (displayName: string) => void;
  joining: boolean;
  error: string | null;
};

export function ConnectPage({
  serverAddress,
  onServerAddressChange,
  onJoin,
  joining,
  error,
}: Props) {
  const [name, setName] = useState("");
  const [localError, setLocalError] = useState<string | null>(null);

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    const trimmed = name.trim();
    if (trimmed.length < 1 || trimmed.length > 20) {
      setLocalError("Display name must be 1–20 characters.");
      return;
    }
    setLocalError(null);
    onJoin(trimmed);
  }

  const shownError = localError ?? error;

  return (
    <div className="page connect-page">
      <header className="brand">
        <h1>CipherChat</h1>
        <p className="subtitle">Two-user LAN chat — Phase 1</p>
      </header>

      <form className="panel" onSubmit={handleSubmit}>
        <ServerAddressInput
          value={serverAddress}
          onChange={onServerAddressChange}
        />

        <label className="field-label" htmlFor="display-name">
          Display name
        </label>
        <input
          id="display-name"
          className="text-input"
          type="text"
          maxLength={20}
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="1–20 characters"
          autoComplete="nickname"
        />

        {shownError ? (
          <p className="msg err" role="alert">
            {shownError}
          </p>
        ) : null}

        <button type="submit" className="btn primary" disabled={joining}>
          {joining ? "Joining…" : "Join"}
        </button>
      </form>
    </div>
  );
}
