import { useState } from "react";
import { fetchHealth } from "../api/health";
import {
  saveServerAddress,
  type ServerAddress,
} from "../config/serverAddress";

type Props = {
  value: ServerAddress;
  onChange: (addr: ServerAddress) => void;
};

function clampOctet(n: number): number {
  if (Number.isNaN(n)) return 0;
  return Math.min(255, Math.max(0, n));
}

function parseIp(ip: string): [number, number, number, number] {
  const parts = ip.split(".");
  const octets = [0, 0, 0, 0] as [number, number, number, number];
  for (let i = 0; i < 4; i++) {
    const n = Number.parseInt(parts[i] ?? "0", 10);
    octets[i] = clampOctet(Number.isNaN(n) ? 0 : n);
  }
  return octets;
}

export function ServerAddressInput({ value, onChange }: Props) {
  const [octets, setOctets] = useState<[number, number, number, number]>(() =>
    parseIp(value.ip)
  );
  const [port, setPort] = useState<number>(value.port);
  const [testMsg, setTestMsg] = useState<string | null>(null);
  const [testOk, setTestOk] = useState<boolean | null>(null);
  const [testing, setTesting] = useState(false);

  function emit(nextOctets: [number, number, number, number], nextPort: number) {
    const addr: ServerAddress = {
      ip: nextOctets.join("."),
      port: nextPort,
    };
    onChange(addr);
    saveServerAddress(addr);
  }

  function updateOctet(index: number, raw: string) {
    const n = clampOctet(Number.parseInt(raw, 10) || 0);
    const next: [number, number, number, number] = [...octets];
    next[index] = n;
    setOctets(next);
    emit(next, port);
  }

  function updatePort(raw: string) {
    let n = Number.parseInt(raw, 10);
    if (Number.isNaN(n)) n = 8000;
    n = Math.min(65535, Math.max(1, n));
    setPort(n);
    emit(octets, n);
  }

  function useLocalhost() {
    const next: [number, number, number, number] = [127, 0, 0, 1];
    setOctets(next);
    setPort(8000);
    emit(next, 8000);
    setTestMsg(null);
    setTestOk(null);
  }

  async function testConnection() {
    const addr: ServerAddress = { ip: octets.join("."), port };
    setTesting(true);
    setTestMsg(null);
    setTestOk(null);
    try {
      const health = await fetchHealth(addr);
      setTestOk(true);
      setTestMsg(
        `Connected — status ${health.status}, online users: ${health.online_users}`
      );
    } catch {
      setTestOk(false);
      setTestMsg(
        "Could not reach server. Check IP, port, that the backend is running, and firewall settings."
      );
    } finally {
      setTesting(false);
    }
  }

  return (
    <div className="server-address">
      <label className="field-label">Server address</label>
      <div className="ip-row">
        {octets.map((o, i) => (
          <span key={i} className="octet-wrap">
            <input
              className="octet"
              type="number"
              min={0}
              max={255}
              value={o}
              onChange={(e) => updateOctet(i, e.target.value)}
              aria-label={`IP octet ${i + 1}`}
            />
            {i < 3 ? <span className="dot">.</span> : null}
          </span>
        ))}
        <span className="port-sep">:</span>
        <input
          className="port"
          type="number"
          min={1}
          max={65535}
          value={port}
          onChange={(e) => updatePort(e.target.value)}
          aria-label="Port"
        />
      </div>
      <div className="btn-row">
        <button type="button" className="btn secondary" onClick={useLocalhost}>
          Use this device (localhost)
        </button>
        <button
          type="button"
          className="btn secondary"
          onClick={() => void testConnection()}
          disabled={testing}
        >
          {testing ? "Testing…" : "Test connection"}
        </button>
      </div>
      {testMsg ? (
        <p className={testOk ? "msg ok" : "msg err"} role="status">
          {testMsg}
        </p>
      ) : null}
    </div>
  );
}
