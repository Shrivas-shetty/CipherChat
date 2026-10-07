const STORAGE_KEY = "cipherchat.serverAddress";

export type ServerAddress = {
  ip: string;
  port: number;
};

function isIpv4(value: string): boolean {
  const parts = value.split(".");
  if (parts.length !== 4) return false;
  return parts.every((p) => {
    if (!/^\d{1,3}$/.test(p)) return false;
    const n = Number(p);
    return n >= 0 && n <= 255;
  });
}

function defaultAddress(): ServerAddress {
  const hostname =
    typeof window !== "undefined" && window.location.hostname
      ? window.location.hostname
      : "127.0.0.1";
  if (hostname === "localhost" || !isIpv4(hostname)) {
    return { ip: "127.0.0.1", port: 8000 };
  }
  return { ip: hostname, port: 8000 };
}

export function loadServerAddress(): ServerAddress {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return defaultAddress();
    const parsed = JSON.parse(raw) as Partial<ServerAddress>;
    if (typeof parsed.ip === "string" && typeof parsed.port === "number") {
      return { ip: parsed.ip, port: parsed.port };
    }
  } catch {
    // fall through
  }
  return defaultAddress();
}

export function saveServerAddress(addr: ServerAddress): void {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(addr));
}

export function httpBase(addr: ServerAddress = loadServerAddress()): string {
  return `http://${addr.ip}:${addr.port}`;
}

export function wsUrl(addr: ServerAddress = loadServerAddress()): string {
  return `ws://${addr.ip}:${addr.port}/ws`;
}
