import { httpBase, type ServerAddress } from "../config/serverAddress";

export type HealthResponse = {
  status: string;
  server_time: string;
  online_users: number;
};

export async function fetchHealth(
  addr: ServerAddress,
  timeoutMs = 3000
): Promise<HealthResponse> {
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(`${httpBase(addr)}/api/health`, {
      signal: controller.signal,
    });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }
    return (await res.json()) as HealthResponse;
  } finally {
    window.clearTimeout(timer);
  }
}
