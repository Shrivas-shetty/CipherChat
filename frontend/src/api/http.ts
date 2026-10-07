import { clearSession, loadSession } from "../auth/session";
import { httpBase, loadServerAddress } from "../config/serverAddress";

export class ApiError extends Error {
  status: number;
  detail: string;
  retryAfterSeconds?: number;
  data?: unknown;

  constructor(
    status: number,
    detail: string,
    retryAfterSeconds?: number,
    data?: unknown
  ) {
    super(detail);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
    this.retryAfterSeconds = retryAfterSeconds;
    this.data = data;
  }
}

type UnauthorizedListener = (message: string) => void;
let unauthorizedListener: UnauthorizedListener | null = null;

export function setOnUnauthorized(listener: UnauthorizedListener | null): void {
  unauthorizedListener = listener;
}

export type RequestOptions = RequestInit & {
  token?: string;
  skipAuth?: boolean;
};

export async function requestJson<T>(
  path: string,
  options: RequestOptions = {}
): Promise<T> {
  const addr = loadServerAddress();
  const base = httpBase(addr);
  const url = `${base}${path.startsWith("/") ? path : `/${path}`}`;

  const headers = new Headers(options.headers || {});
  if (!headers.has("Content-Type") && options.body && typeof options.body === "string") {
    headers.set("Content-Type", "application/json");
  }

  if (!options.skipAuth && !headers.has("Authorization")) {
    const session = loadSession();
    if (session?.token) {
      headers.set("Authorization", `Bearer ${session.token}`);
    }
  }

  const res = await fetch(url, {
    ...options,
    headers,
  });

  if (res.status === 401) {
    clearSession();
    const sessionExpiredMsg = "Session expired, please log in again";
    unauthorizedListener?.(sessionExpiredMsg);
    throw new ApiError(401, sessionExpiredMsg);
  }

  if (!res.ok) {
    let errorDetail = `HTTP ${res.status}`;
    let retryAfter: number | undefined;
    let data: unknown;

    try {
      data = await res.json();
      if (data && typeof data === "object") {
        const obj = data as Record<string, unknown>;
        if (typeof obj.detail === "string") {
          errorDetail = obj.detail;
        } else if (obj.detail) {
          errorDetail = JSON.stringify(obj.detail);
        }
        if (typeof obj.retry_after_seconds === "number") {
          retryAfter = obj.retry_after_seconds;
        }
      }
    } catch {
      // not JSON
    }

    throw new ApiError(res.status, errorDetail, retryAfter, data);
  }

  if (res.status === 204) {
    return null as unknown as T;
  }

  return (await res.json()) as T;
}

