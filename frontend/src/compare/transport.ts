import { handleUnauthorized, ApiError } from "../api/http";
import { httpBase, loadServerAddress } from "../config/serverAddress";
import { loadSession } from "../auth/session";

export type TimedExchangeResult<T = any> = {
  status: number; json: T; reqBytes: number; respBytes: number;
};
export type TimedExchangeOptions = {
  signal?: AbortSignal;
  onFetchStart?: () => void;
  onResponseParsed?: () => void;
};

export class CompareTransportError extends Error {
  status: number;
  code: string;
  data?: unknown;
  constructor(status: number, code: string, data?: unknown) {
    super(code);
    this.name = "CompareTransportError";
    this.status = status; this.code = code; this.data = data;
  }
}

export async function exchange<T = any>(
  method: string,
  path: string,
  bodyObj?: unknown,
  options: TimedExchangeOptions = {},
): Promise<TimedExchangeResult<T>> {
  const body = bodyObj === undefined ? undefined : JSON.stringify(bodyObj);
  const requestBytes = body === undefined ? new Uint8Array() : new TextEncoder().encode(body);
  const headers = new Headers();
  if (body !== undefined) headers.set("Content-Type", "application/json");
  const session = loadSession();
  if (session?.token) headers.set("Authorization", `Bearer ${session.token}`);
  const url = `${httpBase(loadServerAddress())}${path.startsWith("/") ? path : `/${path}`}`;
  options.onFetchStart?.();
  const response = await fetch(url, {
    method,
    headers,
    body,
    signal: options.signal,
  });
  const raw = await response.arrayBuffer();
  const responseBytes = raw.byteLength;
  let parsed: any = null;
  if (responseBytes) {
    try {
      parsed = JSON.parse(new TextDecoder().decode(raw));
    } catch {
      throw new CompareTransportError(response.status, "invalid_response");
    }
  }
  options.onResponseParsed?.();
  if (response.status === 401) {
    const message = "Session expired, please log in again";
    handleUnauthorized(message);
    throw new ApiError(401, message);
  }
  if (!response.ok) {
    const detail = parsed && typeof parsed === "object" ? parsed.detail : null;
    const code = typeof detail === "string" ? detail : detail ? JSON.stringify(detail) : `HTTP ${response.status}`;
    throw new CompareTransportError(response.status, code, parsed);
  }
  return { status: response.status, json: parsed as T, reqBytes: requestBytes.byteLength, respBytes: responseBytes };
}
