import { afterEach, describe, expect, it, vi } from "vitest";
import { ChatSocket } from "../chatSocket";

class FakeWebSocket {
  static OPEN = 1;
  static CLOSED = 3;
  readyState = 0;
  onopen: (() => void) | null = null;
  onclose: ((event: CloseEvent) => void) | null = null;
  onerror: ((event: Event) => void) | null = null;
  onmessage: ((event: MessageEvent) => void) | null = null;
  send = vi.fn();
  close = vi.fn();
  constructor(_url: string) { latestSocket = this; }
}
let latestSocket: FakeWebSocket;

describe("ChatSocket unknown frame handling", () => {
  afterEach(() => vi.unstubAllGlobals());
  it("ignores baseline_available and unknown future frames without surfacing errors", () => {
    vi.stubGlobal("WebSocket", FakeWebSocket);
    const client = new ChatSocket();
    const onFrame = vi.fn();
    const onError = vi.fn();
    client.setHandlers({ onFrame, onError });
    client.connect({ ip: "127.0.0.1", port: 8000 }, "token");
    latestSocket.onmessage?.({ data: JSON.stringify({ v: 1, type: "baseline_available", session_id: "sid", message_id: 7, kind: "text" }) } as MessageEvent);
    latestSocket.onmessage?.({ data: JSON.stringify({ v: 1, type: "not_in_protocol_yet" }) } as MessageEvent);
    expect(onFrame).not.toHaveBeenCalled();
    expect(onError).not.toHaveBeenCalled();
  });
});
