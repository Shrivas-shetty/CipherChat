import { describe, expect, it } from "vitest";
import { DASHBOARD_CATEGORIES, eventLabel, formatTs, severityClass } from "../labels";

describe("dashboard labels", () => {
  it("maps the named audit events and detail-dependent labels", () => {
    const cases: [string, string, Record<string, unknown>?][] = [
      ["LOGIN_FAILED", "Unauthorized access attempt"], ["LOGIN_LOCKED", "Account locked (too many failures)"],
      ["TOKEN_REJECTED", "Rejected token"], ["TAMPER_DETECTED", "Tampering detected (HMAC failed)"],
      ["MESSAGE_VERIFIED", "Message integrity verified"], ["REGISTER", "User registered"],
      ["LOGIN_SUCCESS", "Login"], ["LOGOUT", "Logout"], ["SESSION_WAITING", "Waiting for peer"],
      ["SESSION_STARTED", "Session started"], ["KEY_EXCHANGE_OK", "Key exchange completed"],
      ["KEY_EXCHANGE_FAILED", "Key exchange FAILED"], ["ROOM_FULL", "Room full (extra user refused)"],
      ["MESSAGE_SENT", "Message sent (image)", { msg_type: "image" }],
      ["SESSION_ENDED", "Session ended (logout)", { reason: "logout" }],
      ["ODD_EVENT_NAME", "Odd Event Name"],
      ["METRICS_REJECTED", "Metrics rejected (invalid data)"],
      ["LAB_DATA_CLEARED", "Lab data cleared"],
    ];
    for (const [type, expected, details] of cases) expect(eventLabel(type, details)).toBe(expected);
    expect(eventLabel("LAB_DATA_CLEARED", { table: "image_metrics" })).toBe("Lab data cleared (image metrics)");
    expect(eventLabel("LAB_DATA_CLEARED", { table: "text_metrics" })).toBe("Lab data cleared (text metrics)");
    expect(eventLabel("MESSAGE_SENT", { msg_type: "text" })).toBe("Message sent (text)");
  });
  it("maps severity styles and formats UTC timestamps locally", () => {
    expect(severityClass("info")).toBe("severity-info");
    expect(severityClass("warning")).toBe("severity-warning");
    expect(severityClass("alert")).toBe("severity-alert");
    expect(formatTs("2024-01-01T00:00:00Z")).toBe(new Date("2024-01-01T00:00:00Z").toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }));
  });
  it("keeps category values unique", () => {
    expect(new Set(DASHBOARD_CATEGORIES).size).toBe(DASHBOARD_CATEGORIES.length);
    expect(DASHBOARD_CATEGORIES).toContain("lab");
  });
});
