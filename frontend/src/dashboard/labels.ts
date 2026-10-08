export const DASHBOARD_CATEGORIES = ["all", "auth", "session", "message", "demo", "lab"] as const;

export function eventLabel(eventType: string, details?: Record<string, unknown> | null): string {
  switch (eventType) {
    case "LOGIN_FAILED": return "Unauthorized access attempt";
    case "LOGIN_LOCKED": return "Account locked (too many failures)";
    case "TOKEN_REJECTED": return "Rejected token";
    case "TAMPER_DETECTED": return "Tampering detected (HMAC failed)";
    case "MESSAGE_VERIFIED": return "Message integrity verified";
    case "MESSAGE_SENT": return `Message sent (${details?.msg_type === "image" ? "image" : "text"})`;
    case "REGISTER": return "User registered";
    case "LOGIN_SUCCESS": return "Login";
    case "LOGOUT": return "Logout";
    case "SESSION_WAITING": return "Waiting for peer";
    case "SESSION_STARTED": return "Session started";
    case "KEY_EXCHANGE_OK": return "Key exchange completed";
    case "KEY_EXCHANGE_FAILED": return "Key exchange FAILED";
    case "SESSION_ENDED": return `Session ended (${String(details?.reason ?? "unknown")})`;
    case "ROOM_FULL": return "Room full (extra user refused)";
    case "METRICS_REJECTED": return "Metrics rejected (invalid data)";
    case "LAB_DATA_CLEARED": return details?.table === "image_metrics" ? "Lab data cleared (image metrics)" : details?.table === "text_metrics" ? "Lab data cleared (text metrics)" : "Lab data cleared";
    default: return eventType.toLowerCase().split("_").map((part) => part ? part[0].toUpperCase() + part.slice(1) : "").join(" ");
  }
}

export function severityClass(severity: string): string {
  return severity === "alert" ? "severity-alert" : severity === "warning" ? "severity-warning" : "severity-info";
}

export function formatTs(iso: string): string {
  return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}
