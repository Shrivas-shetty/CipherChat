import { describe, expect, it } from "vitest";
import type { BenchSample } from "../../api";
import { groupSamples, mean, median, overheadRows, percentile, stddev, summarize } from "../aggregate";

function sample(mode: "secure" | "plain", kind: "text" | "image", size: number, e2e: number, bytes: number): BenchSample {
  return { id: size, seq: size, mode, kind, size_param: size, plaintext_bytes: kind === "text" ? size : size * size * 3,
    crypto_send_ms: 1, to_notify_ms: e2e - 3, fetch_ms: 1, crypto_recv_ms: 1, e2e_ms: e2e,
    post_ms: 2, verify_post_ms: mode === "secure" ? 0.5 : null, bytes_up: bytes, bytes_down: bytes + 5, ws_notify_bytes: 80 };
}

describe("performance aggregates", () => {
  it("uses mean, median and nearest-rank percentile, including small/even samples", () => {
    expect(mean([1, 2, 3, 4])).toBe(2.5);
    expect(median([1, 2, 3, 4])).toBe(2.5);
    expect(percentile(Array.from({ length: 20 }, (_, i) => i + 1), 0.95)).toBe(19);
    expect(percentile([7], 0.95)).toBe(7);
    expect(stddev([2, 2, 2])).toBe(0);
  });
  it("groups samples and calculates paired and missing-plain overhead", () => {
    const groups = groupSamples([sample("secure", "text", 16, 10, 180), sample("plain", "text", 16, 5, 80), sample("secure", "text", 64, 15, 250)]);
    expect(groups).toHaveLength(3);
    const rows = overheadRows(groups.map(summarize));
    expect(rows.find(x => x.size_param === 16)?.overheadMs).toBe(5);
    expect(rows.find(x => x.size_param === 16)?.overheadPct).toBe(100);
    expect(rows.find(x => x.size_param === 64)?.plainMean).toBeNull();
    expect(rows.find(x => x.size_param === 64)?.byteOverheadPct).toBeNull();
  });
  it("has four non-overlapping segments whose sum matches e2e", () => {
    const row = sample("secure", "image", 8, 29, 900);
    expect(row.crypto_send_ms + row.to_notify_ms + row.fetch_ms + row.crypto_recv_ms).toBe(row.e2e_ms);
  });
});
