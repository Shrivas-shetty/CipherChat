import { describe, expect, it } from "vitest";
import { sortTextRecords } from "../recordsTable";
import type { TextLabRecord } from "../../../api";
import { linearRegression, regressionLineEnds } from "../../../../analysis/stats";

const row = (message_id: number, pt_len_bytes: number): TextLabRecord => ({ id: message_id, message_id, session_id: "s", sender: "alice", message_created_at: null, pt_len_bytes, ct_len_bytes: 16, ct_preview_hex: "", total_ct_bits: 128, key_trials: 8, confusion_pct: 50, key_flip_pcts: [], pt_trials: 8, diffusion_bits: 64, avalanche_pct: 50, block_avalanche_pct: 50, pt_flip_bit_idx: [], pt_flip_changed_bits: [], pt_flip_block_changed_bits: [], enc_us: 1, dec_us: 2, timing_iters: 1, created_at: "2024-01-01T00:00:00Z" });
describe("text metric record utilities", () => {
  it("sorts without changing the source rows", () => { const rows = [row(2, 50), row(1, 10)]; expect(sortTextRecords(rows, "pt_len_bytes", "asc").map((r) => r.message_id)).toEqual([1, 2]); expect(rows[0].message_id).toBe(2); });
  it("returns OLS endpoints at the observed X extrema", () => { const points = [{ x: 1, y: 2 }, { x: 3, y: 6 }]; expect(regressionLineEnds(points, linearRegression(points))).toEqual([{ x: 1, y: 2 }, { x: 3, y: 6 }]); });
});
