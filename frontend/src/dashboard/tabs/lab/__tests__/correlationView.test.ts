import { describe, expect, it } from "vitest";
import type { ImageLabRecord } from "../../../api";
import { correlationAverages, prePhaseRecords } from "../correlationView";
const record = (patch: Partial<ImageLabRecord> = {}): ImageLabRecord => ({
  id: 1, message_id: 1, session_id: "x", sender: null, message_created_at: null, created_at: "", width: 2, height: 2, n_pixels: 4, pt_len_bytes: 12, ct_len_bytes: 16,
  npcr_trials: 1, npcr_pct: 1, npcr_trial_pcts: [1], npcr_changed_counts: [1], uaci_pct: 1, uaci_trial_pcts: [1], flip_byte_idx: [0],
  entropy_r: 1, entropy_g: 1, entropy_b: 1, entropy_avg: 1,
  corr_pt_r: .2, corr_pt_g: null, corr_pt_b: .4, corr_pt_avg: .3, corr_ct_r: .1, corr_ct_g: .2, corr_ct_b: .3, corr_ct_avg: .2,
  corr_v_pt_r: null, corr_v_pt_g: null, corr_v_pt_b: null, corr_v_pt_avg: null, corr_v_ct_r: null, corr_v_ct_g: null, corr_v_ct_b: null, corr_v_ct_avg: null,
  corr_d_pt_r: null, corr_d_pt_g: null, corr_d_pt_b: null, corr_d_pt_avg: null, corr_d_ct_r: null, corr_d_ct_g: null, corr_d_ct_b: null, corr_d_ct_avg: null,
  mse_dec: 0, psnr_dec: null, mse_enc: 1, psnr_enc: 1, enc_us: 1, dec_us: 1, timing_iters: 1, ...patch,
});
describe("Image Lab correlation view helpers", () => {
  it("averages only non-null values and counts old directional records", () => {
    const rows = [record({ corr_v_pt_r: .8, corr_v_pt_g: .6 }), record(), record({ width: 1 })];
    expect(correlationAverages(rows, "v")[0]).toBe(.8);
    expect(prePhaseRecords(rows, "v")).toBe(2);
    expect(prePhaseRecords(rows, "d")).toBe(2);
  });
});
