import type { ImageLabRecord } from "../../api";
import { mean } from "../../../analysis/stats";

const average = (values: (number | null)[]) => {
  const present = values.filter((value): value is number => value !== null);
  return present.length ? mean(present) : null;
};
const show = (value: number | null) => value === null ? "n/a" : value.toFixed(4);
export function ImageSummaryCards({ records, total }: { records: ImageLabRecord[]; total: number }) {
  const failed = records.filter((row) => row.mse_dec !== 0).length;
  const cards: [string, string, boolean?][] = [
    ["Image records", String(total)], ["Mean NPCR", `${(average(records.map((r) => r.npcr_pct)) ?? 0).toFixed(2)}%`],
    ["Mean UACI", `${(average(records.map((r) => r.uaci_pct)) ?? 0).toFixed(2)}%`], ["Mean entropy", show(average(records.map((r) => r.entropy_avg)))],
    ["Mean plaintext correlation", show(average(records.map((r) => r.corr_pt_avg)))], ["Mean cipher correlation", show(average(records.map((r) => r.corr_ct_avg)))],
    ["Lossless failures", String(failed), failed > 0], ["Mean AES time", `${((average(records.map((r) => r.enc_us)) ?? 0) / 1000).toFixed(3)} / ${((average(records.map((r) => r.dec_us)) ?? 0) / 1000).toFixed(3)} ms enc / dec`],
  ];
  return <div className="dash-cards image-lab-cards">{cards.map(([label, value, bad]) => <div className={bad ? "failed-card" : ""} key={label}><small>{label}</small><b>{value}</b></div>)}</div>;
}
