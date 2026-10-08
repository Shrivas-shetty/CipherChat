import type { TextLabRecord } from "../../api";
import { mean } from "../../../analysis/stats";

export function TextSummaryCards({ records, total = records.length }: { records: TextLabRecord[]; total?: number }) {
  const cards: [string, string][] = [
    ["Records", String(total)],
    ["Mean confusion", `${mean(records.map((r) => r.confusion_pct)).toFixed(2)}%`],
    ["Mean avalanche", `${mean(records.map((r) => r.avalanche_pct)).toFixed(2)}%`],
    ["Mean block avalanche", `${mean(records.map((r) => r.block_avalanche_pct)).toFixed(2)}%`],
    ["Mean diffusion", `${mean(records.map((r) => r.diffusion_bits)).toFixed(1)} bits`],
    ["Mean AES time", `${mean(records.map((r) => r.enc_us)).toFixed(2)} / ${mean(records.map((r) => r.dec_us)).toFixed(2)} μs enc / dec`],
  ];
  return <div className="dash-cards text-lab-cards">{cards.map(([label, value]) => <div key={label}><small>{label}</small><b>{value}</b></div>)}</div>;
}
