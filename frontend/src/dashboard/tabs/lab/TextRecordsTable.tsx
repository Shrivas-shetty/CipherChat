import { useMemo, useState } from "react";
import type { TextLabRecord } from "../../api";
import { formatTs } from "../../labels";
import { sortTextRecords, type RecordSortKey } from "./recordsTable";

const COLS: [string, RecordSortKey | null][] = [["Time", "created_at"], ["Sender", "sender"], ["Message id", "message_id"], ["PT length (bytes)", "pt_len_bytes"], ["CT length", "ct_len_bytes"], ["Confusion %", "confusion_pct"], ["Diffusion bits", "diffusion_bits"], ["Avalanche %", "avalanche_pct"], ["Block avalanche %", "block_avalanche_pct"], ["Enc μs", "enc_us"], ["Dec μs", "dec_us"]];
export function TextRecordsTable({ records }: { records: TextLabRecord[] }) {
  const [sortKey, setSortKey] = useState<RecordSortKey>("created_at"), [direction, setDirection] = useState<"asc" | "desc">("desc"), [page, setPage] = useState(0);
  const sorted = useMemo(() => sortTextRecords(records, sortKey, direction), [records, sortKey, direction]);
  const pageCount = Math.max(1, Math.ceil(sorted.length / 25));
  const visible = sorted.slice(page * 25, (page + 1) * 25);
  const toggle = (key: RecordSortKey | null) => { if (!key) return; setPage(0); setDirection(sortKey === key && direction === "desc" ? "asc" : "desc"); setSortKey(key); };
  return <section className="dash-panel"><h3>Text metric records</h3><p className="dash-note">Plaintext and keys are never available to the server.</p>
    <div className="dash-table-wrap"><table className="dash-table"><thead><tr>{COLS.map(([label, key]) => <th key={label}>{key ? <button className="sort-button" onClick={() => toggle(key)}>{label}{sortKey === key ? direction === "asc" ? " ↑" : " ↓" : ""}</button> : label}</th>)}</tr></thead><tbody>{visible.map((r) => <tr key={r.id}><td title={r.created_at}>{formatTs(r.created_at)}</td><td>{r.sender ?? "Unknown"}</td><td>{r.message_id}</td><td>{r.pt_len_bytes}</td><td>{r.ct_len_bytes}</td><td>{r.confusion_pct.toFixed(2)}</td><td>{r.diffusion_bits.toFixed(1)}</td><td>{r.avalanche_pct.toFixed(2)}</td><td>{r.block_avalanche_pct.toFixed(2)}</td><td>{r.enc_us.toFixed(2)}</td><td>{r.dec_us.toFixed(2)}</td></tr>)}</tbody></table></div>
    <div className="lab-pagination"><button disabled={page === 0} onClick={() => setPage((p) => p - 1)}>Previous</button><span>Page {page + 1} of {pageCount}</span><button disabled={page + 1 >= pageCount} onClick={() => setPage((p) => p + 1)}>Next</button></div>
  </section>;
}
