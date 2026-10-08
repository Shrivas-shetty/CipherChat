import { useEffect, useMemo, useRef, useState } from "react";
import type { ImageLabRecord } from "../../api";
import { formatTs } from "../../labels";
import { CipherNoiseThumb, fetchNoiseCanvas } from "./CipherNoiseThumb";

type SortKey = "created_at" | "sender" | "message_id" | "width" | "n_pixels" | "ct_len_bytes" | "npcr_pct" | "uaci_pct" | "entropy_avg";
const columns: [string, SortKey][] = [["Time", "created_at"], ["Sender", "sender"], ["Message id", "message_id"], ["Dimensions", "width"], ["Pixels", "n_pixels"], ["Ciphertext bytes", "ct_len_bytes"], ["NPCR %", "npcr_pct"], ["UACI %", "uaci_pct"], ["Entropy avg", "entropy_avg"]];

function NoiseLightbox({ record, onClose }: { record: ImageLabRecord; onClose: () => void }) {
  const host = useRef<HTMLDivElement>(null), [error, setError] = useState("");
  useEffect(() => {
    let live = true;
    void fetchNoiseCanvas(record.message_id).then(({ canvas }) => { if (live) host.current?.replaceChildren(canvas); else { canvas.width = 0; canvas.height = 0; } }).catch(() => { if (live) setError("Could not load encrypted noise image."); });
    return () => { live = false; host.current?.replaceChildren(); };
  }, [record.message_id]);
  return <div className="image-lightbox noise-lightbox" role="dialog" aria-modal="true" aria-label={`Encrypted image ${record.message_id}`} onClick={onClose}>
    <div className="noise-lightbox-content" onClick={(event) => event.stopPropagation()}><button onClick={onClose}>Close</button><h3>Encrypted noise · Message #{record.message_id}</h3><p>{record.width} × {record.height} pixels</p>{error && <p className="dash-error">{error}</p>}<div className="noise-native-scroll" ref={host} /></div>
  </div>;
}

export function ImageRecordsTable({ records }: { records: ImageLabRecord[] }) {
  const [sortKey, setSortKey] = useState<SortKey>("created_at"), [direction, setDirection] = useState<"asc" | "desc">("desc"), [page, setPage] = useState(0), [opened, setOpened] = useState<ImageLabRecord | null>(null);
  const sorted = useMemo(() => [...records].sort((a, b) => {
    const left = a[sortKey], right = b[sortKey];
    const cmp = typeof left === "number" && typeof right === "number" ? left - right : String(left ?? "").localeCompare(String(right ?? ""));
    return direction === "asc" ? cmp : -cmp;
  }), [records, sortKey, direction]);
  const pageCount = Math.max(1, Math.ceil(sorted.length / 25)), visible = sorted.slice(page * 25, (page + 1) * 25);
  function sort(key: SortKey) { setPage(0); setDirection(sortKey === key && direction === "desc" ? "asc" : "desc"); setSortKey(key); }
  return <section className="dash-panel"><h3>Encrypted images</h3><p className="dash-note">Only the ciphertext noise image is available here; original and decrypted images are not accessible to analysts.</p>
    <div className="dash-table-wrap"><table className="dash-table image-records-table"><thead><tr><th>Encrypted thumbnail</th>{columns.map(([label, key]) => <th key={key}><button className="sort-button" onClick={() => sort(key)}>{label}{sortKey === key ? direction === "asc" ? " ↑" : " ↓" : ""}</button></th>)}</tr></thead>
      <tbody>{visible.map((row) => <tr key={row.id}><td><CipherNoiseThumb record={row} onOpen={setOpened} /></td><td title={row.created_at}>{formatTs(row.created_at)}</td><td>{row.sender ?? "Unknown"}</td><td>{row.message_id}</td><td>{row.width} × {row.height}</td><td>{row.n_pixels.toLocaleString()}</td><td>{row.ct_len_bytes.toLocaleString()}</td><td>{row.npcr_pct.toFixed(2)}</td><td>{row.uaci_pct.toFixed(2)}</td><td>{row.entropy_avg.toFixed(4)}</td></tr>)}</tbody></table></div>
    <div className="lab-pagination"><button disabled={page === 0} onClick={() => setPage((p) => p - 1)}>Previous</button><span>Page {page + 1} of {pageCount}</span><button disabled={page + 1 >= pageCount} onClick={() => setPage((p) => p + 1)}>Next</button></div>
    {opened && <NoiseLightbox record={opened} onClose={() => setOpened(null)} />}
  </section>;
}
