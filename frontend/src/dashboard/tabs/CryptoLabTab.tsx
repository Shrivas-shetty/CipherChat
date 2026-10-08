import { lazy, Suspense, useState } from "react";

const TextLab = lazy(() => import("./lab/TextLab").then((module) => ({ default: module.TextLab })));

const NOTE = "Coming soon. Metrics will be computed in the senders' browsers and only numeric results are sent to the server; the server never sees plaintext, keys or decrypted images.";
export function CryptoLabTab() {
  const [tab, setTab] = useState<"text" | "image">("text");
  return <section className="dash-panel"><nav className="dash-subtabs"><button className={tab === "text" ? "selected" : ""} onClick={() => setTab("text")}>Text Lab</button><button className={tab === "image" ? "selected" : ""} onClick={() => setTab("image")}>Image Lab</button></nav>{tab === "text" ? <Suspense fallback={<div className="dash-empty">Loading Text Lab…</div>}><TextLab /></Suspense> : <div className="dash-placeholder"><h2>Image Lab</h2><p>{NOTE}</p></div>}</section>;
}
