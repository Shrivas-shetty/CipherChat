import { lazy, Suspense, useState } from "react";

const TextLab = lazy(() => import("./lab/TextLab").then((module) => ({ default: module.TextLab })));
const ImageLab = lazy(() => import("./lab/ImageLab").then((module) => ({ default: module.ImageLab })));
const HashingLab = lazy(() => import("./lab/hashing/HashingLab").then((module) => ({ default: module.HashingLab })));

export function CryptoLabTab() {
  const [tab, setTab] = useState<"text" | "image" | "hashing">("text");
  return <section className="dash-panel"><nav className="dash-subtabs"><button className={tab === "text" ? "selected" : ""} onClick={() => setTab("text")}>Text Lab</button><button className={tab === "image" ? "selected" : ""} onClick={() => setTab("image")}>Image Lab</button><button className={tab === "hashing" ? "selected" : ""} onClick={() => setTab("hashing")}>Hashing Lab</button></nav>{tab === "text" ? <Suspense fallback={<div className="dash-empty">Loading Text Lab…</div>}><TextLab /></Suspense> : tab === "image" ? <Suspense fallback={<div className="dash-empty">Loading Image Lab…</div>}><ImageLab /></Suspense> : <Suspense fallback={<div className="dash-empty">Loading Hashing Lab…</div>}><HashingLab /></Suspense>}</section>;
}
