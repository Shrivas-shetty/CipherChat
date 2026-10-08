import { lazy, Suspense, useState } from "react";

const TextLab = lazy(() => import("./lab/TextLab").then((module) => ({ default: module.TextLab })));
const ImageLab = lazy(() => import("./lab/ImageLab").then((module) => ({ default: module.ImageLab })));

export function CryptoLabTab() {
  const [tab, setTab] = useState<"text" | "image">("text");
  return <section className="dash-panel"><nav className="dash-subtabs"><button className={tab === "text" ? "selected" : ""} onClick={() => setTab("text")}>Text Lab</button><button className={tab === "image" ? "selected" : ""} onClick={() => setTab("image")}>Image Lab</button></nav>{tab === "text" ? <Suspense fallback={<div className="dash-empty">Loading Text Lab…</div>}><TextLab /></Suspense> : <Suspense fallback={<div className="dash-empty">Loading Image Lab…</div>}><ImageLab /></Suspense>}</section>;
}
