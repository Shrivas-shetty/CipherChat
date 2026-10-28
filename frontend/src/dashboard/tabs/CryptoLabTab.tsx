import { Component, lazy, Suspense, useState, type ErrorInfo, type ReactNode } from "react";

const TextLab = lazy(() => import("./lab/TextLab").then((module) => ({ default: module.TextLab })));
const ImageLab = lazy(() => import("./lab/ImageLab").then((module) => ({ default: module.ImageLab })));
const HashingLab = lazy(() => import("./lab/hashing/HashingLab").then((module) => ({ default: module.HashingLab })));
const SignatureLab = lazy(() => import("./lab/signature/SignatureLab").then((module) => ({ default: module.SignatureLab })));

type LabBoundaryState = { error: string | null };

class LabContentBoundary extends Component<{ children: ReactNode }, LabBoundaryState> {
  state: LabBoundaryState = { error: null };

  static getDerivedStateFromError(error: unknown): LabBoundaryState {
    return { error: error instanceof Error ? error.message : "Unexpected rendering error" };
  }

  componentDidCatch(_error: Error, _info: ErrorInfo): void {
    // Keep a lab tab failure local so the analyst dashboard remains usable.
  }

  render() {
    if (this.state.error) {
      return <div className="dash-error" role="alert">
        <p>Crypto Lab could not render: {this.state.error}</p>
        <button onClick={() => this.setState({ error: null })}>Retry</button>
      </div>;
    }
    return this.props.children;
  }
}

export function CryptoLabTab() {
  const [tab, setTab] = useState<"text" | "image" | "hashing" | "signature">("text");
  return <section className="dash-panel"><nav className="dash-subtabs"><button className={tab === "text" ? "selected" : ""} onClick={() => setTab("text")}>Text Lab</button><button className={tab === "image" ? "selected" : ""} onClick={() => setTab("image")}>Image Lab</button><button className={tab === "hashing" ? "selected" : ""} onClick={() => setTab("hashing")}>Hashing Lab</button><button className={tab === "signature" ? "selected" : ""} onClick={() => setTab("signature")}>Signature Lab</button></nav><LabContentBoundary key={tab}>{tab === "text" ? <Suspense fallback={<div className="dash-empty">Loading Text Lab…</div>}><TextLab /></Suspense> : tab === "image" ? <Suspense fallback={<div className="dash-empty">Loading Image Lab…</div>}><ImageLab /></Suspense> : tab === "hashing" ? <Suspense fallback={<div className="dash-empty">Loading Hashing Lab…</div>}><HashingLab /></Suspense> : <Suspense fallback={<div className="dash-empty">Loading Signature Lab…</div>}><SignatureLab /></Suspense>}</LabContentBoundary></section>;
}
