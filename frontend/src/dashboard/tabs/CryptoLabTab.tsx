import { useState } from "react";

const NOTE = "Coming soon. Metrics will be computed in the senders' browsers and only numeric results are sent to the server; the server never sees plaintext, keys or decrypted images.";
export function CryptoLabTab() {
  const [tab, setTab] = useState<"text" | "image">("text");
  return <section className="dash-panel"><nav className="dash-subtabs"><button className={tab === "text" ? "selected" : ""} onClick={() => setTab("text")}>Text Lab</button><button className={tab === "image" ? "selected" : ""} onClick={() => setTab("image")}>Image Lab</button></nav><div className="dash-placeholder"><h2>{tab === "text" ? "Text Lab" : "Image Lab"}</h2><p>{NOTE}</p></div></section>;
}
