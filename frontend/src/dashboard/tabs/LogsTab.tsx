import { useState } from "react";
import { EventsView } from "./EventsView";
import { MessagesView } from "./MessagesView";
import { SessionsView } from "./SessionsView";

export function LogsTab() {
  const [view, setView] = useState<"events" | "messages" | "sessions">("events");
  const [sessionFilter, setSessionFilter] = useState("");
  return <section className="dash-panel">
    <nav className="dash-subtabs">{(["events", "messages", "sessions"] as const).map((v) => <button key={v} className={view === v ? "selected" : ""} onClick={() => setView(v)}>{v[0].toUpperCase() + v.slice(1)}</button>)}</nav>
    {view === "events" && <EventsView sessionFilter={sessionFilter} onSessionFilter={setSessionFilter} />}
    {view === "messages" && <MessagesView sessionFilter={sessionFilter} onSessionFilter={setSessionFilter} />}
    {view === "sessions" && <SessionsView onOpenSession={(id) => { setSessionFilter(id); setView("events"); }} />}
  </section>;
}
