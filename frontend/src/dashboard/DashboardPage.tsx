import { useState } from "react";
import { useAuth } from "../auth/AuthContext";
import { AuditIntegrity } from "./components/AuditIntegrity";
import { DemoControls } from "./components/DemoControls";
import { SummaryStrip } from "./components/SummaryStrip";
import { CryptoLabTab } from "./tabs/CryptoLabTab";
import { LogsTab } from "./tabs/LogsTab";
import { NetworkTab } from "./tabs/NetworkTab";

type Tab = "logs" | "crypto" | "network";
export function DashboardPage() {
  const { user, logout } = useAuth();
  const [tab, setTab] = useState<Tab>("logs");
  return <main className="page dashboard-page">
    <header className="dashboard-header"><div><h1>CipherChat Security Dashboard</h1><p>Logged in as {user?.username}</p></div><button className="btn secondary" onClick={() => void logout()}>Logout</button></header>
    <SummaryStrip />
    <div className="dash-tools"><DemoControls /><AuditIntegrity /></div>
    <nav className="dash-tabs">{([ ["logs", "Security Logs"], ["crypto", "Crypto Lab"], ["network", "Network Analysis"] ] as const).map(([value, label]) => <button key={value} className={tab === value ? "selected" : ""} onClick={() => setTab(value)}>{label}</button>)}</nav>
    {tab === "logs" ? <LogsTab /> : tab === "crypto" ? <CryptoLabTab /> : <NetworkTab />}
  </main>;
}
