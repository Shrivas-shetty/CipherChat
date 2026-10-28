import { useEffect, useMemo, useState, useSyncExternalStore } from "react";
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { DEFAULT_MAX_ATTEMPTS_DEMO, DEFAULT_MAX_ATTEMPTS_FULL, DEFAULT_MAX_SECONDS, DEFAULT_PERF_COUNTS, DEMO_BITS, FULL_BITS, MAX_SECONDS_CAP, PERF_TRIALS_DEFAULT, TRIALS_MAX, ATTACK_MAX_ATTEMPTS_CAP } from "../../../../hashlab/config";
import { makeNonce } from "../../../../hashlab/candidates";
import { runCollision, runPreimage, runSecondPreimage, type AttackResult } from "../../../../hashlab/attacks";
import { prefixHex, sha256, toHex, utf8 } from "../../../../hashlab/hashing";
import { expectedAttempts, formatPow2, formatSci, successProbability, type Attack } from "../../../../hashlab/probability";
import { runPerformance, type PerformanceRow } from "../../../../hashlab/performance";
import { hashLabStore, type HashLabEntry } from "../../../../hashlab/store";

type Tab = "performance" | Attack;
const tabs: [Tab, string][] = [["performance", "Performance"], ["preimage", "Preimage"], ["second_preimage", "Second-Preimage"], ["collision", "Collision"]];
const number = (value: string, min: number, max: number) => Number.isInteger(Number(value)) && Number(value) >= min && Number(value) <= max;
const bytesHex = (s: string) => /^[0-9a-fA-F]+$/.test(s) && s.length % 2 === 0 ? Uint8Array.from(s.match(/.{2}/g)!.map((x) => parseInt(x, 16))) : null;
const stopText = (reason: string) => reason === "attempt_limit" ? "NOT FOUND (attempt limit)" : reason === "time_limit" ? "NOT FOUND (time limit)" : reason === "cancelled" ? "CANCELLED" : "FOUND";

function ChartTip({ active, payload }: { active?: boolean; payload?: { name?: string; value?: number; payload?: Record<string, string | number | null> }[] }) {
  if (!active || !payload?.length) return null;
  const row = payload[0].payload;
  if (!row) return null;
  return <div className="lab-tooltip"><b>{row.name}</b>{payload.map((item) => <div key={item.name}>{item.name}: {item.value?.toLocaleString()}</div>)}{typeof row.runs === "number" && <div>Successful runs: {row.runs}</div>}</div>;
}

function Chart({ title, rows, logScale = false, keys, emptyText }: { title: string; rows: Record<string, string | number | null>[]; logScale?: boolean; keys: [string, string][]; emptyText?: string }) {
  return <section className="dash-panel"><h3>{title}</h3>{rows.length ? <div className="hash-chart"><ResponsiveContainer width="100%" height="100%"><BarChart data={rows}><CartesianGrid strokeDasharray="3 3"/><XAxis dataKey="name"/><YAxis scale={logScale ? "log" : "auto"} domain={logScale ? ["auto", "auto"] : undefined} allowDataOverflow/><Tooltip content={<ChartTip/>}/><Legend/>{keys.map(([key, fill]) => <Bar key={key} dataKey={key} fill={fill}/>)}</BarChart></ResponsiveContainer></div> : <p className="dash-empty">{emptyText ?? "No results available."}</p>}</section>;
}

export function HashingLab() {
  const [tab, setTab] = useState<Tab>("performance");
  const [bits, setBits] = useState(FULL_BITS);
  const [maxAttempts, setMaxAttempts] = useState(DEFAULT_MAX_ATTEMPTS_FULL);
  const [maxSeconds, setMaxSeconds] = useState(DEFAULT_MAX_SECONDS);
  const [trials, setTrials] = useState(1);
  const [counts, setCounts] = useState<number[]>([...DEFAULT_PERF_COUNTS]);
  const [perfTrials, setPerfTrials] = useState(PERF_TRIALS_DEFAULT);
  const [original, setOriginal] = useState("CipherChat second-preimage demo message");
  const [targetInput, setTargetInput] = useState("");
  const [targetSecret, setTargetSecret] = useState<string | null>(null);
  const [targetFromRandom, setTargetFromRandom] = useState(false);
  const [textToHash, setTextToHash] = useState("");
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState({ attempts: 0, elapsed_ms: 0, hashesPerSecond: 0 });
  const [error, setError] = useState("");
  const [logScale, setLogScale] = useState(true);
  const state = useSyncExternalStore(hashLabStore.subscribe, hashLabStore.getSnapshot, hashLabStore.getSnapshot);
  const active = useMemo(() => ({ controller: null as AbortController | null }), []);
  useEffect(() => () => active.controller?.abort(), [active]);
  useEffect(() => { if (bits === FULL_BITS) setMaxAttempts(DEFAULT_MAX_ATTEMPTS_FULL); else setMaxAttempts(DEFAULT_MAX_ATTEMPTS_DEMO); }, [bits]);

  const attackEntries = state.entries.filter((entry) => entry.attack !== "performance");
  const successful = (kind: Attack) => attackEntries.filter((entry) => entry.attack === kind && entry.bits === bits).map((entry) => entry.result as AttackResult).filter((result) => result.found);
  const attackChartRows = (["preimage", "second_preimage", "collision"] as Attack[]).map((kind) => ({ name: kind.replace("_", " "), measured: successful(kind).length ? successful(kind).reduce((sum, x) => sum + x.attempts, 0) / successful(kind).length : null, theory: expectedAttempts(kind, bits), runs: successful(kind).length }));

  async function runBench() {
    setError(""); setRunning(true); active.controller = new AbortController(); setProgress({ attempts: 0, elapsed_ms: 0, hashesPerSecond: 0 });
    try {
      const result = await runPerformance({ counts, trials: perfTrials, hash: (message) => { sha256(utf8(message)); }, signal: active.controller.signal, onProgress: setProgress });
      if (result.length) hashLabStore.add({ attack: "performance", bits: FULL_BITS, limit: counts.reduce((a, b) => a + b, 0), result, expected: 0, mode: "FULL" });
    } catch (e) { if (!active.controller?.signal.aborted) setError(e instanceof Error ? e.message : "Benchmark failed"); }
    finally { setRunning(false); active.controller = null; }
  }
  async function runAttack() {
    setError("");
    if (!number(String(maxAttempts), 1, ATTACK_MAX_ATTEMPTS_CAP) || !number(String(maxSeconds), 1, MAX_SECONDS_CAP) || !number(String(trials), 1, TRIALS_MAX)) { setError("Enter valid attempts, seconds, and trials within the displayed limits."); return; }
    if (tab === "preimage" && !targetFromRandom && !targetInput.match(bits === FULL_BITS ? /^[0-9a-fA-F]{64}$/ : /^(?:[0-9a-fA-F]{4}|[0-9a-fA-F]{64})$/)) { setError(bits === FULL_BITS ? "Enter exactly 64 hexadecimal characters." : "Enter 4 or 64 hexadecimal characters."); return; }
    setRunning(true); active.controller = new AbortController(); setProgress({ attempts: 0, elapsed_ms: 0, hashesPerSecond: 0 });
    try {
      for (let i = 0; i < trials; i += 1) {
        const nonce = makeNonce();
        let result: AttackResult;
        const shared = { bits, maxAttempts, maxMs: maxSeconds * 1000, nonce, signal: active.controller.signal, onProgress: setProgress };
        if (tab === "collision") result = await runCollision(shared);
        else if (tab === "second_preimage") result = await runSecondPreimage({ ...shared, original });
        else {
          let target: Uint8Array | number;
          let secret: string | null = null;
          if (targetFromRandom) {
            const bytes = i === 0 && targetSecret ? bytesHex(targetSecret)! : crypto.getRandomValues(new Uint8Array(16)); secret = toHex(bytes); target = sha256(bytes); bytes.fill(0);
          } else if (bits === FULL_BITS || targetInput.length === 64) target = bytesHex(targetInput) ?? new Uint8Array();
          else target = Number.parseInt(targetInput.slice(0, 4), 16);
          result = await runPreimage({ ...shared, target });
          if (secret && result.details) result.details.secretMessage = secret;
        }
        hashLabStore.add({ attack: tab, bits, limit: maxAttempts, result, expected: expectedAttempts(tab as Attack, bits), mode: bits === FULL_BITS ? "FULL" : "16-BIT DEMO" });
        if (active.controller.signal.aborted) break;
      }
    } catch (e) { setError(e instanceof Error ? e.message : "Attack failed"); }
    finally { setRunning(false); active.controller = null; }
  }

  const currentRows = state.entries.filter((entry) => entry.attack === tab);
  const selectedTarget = targetFromRandom ? null : bytesHex(targetInput);
  const targetDigest = selectedTarget ? sha256(selectedTarget) : null;
  return <div className="hashing-lab">
    <p className="lab-blind-note">SHA-256 runs in your browser in pure JavaScript. Nothing is sent to the server. Browser speeds are far below GPU/ASIC speeds, which does not change the conclusions.</p>
    <div className="text-lab-header"><span>Results stay in memory for this dashboard session.</span><button onClick={() => hashLabStore.clear()}>Clear results</button></div>
    <nav className="dash-subtabs">{tabs.map(([value, label]) => <button key={value} className={tab === value ? "selected" : ""} onClick={() => setTab(value)}>{label}</button>)}</nav>
    {tab === "performance" ? <>
      <div className="hash-settings"><label>Count 1 <input type="number" value={counts[0]} min={1} max={2_000_000} onChange={(e) => setCounts([Number(e.target.value), counts[1], counts[2]])}/></label><label>Count 2 <input type="number" value={counts[1]} min={1} max={2_000_000} onChange={(e) => setCounts([counts[0], Number(e.target.value), counts[2]])}/></label><label>Count 3 <input type="number" value={counts[2]} min={1} max={2_000_000} onChange={(e) => setCounts([counts[0], counts[1], Number(e.target.value)])}/></label><label>Trials <input type="number" min={1} max={20} value={perfTrials} onChange={(e) => setPerfTrials(Number(e.target.value))}/></label><button disabled={running} onClick={() => void runBench()}>Run benchmark</button><button disabled={!running} onClick={() => active.controller?.abort()}>Stop</button></div>
      {error && <div className="dash-error">{error}</div>}{running && <Progress progress={progress} max={counts.reduce((a, b) => a + b, 0)}/>}<p className="dash-note">Time grows linearly with the number of hashes; throughput stays roughly constant. Very small runs are repeated internally so the timer can measure them.</p>
      {currentRows.map((entry) => <PerformanceResult key={entry.id} rows={entry.result as PerformanceRow[]} logScale={logScale} setLogScale={setLogScale}/>)}
    </> : <>
      {bits === DEMO_BITS && <div className="hash-warning"><b>EDUCATIONAL DEMO:</b> the hash is truncated to its first 16 bits (4 hex characters), so attacks succeed quickly. This is NOT a break of SHA-256. The full 256-bit hash cannot be attacked this way.</div>}
      <div className="hash-settings"><fieldset><legend>Hash mode</legend><label><input type="radio" name="hash-mode" checked={bits === FULL_BITS} onChange={() => setBits(FULL_BITS)}/> Full SHA-256 (256-bit)</label><label><input type="radio" name="hash-mode" checked={bits === DEMO_BITS} onChange={() => setBits(DEMO_BITS)}/> Educational: 16-bit truncated hash</label></fieldset><label>Max attempts <input type="number" min={1} max={ATTACK_MAX_ATTEMPTS_CAP} value={maxAttempts} onChange={(e) => setMaxAttempts(Number(e.target.value))}/></label><label>Max time (seconds) <input type="number" min={1} max={MAX_SECONDS_CAP} value={maxSeconds} onChange={(e) => setMaxSeconds(Number(e.target.value))}/></label><label>Trials <input type="number" min={1} max={TRIALS_MAX} value={trials} onChange={(e) => setTrials(Number(e.target.value))}/></label><button disabled={running} onClick={() => void runAttack()}>Start</button><button disabled={!running} onClick={() => active.controller?.abort()}>Stop</button></div>
      {error && <div className="dash-error">{error}</div>}{running && <Progress progress={progress} max={maxAttempts}/>}
      {tab === "preimage" && <div className="dash-panel hash-settings"><label>Target hash <input value={targetInput} onChange={(e) => { setTargetInput(e.target.value); setTargetFromRandom(false); setTargetSecret(null); }}/></label><button onClick={() => { const bytes = crypto.getRandomValues(new Uint8Array(16)); const digest = sha256(bytes); setTargetInput(bits === FULL_BITS ? toHex(digest) : prefixHex(digest, DEMO_BITS)); setTargetFromRandom(true); setTargetSecret(toHex(bytes)); bytes.fill(0); }}>Generate random target</button><label>Hash of this text <input value={textToHash} onChange={(e) => setTextToHash(e.target.value)}/></label><button onClick={() => { const digest = sha256(utf8(textToHash)); setTargetInput(bits === FULL_BITS ? toHex(digest) : prefixHex(digest, DEMO_BITS)); setTargetFromRandom(false); }}>Use hash</button>{bits === DEMO_BITS && targetInput.length === 64 && <small>Only the first 16 bits are matched.</small>}{targetDigest && <small>Computed target prefix: {prefixHex(targetDigest, bits === FULL_BITS ? 256 : 16)}</small>}{targetSecret && <small>Random target is prepared; its secret message is revealed only in run details.</small>}</div>}
      {tab === "second_preimage" && <div className="dash-panel"><label>Original message <textarea value={original} onChange={(e) => setOriginal(e.target.value)}/></label><p>SHA-256: <code>{toHex(sha256(utf8(original)))}</code></p>{bits === DEMO_BITS && <p>16-bit prefix: <b>{prefixHex(sha256(utf8(original)), 16)}</b></p>}</div>}
      <Theory attack={tab} bits={bits} attempts={maxAttempts}/>
      <div className="text-lab-header"><h3>Results</h3><button onClick={() => setLogScale(!logScale)}>Log scale: {logScale ? "On" : "Off"}</button></div>
      <AttackResults entries={currentRows}/>
      <Chart title="Attempts needed by attack" rows={successful("preimage").length || successful("second_preimage").length || successful("collision").length ? attackChartRows : []} logScale={logScale} keys={[["measured", "#43c59e"], ["theory", "#56a7ff"]]} emptyText="No successful attacks yet. In Full SHA-256 mode this is the expected outcome; switch to the educational mode to watch attacks succeed. Note how a collision needs only about 2^8 attempts while a preimage needs about 2^16: that is the birthday paradox."/>
    </>}
  </div>;
}

function Progress({ progress, max }: { progress: { attempts: number; elapsed_ms: number; hashesPerSecond: number }; max: number }) { return <div className="dash-panel"><progress max={max} value={Math.min(max, progress.attempts)}/><p>{progress.attempts.toLocaleString()} attempts · {(progress.elapsed_ms / 1000).toFixed(2)} s · {Math.round(progress.hashesPerSecond).toLocaleString()} hashes/s</p></div>; }
function Theory({ attack, bits, attempts }: { attack: Attack; bits: number; attempts: number }) { return <section className="dash-panel"><h3>Theory</h3><p>Expected attempts: {bits === 256 && attack !== "collision" ? formatPow2(256) : formatSci(expectedAttempts(attack, bits))}</p><p>Probability within the configured limit: {formatSci(successProbability(attack, bits, attempts))}</p>{bits === 256 && <p>Expected work is about 2^256 for preimages and 2^128 for collisions; no limit you can set here will find one.</p>}</section>; }
function PerformanceResult({ rows, logScale, setLogScale }: { rows: PerformanceRow[]; logScale: boolean; setLogScale: (value: boolean) => void }) { return <><label><input type="checkbox" checked={logScale} onChange={(e) => setLogScale(e.target.checked)}/> Log scale</label><div className="dash-table-wrap"><table className="dash-table"><thead><tr><th>Iterations</th><th>Median time</th><th>Time per hash (µs)</th><th>Hashes/s</th></tr></thead><tbody>{rows.map((r) => <tr key={r.count}><td>{r.count.toLocaleString()}</td><td>{r.time_ms < 1 ? `${(r.time_ms * 1000).toPrecision(3)} µs` : `${r.time_ms.toFixed(3)} ms`}</td><td>{r.us_per_hash.toFixed(3)}</td><td>{Math.round(r.hashes_per_second).toLocaleString()}</td></tr>)}</tbody></table></div><Chart title="Time per iteration count" rows={rows.map((r) => ({ name: r.count.toLocaleString(), "Time (ms)": r.time_ms }))} logScale={logScale} keys={[["Time (ms)", "#56a7ff"]]}/><Chart title="Hashes per second" rows={rows.map((r) => ({ name: r.count.toLocaleString(), "Hashes/s": r.hashes_per_second }))} keys={[["Hashes/s", "#43c59e"]]}/></>; }
function AttackResults({ entries }: { entries: HashLabEntry[] }) { return <div className="dash-table-wrap"><table className="dash-table"><thead><tr><th>Run #</th><th>Mode</th><th>Limit</th><th>Attempts</th><th>Time</th><th>Hashes/s</th><th>Outcome</th><th>Details</th></tr></thead><tbody>{entries.map((entry, i) => { const result = entry.result as AttackResult; const foundMessage = result.details?.message; const verification = foundMessage && entry.bits === DEMO_BITS ? prefixHex(sha256(utf8(foundMessage)), DEMO_BITS) : null; const verificationTarget = entry.attack === "second_preimage" ? prefixHex(bytesHex(result.details?.originalHashHex ?? "") ?? new Uint8Array(), DEMO_BITS) : result.details?.target; return <tr key={entry.id}><td>{entries.length - i}</td><td><span className="hash-mode-badge">{entry.mode}</span></td><td>{entry.limit.toLocaleString()}</td><td>{result.attempts.toLocaleString()}</td><td>{(result.elapsed_ms / 1000).toFixed(3)} s</td><td>{Math.round(result.attempts * 1000 / Math.max(result.elapsed_ms, 0.001)).toLocaleString()}</td><td className={result.found ? "hash-found" : ""}>{stopText(result.stopReason)}</td><td><details><summary>Expand</summary><pre>{JSON.stringify({ nonce: result.nonce, expectedAttempts: entry.expected, ...result.details }, null, 2)}</pre>{verification && <p>verification: SHA-256(message) first 16 bits = {verification}{verificationTarget ? ` = target ${verificationTarget}` : ""}</p>}</details></td></tr>; })}</tbody></table></div>; }
