"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { type ScenarioImpact, type ScenarioReplayPlan, type ScenarioReplayResult,
  type ScenarioReplayRun } from "@contracthunter/core";

const modeHelp = {
  "independent-replay": "Each repetition begins from the same local baseline. Use this to test whether the reproduction is consistent.",
  "cumulative-replay": "Repetitions run sequentially on evolving local state. Use this to observe how the exact scenario changes over a bounded number of repetitions.",
} as const;
const raw = (value: string) => value.startsWith("-") || value === "0" ? value : `+${value}`;
export function ScenarioReplayView({ scanId, executionId, scenarioId, plan, plans = [], runs = [],
  result: initialResult, activeRun, stale = false, reference, source }: {
  scanId: string; executionId: string; scenarioId: string; plan: ScenarioReplayPlan | null;
  plans?: ScenarioReplayPlan[]; runs?: ScenarioReplayRun[]; result?: ScenarioReplayResult | null;
  activeRun?: ScenarioReplayRun | null; stale?: boolean; reference: ScenarioImpact | null;
  source: { artifactId: string; sourceSha256: string; chainId: number; forkBlock: number;
    forkBlockHash: string; forgeVersion: string | null; assets: string[];
    startingObservations: Array<{ id: string; status: string; value: string | null }> };
}) {
  const router = useRouter();
  const [mode, setMode] = useState<"independent-replay" | "cumulative-replay">(plan?.mode ?? "independent-replay");
  const [count, setCount] = useState(plan?.iterationCount ?? 2);
  const [confirmed, setConfirmed] = useState(false), [dirty, setDirty] = useState(false);
  const [busy, setBusy] = useState(false), [error, setError] = useState("");
  const [run, setRun] = useState<ScenarioReplayRun | null>(activeRun ?? null);
  const [result, setResult] = useState<ScenarioReplayResult | null>(initialResult ?? null);
  const base = `/hunts/${encodeURIComponent(scanId)}/impact/executions/${encodeURIComponent(executionId)}/assets/scenarios/${encodeURIComponent(scenarioId)}`;
  const api = `/api/scans/${encodeURIComponent(scanId)}/impact/poc-executions/${encodeURIComponent(executionId)}/scenarios/${encodeURIComponent(scenarioId)}/replay-plans`;
  const resource = plan ? `${api}/${encodeURIComponent(plan.planId)}` : api;
  useEffect(() => {
    if (!plan || !run || !["queued", "running"].includes(run.status)) return;
    const timer = window.setInterval(async () => {
      try { const response = await fetch(`${resource}/runs/${encodeURIComponent(run.id)}`, { cache: "no-store" });
        if (!response.ok) return;
        const payload = await response.json() as { run: ScenarioReplayRun; result: ScenarioReplayResult | null };
        setRun(payload.run); setResult(payload.result);
      } catch { /* a later poll or explicit refresh can recover */ }
    }, 2000);
    return () => window.clearInterval(timer);
  }, [plan, resource, run]);
  async function action(url: string, body: unknown, method: "POST" | "PATCH" = "POST") {
    setBusy(true); setError("");
    try { const response = await fetch(url, { method, headers: { "content-type": "application/json" },
      body: JSON.stringify(body) });
      const value = await response.json() as { plan?: ScenarioReplayPlan; run?: ScenarioReplayRun; error?: string };
      if (!response.ok) throw Error(value.error ?? "Replay action refused.");
      return value;
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Replay action refused."); return null; }
    finally { setBusy(false); }
  }
  const editable = plan?.status === "draft" && !stale;
  return <div className="af-view">
    <header className="page-head"><div><div className="eyebrow">ISOLATED LOCAL FORK · REVIEWED POC ONLY</div>
      <h1>Scenario Replay</h1><p className="subhead">Bounded repetitions of one existing reviewed PoC and reviewed F1 scenario.</p></div></header>
    <nav className="ip-actions"><Link href={base}>Back to Reviewed Scenario</Link>
      <Link href={`${base}/replay`}>Replay Plans</Link></nav>
    <p role="note" className="af-warning">Bounded local replay does not establish unlimited repeatability or maximum protocol impact.</p>
    {error && <p role="alert" className="af-warning">{error}</p>}
    {stale && <p role="alert" className="af-warning">This plan is bound to earlier scenario or asset-accounting evidence. It cannot run.</p>}
    <section className="card"><h2>Reviewed source and local fork</h2>
      <p>Scenario revision {reference?.revisionId ?? plan?.scenarioRevisionId ?? "UNAVAILABLE"} · PoC artifact {source.artifactId} · source hash {source.sourceSha256}</p>
      <p>Chain {source.chainId} · fork block {source.forkBlock} · block hash {source.forkBlockHash} · Forge {source.forgeVersion ?? "UNAVAILABLE"}</p>
      <p>Reviewed roles: {reference?.roles.length ? reference.roles.map((item) => `${item.role}: ${item.address}`).join(" · ") : "UNAVAILABLE"}</p>
      <p>Assets observed in F1: {source.assets.length ? source.assets.join(" · ") : "none"}</p>
      <p>Starting captured resources: {source.startingObservations.map((item) =>
        `${item.id}: ${item.status === "available" ? item.value : "UNAVAILABLE"}`).join(" · ") || "UNAVAILABLE"}</p>
      <p>This will repeat the existing reviewed PoC only on ContractHunter&apos;s isolated local fork.</p></section>
    {plans.length > 0 && <section className="card"><h2>Plans</h2><ul>{plans.map((item) => <li key={item.id}><Link href={`${base}/replay/${encodeURIComponent(item.planId)}`}>Revision {item.revision} · {item.mode} · {item.iterationCount} repetitions · {item.status}</Link></li>)}</ul></section>}
    <section className="card"><h2>{plan ? `Plan revision ${plan.revision} · ${plan.status.toUpperCase()}` : "Create Replay Plan"}</h2>
      <label>Mode <select value={mode} disabled={Boolean(plan) && !editable} onChange={(event) => {
        setMode(event.target.value as typeof mode); setDirty(true); setConfirmed(false); }}>
        <option value="independent-replay">Independent replay</option><option value="cumulative-replay">Cumulative replay</option></select></label>
      <p>{modeHelp[mode]}</p>
      <label>Repetitions (2–5) <input type="number" min={2} max={5} step={1} value={count}
        disabled={Boolean(plan) && !editable} onChange={(event) => { setCount(Number(event.target.value)); setDirty(true); setConfirmed(false); }} /></label>
      <p>Same reviewed PoC, disposable accounts, fork identity, observation definitions, and manually reviewed roles. No resource top-up or parameter sweep is added.</p>
      {!plan && <button type="button" disabled={busy} onClick={async () => { const value = await action(api, { mode, iterationCount: count });
        if (value?.plan) router.push(`${base}/replay/${encodeURIComponent(value.plan.planId)}`); }}>Create Draft Plan</button>}
      {editable && <><button type="button" disabled={busy || !dirty} onClick={async () => { const value = await action(resource,
        { revisionId: plan.id, mode, iterationCount: count }, "PATCH"); if (value?.plan) { setDirty(false); router.refresh(); } }}>Save Draft</button>
        <p><label><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} /> I reviewed the exact PoC, fork, mode, and repetition bound. This is local replay only.</label></p>
        <button type="button" disabled={busy || dirty || !confirmed} onClick={async () => { const value = await action(`${resource}/review`,
          { revisionId: plan.id, decision: "reviewed" }); if (value?.plan) router.refresh(); }}>Review Plan</button>
        <button type="button" disabled={busy} onClick={async () => { const value = await action(`${resource}/review`,
          { revisionId: plan.id, decision: "rejected" }); if (value?.plan) router.refresh(); }}>Reject Draft</button></>}
      {plan && plan.status !== "draft" && <button type="button" disabled={busy || stale} onClick={async () => {
        const value = await action(`${resource}/revisions`, { revisionId: plan.id }); if (value?.plan) router.refresh();
      }}>Edit Mode or Count — New Draft Revision</button>}
      {plan?.status === "reviewed" && !stale && <button type="button" disabled={busy || Boolean(run && ["queued", "running"].includes(run.status))}
        onClick={async () => { const value = await action(`${resource}/runs`, { revisionId: plan.id });
          if (value?.run) { setRun(value.run); setResult(null); } }}>Start Reviewed Local Replay</button>}
      {plan && <p className="mono">Plan revision ID {plan.id} · content {plan.contentSha256} · ruleset contracthunter-scenario-replay-ruleset-v1</p>}
    </section>
    {runs.length > 0 && <section className="card"><h2>Run history</h2><ul>{runs.map((item) => <li key={item.id}><Link href={`${base}/replay/${encodeURIComponent(plan!.planId)}?run=${encodeURIComponent(item.id)}`}>Run {item.id} · {item.status} · {item.stopReason ?? "no stop reason"}</Link></li>)}</ul></section>}
    {run && <section className="card"><h2>Run status</h2><p>{run.status.toUpperCase()} · {run.id} · {run.stopReason ?? "No stop reason"}</p>
      {["queued", "running"].includes(run.status) && <button type="button" disabled={busy || run.cancelRequested}
        onClick={async () => { const value = await action(`${resource}/runs/${encodeURIComponent(run.id)}/cancel`, {});
          if (value?.run) setRun(value.run); }}>Cancel after current iteration</button>}</section>}
    {result && <><section className="card"><h2>Observed repeatability</h2>
      <p>{result.repeatability.replaceAll("-", " ")} · {result.completedIterations} completed of {result.requestedIterations} requested local repetitions.
        {result.mode === "independent-replay" && ` ${result.matchingIterations} matched reference accounting.`}</p>
      <p>{result.stopReason ?? "No stop reason"}</p><p className="mono">Result content {result.contentSha256}</p></section>
      <section className="card"><h2>Iteration accounting</h2><div className="af-table-wrap"><table>
        <thead><tr><th>Iteration</th><th>Outcome</th><th>Transactions</th><th>Subject net by asset</th><th>Protocol net by asset</th><th>Direct role transfer</th><th>Reconciliation</th><th>Execution cost</th><th>Warnings</th></tr></thead>
        <tbody>{result.iterations.map((item) => { const accounting = item.accounting;
          const position = (role: string) => accounting?.rolePositions.filter((row) =>
            row.transactionOrdinal === null && row.role === role).map((row) => `${row.assetId}: ${raw(row.netObservedMovement)}`).join(" · ") || "UNAVAILABLE";
          return <tr key={item.iteration.id}><td>{item.iteration.index}</td><td>{item.iteration.status} {item.iteration.stopReason ?? ""}</td>
            <td>{item.iteration.executionId ? <Link href={`/hunts/${encodeURIComponent(scanId)}/impact/executions/${encodeURIComponent(item.iteration.executionId)}/assets`}>View exact execution</Link> : "UNAVAILABLE"}</td>
            <td>{position("scenario-subject")}</td><td>{position("protocol")}</td>
            <td>{accounting?.directRoleTransfers.filter((row) => row.transactionOrdinal === null && row.amount !== "0")
              .map((row) => `${row.direction} ${row.assetId}: ${row.amount}`).join(" · ") || "none or unavailable"}</td>
            <td>{accounting?.reconciliation.map((row) => `${row.assetId}: ${row.status}`).join(" · ") || "UNAVAILABLE"}</td>
            <td>{accounting?.executionCosts.map((cost) => cost.amountWei ?? "UNAVAILABLE").join(" · ") ?? "UNAVAILABLE"}</td>
            <td>{accounting?.warnings.join(" · ") || "none or unavailable"}</td></tr>; })}</tbody></table></div></section>
      {result.mode === "independent-replay" && <section className="card"><h2>Independent match table</h2><p>Every iteration starts from the same captured baseline. Movement is never summed as cumulative impact.</p><ul>
        {result.iterations.map((item) => <li key={item.iteration.id}>Iteration {item.iteration.index}: {item.matchedReference === null ? "UNAVAILABLE" : item.matchedReference ? "matches reference accounting" : `variation — ${item.variation.join(", ")}`} · reconciliation {item.accounting?.reconciliation.map((row) => row.status).join(", ") ?? "UNAVAILABLE"}</li>)}
      </ul></section>}
      {result.mode === "cumulative-replay" && <section className="card"><h2>Observed cumulative scenario movement after {result.completedIterations} local repetitions</h2>
        <p>Only completed sequential iterations contribute. ERC721 identity movements remain in the iteration table.</p>
        <div className="af-table-wrap"><table><thead><tr><th>Asset</th><th>Role</th><th>Incoming</th><th>Outgoing</th><th>Net</th><th>Contributing iterations</th></tr></thead><tbody>
          {result.cumulativePositions.map((item) => <tr key={`${item.assetId}:${item.role}`}><td>{item.assetId}</td><td>{item.role}</td><td>{item.incoming}</td><td>{item.outgoing}</td><td>{raw(item.netObservedMovement)}</td><td>{item.iterationIndexes.join(", ")}</td></tr>)}
        </tbody></table></div><h3>Observed resource evolution</h3><ul>{result.iterations.map((item) =>
          <li key={item.iteration.id}>Iteration {item.iteration.index}: {item.accounting?.reconciliation.map((row) =>
            `${row.assetId} / ${row.participant}: ${row.before ?? "UNAVAILABLE"} → ${row.after ?? "UNAVAILABLE"}`)
            .join(" · ") ?? "UNAVAILABLE"}</li>)}</ul></section>}
    </>}
  </div>;
}
