"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useMemo, useState } from "react";
import { type ReplayMovementStep, type ScenarioReplayPlan, type ScenarioReplayResult,
  type ScenarioReplayRun, type ScenarioRole } from "@contracthunter/core";

export type ReplayIterationEvidence = Readonly<{ index: number; executionId: string | null;
  executionStatus: string | null; errorCode: string | null; transactionHashes: string[];
  traceCaptureStatus: string | null; traceIds: string[]; stateCaptureAvailable: boolean;
  stateChangeCount: number | null; mappedContracts: Array<{ address: string; contractNodeId: string }>;
  mappedFunctions: Array<{ contractNodeId: string; functionNodeId: string }> }>;

const names: Record<ScenarioRole, string> = { "scenario-subject": "Scenario Subject", protocol: "Protocol",
  counterparty: "Counterparty", unassigned: "Unassigned" };
const explanations: Record<ScenarioReplayResult["repeatability"], string> = {
  "reproduced-consistently": "The bounded repetitions produced equivalent relevant scenario accounting under the reviewed comparison rules.",
  "reproduced-with-variation": "Completed repetitions produced different relevant scenario accounting. Inspect each exact difference below.",
  "stopped-after-state-change": "Cumulative replay stopped after an observed outcome or state-continuity change. This is not a maximum repetition claim.",
  "not-reproduced": "The reference movement was not observed in the completed bounded repetitions.",
  partial: "Some requested repetitions or accounting evidence are incomplete. Missing values are not zero.",
  unavailable: "The available evidence cannot establish a bounded replay comparison.",
};
const signed = (value: string) => BigInt(value) > 0n ? `+${value}` : value;
const title = (value: string) => value.replaceAll("-", " ").replaceAll("_", " ").toUpperCase();
const assetName = (id: string) => id.startsWith("erc721:") ?
  `ERC721 ${id.split(":")[2]} · token ID ${id.split(":")[3]}` :
  id.startsWith("erc1155:") ? `ERC1155 ${id.split(":")[2]} · token ID ${id.split(":")[3]}` :
  id === "native" || id.startsWith("native:") ? `${id} · wei` : id;
const positionValue = (assetId: string, value: string) => assetId.startsWith("erc721:") ?
  `${signed(value)} identity movement count` : signed(value);
const isCompleted = (status: string, reason: string | null) =>
  status === "completed" || status === "reverted" && reason === null;
function resetLabel(run: ScenarioReplayRun, forkStatus: string | null) {
  if (run.status === "queued" || run.status === "running") return "Pending finalization";
  if (run.stopReason === "replay_final_reset_failed") return `FAILED — fork ${forkStatus ?? "status unavailable"}`;
  if (run.stopReason === "impact_server_restart" || run.stopReason === "replay_total_timeout")
    return `UNAVAILABLE — fork ${forkStatus ?? "status unavailable"}`;
  return "Successful final baseline reset";
}
function resourceRows(result: ScenarioReplayResult, asset: string) {
  type Row = { key: string; assetId: string; participant: string | null; kind: string;
    values: Array<{ index: number; before: string | null; after: string | null; status: string; observationId: string }> };
  const rows = new Map<string, Row>();
  for (const item of result.iterations) {
    if (!item.accounting) continue;
    for (const rec of item.accounting.reconciliation) {
      if (asset !== "all" && rec.assetId !== asset) continue;
      const key = `${rec.assetId}|${rec.participant ?? ""}|${rec.kind}`;
      const row = rows.get(key) ?? { key, assetId: rec.assetId, participant: rec.participant,
        kind: rec.kind, values: [] };
      row.values.push({ index: item.iteration.index, before: rec.before, after: rec.after,
        status: rec.status, observationId: rec.observationId });
      rows.set(key, row);
    }
  }
  return [...rows.values()].sort((a, b) => a.key.localeCompare(b.key));
}
function resourceChart(values: Array<{ before: string | null; after: string | null }>) {
  const points = [values[0]?.before, ...values.map((item) => item.after)];
  if (points.length < 2 || points.some((value) => value === null || !/^-?\d+$/.test(value))) return null;
  const integers = points.map((value) => BigInt(value!));
  const low = integers.reduce((a, b) => a < b ? a : b), high = integers.reduce((a, b) => a > b ? a : b);
  // Only bounded 0–100 coordinates become Numbers; observed integers remain BigInt/string.
  return integers.map((value, index) => ({ x: 8 + Math.round(index * 84 / (integers.length - 1)),
    y: high === low ? 50 : 90 - Number((value - low) * 80n / (high - low)) }));
}
export function ScenarioReplayResultView({ scanId, executionId, scenarioId, plan, run, result,
  movementSteps, evidence, subject, forkStatus }: {
  scanId: string; executionId: string; scenarioId: string; plan: ScenarioReplayPlan;
  run: ScenarioReplayRun; result: ScenarioReplayResult | null; movementSteps: ReplayMovementStep[];
  evidence: ReplayIterationEvidence[]; subject: { type: "finding" | "hypothesis"; id: string } | null;
  forkStatus: string | null;
}) {
  const router = useRouter();
  const [mode, setMode] = useState<"beginner" | "researcher">("beginner");
  const [iteration, setIteration] = useState("all"), [asset, setAsset] = useState("all");
  const [role, setRole] = useState<ScenarioRole | "all">("all");
  const [filter, setFilter] = useState("all"), [search, setSearch] = useState("");
  const [resourceKey, setResourceKey] = useState("");
  useEffect(() => {
    if (run.status !== "queued" && run.status !== "running") return;
    const timer = window.setInterval(() => router.refresh(), 3000);
    return () => window.clearInterval(timer);
  }, [router, run.status]);
  const base = `/hunts/${encodeURIComponent(scanId)}/impact/executions/${encodeURIComponent(executionId)}`;
  const scenarioBase = `${base}/assets/scenarios/${encodeURIComponent(scenarioId)}`;
  const context = `/hunts/${encodeURIComponent(scanId)}`;
  const meta = new Map(evidence.map((item) => [item.index, item]));
  const assets = useMemo(() => result ? [...new Set([
    ...result.iterations.flatMap((item) => [
      ...(item.accounting?.rolePositions.map((position) => position.assetId) ?? []),
      ...(item.accounting?.reconciliation.map((rec) => rec.assetId) ?? [])]),
    ...result.cumulativePositions.map((item) => item.assetId)
  ])].sort() : [], [result]);
  const term = search.trim().toLowerCase();
  const visible = (result?.iterations ?? []).filter((item) => {
    const detail = meta.get(item.iteration.index);
    const matches = !term || `${item.iteration.index} ${detail?.executionId ?? ""} ${detail?.transactionHashes.join(" ") ?? ""} ${detail?.mappedContracts.map((c) => `${c.address} ${c.contractNodeId}`).join(" ") ?? ""} ${item.accounting?.roles.map((r) => r.address).join(" ") ?? ""} ${item.accounting?.rolePositions.map((p) => p.assetId).join(" ") ?? ""}`.toLowerCase().includes(term);
    return (iteration === "all" || String(item.iteration.index) === iteration) && matches &&
      (asset === "all" || item.accounting?.rolePositions.some((row) => row.assetId === asset) ||
        item.accounting?.reconciliation.some((row) => row.assetId === asset)) &&
      (role === "all" || item.accounting?.rolePositions.some((row) => row.role === role)) &&
      (filter === "all" || filter === item.iteration.status || filter === "partial" &&
        item.accounting?.status !== "complete-within-evidence" ||
        filter === "matching" && item.matchedReference === true ||
        filter === "variation" && item.matchedReference === false);
  });
  const rows = result ? resourceRows(result, asset) : [];
  const selectedResource = rows.find((item) => item.key === resourceKey) ?? rows[0];
  const completedResources = selectedResource?.values.filter((value) => result?.iterations.some((item) =>
    item.iteration.index === value.index && isCompleted(item.iteration.status, item.iteration.stopReason))) ?? [];
  const points = selectedResource && result?.mode === "cumulative-replay" ? resourceChart(completedResources) : null;
  const totalTx = result?.iterations.reduce((sum, item) => sum + (meta.get(item.iteration.index)?.transactionHashes.length ?? 0), 0) ?? 0;
  const partialCount = result?.iterations.filter((item) => item.accounting && item.accounting.status !== "complete-within-evidence" ||
    isCompleted(item.iteration.status, item.iteration.stopReason) && !item.accounting).length ?? 0;
  const lastCompleted = result?.iterations.filter((item) => isCompleted(item.iteration.status,
    item.iteration.stopReason) && item.accounting).at(-1)?.iteration.index ?? 0;
  return <div className="af-view sr-view">
    <header className="page-head"><div><div className="eyebrow">BOUNDED LOCAL REPLAY · ISOLATED LOCAL FORK</div>
      <h1>Scenario Replay Result</h1><p className="subhead">This result describes only the bounded local repetitions that actually ran.</p></div></header>
    <nav className="ip-actions" aria-label="Replay evidence navigation"><Link href={scenarioBase}>Reviewed Scenario</Link>
      <Link href={`${scenarioBase}/replay/${encodeURIComponent(plan.planId)}`}>Replay Plan</Link>
      <Link href={base}>Single Observed Reproduction</Link><Link href={`${base}/assets`}>Source Asset Flow</Link>
      {subject && <Link href={`${context}/investigation-paths/${subject.type}/${encodeURIComponent(subject.id)}`}>Static Investigation Path</Link>}</nav>
    <p role="note" className="af-warning">Bounded replay does not establish unlimited repeatability, maximum protocol impact, or real-chain exploitability.</p>
    <div className="sh-mode" aria-label="Display mode">{(["beginner", "researcher"] as const).map((value) =>
      <button key={value} type="button" aria-pressed={mode === value} onClick={() => setMode(value)}>{value === "beginner" ? "Beginner" : "Researcher"}</button>)}</div>
    {mode === "beginner" && <p>Independent replay runs the same reviewed reproduction from the same baseline several times. Cumulative replay runs it while local state changes. Repeatability describes these bounded local repetitions only.</p>}
    <section className="card"><h2>Run identity</h2><dl className="io-grid">
      <div><dt>Mode</dt><dd>{plan.mode === "independent-replay" ? "INDEPENDENT REPLAY" : "CUMULATIVE REPLAY"}</dd></div>
      <div><dt>Requested / completed</dt><dd>{plan.iterationCount} / {result?.completedIterations ?? "UNAVAILABLE"}</dd></div>
      <div><dt>Run status</dt><dd>{title(run.status)}</dd></div>
      <div><dt>PoC source hash</dt><dd className="mono">{plan.sourceSha256}</dd></div>
      <div><dt>Fork block</dt><dd>{plan.chainId} / {plan.forkBlock}</dd></div>
      <div><dt>Ruleset</dt><dd className="mono">{result?.rulesetVersion ?? "contracthunter-scenario-replay-ruleset-v1"}</dd></div>
    </dl>{mode === "researcher" && <p className="mono">Plan {plan.id} · run {run.id} · scenario revision {plan.scenarioRevisionId} · E1 {plan.assetFlowContentSha256} · F1 {plan.scenarioContentSha256} · plan content {plan.contentSha256} · result content {result?.contentSha256 ?? "UNAVAILABLE"} · fork hash {plan.forkBlockHash} · Forge {plan.forgeVersion} / {plan.forgeSha256}</p>}</section>
    {!result ? <section className="card af-warning" role="status"><h2>{run.status === "queued" || run.status === "running" ? "Replay in progress" : "Replay accounting unavailable"}</h2><p>{run.status === "queued" || run.status === "running" ? "The page refreshes as exact iteration evidence is finalized." : "The exact historical run or its bound E1/F1 evidence cannot currently be derived. Missing accounting is not zero."}</p><p>Run status: {title(run.status)} · {run.stopReason ? title(run.stopReason) : "No recorded stop reason"}</p></section> : <>
      <section className="card"><h2>{plan.mode === "independent-replay" ? "INDEPENDENT REPLAY" : "CUMULATIVE REPLAY"}</h2>
        <p><strong>{title(result.repeatability)}</strong> · {result.completedIterations} of {result.requestedIterations} completed{plan.mode === "independent-replay" ? ` · ${result.matchingIterations} matched the original reviewed reproduction` : ""}.</p>
        <p>{explanations[result.repeatability]}</p>
        <p>Reference: the original reviewed single execution <Link href={base}>{executionId}</Link>. F2A compares relevant role positions, direct transfers and reconciliation; local transaction hashes and block numbers are excluded.</p>
        {plan.mode === "independent-replay" ? <p>Each iteration began from the same captured baseline. Repeated movement is never summed as cumulative impact.</p> :
          <p>Observed cumulative movement after {result.completedIterations} local repetitions is shown per asset below. There is no forward projection.</p>}
        {run.status === "cancelled" && <p>CANCELLED AFTER ITERATION {lastCompleted}. Completed evidence remains inspectable; no run resumes automatically.</p>}
        {run.stopReason && <p className="af-warning"><strong>Why did it stop?</strong> {title(run.stopReason)}. Inspect the recorded iteration and state observations; this status does not establish a cause beyond the evidence.</p>}
        {result.warnings.length > 0 && <div className="af-warning"><strong>Accounting warnings</strong><ul>{result.warnings.map((warning, index) => <li key={index}>{warning}</li>)}</ul></div>}
      </section>
      <section className="card"><h2>Replay timeline</h2><ol className="sr-timeline"><li>Baseline fork state</li>{result.iterations.map((item) => <li key={item.iteration.id}>Iteration {item.iteration.index}: {title(item.iteration.status)}{plan.mode === "independent-replay" && <span> → baseline reset before the next iteration</span>}</li>)}<li>Finalization: {resetLabel(run, forkStatus)}</li></ol>
        <p>{plan.mode === "independent-replay" ? "Baseline → iteration → reset, repeated for each requested iteration." : "Baseline → sequential iterations on evolving local state → final reset."}</p></section>
      <section className="card"><h2>Evidence summary</h2><dl className="io-grid"><div><dt>Requested / completed</dt><dd>{result.requestedIterations} / {result.completedIterations}</dd></div><div><dt>Recorded transactions</dt><dd>{totalTx}</dd></div><div><dt>Trace captures finalized</dt><dd>{evidence.filter((item) => item.traceCaptureStatus === "finalized").length}</dd></div><div><dt>State captures available</dt><dd>{evidence.filter((item) => item.stateCaptureAvailable).length}</dd></div><div><dt>Asset accounting results</dt><dd>{result.iterations.filter((item) => item.assetFlowStatus !== null).length}</dd></div><div><dt>Scenario accounting results</dt><dd>{result.iterations.filter((item) => item.accounting !== null).length}</dd></div><div><dt>Partial iterations</dt><dd>{partialCount}</dd></div><div><dt>Reverted / failed iterations</dt><dd>{result.iterations.filter((item) => item.iteration.status === "reverted" || item.iteration.status === "failed").length}</dd></div></dl></section>
      <section className="card"><h2>View controls</h2><div className="io-controls"><label>Iteration<select aria-label="Iteration" value={iteration} onChange={(event) => setIteration(event.target.value)}><option value="all">All iterations</option>{result.iterations.map((item) => <option key={item.iteration.id} value={item.iteration.index}>Iteration {item.iteration.index}</option>)}</select></label>
        <label>Asset<select aria-label="Asset" value={asset} onChange={(event) => { setAsset(event.target.value); setResourceKey(""); }}><option value="all">All assets</option>{assets.map((id) => <option key={id} value={id}>{assetName(id)}</option>)}</select></label>
        <label>Role<select aria-label="Role" value={role} onChange={(event) => setRole(event.target.value as typeof role)}><option value="all">All roles</option>{Object.entries(names).map(([value, name]) => <option key={value} value={value}>{name}</option>)}</select></label>
        <label>Outcome<select aria-label="Outcome" value={filter} onChange={(event) => setFilter(event.target.value)}>{["all", "completed", "reverted", "failed", "partial", "matching", "variation"].map((value) => <option key={value} value={value}>{title(value)}</option>)}</select></label>
        <label>Search evidence<input aria-label="Search evidence" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Iteration, transaction, address, asset" /></label></div><p>Filters change presentation only. Showing {visible.length} of {result.iterations.length} recorded iterations.</p></section>
      <section className="card"><h2>Iteration accounting</h2><div className="af-table-wrap"><table><thead><tr><th>Iteration</th><th>Outcome</th><th>Transactions</th><th>Subject net by asset</th><th>Protocol net by asset</th><th>Direct role transfers</th><th>Reconciliation</th><th>Local execution cost</th><th>Warnings</th></tr></thead><tbody>{visible.map((item) => {
        const impact = item.accounting, detail = meta.get(item.iteration.index);
        const positions = (which: ScenarioRole) => impact?.rolePositions.filter((row) => row.transactionOrdinal === null && row.role === which && (asset === "all" || row.assetId === asset)).map((row) => `${assetName(row.assetId)}: ${positionValue(row.assetId, row.netObservedMovement)}`).join(" · ") || "UNAVAILABLE";
        return <tr key={item.iteration.id}><td><a href={`#iteration-${item.iteration.index}`}>Iteration {item.iteration.index}</a></td><td>{title(item.iteration.status)}{detail?.executionStatus === "failed" && item.iteration.status !== "reverted" ? " · EXECUTION FAILED" : ""}{impact?.status === "partial" ? " · ACCOUNTING PARTIAL" : ""}</td><td>{detail?.transactionHashes.length ?? 0}{mode === "researcher" && detail?.transactionHashes.map((hash) => <div className="mono" key={hash}>{hash}</div>)}</td><td>{positions("scenario-subject")}</td><td>{positions("protocol")}</td><td>{impact?.directRoleTransfers.filter((row) => row.transactionOrdinal === null && row.amount !== "0" && (asset === "all" || row.assetId === asset)).map((row) => `${row.direction} · ${assetName(row.assetId)} · ${row.assetId.startsWith("erc721:") ? `${row.amount} identity movement` : row.amount}`).join(" · ") || "None supported / unavailable"}</td><td>{impact?.reconciliation.filter((row) => asset === "all" || row.assetId === asset).map((row) => `${assetName(row.assetId)}: ${title(row.status)}`).join(" · ") || "UNAVAILABLE"}</td><td>{impact?.executionCosts.map((cost) => cost.amountWei ?? "UNAVAILABLE").join(" · ") ?? "UNAVAILABLE"}</td><td>{impact?.warnings.join(" · ") || item.iteration.stopReason || "None recorded"}</td></tr>;
      })}</tbody></table></div></section>
      {plan.mode === "independent-replay" ? <section className="card"><h2>Independent comparison</h2><p>Text labels identify every match or variation; no average or cumulative amount is calculated.</p><div className="sr-match-strip" role="list" aria-label="Bounded consistency">{result.iterations.map((item) => <span key={item.iteration.id} role="listitem">Iteration {item.iteration.index}: {item.matchedReference === null ? "UNAVAILABLE" : item.matchedReference ? "MATCH" : "VARIATION"}</span>)}</div><div className="af-table-wrap"><table><thead><tr><th>Iteration</th><th>Outcome</th><th>Scenario accounting</th><th>Matches reference?</th><th>Exact variation</th><th>Reconciliation</th></tr></thead><tbody>{visible.map((item) => <tr key={item.iteration.id}><td>{item.iteration.index}</td><td>{title(item.iteration.status)}</td><td>{item.accounting?.rolePositions.filter((row) => row.transactionOrdinal === null && (asset === "all" || row.assetId === asset) && (role === "all" || row.role === role)).map((row) => `${names[row.role]} ${assetName(row.assetId)} ${positionValue(row.assetId, row.netObservedMovement)}`).join(" · ") || "UNAVAILABLE"}</td><td>{item.matchedReference === null ? "UNAVAILABLE" : item.matchedReference ? "MATCH" : "VARIATION"}</td><td>{item.variation.length ? <ul>{item.variation.map((value, index) => <li key={index}>{value}</li>)}</ul> : "None recorded"}</td><td>{item.accounting?.reconciliation.map((row) => title(row.status)).join(" · ") || "UNAVAILABLE"}</td></tr>)}</tbody></table></div></section> : <>
        <section className="card"><h2>Observed cumulative movement after {result.completedIterations} local repetitions</h2><p>Final totals are the F2A result. Progress rows are a server-owned presentation of completed per-iteration positions. Different assets and NFT identities are never combined.</p><div className="af-table-wrap"><table><thead><tr><th>Iteration</th><th>Asset</th><th>Role</th><th>Per-iteration incoming</th><th>Per-iteration outgoing</th><th>Per-iteration net</th><th>Cumulative net</th></tr></thead><tbody>{movementSteps.filter((row) => (iteration === "all" || String(row.iterationIndex) === iteration) && (asset === "all" || row.assetId === asset) && (role === "all" || row.role === role)).map((row) => <tr key={`${row.iterationIndex}:${row.assetId}:${row.role}`}><td>{row.iterationIndex}</td><td>{assetName(row.assetId)}</td><td>{names[row.role]}</td><td>{row.incoming}</td><td>{row.outgoing}</td><td>{signed(row.netObservedMovement)}</td><td>{signed(row.cumulativeNetObservedMovement)}</td></tr>)}</tbody></table></div>
          <h3>F2A final cumulative positions</h3><ul>{result.cumulativePositions.filter((row) => (asset === "all" || row.assetId === asset) && (role === "all" || row.role === role)).map((row) => <li key={`${row.assetId}:${row.role}`}>{names[row.role]} · {assetName(row.assetId)} · {signed(row.netObservedMovement)} raw · iterations {row.iterationIndexes.join(", ")}</li>)}</ul>
          <h3>Direct role transfers</h3><ul>{result.cumulativeDirect.filter((row) => asset === "all" || row.assetId === asset).map((row) => <li key={`${row.assetId}:${row.direction}`}>{row.direction === "protocol-to-subject" ? "Protocol → Scenario Subject" : "Scenario Subject → Protocol"} · {assetName(row.assetId)} · {row.amount} raw · iterations {row.iterationIndexes.join(", ")}</li>)}</ul><p>These are direct committed E1 ledger edges only. Intermediary movement is not inferred.</p>
        </section>
        <section className="card"><h2>Observed resource evolution</h2><p>These values are captured PRE/POST observations. They are not a claim about available liquidity or why a later iteration stopped. NFT ownership and unavailable values remain text only.</p>
          {rows.length > 0 && <label>Observed resource<select aria-label="Observed resource" value={selectedResource?.key ?? ""} onChange={(event) => setResourceKey(event.target.value)}>{rows.map((row) => <option key={row.key} value={row.key}>{assetName(row.assetId)} · {row.participant ?? "supply"} · {row.kind}</option>)}</select></label>}
          {selectedResource && <><p>Observed starting value: {completedResources[0]?.before ?? "UNAVAILABLE"}. Ending value after the last completed iteration: {completedResources.at(-1)?.after ?? "UNAVAILABLE"}.</p>
            {points && <figure className="sr-chart"><svg viewBox="0 0 100 100" role="img" aria-label={`Observed ${selectedResource.assetId} resource across recorded iterations`}><polyline fill="none" stroke="currentColor" strokeWidth="2" points={points.map((point) => `${point.x},${point.y}`).join(" ")} />{points.map((point, index) => <circle key={index} cx={point.x} cy={point.y} r="2.5" fill="currentColor" />)}</svg><figcaption>Horizontal: baseline then completed iteration. Vertical: this resource&apos;s raw observed value. Exact integers are in the table; the line ends at the last completed observation.</figcaption></figure>}
            <div className="af-table-wrap"><table><thead><tr><th>Iteration</th><th>Observed start</th><th>Observed end</th><th>Reconciliation</th><th>State observation</th></tr></thead><tbody>{selectedResource.values.map((value) => <tr key={`${value.index}:${value.observationId}`}><td>{value.index}</td><td>{value.before ?? "UNAVAILABLE"}</td><td>{value.after ?? "UNAVAILABLE"}</td><td>{title(value.status)}</td><td><Link href={`${context}/impact/executions/${encodeURIComponent(meta.get(value.index)?.executionId ?? "")}?state=all#obs-${encodeURIComponent(value.observationId)}`}>View State Observation</Link></td></tr>)}</tbody></table></div></>}
          {rows.length === 0 && <p>No captured resource observations are available for this asset.</p>}</section>
      </>}
      <section className="card"><h2>Iteration evidence</h2>{visible.map((item) => { const detail = meta.get(item.iteration.index);
        const exec = detail?.executionId;
        return <article className="sr-iteration" id={`iteration-${item.iteration.index}`} key={item.iteration.id}><h3>Iteration {item.iteration.index} · {title(item.iteration.status)}</h3>
          <p>{item.iteration.stopReason ? `Recorded stop: ${title(item.iteration.stopReason)}.` : "No iteration stop reason recorded."} {detail?.errorCode && `Execution code: ${title(detail.errorCode)}.`} {item.accounting?.status === "partial" && "Execution evidence exists; asset accounting is partial."}</p>
          <p>Transactions: {detail?.transactionHashes.length ? detail.transactionHashes.join(" · ") : "UNAVAILABLE / none recorded"}</p>
          {exec && <nav className="ip-actions" aria-label={`Iteration ${item.iteration.index} evidence`}><Link href={`${context}/impact/executions/${encodeURIComponent(exec)}`}>View Observed Execution</Link>
            {detail.stateCaptureAvailable && <Link href={`${context}/impact/executions/${encodeURIComponent(exec)}?state=all#observed-state`}>View State Changes</Link>}
            {item.assetFlowStatus && <Link href={`${context}/impact/executions/${encodeURIComponent(exec)}/assets`}>View Asset Flow</Link>}</nav>}
          <p>Scenario positions: {item.accounting?.rolePositions.filter((row) => row.transactionOrdinal === null && (asset === "all" || row.assetId === asset) && (role === "all" || row.role === role)).map((row) => `${names[row.role]} ${assetName(row.assetId)} ${positionValue(row.assetId, row.netObservedMovement)}`).join(" · ") || "UNAVAILABLE"}</p>
          <p>Direct transfers: {item.accounting?.directRoleTransfers.filter((row) => row.transactionOrdinal === null && row.amount !== "0" && (asset === "all" || row.assetId === asset)).map((row) => `${row.direction} ${assetName(row.assetId)} ${row.amount}`).join(" · ") || "None supported / unavailable"}</p>
          <p>Reconciliation: {item.accounting?.reconciliation.filter((row) => asset === "all" || row.assetId === asset).map((row) => `${assetName(row.assetId)} / ${row.participant ?? "supply"}: ${title(row.status)} · ${row.before ?? "UNAVAILABLE"} → ${row.after ?? "UNAVAILABLE"}`).join(" · ") || "UNAVAILABLE"}</p>
          {item.accounting?.warnings.length ? <ul>{item.accounting.warnings.map((warning, index) => <li key={index}>{warning}</li>)}</ul> : null}
          {detail && detail.mappedContracts.length > 0 && <p>Exact mapped contracts: {detail.mappedContracts.map((mapped) => <span key={`${mapped.address}:${mapped.contractNodeId}`}><Link href={`${context}/contracts/${encodeURIComponent(mapped.contractNodeId)}`}>Open Contract Explorer</Link> · <Link href={`${context}/protocol-map?execution=${encodeURIComponent(exec ?? "")}&observed=1`}>Show on Protocol Map</Link> <span className="mono">{mapped.address}</span> </span>)}</p>}
          {detail && detail.mappedFunctions.length > 0 && <p>Exact mapped functions: {detail.mappedFunctions.map((mapped) => <Link key={`${mapped.contractNodeId}:${mapped.functionNodeId}`} href={`${context}/contracts/${encodeURIComponent(mapped.contractNodeId)}/functions/${encodeURIComponent(mapped.functionNodeId)}?execution=${encodeURIComponent(exec ?? "")}`}>Open Function Explorer · {mapped.functionNodeId} </Link>)}</p>}
          {mode === "researcher" && <p className="mono">Iteration ID {item.iteration.id} · execution {exec ?? "UNAVAILABLE"} · E1 {item.iteration.assetFlowContentSha256 ?? "UNAVAILABLE"} · F1 {item.accounting?.contentSha256 ?? "UNAVAILABLE"} · PRE {item.iteration.preSnapshotId ?? "UNAVAILABLE"} · POST {item.iteration.postSnapshotId ?? "UNAVAILABLE"} · trace IDs {detail?.traceIds.join(", ") || "UNAVAILABLE"}</p>}
        </article>;
      })}</section>
      <section className="card"><h2>Local execution cost</h2><p>This cost belongs to the local fork execution. It is not subtracted from scenario asset movement.</p><div className="af-table-wrap"><table><thead><tr><th>Iteration / transaction</th><th>Gas used</th><th>Effective gas price</th><th>Exact local gas cost</th></tr></thead><tbody>{visible.flatMap((item) => item.accounting?.executionCosts.map((cost, index) => <tr key={`${item.iteration.id}:${index}`}><td>{item.iteration.index} / {index + 1}</td><td>{cost.gasUsed ?? "UNAVAILABLE"}</td><td>{cost.effectiveGasPrice ?? "UNAVAILABLE"}</td><td>{cost.amountWei ?? "UNAVAILABLE"}</td></tr>) ?? [])}</tbody></table></div>{plan.mode === "cumulative-replay" && <p>Exact total local execution cost across completed iterations: UNAVAILABLE.</p>}<p>F2A does not provide an authoritative effective gas price for these D1 captures; an unavailable exact cost is never shown as zero.</p></section>
      <section className="card"><h2>Assumptions and safety boundary</h2><ul><li>Same reviewed PoC source and disposable accounts for every iteration.</li><li>Same verified local fork chain, block, block hash, and target code hashes.</li><li>Same manually reviewed scenario roles and C1 capture definitions.</li><li>{plan.mode === "independent-replay" ? "The captured baseline is restored before each independent iteration." : "Cumulative iterations use evolving local state without intermediate reset."}</li><li>Only {plan.iterationCount} requested local repetitions; no parameter sweep, resource top-up, or projection.</li><li>Existing isolated worker and guarded local fork boundary; upstream remains read-only.</li></ul><p>Final baseline reset: <strong>{resetLabel(run, forkStatus)}</strong>.</p></section>
    </>}
  </div>;
}
