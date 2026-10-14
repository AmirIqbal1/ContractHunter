"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useMemo, useState } from "react";
import { type AssetFlow, type ImpactScenario,
  type ScenarioImpact, type ScenarioRole } from "@contracthunter/core";

const roleNames: Record<ScenarioRole, string> = { "scenario-subject": "Scenario Subject",
  protocol: "Protocol", counterparty: "Counterparty", unassigned: "Unassigned" };
const short = (value: string) => value.length > 18 ? `${value.slice(0, 8)}…${value.slice(-6)}` : value;
const signed = (value: string) => BigInt(value) > 0n ? `+${value}` : value;
function assetLabel(flow: AssetFlow, id: string) {
  const asset = flow.assets.find((item) => item.id === id);
  return !asset ? id : asset.standard === "native" ? "NATIVE · wei" :
    `${asset.standard === "token-unknown-standard" ? "UNKNOWN TOKEN STANDARD" : asset.standard.toUpperCase()} · ${asset.contractAddress}${asset.tokenId !== null ? ` · token ID ${asset.tokenId}` : ""}`;
}
export function ScenarioReviewView({ flow, labels, participantIds, scenario, impact, stale, historical = false,
  revisions = [] }: { flow: AssetFlow; labels: Record<string, string>; participantIds: Record<string, string>;
  scenario: ImpactScenario | null;
  impact: ScenarioImpact | null; stale: boolean; historical?: boolean; revisions?: ImpactScenario[] }) {
  const router = useRouter();
  const [assignments, setAssignments] = useState<Record<string, ScenarioRole>>(
    Object.fromEntries((scenario?.assignments ?? []).map((item) => [item.participantId, item.role])));
  const [note, setNote] = useState(scenario?.note ?? ""), [dirty, setDirty] = useState(false);
  const [confirmed, setConfirmed] = useState(false), [busy, setBusy] = useState(false);
  const [error, setError] = useState(""), [mode, setMode] = useState<"beginner" | "researcher">("beginner");
  const [tx, setTx] = useState("all");
  const base = `/hunts/${encodeURIComponent(flow.scanId)}/impact/executions/${encodeURIComponent(flow.executionId)}/assets`;
  const api = `/api/scans/${encodeURIComponent(flow.scanId)}/impact/poc-executions/${encodeURIComponent(flow.executionId)}/scenarios`;
  const resource = scenario ? `${api}/${encodeURIComponent(scenario.scenarioId)}` : api;
  const roleInput = flow.participants.map((item) => ({ participantId: participantIds[item.address]!,
    role: assignments[participantIds[item.address]!] ?? "unassigned" }))
    .filter((item) => item.role !== "unassigned");
  async function request(url: string, method: "POST" | "PATCH", body: unknown) {
    setBusy(true); setError("");
    try {
      const response = await fetch(url, { method, headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
      const payload = await response.json() as { scenario?: ImpactScenario; error?: string };
      if (!response.ok || !payload.scenario) throw Error(payload.error ?? "Scenario action unavailable.");
      return payload.scenario;
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Scenario action unavailable."); return null; }
    finally { setBusy(false); }
  }
  async function create() {
    const created = await request(api, "POST", { assignments: [], note: "" });
    if (created) router.push(`${base}/scenarios/${encodeURIComponent(created.scenarioId)}`);
  }
  async function save() {
    if (!scenario) return;
    const saved = await request(resource, "PATCH", { revisionId: scenario.id, assignments: roleInput,
      note: note.trim() });
    if (saved) { setDirty(false); router.refresh(); }
  }
  async function decide(decision: "reviewed" | "rejected") {
    if (!scenario) return;
    const result = await request(`${resource}/review`, "POST", { revisionId: scenario.id, decision });
    if (result) { setConfirmed(false); router.refresh(); }
  }
  async function revise() {
    if (!scenario) return;
    const result = await request(`${resource}/revisions`, "POST", { revisionId: scenario.id });
    if (result) { setAssignments(Object.fromEntries(result.assignments.map((item) => [item.participantId, item.role])));
      setNote(result.note); setDirty(false); setConfirmed(false); router.refresh(); }
  }
  const editable = scenario?.status === "draft" && !stale && !historical;
  const positions = impact?.rolePositions.filter((item) => tx === "all" ? item.transactionOrdinal === null :
    String(item.transactionOrdinal) === tx) ?? [];
  const direct = impact?.directRoleTransfers.filter((item) => tx === "all" ? item.transactionOrdinal === null :
    String(item.transactionOrdinal) === tx) ?? [];
  const participantViews = useMemo(() => {
    type View = { stats: AssetFlow["netPositions"]; transactions: Set<number>; attemptedAssets: Set<string> };
    const views = new Map<string, View>();
    const get = (address: string) => {
      let view = views.get(address);
      if (!view) { view = { stats: [], transactions: new Set(), attemptedAssets: new Set() }; views.set(address, view); }
      return view;
    };
    for (const item of flow.participants) get(item.address);
    for (const item of flow.netPositions) get(item.participant).stats.push(item);
    for (const item of flow.ledgerEntries) {
      get(item.from).transactions.add(item.transactionOrdinal);
      get(item.to).transactions.add(item.transactionOrdinal);
    }
    for (const item of flow.attemptedFlows) {
      for (const address of [item.from, item.to]) {
        get(address).transactions.add(item.transactionOrdinal);
        get(address).attemptedAssets.add(item.assetId);
      }
    }
    return views;
  }, [flow]);
  return <div className="af-view">
    <header className="page-head"><div><div className="eyebrow">ISOLATED LOCAL FORK · MANUAL SCENARIO ROLES</div><h1>Scenario Analysis</h1>
      <p className="subhead">Reviewed research annotations over exact E1 asset accounting. Roles do not change protocol facts or finding status.</p></div></header>
    <nav className="ip-actions"><Link href={base}>Back to Asset Flow</Link><Link href={`/hunts/${encodeURIComponent(flow.scanId)}/impact/executions/${encodeURIComponent(flow.executionId)}`}>Observed Execution</Link></nav>
    <div className="sh-mode" aria-label="Display mode">{(["beginner", "researcher"] as const).map((item) =>
      <button type="button" key={item} aria-pressed={mode === item} onClick={() => setMode(item)}>{item === "beginner" ? "Beginner" : "Researcher"}</button>)}</div>
    {mode === "beginner" && <p>Scenario Subject is the participant whose observed position you want to evaluate. Protocol participants are those you explicitly identify as protocol-related. A direct transfer is a committed ledger movement between reviewed roles. Net movement means assets received minus assets sent in this reproduction.</p>}
    {error && <p role="alert" className="af-warning">{error}</p>}
    {stale && <p role="alert" className="af-warning"><strong>Scenario is bound to an earlier asset-accounting result.</strong> Its roles and impact are historical. Create a new draft revision and review the current E1 participants explicitly.</p>}
    {historical && <p role="status" className="af-warning"><strong>HISTORICAL REVISION.</strong> Its reviewed roles remain inspectable; it is not the current reviewed interpretation.</p>}
    {!scenario ? <section className="card"><h2>Create Impact Scenario</h2><p>All participants start unassigned. Creating a draft does not run a PoC or change a finding.</p>
      <button type="button" disabled={busy || !flow.capabilities.assetAccountingAvailable} onClick={create}>Create Scenario Draft</button></section> :
      <section className="card"><h2>{scenario.status === "reviewed" && !stale ? "REVIEWED SCENARIO" : scenario.status === "draft" ? "DRAFT SCENARIO" : "REJECTED SCENARIO"}</h2>
        <p>Revision {scenario.revision} · Execution {short(scenario.executionId)} · <Link href={scenario.subject.type === "finding" ? `/findings/${encodeURIComponent(scenario.subject.id)}` : `/hypotheses/${encodeURIComponent(scenario.subject.id)}`}>{scenario.subject.type}</Link></p>
        <p className="mono">Scenario {scenario.scenarioId} · Revision ID {scenario.id} · E1 {scenario.assetFlowContentSha256} · E1 ruleset {scenario.assetAccountingRulesetVersion}</p>
        {scenario.note && <p>Researcher note: {scenario.note}</p>}
        {mode === "researcher" && <p className="mono">Review content {scenario.contentSha256} · Created {new Date(scenario.createdAt).toISOString()} · Reviewed {scenario.reviewedAt ? new Date(scenario.reviewedAt).toISOString() : "—"} · Rejected {scenario.rejectedAt ? new Date(scenario.rejectedAt).toISOString() : "—"}</p>}
        {scenario.status !== "draft" && !historical && <button type="button" disabled={busy} onClick={revise}>Edit Roles — Create New Draft Revision</button>}
        {scenario.status === "draft" && stale && <p>This draft cannot be reviewed against changed E1 evidence.</p>}
      </section>}
    {revisions.length > 1 && <section className="card"><h2>Revision history</h2><ul>{revisions.map((item) => <li key={item.id}><Link href={`${base}/scenarios/${encodeURIComponent(item.scenarioId)}?revision=${encodeURIComponent(item.id)}`}>Revision {item.revision} · {item.status.toUpperCase()} · {short(item.id)}</Link></li>)}</ul></section>}
    <section className="card"><h2>1. Review participants and assign roles</h2><p>E1 mapping and manual scenario role are separate facts. Balance direction does not choose a role. The zero address remains unassigned.</p>
      <div className="af-table-wrap"><table><thead><tr><th>Participant</th><th>E1 classification</th><th>Observed assets and movement</th><th>Transactions</th><th>Manual scenario role</th></tr></thead><tbody>{flow.participants.map((item) => {
        const id = participantIds[item.address]!, view = participantViews.get(item.address)!;
        const stats = view.stats, attempts = [...view.attemptedAssets], txCount = view.transactions.size;
        return <tr key={id}><td className="mono">{mode === "researcher" ? item.address : short(item.address)}{mode === "researcher" && <small> · {id}</small>}</td>
          <td>{item.label}{item.contractNodeId && labels[item.contractNodeId] ? ` · ${labels[item.contractNodeId]}` : ""}</td>
          <td>{stats.length ? stats.map((stat) => <div key={stat.assetId}>{assetLabel(flow, stat.assetId)} · in {stat.incoming} · out {stat.outgoing} · net {signed(stat.netObservedMovement)}</div>) : "No committed position"}
            {attempts.length > 0 && <div>Attempted context: {attempts.map((assetId) => assetLabel(flow, assetId)).join(", ")}</div>}</td>
          <td>{txCount}</td><td>{editable ? <select aria-label={`Role for ${item.address}`} value={assignments[id] ?? "unassigned"}
            disabled={item.label === "Zero address"} onChange={(event) => { setAssignments({ ...assignments, [id]: event.target.value as ScenarioRole }); setDirty(true); setConfirmed(false); }}>
            {Object.entries(roleNames).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select> :
            roleNames[scenario?.assignments.find((assignment) => assignment.participantId === id)?.role ?? "unassigned"]}</td></tr>;
      })}</tbody></table></div>
      {editable && <><label>Optional review note (plain text, at most 1,000 characters)<textarea maxLength={1000} value={note} onChange={(event) => { setNote(event.target.value); setDirty(true); setConfirmed(false); }} /></label>
        <p><button type="button" disabled={busy || !dirty} onClick={save}>Save Draft and Refresh Preview</button></p></>}
      {!scenario && <p>Choose Create Scenario Draft above to begin assigning roles.</p>}
    </section>
    {scenario?.status === "draft" && !stale && !historical && <section className="card"><h2>2. Review accounting preview</h2><p><strong>PREVIEW — NOT REVIEWED.</strong> The preview uses saved draft roles. Save any edits above before reviewing.</p>
      <label><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} /> These roles are manual scenario annotations. They do not establish attacker, victim, ownership, exploitability, or finding validity.</label>
      <p><button type="button" disabled={busy || dirty || !confirmed} onClick={() => decide("reviewed")}>Confirm and Review Scenario</button> <button type="button" disabled={busy} onClick={() => decide("rejected")}>Reject Draft</button></p></section>}
    {scenario?.status === "reviewed" && !stale && !historical && <section className="card"><h2>Review decision</h2><p>This reviewed revision is immutable. Rejecting it creates a separate historical rejection revision and removes it as the current reviewed interpretation.</p>
      <button type="button" disabled={busy} onClick={() => decide("rejected")}>Reject Current Interpretation</button></section>}
    {impact && <>
      <section className="card"><h2>{impact.preview ? "PREVIEW — NOT REVIEWED" : "ROLE-BASED OBSERVED ACCOUNTING"}</h2>
        <p>Exact raw units per asset. A role net is assets received minus assets sent in this isolated reproduction. ERC721 rows count movement of the exact token ID shown; they do not express fungible value.</p>
        {impact.status !== "complete-within-evidence" && <p className="af-warning" role="status"><strong>{impact.status === "partial" ? "PARTIAL" : "UNAVAILABLE"} ACCOUNTING.</strong> Role review does not improve underlying evidence completeness.</p>}
        <label>Transaction <select value={tx} onChange={(event) => setTx(event.target.value)}><option value="all">All transactions</option>{flow.transactions.map((item) => <option key={item.ordinal} value={item.ordinal}>Transaction {item.ordinal + 1}</option>)}</select></label>
        <div className="af-table-wrap"><table><thead><tr><th>Role</th><th>Asset</th><th>Incoming</th><th>Outgoing</th><th>Net observed movement</th><th>Ledger evidence</th></tr></thead><tbody>{positions.map((item) => <tr key={`${item.transactionOrdinal}:${item.role}:${item.assetId}`}><td>{roleNames[item.role]}</td><td>{assetLabel(flow, item.assetId)}</td><td className="mono">{item.incoming}</td><td className="mono">{item.outgoing}</td><td className="mono">{signed(item.netObservedMovement)}</td><td>{item.ledgerEntryIds.map((id) => <Link key={id} href={`${base}?tx=${item.transactionOrdinal ?? "all"}&entry=${encodeURIComponent(id)}#asset-ledger`}>{short(id)} </Link>)}</td></tr>)}</tbody></table></div>
        {positions.length === 0 && <p>No committed role positions in this transaction.</p>}
      </section>
      <section className="card"><h2>DIRECT ROLE TRANSFERS</h2><p>Only exact committed E1 ledger edges count. Matching net positions through an intermediary do not create a direct transfer.</p>
        <div className="af-table-wrap"><table><thead><tr><th>Direction</th><th>Asset</th><th>Raw amount</th><th>Ledger entries</th></tr></thead><tbody>{direct.map((item) => <tr key={`${item.transactionOrdinal}:${item.assetId}:${item.direction}`}><td>{item.direction === "protocol-to-subject" ? "Protocol → Scenario Subject" : "Scenario Subject → Protocol"}</td><td>{assetLabel(flow, item.assetId)}</td><td className="mono">{item.amount}</td><td>{item.ledgerEntryIds.map((id) => <Link key={id} href={`${base}?tx=${item.transactionOrdinal ?? "all"}&entry=${encodeURIComponent(id)}#asset-ledger`}>{short(id)} </Link>)}</td></tr>)}</tbody></table></div>
        {direct.length === 0 && <p>No direct protocol ↔ scenario-subject transfer in this selection.</p>}
      </section>
      <section className="card"><h2>Reconciliation and supply observations</h2><p>E1 reconciliation is execution-wide; differences do not by themselves identify a vulnerability. Supply observations are separate from account movement.</p>
        {impact.supplyObservations.length > 0 && <div><h3>Observed supply changes</h3><ul>{impact.supplyObservations.map((item) => <li key={item.observationId}>{assetLabel(flow, item.assetId)} · {item.observedDelta === null ? "UNAVAILABLE" : BigInt(item.observedDelta) > 0n ? "Observed supply increase" : BigInt(item.observedDelta) < 0n ? "Observed supply decrease" : "No observed supply change"} · {item.observedDelta ?? "UNAVAILABLE"} raw units</li>)}</ul></div>}
        <ul>{impact.reconciliation.map((item) => <li key={item.observationId}>{assetLabel(flow, item.assetId)} · {item.kind} · {item.status.toUpperCase()} · PRE {item.before ?? "UNAVAILABLE"} → POST {item.after ?? "UNAVAILABLE"} · delta {item.observedDelta ?? "UNAVAILABLE"} · <Link href={`/hunts/${encodeURIComponent(flow.scanId)}/impact/executions/${encodeURIComponent(flow.executionId)}?state=all#obs-${encodeURIComponent(item.observationId)}`}>View State Observation</Link></li>)}</ul>
        {impact.reconciliation.length === 0 && <p>No captured asset reconciliation observations.</p>}
      </section>
      <section className="card"><h2>Local Execution Cost</h2><p>Gas is separate from asset movements and is never subtracted from role positions.</p><ul>{flow.transactions.map((item) => <li key={item.hash}>Transaction {item.ordinal + 1}: gas used {item.executionCost.gasUsed ?? "UNAVAILABLE"}; effective gas price and exact local gas cost UNAVAILABLE.</li>)}</ul></section>
      {impact.attemptedFlowIds.length > 0 && <section className="card"><h2>Attempted / reverted context</h2><p>{impact.attemptedFlowIds.length} attempted flow(s) remain outside committed scenario accounting. <Link href={`${base}?status=attempted`}>Inspect in Asset Flow</Link></p></section>}
      {impact.warnings.length > 0 && <section className="card af-warning"><h2>Accounting warnings</h2><ul>{impact.warnings.map((item) => <li key={item}>{item === "unassigned-participant-flow" ? "Observed asset movement includes participants that are not assigned a scenario role." : item.replaceAll("-", " ")}</li>)}</ul></section>}
      {mode === "researcher" && <section className="card"><h2>Derivation identity</h2><p className="mono">Scenario {impact.scenarioId} · revision {impact.revisionId} · E1 {impact.assetFlowContentSha256} · E1 ruleset {impact.assetAccountingRulesetVersion} · {impact.schema} · {impact.derivationVersion} · {impact.rulesetVersion} · content {impact.contentSha256}</p></section>}
    </>}
  </div>;
}
