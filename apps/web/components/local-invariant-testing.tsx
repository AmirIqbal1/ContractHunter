"use client";

import { useCallback, useEffect, useState } from "react";
import type { HypothesisStatus } from "@contracthunter/core";
import type { PublicInvariantProposal, PublicInvariantRun } from "@/lib/verification/public-invariants";

type Props = { hypothesisId: string; hypothesisStatus: HypothesisStatus; initialProposals: PublicInvariantProposal[]; initialRuns: PublicInvariantRun[] };
const when = (value: string) => new Intl.DateTimeFormat("en-GB", { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
const duration = (value: number | null) => value === null ? "—" : value < 1000 ? `${value} ms` : `${(value / 1000).toFixed(1)} s`;
const label = (value: string) => value.replaceAll("_", " ").replaceAll("-", " ");
const state = (run: PublicInvariantRun) => run.status === "completed" ? run.outcome === "held-within-bounds" ? "HELD WITHIN BOUNDS" : "COUNTEREXAMPLE FOUND" : run.status === "failed" ? "EXECUTION FAILED" : run.status.toUpperCase();
export function LocalInvariantTesting({ hypothesisId, hypothesisStatus, initialProposals, initialRuns }: Props) {
  const [proposals, setProposals] = useState(initialProposals), [runs, setRuns] = useState(initialRuns);
  const [generating, setGenerating] = useState(false), [validating, setValidating] = useState(false), [running, setRunning] = useState(false);
  const [validatedId, setValidatedId] = useState<string | null>(null), [message, setMessage] = useState("");
  const latest = proposals[0], active = runs.some((run) => run.status === "queued" || run.status === "running");
  const refresh = useCallback(async () => {
    const response = await fetch(`/api/hypotheses/${hypothesisId}/invariant-proposals`, { cache: "no-store" }).catch(() => null);
    if (!response?.ok) return;
    const body = await response.json() as { proposals?: PublicInvariantProposal[]; runs?: PublicInvariantRun[] };
    if (body.proposals) setProposals(body.proposals); if (body.runs) setRuns(body.runs);
  }, [hypothesisId]);
  useEffect(() => { if (!active && !running) return; const timer = window.setInterval(() => void refresh(), 1500); return () => window.clearInterval(timer); }, [active, running, refresh]);
  async function generate() {
    setGenerating(true); setValidatedId(null); setMessage("");
    const response = await fetch(`/api/hypotheses/${hypothesisId}/invariant-proposals`, { method: "POST" }).catch(() => null);
    const body = response ? await response.json().catch(() => ({})) as { proposal?: PublicInvariantProposal; error?: string } : {};
    if (!response?.ok || !body.proposal) setMessage(body.error ?? "Invariant proposal generation failed safely.");
    else { setProposals((current) => [body.proposal!, ...current]); setMessage(body.proposal.status === "generated" ? "Review the proposal, then validate it before local execution." : "Proposal saved without an executable plan."); }
    setGenerating(false);
  }
  async function validate() {
    if (!latest) return; setValidating(true); setValidatedId(null); setMessage("");
    const response = await fetch(`/api/hypotheses/${hypothesisId}/invariant-proposals/${latest.id}/validate`, { method: "POST" }).catch(() => null);
    const body = response ? await response.json().catch(() => ({})) as { planHash?: string; error?: string } : {};
    if (response?.ok && body.planHash === latest.planHash) { setValidatedId(latest.id); setMessage("Validated against the current trusted source and compiler. Local execution requires a separate click."); }
    else setMessage(body.error ?? "Invariant proposal could not be validated.");
    setValidating(false);
  }
  async function run() {
    if (!latest || validatedId !== latest.id) return; setRunning(true); setValidatedId(null); setMessage("");
    const response = await fetch(`/api/hypotheses/${hypothesisId}/invariant-proposals/${latest.id}/run`, { method: "POST" }).catch(() => null);
    const body = response ? await response.json().catch(() => ({})) as { run?: PublicInvariantRun; error?: string } : {};
    if (body.run) setRuns((current) => [body.run!, ...current.filter((item) => item.id !== body.run!.id)]);
    setMessage(response?.ok ? "Local invariant execution finished. Review the bounded evidence below." : body.error ?? "Local invariant execution failed safely.");
    setRunning(false); await refresh();
  }
  return <section className="article-section verification-section" aria-labelledby="invariant-testing-heading">
    <h2 id="invariant-testing-heading">Executable invariant testing</h2>
    <p className="muted">AI proposes one structured property. You review and validate it before explicitly running a local fuzz or stateful test in the networkless worker. Evidence here does not change hypothesis status.</p>
    <div className="plan-generation"><button className="button" type="button" disabled={generating || running || hypothesisStatus === "rejected"} onClick={() => void generate()}>{generating ? "GENERATING…" : "Generate invariant proposal"}</button><span className="hint">One manual AI request. Generation never starts Forge.</span></div>
    {generating && <div className="plan-proposal"><span className="badge blue">Generating</span></div>}
    {latest && <div className="plan-proposal"><h3>AI invariant proposal</h3><span className={`badge ${latest.status === "generated" ? "green" : latest.status === "failed" ? "red" : "amber"}`}>{latest.status === "generated" ? "Generated preview" : latest.status === "not_plannable" ? "Not plannable" : "Failed"}</span>
      {latest.rationale && <p>{latest.rationale}</p>}{latest.failureCode && <p className="mono">{latest.failureCode}</p>}
      {latest.notPlannableReasons.length > 0 && <ul className="reason-list">{latest.notPlannableReasons.map((reason) => <li key={reason}>{label(reason)}</li>)}</ul>}
      {latest.plan && <><ProposalPlan plan={latest.plan} planHash={latest.planHash} /><p className="muted">Configured budget: {latest.plan.mode === "fuzz-property" ? "128 fuzz runs" : "64 invariant runs × depth 32"}. A pass means no counterexample was found within that budget.</p>
        <div className="verification-actions"><button className="button secondary-button" type="button" disabled={validating || running || hypothesisStatus === "rejected"} onClick={() => void validate()}>{validating ? "VALIDATING…" : "Validate proposal"}</button><button className="button" type="button" disabled={validatedId !== latest.id || running || active || hypothesisStatus === "rejected"} onClick={() => void run()}>{running || active ? "RUNNING…" : "Run invariant locally"}</button></div></>}
      <p className="muted">{latest.provider} · {latest.model} · {latest.promptVersion} · {latest.sourceFileCount} source files · {latest.totalTokens ?? "unknown"} tokens · {latest.estimatedCostUsd === null ? "cost unavailable" : `$${latest.estimatedCostUsd.toFixed(4)} estimated`} · {duration(latest.durationMs)}</p>
    </div>}
    {message && <p className={message.includes("failed") || message.includes("could not") ? "error" : "verification-message"}>{message}</p>}
    <div className="verification-history"><h3>Local invariant execution</h3>{runs.length ? runs.map((run) => <details key={run.id} open={run.id === runs[0]?.id}><summary><span>{when(run.createdAt)}</span><span className={`badge ${run.outcome === "counterexample-found" || run.status === "failed" ? "red" : run.outcome === "held-within-bounds" ? "green" : "blue"}`}>{state(run)}</span><span>{run.mode}</span><span>{duration(run.durationMs)}</span></summary><RunDetails run={run} plan={proposals.find((proposal) => proposal.planHash === run.planHash)?.plan ?? null} /></details>) : <p className="muted">No local invariant execution has been started.</p>}</div>
    {proposals.length > 1 && <div className="verification-history"><h3>Proposal history</h3>{proposals.slice(1).map((proposal) => <p key={proposal.id}>{when(proposal.createdAt)} · {proposal.status} · {proposal.planHash?.slice(0, 12) ?? proposal.failureCode ?? "—"}</p>)}</div>}
  </section>;
}
function ProposalPlan({ plan, planHash }: { plan: NonNullable<PublicInvariantProposal["plan"]>; planHash: string | null }) {
  const properties = plan.mode === "fuzz-property" ? [plan.property] : plan.properties;
  return <div><dl className="details"><div className="detail"><dt>Mode</dt><dd>{plan.mode}</dd></div><div className="detail"><dt>Contract</dt><dd>{plan.primaryContract}</dd></div><div className="detail"><dt>Trusted compiler</dt><dd className="mono">{plan.compilerVersion}</dd></div><div className="detail"><dt>Plan hash</dt><dd className="mono">{planHash ?? "—"}</dd></div></dl>
    <p><strong>Setup:</strong> {plan.setup.map((item) => item.kind === "deploy" ? `deploy ${item.contractName} as ${item.instanceName}` : item.kind === "fund" ? `fund ${item.target.name}` : `call ${item.instanceName}.${item.functionName}`).join("; ")}</p>
    {plan.mode === "fuzz-property" ? <p><strong>Fuzz call:</strong> {plan.fuzzAction.instanceName}.{plan.fuzzAction.functionName}({plan.fuzzAction.parameters.map((item) => `${item.type} ${item.name}`).join(", ")}) · caller {plan.fuzzAction.caller ?? "default"}</p> : <div><strong>Handler actions:</strong><ul className="reason-list">{plan.handlerActions.map((action) => <li key={action.name}>{action.name}: {action.instanceName}.{action.functionName}({action.parameters.map((item) => `${item.type} ${item.name}`).join(", ")}) · caller {action.caller ?? "default"}</li>)}</ul></div>}
    {properties.map((property) => <div key={property.name}><strong>Property {property.name}</strong><p>Observations: {property.observations.map((item) => item.kind === "read-balance" ? `balance(${item.target.name}) → ${item.resultName}` : `${item.instanceName}.${item.functionName}() → ${item.resultName}`).join("; ")}</p><p>Assertions: {property.assertions.map((item) => `${item.id}: ${item.actual} ${item.kind}`).join("; ")}</p></div>)}
  </div>;
}
function RunDetails({ run, plan }: { run: PublicInvariantRun; plan: PublicInvariantProposal["plan"] }) {
  return <div className="verification-result"><dl className="details"><div className="detail"><dt>Outcome</dt><dd>{state(run)}</dd></div><div className="detail"><dt>Mode</dt><dd>{run.mode}</dd></div><div className="detail"><dt>Configured budget</dt><dd>{run.configuredRuns} runs{run.configuredDepth === null ? "" : ` × depth ${run.configuredDepth}`}</dd></div><div className="detail"><dt>Compiler</dt><dd className="mono">{run.compiler}</dd></div><div className="detail"><dt>Duration</dt><dd>{duration(run.durationMs)}</dd></div><div className="detail"><dt>Tests</dt><dd>{run.passedCount} passed · {run.failedCount} failed</dd></div></dl>
    {run.failureCode && <p className="verification-failure">Failure code: {run.failureCode}</p>}
    {run.outcome === "held-within-bounds" && <p>No counterexample was found within the configured execution budget. This is supporting dynamic evidence, not formal proof.</p>}
    {run.outcome === "counterexample-found" && <p>Foundry found a counterexample to the generated property within the configured budget.</p>}
    {run.dynamicEvidence.map((item) => { const property = plan && (plan.mode === "fuzz-property" ? [plan.property] : plan.properties).find((candidate) => candidate.name === item.propertyName); return <article key={item.propertyName} className="dynamic-evidence"><h3>{item.propertyName} <span className={`badge ${item.direction === "supports" ? "green" : "red"}`}>{item.direction}</span></h3><p>{item.summary}</p>{property && <p><strong>Assertion summary:</strong> {property.assertions.map((assertion) => `${assertion.id} (${assertion.kind})`).join("; ")}</p>}{item.counterexample && <><p><strong>Fuzz inputs:</strong> {item.counterexample.fuzzArguments.join(", ") || "—"}</p>{item.counterexample.actionSequence.length > 0 && <p><strong>Handler sequence:</strong> {item.counterexample.actionSequence.map((step) => `${step.signature}${step.arguments.length ? ` args ${step.arguments.join(", ")}` : ""}`).join(" → ")}</p>}</>}</article>; })}
  </div>;
}
