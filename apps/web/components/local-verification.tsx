"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import type { HypothesisStatus } from "@contracthunter/core";
import type { PublicHypothesisVerificationRun } from "@/lib/verification/public-verification";
import { verificationHarnessPlanSchema } from "../../../packages/core/src/hypothesis-verification";
import type { VerificationPlanGenerationResult } from "../../../packages/core/src/verification-plan-generation";

type Props = { hypothesisId: string; hypothesisStatus: HypothesisStatus; initialRuns: PublicHypothesisVerificationRun[] };

const title = (value: string) => value.split("_").join(" ").replace(/\b\w/g, (letter) => letter.toUpperCase());
const duration = (milliseconds: number | null) => milliseconds === null ? "—" : milliseconds < 1000 ? `${milliseconds} ms` : `${(milliseconds / 1000).toFixed(1)} s`;
const date = (value: string) => new Intl.DateTimeFormat("en-GB", { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
const displayState = (run?: PublicHypothesisVerificationRun) => !run ? "Not run" : run.status === "completed" ? title(run.outcome ?? "inconclusive") : title(run.status);
const badge = (run?: PublicHypothesisVerificationRun) => !run ? "gray" : run.status === "failed" || run.outcome === "refuted" ? "red" : run.status === "completed" && run.outcome === "confirmed" ? "green" : run.status === "running" || run.status === "queued" ? "blue" : "amber";

export function LocalVerification({ hypothesisId, hypothesisStatus, initialRuns }: Props) {
  const [runs, setRuns] = useState(initialRuns);
  const [planText, setPlanText] = useState("");
  const [plan, setPlan] = useState<unknown>(null);
  const [message, setMessage] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [generation, setGeneration] = useState<VerificationPlanGenerationResult | null>(null);
  const latest = runs[0];
  const active = runs.some((run) => run.status === "queued" || run.status === "running");

  const refresh = useCallback(async () => {
    const response = await fetch(`/api/hypotheses/${hypothesisId}/verifications`, { cache: "no-store" }).catch(() => null);
    if (!response?.ok) return;
    const body = await response.json() as { verifications?: PublicHypothesisVerificationRun[] };
    if (body.verifications) setRuns(body.verifications);
  }, [hypothesisId]);

  useEffect(() => {
    if (!active && !submitting) return;
    const timer = window.setInterval(() => void refresh(), 1500);
    return () => window.clearInterval(timer);
  }, [active, submitting, refresh]);

  function validate() {
    setMessage(""); setPlan(null);
    let value: unknown;
    try { value = JSON.parse(planText); }
    catch { setMessage("The verification plan is not valid JSON."); return; }
    const parsed = verificationHarnessPlanSchema.safeParse(value);
    if (!parsed.success) { setMessage("The JSON does not match the strict verification plan schema."); return; }
    if (parsed.data.hypothesisId !== hypothesisId) { setMessage("The plan hypothesisId does not match this hypothesis."); return; }
    setPlan(parsed.data); setMessage("Plan is valid and ready for explicit local verification.");
  }

  async function verify() {
    if (!plan) return;
    setSubmitting(true); setMessage("");
    const response = await fetch(`/api/hypotheses/${hypothesisId}/verify`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(plan) }).catch(() => null);
    const body = response ? await response.json().catch(() => ({})) as { error?: string; verification?: PublicHypothesisVerificationRun } : {};
    if (!response?.ok) setMessage(body.error ?? "Local verification could not be started.");
    else { setMessage("Local verification finished."); if (body.verification) setRuns((current) => [body.verification!, ...current.filter((run) => run.id !== body.verification!.id)]); }
    setSubmitting(false); await refresh();
  }

  async function generatePlan() {
    setGenerating(true); setGeneration(null); setMessage(""); setPlan(null);
    const response = await fetch(`/api/hypotheses/${hypothesisId}/verification-plan`, { method: "POST" }).catch(() => null);
    const body = response ? await response.json().catch(() => ({})) as VerificationPlanGenerationResult & { error?: string } : null;
    if (!response?.ok || !body) setMessage(body?.error ?? "Verification plan generation failed safely.");
    else {
      setGeneration(body);
      if (body.status === "generated" && body.plan) { setPlanText(JSON.stringify(body.plan, null, 2)); setMessage("Generated proposal loaded. Review it, then validate the plan before verification."); }
    }
    setGenerating(false);
  }

  const currentExplanation = useMemo(() => {
    if (!latest) return "No local verification has been run.";
    if (latest.status === "failed") return latest.failureCode === "network_isolation_unavailable"
      ? "Local verification could not run because the required isolation environment is unavailable. ContractHunter did not fall back to unsafe execution."
      : latest.failureCode === "trusted_compiler_unavailable"
        ? "Local verification could not run because the scan's trusted compiler is unavailable or invalid. ContractHunter did not download a compiler or use an untrusted fallback."
        : "The verification process could not be completed safely.";
    if (latest.outcome === "inconclusive") return "Local execution did not produce sufficient evidence either way.";
    if (latest.outcome === "refuted") return "Local evidence contradicted the plan's expected vulnerability property; the original hypothesis and evidence remain available.";
    return null;
  }, [latest]);

  return <section className="article-section verification-section" aria-labelledby="local-verification-heading">
    <h2 id="local-verification-heading">Local verification</h2>
    <div className="verification-statuses">
      <div><span className="stat-label">Hypothesis status</span><div><span className={`badge ${hypothesisStatus === "verified" ? "green" : "gray"}`}>{hypothesisStatus}</span></div></div>
      <div><span className="stat-label">Local verification</span><div><span className={`badge ${badge(latest)}`}>{displayState(latest)}</span></div></div>
    </div>
    {currentExplanation && <p className={latest?.status === "failed" ? "verification-failure" : "muted"}>{currentExplanation}</p>}
    {latest && <VerificationDetails run={latest} />}
    <p className="verification-safety">Runs entirely locally with no live chain or wallet. Execution requires the local isolation backend; if isolation is unavailable, ContractHunter refuses to execute.</p>
    <div className="plan-generation"><button className="button" type="button" disabled={generating || hypothesisStatus === "rejected"} onClick={() => void generatePlan()}>{generating ? "GENERATING…" : "Generate verification plan"}</button><span className="hint">Creates a reviewable structured proposal only. It never starts verification.</span></div>
    <PlanGenerationView generating={generating} result={generation} />
    <details className="plan-panel">
      <summary>Open developer verification-plan input</summary>
      <p className="muted">Review or edit the generated proposal, or paste a canonical VerificationHarnessPlan as JSON. Unknown fields and executable inputs are rejected.</p>
      <label htmlFor="verification-plan">Verification plan JSON</label>
      <textarea id="verification-plan" value={planText} onChange={(event) => { setPlanText(event.target.value); setPlan(null); setMessage(""); }} spellCheck={false} placeholder="Paste a canonical VerificationHarnessPlan JSON object" />
      <div className="verification-actions"><button className="button secondary-button" type="button" onClick={validate}>Validate plan</button><button className="button" type="button" disabled={!plan || active || submitting || hypothesisStatus === "rejected"} onClick={() => void verify()}>{submitting || active ? "VERIFYING…" : "Verify locally"}</button></div>
      {hypothesisStatus === "rejected" && <div className="hint">Rejected hypotheses cannot start local verification.</div>}
      {message && <div className={message.startsWith("Plan is valid") || message === "Local verification finished." ? "verification-message" : "error"}>{message}</div>}
    </details>
    <div className="verification-history"><h3>Verification history</h3>{runs.length ? runs.map((run) => <details key={run.id}><summary><span>{date(run.createdAt)}</span><span className={`badge ${badge(run)}`}>{displayState(run)}</span><span>{duration(run.durationMs)}</span><span className="mono">solc {run.compiler}</span><span className="mono">{run.contentFingerprint?.slice(0, 12) ?? "fingerprint pending"}</span></summary><VerificationDetails run={run} /></details>) : <p className="muted">No previous verification runs.</p>}</div>
  </section>;
}

export function PlanGenerationView({ generating, result }: { generating: boolean; result: VerificationPlanGenerationResult | null }) {
  if (generating) return <div className="plan-proposal"><span className="badge blue">Generating</span><p>Building one bounded, tool-free structured proposal from persisted evidence.</p></div>;
  if (!result) return null;
  if (result.status === "not_plannable") return <div className="plan-proposal"><span className="badge amber">Not plannable</span><p>ContractHunter could not safely express this hypothesis using the current local verification capabilities.</p><p>{result.rationale}</p>{result.notPlannableReasons.length > 0 && <ul className="reason-list">{result.notPlannableReasons.map((reason) => <li key={reason}>{title(reason)}</li>)}</ul>}<ProposalMetadata result={result} /></div>;
  if (result.status === "failed") return <div className="plan-proposal"><span className="badge red">Failed</span><p>Verification plan generation failed safely. The hypothesis and verification history were not changed.</p>{result.failureCode && <p className="mono">{result.failureCode}</p>}<ProposalMetadata result={result} /></div>;
  return <div className="plan-proposal"><span className="badge green">Generated preview</span><p>{result.rationale}</p><p className="muted">This proposal has not been executed. Review the JSON and select Validate plan before Verify locally becomes available.</p>{result.limitations.length > 0 && <><h3>Limitations</h3><ul className="reason-list">{result.limitations.map((limitation, index) => <li key={`${index}-${limitation}`}>{limitation}</li>)}</ul></>}<pre>{JSON.stringify(result.plan, null, 2)}</pre><ProposalMetadata result={result} /></div>;
}

function ProposalMetadata({ result }: { result: VerificationPlanGenerationResult }) {
  return <dl className="proposal-metadata"><dt>Provider</dt><dd>{result.provenance.provider}</dd><dt>Model</dt><dd>{result.provenance.actualModel ?? result.provenance.requestedModel}</dd><dt>Prompt</dt><dd className="mono">{result.provenance.promptVersion}</dd><dt>Context</dt><dd>{result.provenance.sourceFileCount} files · {result.provenance.totalSourceBytes} bytes{result.provenance.sourceContextTruncated ? " · truncated" : ""}</dd><dt>Tokens</dt><dd>{result.provenance.totalTokens ?? "not supplied"}</dd><dt>Duration</dt><dd>{duration(result.provenance.durationMs)}</dd></dl>;
}

function VerificationDetails({ run }: { run: PublicHypothesisVerificationRun }) {
  return <div className="verification-result">
    <dl className="details"><div className="detail"><dt>Outcome</dt><dd>{run.outcome ? title(run.outcome) : "—"}</dd></div><div className="detail"><dt>Compiler</dt><dd className="mono">{run.compiler}</dd></div><div className="detail"><dt>Verifier / backend</dt><dd>{run.verifier}<br /><span className="muted">{run.isolationBackend ?? "—"}</span></dd></div><div className="detail"><dt>Duration</dt><dd>{duration(run.durationMs)}</dd></div><div className="detail"><dt>Tests</dt><dd>{run.testCounts.total} total · {run.testCounts.passed} passed · {run.testCounts.failed} failed</dd></div><div className="detail"><dt>Fingerprint</dt><dd className="mono">{run.contentFingerprint?.slice(0, 12) ?? "—"}</dd></div></dl>
    {run.failureCode && <p className="verification-failure">Failure code: <span className="mono">{run.failureCode}</span></p>}
    {run.dynamicEvidence.length > 0 && <div className="dynamic-evidence"><h3>Dynamic evidence</h3>{run.dynamicEvidence.map((item) => <article key={item.assertionId}><div><strong>{item.assertionName}</strong> <span className={`badge ${item.direction === "supports" ? "green" : item.direction === "contradicts" ? "red" : "gray"}`}>{item.direction}</span></div><dl><dt>Assertion</dt><dd>{item.details}</dd><dt>Expected property</dt><dd>{item.expectedBehavior}</dd><dt>Observed result</dt><dd>{item.observedBehavior}</dd>{(item.contract || item.functionName) && <><dt>Relevant target</dt><dd>{[item.contract, item.functionName].filter(Boolean).join(".")}</dd></>}</dl></article>)}</div>}
  </div>;
}
