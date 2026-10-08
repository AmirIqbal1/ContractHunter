import Link from "next/link";
import type { PublicVerificationTargetSummary, PlanningCandidate } from "@/lib/verification/verification-target-discovery";

const strategyNames = {
  "structured-verification": "Structured verification",
  "foundry-fuzz-property": "Foundry fuzz property",
  "foundry-stateful-invariant": "Foundry stateful invariant",
  "echidna-stateful-invariant": "Echidna stateful invariant",
  "legacy-unknown-strategy": "Legacy manual planning",
} as const;
const reasonNames = {
  "matching-persisted-validation": "Matching source, strategy and persisted validation history",
  "validation-not-recorded": "Validation is not recorded in planning history",
  "source-fingerprint-unavailable": "Generation-time source closure fingerprint unavailable",
  "stale-scan": "Scan identity changed",
  "stale-commit": "Commit identity changed",
  "stale-source": "Source target changed",
  "stale-compiler": "Compiler assumptions changed",
  "strategy-not-compatible": "Strategy is not currently compatible",
  "strategy-mode-mismatch": "Strategy and plan mode differ",
  "property-target-unproven": "Exact property target is not established for this hypothesis",
  "legacy-unknown-strategy": "Selected strategy was not recorded",
  "invalid-plan": "Stored plan is invalid",
} as const;
const shortId = (id: string) => id.slice(0, 8);

function Candidate({ candidate }: { candidate: PlanningCandidate }) {
  const label = candidate.artifactType === "structured-plan" ? "structured plan" : "invariant proposal";
  return <li>
    <strong>{strategyNames[candidate.strategy]} {label}</strong> · {candidate.validationState === "validated-at-execution" ? "Validated before a recorded execution" : candidate.validationState === "generated" ? "Generated; validation not recorded" : "Invalid"} · {candidate.eligibility === "eligible" ? "Eligible for future explicit reuse" : candidate.eligibility === "stale" ? "Stale; cannot reuse" : "Not eligible for reuse"}
    <br /><span className="muted">{candidate.reasons.map((reason) => reasonNames[reason]).join("; ")} · Source fingerprint {candidate.sourceClosureFingerprintRecorded ? "recorded" : "unavailable"} · From <Link className="muted-link" href={`/hypotheses/${candidate.hypothesisId}`}>{shortId(candidate.hypothesisId)}</Link> · Artifact {shortId(candidate.artifactId)}</span>
  </li>;
}

export function VerificationTargetSection({ target }: { target: PublicVerificationTargetSummary }) {
  return <section className="article-section" aria-label="Verification target"><h2>Verification target</h2>
    <p><strong>Root cause:</strong> {target.familyLabel}<br /><strong>This hypothesis is:</strong> {target.currentHypothesisIsRepresentative ? "Representative planning target" : "Related to the representative planning target"}<br /><strong>Related hypotheses:</strong> {target.relatedHypothesisCount}<br /><strong>Reason:</strong> {target.reason}</p>
    {!target.currentHypothesisIsRepresentative && <p><Link className="muted-link" href={`/hypotheses/${target.representativeHypothesisId}`}>View representative target ({shortId(target.representativeHypothesisId)})</Link></p>}
    {target.relatedHypotheses.length > 0 && <p className="muted">Same verification target: {target.relatedHypotheses.map((id, index) => <span key={id}>{index ? ", " : ""}<Link className="muted-link" href={`/hypotheses/${id}`}>{shortId(id)}</Link></span>)}</p>}
    <p className="muted">Planning readiness: {target.strategyReadiness.compatible.length} compatible, {target.strategyReadiness.incompatible.length} incompatible, {target.strategyReadiness.unknown.length} unknown strategies. This grouping is advisory; direct planning remains available.</p>
    {target.candidates.length > 0 && <><h3>Existing planning</h3><ul className="reason-list">{target.candidates.map((candidate) => <Candidate key={candidate.artifactId} candidate={candidate} />)}</ul><p className="muted">{target.candidateCount > target.candidates.length ? `Showing ${target.candidates.length} of ${target.candidateCount} artifacts. ` : ""}Candidate discovery is advisory. Reuse requires a later explicit workflow and fresh validation.</p></>}
  </section>;
}
