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

type ReuseFeedback = { artifactId: string; message: string; failed: boolean } | null;
type ReuseControls = { requestedHypothesisId?: string; onReuse?: (candidate: PlanningCandidate) => void | Promise<void>; reusingId?: string | null; reuseFeedback?: ReuseFeedback };

function Candidate({ candidate, requestedHypothesisId, onReuse, reusingId, reuseFeedback }: { candidate: PlanningCandidate } & ReuseControls) {
  const label = candidate.artifactType === "structured-plan" ? "structured plan" : "invariant proposal";
  const related = requestedHypothesisId && candidate.hypothesisId !== requestedHypothesisId;
  return <li>
    <strong>{strategyNames[candidate.strategy]} {label}</strong> · {candidate.validationState === "validated-at-execution" ? "Validated before a recorded execution" : candidate.validationState === "generated" ? "Generated; validation not recorded" : "Invalid"} · {candidate.eligibility === "eligible" ? "Eligible for explicit reuse" : candidate.eligibility === "stale" ? "Stale; cannot reuse" : "Not eligible for reuse"}
    <br /><span className="muted">{candidate.reasons.map((reason) => reasonNames[reason]).join("; ")} · Source fingerprint {candidate.sourceClosureFingerprintRecorded ? "recorded" : "unavailable"} · {related ? "From related hypothesis" : "From this hypothesis"} <Link className="muted-link" href={`/hypotheses/${candidate.hypothesisId}`}>{shortId(candidate.hypothesisId)}</Link> · Artifact {shortId(candidate.artifactId)}</span>
    {candidate.eligibility === "eligible" && onReuse && <span> · <button className="button secondary-button" type="button" disabled={!!reusingId} aria-label={`Reuse plan from ${strategyNames[candidate.strategy]} artifact ${shortId(candidate.artifactId)}`} aria-describedby={reuseFeedback?.artifactId === candidate.artifactId ? `reuse-feedback-${candidate.artifactId}` : undefined} onClick={() => void onReuse(candidate)}>{reusingId === candidate.artifactId ? "REUSING…" : "Reuse plan"}</button></span>}
  </li>;
}

export function VerificationTargetSection({ target, requestedHypothesisId, onReuse, reusingId, reuseFeedback }: { target: PublicVerificationTargetSummary } & ReuseControls) {
  return <section className="article-section" aria-label="Verification target"><h2>Verification target</h2>
    <p><strong>Root cause:</strong> {target.familyLabel}<br /><strong>This hypothesis is:</strong> {target.currentHypothesisIsRepresentative ? "Representative planning target" : "Related to the representative planning target"}<br /><strong>Related hypotheses:</strong> {target.relatedHypothesisCount}<br /><strong>Reason:</strong> {target.reason}</p>
    {!target.currentHypothesisIsRepresentative && <p><Link className="muted-link" href={`/hypotheses/${target.representativeHypothesisId}`}>View representative target ({shortId(target.representativeHypothesisId)})</Link></p>}
    {target.relatedHypotheses.length > 0 && <p className="muted">Same verification target: {target.relatedHypotheses.map((id, index) => <span key={id}>{index ? ", " : ""}<Link className="muted-link" href={`/hypotheses/${id}`}>{shortId(id)}</Link></span>)}</p>}
    <p className="muted">Planning readiness: {target.strategyReadiness.compatible.length} compatible, {target.strategyReadiness.incompatible.length} incompatible, {target.strategyReadiness.unknown.length} unknown strategies. This grouping is advisory; direct planning remains available.</p>
    {target.candidates.length > 0 && <><h3>Existing planning</h3><ul className="reason-list">{target.candidates.map((candidate) => <Candidate key={candidate.artifactId} candidate={candidate} requestedHypothesisId={requestedHypothesisId} onReuse={onReuse} reusingId={reusingId} reuseFeedback={reuseFeedback} />)}</ul><p className="muted">{target.candidateCount > target.candidates.length ? `Showing ${target.candidates.length} of ${target.candidateCount} artifacts. ` : ""}Candidate discovery is advisory. The server reassesses every reuse request. Review and validate a new artifact before executing it.</p></>}
    {reuseFeedback && <p id={`reuse-feedback-${reuseFeedback.artifactId}`} className={reuseFeedback.failed ? "error" : "verification-message"} role={reuseFeedback.failed ? "alert" : "status"}>Artifact {shortId(reuseFeedback.artifactId)}: {reuseFeedback.message}</p>}
  </section>;
}
