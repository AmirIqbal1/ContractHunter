import type { PublicInvariantProposal } from "./public-invariants";
import type { PublicVerificationPlanAttempt } from "./public-strategy-planning";
import type { PlanningCandidate, PublicVerificationTargetSummary } from "./verification-target-discovery";

const reuseMessages: Record<string, string> = {
  reuse_artifact_not_found: "This planning artifact is no longer available.",
  reuse_candidate_not_eligible: "This planning artifact is no longer eligible for reuse.",
  reuse_source_identity_unprovable: "The source identity of this planning artifact cannot be proven.",
  reuse_source_changed: "The authoritative source closure changed. Review the current candidates.",
  reuse_scan_mismatch: "The source and current hypothesis belong to different scans.",
  reuse_commit_mismatch: "The resolved commit changed. Review the current candidates.",
  reuse_compiler_mismatch: "The trusted compiler identity changed. Review the current candidates.",
  reuse_target_changed: "The verification target changed. Review the current candidates.",
  reuse_strategy_mismatch: "The selected strategy is no longer compatible.",
  reuse_mode_mismatch: "The plan mode no longer matches the selected strategy.",
  reuse_property_target_mismatch: "The exact property target changed. Review the current candidates.",
  reuse_alignment_unavailable: "Current scanner and source alignment is unavailable.",
  reuse_concrete_strategy_incompatible: "The plan no longer passes the selected engine's concrete compatibility check.",
  reuse_authoritative_profile_unsupported: "Authoritative reuse is unsupported for this scan profile.",
  reuse_plan_invalid: "The saved plan no longer passes current validation.",
  reuse_request_invalid: "The reuse request was rejected. Reload this page and try again.",
  reuse_request_too_large: "The reuse request was rejected. Reload this page and try again.",
  reuse_hypothesis_not_found: "This hypothesis is no longer available.",
  reuse_failed_safely: "Planning reuse could not be completed safely.",
};
export const planningReuseFailureMessage = (code: unknown) => typeof code === "string" ? reuseMessages[code] ?? "Planning reuse failed safely." : "Planning reuse failed safely.";

type ReuseResponse = { attempt?: PublicVerificationPlanAttempt; proposal?: PublicInvariantProposal; code?: string };
export type PlanningReuseResult =
  | { ok: true; artifact: PublicVerificationPlanAttempt | PublicInvariantProposal; type: PlanningCandidate["artifactType"] }
  | { ok: false; message: string };

/** IDs select an artifact. No plan, strategy, source, or other authority is sent by the browser. */
export async function requestPlanningReuse(hypothesisId: string, candidate: PlanningCandidate): Promise<PlanningReuseResult> {
  const route = candidate.artifactType === "structured-plan" ? "structured" : "invariant";
  const response = await fetch(`/api/hypotheses/${encodeURIComponent(hypothesisId)}/verification-target/reuse/${route}/${encodeURIComponent(candidate.artifactId)}`, { method: "POST" }).catch(() => null);
  const body = response ? await response.json().catch(() => ({})) as ReuseResponse : {};
  if (!response?.ok) return { ok: false, message: planningReuseFailureMessage(body.code) };
  if (candidate.artifactType === "structured-plan" && body.attempt?.id && body.attempt.origin === "reused" && body.attempt.selectedStrategy === "structured-verification" && body.attempt.reuseSourceArtifactId === candidate.artifactId)
    return { ok: true, artifact: body.attempt, type: candidate.artifactType };
  if (candidate.artifactType === "invariant-proposal" && body.proposal?.id && body.proposal.origin === "reused" && body.proposal.selectedStrategy === candidate.strategy && body.proposal.reuseSourceArtifactId === candidate.artifactId)
    return { ok: true, artifact: body.proposal, type: candidate.artifactType };
  return { ok: false, message: "Planning reuse returned an invalid response." };
}

export async function refreshPlanningCandidates(hypothesisId: string): Promise<PublicVerificationTargetSummary | null> {
  const response = await fetch(`/api/hypotheses/${encodeURIComponent(hypothesisId)}/verification-target`, { cache: "no-store" }).catch(() => null);
  if (!response?.ok) return null;
  const body = await response.json().catch(() => ({})) as { target?: PublicVerificationTargetSummary };
  return body.target ?? null;
}

/** One explicit click, with a synchronous guard before React can rerender the button. */
export async function performPlanningReuse(
  hypothesisId: string,
  candidate: PlanningCandidate,
  pending: { current: string | null },
  handlers: {
    onStart: (artifactId: string) => void;
    onSuccess: (result: Extract<PlanningReuseResult, { ok: true }>, sourceId: string) => void;
    onFailure: (message: string, sourceId: string) => void;
    onRefresh: (target: PublicVerificationTargetSummary | null, failed: boolean) => void;
    onFinish: () => void;
  },
): Promise<void> {
  if (candidate.eligibility !== "eligible" || pending.current) return;
  pending.current = candidate.artifactId;
  handlers.onStart(candidate.artifactId);
  try {
    const result = await requestPlanningReuse(hypothesisId, candidate);
    if (result.ok) handlers.onSuccess(result, candidate.artifactId);
    else handlers.onFailure(result.message, candidate.artifactId);
    handlers.onRefresh(await refreshPlanningCandidates(hypothesisId), !result.ok);
  } finally {
    pending.current = null;
    handlers.onFinish();
  }
}
