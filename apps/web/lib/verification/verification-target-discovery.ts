import { executableInvariantPlanSchema, invariantPlanHash, toPublicVerificationTarget, verificationHarnessPlanSchema, type VerificationStrategy, type VerificationTargetGroup } from "@contracthunter/core";
import { getScan, getVulnerabilityHypothesis, listExecutableInvariantProposals, listExecutableInvariantRuns, listHypothesisVerificationRuns, listPersistedInvariantPropertyTargets, listPersistedVerificationTargetGroups, listVerificationPlanAttempts, type DatabaseClient } from "@contracthunter/db";

export type CandidateEligibility = "eligible" | "stale" | "incompatible";
export type CandidateReason = "matching-persisted-validation" | "validation-not-recorded" | "source-fingerprint-unavailable" | "stale-scan" | "stale-commit" | "stale-source" | "stale-compiler" | "strategy-not-compatible" | "strategy-mode-mismatch" | "property-target-unproven" | "legacy-unknown-strategy" | "invalid-plan";
export type PlanningCandidate = {
  artifactId: string; artifactType: "structured-plan" | "invariant-proposal"; hypothesisId: string;
  strategy: VerificationStrategy | "legacy-unknown-strategy"; propertyTargetIds: string[];
  eligibility: CandidateEligibility; reasons: CandidateReason[];
  validationState: "generated" | "validated-at-execution" | "invalid";
  executionHistoryExists: boolean; createdAt: string;
  sourceClosureFingerprintRecorded: boolean;
};
export type PublicVerificationTargetSummary = {
  targetId: string; rootCauseFamily: VerificationTargetGroup["rootCauseFamily"]; familyLabel: string;
  representativeHypothesisId: string; currentHypothesisIsRepresentative: boolean;
  relatedHypotheses: string[]; relatedHypothesisCount: number;
  representativeReason: VerificationTargetGroup["representativeReason"]; reason: string;
  groupingConfidence: VerificationTargetGroup["groupingConfidence"];
  strategyReadiness: VerificationTargetGroup["strategyReadiness"][number]["strategies"];
  candidates: PlanningCandidate[]; candidateCount: number;
};

function parsed(raw: string | null): unknown {
  if (!raw) return null;
  try { return JSON.parse(raw) as unknown; } catch { return null; }
}
function compilerAvailable(raw: string | null, version: string): boolean {
  const values = parsed(raw);
  return Array.isArray(values) && values.includes(version);
}
const expectedMode = (strategy: VerificationStrategy) => strategy === "foundry-fuzz-property" ? "fuzz-property" : "stateful-invariant";
const expectedEngine = (strategy: VerificationStrategy) => strategy === "echidna-stateful-invariant" ? "echidna" : "foundry";

/** Every decision is recalculated from persisted rows. No client-provided target or candidate fields are accepted. */
export function discoverVerificationTarget(database: DatabaseClient, hypothesisId: string): PublicVerificationTargetSummary | null {
  const hypothesis = getVulnerabilityHypothesis(database, hypothesisId);
  if (!hypothesis) return null;
  const group = listPersistedVerificationTargetGroups(database, hypothesis.scanId).find((item) => item.members.includes(hypothesisId));
  if (!group) return null;
  const scan = getScan(database, hypothesis.scanId);
  const publicGroup = toPublicVerificationTarget(group);
  const strategyReadiness = group.strategyReadiness.find((item) => item.hypothesisId === hypothesisId)!.strategies;
  const propertyTargets = listPersistedInvariantPropertyTargets(database, group.members);
  const propertyIds = new Map<string, string[]>();
  for (const target of propertyTargets) for (const member of target.members) propertyIds.set(member.proposalId, [...(propertyIds.get(member.proposalId) ?? []), target.id]);
  const currentPropertyIds = new Set(propertyTargets.filter((target) => target.members.some((member) => member.hypothesisId === hypothesisId)).map((target) => target.id));
  const candidates: PlanningCandidate[] = [];
  for (const memberId of group.members) {
    const structuredRuns = listHypothesisVerificationRuns(database, memberId);
    for (const attempt of listVerificationPlanAttempts(database, memberId)) {
      if (attempt.status !== "generated") continue;
      const plan = verificationHarnessPlanSchema.safeParse(parsed(attempt.plan));
      const reasons: CandidateReason[] = [];
      if (!attempt.sourceClosureFingerprintSha256) reasons.push("source-fingerprint-unavailable");
      if (!plan.success) reasons.push("invalid-plan");
      else {
        if (plan.data.scanId !== hypothesis.scanId || attempt.scanId !== hypothesis.scanId) reasons.push("stale-scan");
        if (!scan?.resolvedCommit || plan.data.resolvedCommit !== scan.resolvedCommit) reasons.push("stale-commit");
        if (!group.contractIdentity || !group.functionName || plan.data.primaryContract !== group.contractIdentity.contract || plan.data.primarySourcePath !== group.contractIdentity.sourcePath || !plan.data.relevantFunctions.includes(group.functionName)) reasons.push("stale-source");
        if (!scan || !["ready", "cached"].includes(scan.compilerStatus) || !compilerAvailable(scan.compilerVersions, plan.data.compilerVersion)) reasons.push("stale-compiler");
      }
      if (!strategyReadiness.compatible.includes("structured-verification")) reasons.push("strategy-not-compatible");
      const executionHistoryExists = plan.success && structuredRuns.some((run) => run.scanId === attempt.scanId && run.resolvedCommit === plan.data.resolvedCommit && run.compilerVersion === plan.data.compilerVersion && JSON.stringify(parsed(run.verificationPlan)) === JSON.stringify(plan.data));
      if (!executionHistoryExists) reasons.push("validation-not-recorded");
      candidates.push({ artifactId: attempt.id, artifactType: "structured-plan", hypothesisId: memberId, strategy: "structured-verification", propertyTargetIds: [],
        eligibility: classify(reasons), reasons: reasons.length ? reasons : ["matching-persisted-validation"], validationState: reasons.includes("invalid-plan") ? "invalid" : executionHistoryExists ? "validated-at-execution" : "generated", executionHistoryExists: !!executionHistoryExists, sourceClosureFingerprintRecorded: !!attempt.sourceClosureFingerprintSha256, createdAt: attempt.createdAt.toISOString() });
    }
    const runs = listExecutableInvariantRuns(database, memberId);
    for (const proposal of listExecutableInvariantProposals(database, memberId)) {
      if (proposal.status !== "generated") continue;
      const plan = executableInvariantPlanSchema.safeParse(parsed(proposal.plan));
      const strategy = proposal.selectedStrategy;
      const ids = [...new Set(propertyIds.get(proposal.id) ?? [])].sort();
      const reasons: CandidateReason[] = [];
      if (!proposal.sourceClosureFingerprintSha256) reasons.push("source-fingerprint-unavailable");
      if (!plan.success || !proposal.planHash || plan.success && invariantPlanHash(plan.data) !== proposal.planHash) reasons.push("invalid-plan");
      if (!strategy || strategy === "structured-verification") reasons.push("legacy-unknown-strategy");
      else if (!strategyReadiness.compatible.includes(strategy)) reasons.push("strategy-not-compatible");
      if (plan.success) {
        if (plan.data.scanId !== hypothesis.scanId || proposal.scanId !== hypothesis.scanId) reasons.push("stale-scan");
        if (!scan?.resolvedCommit || plan.data.resolvedCommit !== scan.resolvedCommit) reasons.push("stale-commit");
        const actionFunctions = plan.data.mode === "fuzz-property" ? [plan.data.fuzzAction.functionName] : plan.data.handlerActions.map((action) => action.functionName);
        if (!group.contractIdentity || !group.functionName || plan.data.primaryContract !== group.contractIdentity.contract || plan.data.primarySourcePath !== group.contractIdentity.sourcePath || !actionFunctions.includes(group.functionName)) reasons.push("stale-source");
        if (!scan || !["ready", "cached"].includes(scan.compilerStatus) || !compilerAvailable(scan.compilerVersions, plan.data.compilerVersion)) reasons.push("stale-compiler");
        if (strategy && (strategy === "structured-verification" || plan.data.mode !== expectedMode(strategy))) reasons.push("strategy-mode-mismatch");
      }
      if (!ids.length || ids.some((id) => !currentPropertyIds.has(id))) reasons.push("property-target-unproven");
      const executionHistoryExists = !!strategy && strategy !== "structured-verification" && !!proposal.planHash && plan.success && runs.some((run) => run.proposalId === proposal.id && run.planHash === proposal.planHash && run.engine === expectedEngine(strategy) && run.mode === expectedMode(strategy) && run.scanId === proposal.scanId && run.resolvedCommit === plan.data.resolvedCommit && run.compilerVersion === plan.data.compilerVersion);
      if (!executionHistoryExists) reasons.push("validation-not-recorded");
      candidates.push({ artifactId: proposal.id, artifactType: "invariant-proposal", hypothesisId: memberId, strategy: strategy && strategy !== "structured-verification" ? strategy : "legacy-unknown-strategy", propertyTargetIds: ids,
        eligibility: classify(reasons), reasons: reasons.length ? reasons : ["matching-persisted-validation"], validationState: reasons.includes("invalid-plan") ? "invalid" : executionHistoryExists ? "validated-at-execution" : "generated", executionHistoryExists, sourceClosureFingerprintRecorded: !!proposal.sourceClosureFingerprintSha256, createdAt: proposal.createdAt.toISOString() });
    }
  }
  const eligibilityOrder = { eligible: 0, stale: 1, incompatible: 2 };
  candidates.sort((a, b) => eligibilityOrder[a.eligibility] - eligibilityOrder[b.eligibility] || Number(b.validationState === "validated-at-execution") - Number(a.validationState === "validated-at-execution") || b.createdAt.localeCompare(a.createdAt) || a.artifactId.localeCompare(b.artifactId));
  return { targetId: group.id, rootCauseFamily: group.rootCauseFamily, familyLabel: publicGroup.familyLabel, representativeHypothesisId: group.representativeHypothesisId,
    currentHypothesisIsRepresentative: group.representativeHypothesisId === hypothesisId, relatedHypotheses: group.members.filter((id) => id !== hypothesisId).slice(0, 50), relatedHypothesisCount: group.members.length - 1,
    representativeReason: group.representativeReason, reason: publicGroup.reason, groupingConfidence: group.groupingConfidence, strategyReadiness, candidates: candidates.slice(0, 100), candidateCount: candidates.length };
}

function classify(reasons: CandidateReason[]): CandidateEligibility {
  if (!reasons.length) return "eligible";
  return reasons.some((reason) => reason.startsWith("stale-")) ? "stale" : "incompatible";
}
