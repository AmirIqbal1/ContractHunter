import { createHash } from "node:crypto";
import { assessVerificationStrategies, scannerRequirementRules, verificationStrategies, type VerificationStrategy } from "./verification-strategy-assessment";

export const rootCauseFamilies = ["access-control", "reentrancy", "tx-origin-auth", "unchecked-low-level-call", "timestamp-dependence", "arithmetic-order", "unknown-family"] as const;
export type RootCauseFamily = (typeof rootCauseFamilies)[number];

/** Only exact source/detector pairs already accepted by the strategy assessor. */
export const scannerRootCauseFamilies: Readonly<Record<string, Exclude<RootCauseFamily, "unknown-family">>> = {
  "slither:protected-vars": "access-control",
  "slither:reentrancy-eth": "reentrancy",
  "slither:reentrancy-no-eth": "reentrancy",
  "aderyn:reentrancy-state-change": "reentrancy",
  "slither:tx-origin": "tx-origin-auth",
  "slither:unchecked-lowlevel": "unchecked-low-level-call",
  "aderyn:unchecked-low-level-call": "unchecked-low-level-call",
  "slither:timestamp": "timestamp-dependence",
  "aderyn:block-timestamp-deadline": "timestamp-dependence",
  "slither:divide-before-multiply": "arithmetic-order",
};

export type VerificationTargetFinding = {
  id: string; scanId: string; source: string; detectorId: string | null;
  contract: string | null; filePath: string | null; functionName: string | null;
  startLine: number | null; endLine: number | null;
};
export type VerificationTargetInvestigation = {
  id: string; scanId: string; primaryContract: string | null; primaryFilePath: string | null;
  primaryFunction: string | null; findings: VerificationTargetFinding[];
};
export type VerificationTargetHypothesis = {
  id: string; scanId: string; relatedInvestigationIds: string[];
  evidence: Array<{ valid: boolean; filePath: string; contract: string | null; functionName: string | null }>;
};
export type VerificationTargetInput = { hypotheses: VerificationTargetHypothesis[]; investigations: VerificationTargetInvestigation[] };
export type StrategyReadiness = { compatible: VerificationStrategy[]; incompatible: VerificationStrategy[]; unknown: VerificationStrategy[] };
export type RepresentativeReason = "only-candidate" | "validated-source-evidence" | "stronger-structured-linkage" | "mapped-verification-requirements" | "more-compatible-strategies" | "stable-id-tiebreak";
export type VerificationTargetGroup = {
  id: string; scanId: string; rootCauseFamily: RootCauseFamily;
  contractIdentity: { contract: string; sourcePath: string } | null;
  functionName: string | null; sourceRegion: { startLine: number; endLine: number } | null;
  members: string[]; representativeHypothesisId: string; representativeReason: RepresentativeReason;
  groupingConfidence: "exact" | "strong-structured" | "insufficient-to-group";
  strategyReadiness: Array<{ hypothesisId: string; strategies: StrategyReadiness }>;
};

type Claim = { scanId: string; family: Exclude<RootCauseFamily, "unknown-family">; contract: string; path: string; functionName: string | null; region: { startLine: number; endLine: number } | null; investigationId: string; source: string };
type Candidate = { hypothesis: VerificationTargetHypothesis; claim: Claim | null; region: Claim["region"]; sharedInvestigationIds: string[]; sources: string[]; validEvidenceCount: number; linkedInvestigationCount: number; mappedRequirements: boolean; readiness: StrategyReadiness };

const hash = (value: unknown) => createHash("sha256").update(JSON.stringify(value)).digest("hex");
const sameBase = (a: Claim, b: Claim) => a.scanId === b.scanId && a.family === b.family && a.contract === b.contract && a.path === b.path && a.functionName === b.functionName;
const overlap = (a: NonNullable<Claim["region"]>, b: NonNullable<Claim["region"]>) => a.startLine <= b.endLine && b.startLine <= a.endLine;
const intersection = (a: NonNullable<Claim["region"]>, b: NonNullable<Claim["region"]>) => ({ startLine: Math.max(a.startLine, b.startLine), endLine: Math.min(a.endLine, b.endLine) });
const orderedUnique = (items: readonly string[]) => [...new Set(items)].sort();
const validRegion = (start: number | null, end: number | null) => Number.isInteger(start) && start! > 0 && (end === null || Number.isInteger(end) && end >= start!) ? { startLine: start!, endLine: end ?? start! } : null;

function readiness(hypothesis: VerificationTargetHypothesis, linked: VerificationTargetInvestigation[]): StrategyReadiness {
  const assessment = assessVerificationStrategies({
    hypothesis: { scanId: hypothesis.scanId, relatedInvestigationIds: orderedUnique(hypothesis.relatedInvestigationIds) },
    investigations: linked.map((item) => ({ id: item.id, scanId: item.scanId, primaryContract: item.primaryContract, primaryFilePath: item.primaryFilePath,
      findings: item.findings.map((finding) => ({ scanId: finding.scanId, source: finding.source, detectorId: finding.detectorId, contract: finding.contract, filePath: finding.filePath })) })),
  });
  return {
    compatible: verificationStrategies.filter((strategy) => assessment.strategies.some((item) => item.strategy === strategy && item.compatibility === "compatible")),
    incompatible: verificationStrategies.filter((strategy) => assessment.strategies.some((item) => item.strategy === strategy && item.compatibility === "incompatible")),
    unknown: verificationStrategies.filter((strategy) => assessment.strategies.some((item) => item.strategy === strategy && item.compatibility === "unknown")),
  };
}

function candidate(hypothesis: VerificationTargetHypothesis, byId: Map<string, VerificationTargetInvestigation>): Candidate {
  const ids = orderedUnique(hypothesis.relatedInvestigationIds);
  const linked = ids.map((id) => byId.get(id)).filter((item): item is VerificationTargetInvestigation => !!item);
  const strategyReadiness = readiness(hypothesis, linked);
  const empty = (linkedInvestigationCount = 0): Candidate => ({ hypothesis, claim: null, region: null, sharedInvestigationIds: [], sources: [], validEvidenceCount: 0, linkedInvestigationCount, mappedRequirements: false, readiness: strategyReadiness });
  if (!ids.length || linked.length !== ids.length || linked.some((item) => item.scanId !== hypothesis.scanId || !item.primaryContract || !item.primaryFilePath)) return empty();
  const claims: Claim[] = [];
  for (const investigation of linked) {
    for (const finding of investigation.findings) {
      if (finding.scanId !== hypothesis.scanId || finding.contract !== investigation.primaryContract || finding.filePath !== investigation.primaryFilePath) return empty(linked.length);
      const key = `${finding.source}:${finding.detectorId ?? ""}`;
      const family = scannerRootCauseFamilies[key];
      if (!family || !scannerRequirementRules[key]) return empty(linked.length);
      if (finding.functionName && investigation.primaryFunction && finding.functionName !== investigation.primaryFunction) return empty(linked.length);
      const functionName = finding.functionName ?? investigation.primaryFunction;
      const region = validRegion(finding.startLine, finding.endLine);
      if (!functionName && !region) return empty(linked.length);
      claims.push({ scanId: hypothesis.scanId, family, contract: investigation.primaryContract!, path: investigation.primaryFilePath!, functionName, region, investigationId: investigation.id, source: finding.source });
    }
  }
  if (!claims.length) return empty(linked.length);
  const unique = [...new Map(claims.map((item) => [JSON.stringify(item), item])).values()];
  const first = unique[0]; let region = first.region;
  for (const item of unique.slice(1)) {
    if (!sameBase(first, item)) return empty(linked.length);
    if (region && item.region && overlap(region, item.region)) region = intersection(region, item.region);
    else if (region || item.region) return empty(linked.length);
  }
  const sharedInvestigationIds = unique.map((item) => item.investigationId).filter((id) => unique.every((other) => other.investigationId === id));
  if (!region && !sharedInvestigationIds.length) return empty(linked.length);
  const evidenceKeys = new Set(hypothesis.evidence.filter((item) => item.valid && item.filePath === first.path && item.contract === first.contract && (!first.functionName || item.functionName === first.functionName)).map((item) => `${item.filePath}|${item.contract}|${item.functionName}`));
  return { hypothesis, claim: first, region, sharedInvestigationIds: orderedUnique(sharedInvestigationIds), sources: orderedUnique(unique.map((item) => item.source)), validEvidenceCount: Math.min(evidenceKeys.size, 16), linkedInvestigationCount: linked.length, mappedRequirements: true, readiness: strategyReadiness };
}

const metrics = (item: Candidate) => [item.validEvidenceCount, item.sources.length, item.linkedInvestigationCount, Number(item.mappedRequirements), item.readiness.compatible.length];
const reasons: RepresentativeReason[] = ["validated-source-evidence", "stronger-structured-linkage", "stronger-structured-linkage", "mapped-verification-requirements", "more-compatible-strategies"];
function selectRepresentative(items: Candidate[]): { selected: Candidate; reason: RepresentativeReason } {
  const ordered = [...items].sort((a, b) => {
    const left = metrics(a), right = metrics(b);
    for (let index = 0; index < left.length; index++) if (left[index] !== right[index]) return right[index] - left[index];
    return a.hypothesis.id.localeCompare(b.hypothesis.id);
  });
  if (ordered.length === 1) return { selected: ordered[0], reason: "only-candidate" };
  const first = metrics(ordered[0]), second = metrics(ordered[1]);
  const differing = first.findIndex((value, index) => value !== second[index]);
  return { selected: ordered[0], reason: differing < 0 ? "stable-id-tiebreak" : reasons[differing] };
}

/** Advisory grouping only. A hypothesis belongs to exactly one computed target; ambiguous evidence is isolated. */
export function buildVerificationTargetGroups(input: VerificationTargetInput): VerificationTargetGroup[] {
  const byId = new Map(input.investigations.map((item) => [item.id, item]));
  const candidates = [...new Map(input.hypotheses.map((item) => [item.id, item])).values()].sort((a, b) => a.id.localeCompare(b.id)).map((item) => candidate(item, byId));
  const buckets: Array<{ members: Candidate[]; claim: Claim | null; region: Claim["region"]; sharedInvestigationIds: string[] }> = [];
  for (const item of candidates) {
    if (!item.claim) { buckets.push({ members: [item], claim: null, region: null, sharedInvestigationIds: [] }); continue; }
    const matching = buckets.find((bucket) => {
      if (!bucket.claim || !sameBase(bucket.claim, item.claim!)) return false;
      if (bucket.region && item.region) return overlap(bucket.region, item.region);
      return !bucket.region && !item.region && bucket.sharedInvestigationIds.some((id) => item.sharedInvestigationIds.includes(id));
    });
    if (!matching) { buckets.push({ members: [item], claim: item.claim, region: item.region, sharedInvestigationIds: item.sharedInvestigationIds }); continue; }
    matching.members.push(item);
    if (matching.region && item.region) matching.region = intersection(matching.region, item.region);
    if (!matching.region) matching.sharedInvestigationIds = matching.sharedInvestigationIds.filter((id) => item.sharedInvestigationIds.includes(id));
  }
  return buckets.map((bucket) => {
    const members = bucket.members.map((item) => item.hypothesis.id).sort();
    const { selected, reason } = selectRepresentative(bucket.members);
    const identity = bucket.claim ? { scanId: selected.hypothesis.scanId, family: bucket.claim.family, contract: bucket.claim.contract, path: bucket.claim.path, functionName: bucket.claim.functionName, region: bucket.region, investigation: bucket.region ? null : bucket.sharedInvestigationIds[0] } : { scanId: selected.hypothesis.scanId, isolatedHypothesisId: selected.hypothesis.id };
    return { id: hash(identity), scanId: selected.hypothesis.scanId, rootCauseFamily: bucket.claim?.family ?? "unknown-family", contractIdentity: bucket.claim ? { contract: bucket.claim.contract, sourcePath: bucket.claim.path } : null,
      functionName: bucket.claim?.functionName ?? null, sourceRegion: bucket.region, members, representativeHypothesisId: selected.hypothesis.id, representativeReason: reason,
      groupingConfidence: bucket.claim ? bucket.region ? "exact" : "strong-structured" : "insufficient-to-group",
      strategyReadiness: bucket.members.map((item) => ({ hypothesisId: item.hypothesis.id, strategies: item.readiness })).sort((a, b) => a.hypothesisId.localeCompare(b.hypothesisId)),
    } satisfies VerificationTargetGroup;
  }).sort((a, b) => a.scanId.localeCompare(b.scanId) || a.id.localeCompare(b.id));
}

export function verificationTargetForHypothesis(groups: readonly VerificationTargetGroup[], hypothesisId: string) {
  const group = groups.find((item) => item.members.includes(hypothesisId));
  return group ? { targetId: group.id, representativeHypothesisId: group.representativeHypothesisId, isRepresentative: group.representativeHypothesisId === hypothesisId } : null;
}

const familyLabels: Record<RootCauseFamily, string> = { "access-control": "Access control", reentrancy: "Reentrancy", "tx-origin-auth": "tx.origin authorization", "unchecked-low-level-call": "Unchecked low-level call", "timestamp-dependence": "Timestamp dependence", "arithmetic-order": "Arithmetic order", "unknown-family": "Unknown family" };
const reasonLabels: Record<RepresentativeReason, string> = { "only-candidate": "Only structured target candidate", "validated-source-evidence": "Validated source reference for this target", "stronger-structured-linkage": "Stronger structured scanner linkage", "mapped-verification-requirements": "Mapped verification requirements available", "more-compatible-strategies": "More available planning strategies", "stable-id-tiebreak": "Stable identifier tie-break" };
/** Bounded, prose-free shape for a future UI. Source paths and scanner text stay internal. */
export function toPublicVerificationTarget(group: VerificationTargetGroup) {
  return { id: group.id, rootCauseFamily: group.rootCauseFamily, familyLabel: familyLabels[group.rootCauseFamily], primaryTargetHypothesisId: group.representativeHypothesisId,
    relatedHypothesisCount: Math.max(0, group.members.length - 1), contract: group.contractIdentity && /^[A-Za-z_$][A-Za-z0-9_$]{0,199}$/.test(group.contractIdentity.contract) ? group.contractIdentity.contract : null,
    groupingConfidence: group.groupingConfidence, representativeReason: group.representativeReason, reason: reasonLabels[group.representativeReason] };
}
