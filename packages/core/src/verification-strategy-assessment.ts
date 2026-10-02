import { z } from "zod";
import { invariantCapabilityProfile } from "./executable-invariant";
import { verificationCapabilityProfile } from "./hypothesis-verification";

/** Advisory capabilities of the plans ContractHunter can generate today. */
export const verificationStrategies = [
  "structured-verification",
  "foundry-fuzz-property",
  "foundry-stateful-invariant",
  "echidna-stateful-invariant",
] as const;
export type VerificationStrategy = (typeof verificationStrategies)[number];

export const verificationRequirements = [
  "explicit-caller", "multiple-actors", "address-argument", "uint-argument", "bool-argument",
  "setup-call", "funding", "uint-observation", "address-observation", "balance-observation",
  "state-sequence", "fuzzed-inputs", "block-timestamp", "tx-origin",
  "external-return-value", "reentrant-callback",
] as const;
export type VerificationRequirement = (typeof verificationRequirements)[number];

const structuredSupport = [
  ...(verificationCapabilityProfile.callers ? ["explicit-caller"] : []),
  ...(verificationCapabilityProfile.actors ? ["multiple-actors"] : []),
  ...(verificationCapabilityProfile.functionArguments.includes("address") ? ["address-argument"] : []),
  ...(verificationCapabilityProfile.functionArguments.includes("uint256") ? ["uint-argument"] : []),
  ...(verificationCapabilityProfile.functionArguments.includes("bool") ? ["bool-argument"] : []),
  ...(verificationCapabilityProfile.operations.includes("call") ? ["setup-call", "state-sequence"] : []),
  ...(verificationCapabilityProfile.stateSetup.includes("native-eth-funding") ? ["funding"] : []),
  ...(verificationCapabilityProfile.observations.includes("uint") ? ["uint-observation"] : []),
  ...(verificationCapabilityProfile.observations.includes("address") ? ["address-observation"] : []),
  ...(verificationCapabilityProfile.observations.includes("native-balance") ? ["balance-observation"] : []),
] as VerificationRequirement[];
const foundrySupport = [
  ...(invariantCapabilityProfile.symbolicAddresses.includes("actor") ? ["explicit-caller", "multiple-actors", "address-argument"] : []),
  ...(invariantCapabilityProfile.fuzzParameterTypes.includes("uint256") ? ["uint-argument", "fuzzed-inputs"] : []),
  ...(invariantCapabilityProfile.fuzzParameterTypes.includes("bool") ? ["bool-argument"] : []),
  ...(invariantCapabilityProfile.setupOperations.includes("call") ? ["setup-call"] : []),
  ...(invariantCapabilityProfile.setupOperations.includes("fund") ? ["funding"] : []),
  ...(invariantCapabilityProfile.observations.includes("read-uint") ? ["uint-observation"] : []),
  ...(invariantCapabilityProfile.observations.includes("read-address") ? ["address-observation"] : []),
  ...(invariantCapabilityProfile.observations.includes("read-balance") ? ["balance-observation"] : []),
] as VerificationRequirement[];

export type VerificationCapabilityProfile = {
  strategy: VerificationStrategy;
  engine: "foundry" | "echidna" | null;
  planMode: "fuzz-property" | "stateful-invariant" | null;
  supportedRequirements: readonly VerificationRequirement[];
};

export const verificationCapabilityProfiles: readonly VerificationCapabilityProfile[] = [
  { strategy: "structured-verification", engine: null, planMode: null, supportedRequirements: structuredSupport },
  { strategy: "foundry-fuzz-property", engine: "foundry", planMode: "fuzz-property", supportedRequirements: foundrySupport },
  { strategy: "foundry-stateful-invariant", engine: "foundry", planMode: "stateful-invariant", supportedRequirements: [...foundrySupport, "state-sequence"] },
  // The current Echidna validator permits only a single deploy, no caller/actors/setup/funding,
  // uint256/bool actions and uint/balance assertions. Source-sensitive checks remain at plan validation.
  { strategy: "echidna-stateful-invariant", engine: "echidna", planMode: "stateful-invariant", supportedRequirements: [
    "uint-argument", "bool-argument", "uint-observation", "balance-observation", "state-sequence", "fuzzed-inputs",
  ] },
];

// Exact scanner source + detector ID pairs only. Categories and scanner prose are not facts.
// A finding can expose a necessary capability without proving that a plan can be generated.
export const scannerRequirementRules: Readonly<Record<string, readonly VerificationRequirement[]>> = {
  "slither:protected-vars": ["explicit-caller"],
  "slither:reentrancy-eth": ["reentrant-callback", "state-sequence", "balance-observation"],
  "slither:reentrancy-no-eth": ["reentrant-callback", "state-sequence"],
  "slither:timestamp": ["block-timestamp"],
  "slither:tx-origin": ["tx-origin"],
  "slither:unchecked-lowlevel": ["external-return-value"],
  // Numeric division-order findings require a uint observation; concrete ABI and source
  // compatibility still require separate validation before any engine can run.
  "slither:divide-before-multiply": ["uint-observation"],
  "aderyn:reentrancy-state-change": ["reentrant-callback", "state-sequence"],
  "aderyn:block-timestamp-deadline": ["block-timestamp"],
  "aderyn:unchecked-low-level-call": ["external-return-value"],
};

const sourceId = z.string().min(1).max(100);
const contract = z.string().min(1).max(200).nullable();
const sourcePath = z.string().min(1).max(500).nullable();
export const verificationAssessmentInputSchema = z.object({
  hypothesis: z.object({ scanId: sourceId, relatedInvestigationIds: z.array(sourceId).max(32) }).strict(),
  investigations: z.array(z.object({
    id: sourceId, scanId: sourceId, primaryContract: contract, primaryFilePath: sourcePath,
    findings: z.array(z.object({
      scanId: sourceId, source: z.string().min(1).max(32), detectorId: z.string().min(1).max(100).nullable(),
      contract, filePath: sourcePath,
    }).strict()).max(256),
  }).strict()).max(32),
}).strict();
export type VerificationAssessmentInput = z.infer<typeof verificationAssessmentInputSchema>;

export type AssessmentReason =
  | { code: "invalid-assessment-input" | "missing-investigation" | "investigation-scan-mismatch" | "primary-contract-unresolved" | "ambiguous-primary-contract" | "insufficient-structured-evidence" | "unmapped-scanner-rule" }
  | { code: "unsupported-requirement"; requirement: VerificationRequirement };
export type StrategyAssessment = {
  strategy: VerificationStrategy;
  compatibility: "compatible" | "incompatible" | "unknown";
  reasons: AssessmentReason[];
};
export type VerificationStrategyAssessment = {
  requirements: VerificationRequirement[];
  strategies: StrategyAssessment[];
};

const unknownReasonOrder = ["invalid-assessment-input", "missing-investigation", "investigation-scan-mismatch", "primary-contract-unresolved", "ambiguous-primary-contract", "insufficient-structured-evidence", "unmapped-scanner-rule"] as const;
type UnknownReason = (typeof unknownReasonOrder)[number];

/** A requirement-only check for trusted, bounded facts; it does not validate source or execute a plan. */
export function assessVerificationRequirements(requirements: readonly VerificationRequirement[], unknownReasons: readonly UnknownReason[] = []): VerificationStrategyAssessment {
  const orderedRequirements = verificationRequirements.filter((requirement) => requirements.includes(requirement));
  const orderedUnknown = unknownReasonOrder.filter((reason) => unknownReasons.includes(reason));
  if (!orderedRequirements.length && !orderedUnknown.length) orderedUnknown.push("insufficient-structured-evidence");
  return {
    requirements: orderedRequirements,
    strategies: verificationCapabilityProfiles.map((profile) => {
      const unsupported = orderedRequirements.filter((requirement) => !profile.supportedRequirements.includes(requirement));
      if (unsupported.length) return { strategy: profile.strategy, compatibility: "incompatible", reasons: unsupported.map((requirement) => ({ code: "unsupported-requirement" as const, requirement })) };
      if (orderedUnknown.length) return { strategy: profile.strategy, compatibility: "unknown", reasons: orderedUnknown.map((code) => ({ code })) };
      return { strategy: profile.strategy, compatibility: "compatible", reasons: [] };
    }),
  };
}

/** Extract necessary requirements from persisted, correlated scanner identities only. */
export function assessVerificationStrategies(input: unknown): VerificationStrategyAssessment {
  const parsed = verificationAssessmentInputSchema.safeParse(input);
  if (!parsed.success) return assessVerificationRequirements([], ["invalid-assessment-input"]);
  const { hypothesis, investigations } = parsed.data;
  const related = [...new Set(hypothesis.relatedInvestigationIds)];
  if (!related.length) return assessVerificationRequirements([], ["missing-investigation"]);
  const byId = new Map(investigations.map((investigation) => [investigation.id, investigation]));
  const facts = new Set<VerificationRequirement>();
  const gaps = new Set<UnknownReason>();
  const contracts = new Set<string>();
  const paths = new Set<string>();
  for (const id of related) {
    const investigation = byId.get(id);
    if (!investigation) { gaps.add("missing-investigation"); continue; }
    if (investigation.scanId !== hypothesis.scanId) { gaps.add("investigation-scan-mismatch"); continue; }
    if (!investigation.primaryContract || !investigation.primaryFilePath) { gaps.add("primary-contract-unresolved"); continue; }
    contracts.add(investigation.primaryContract);
    paths.add(investigation.primaryFilePath);
    if (!investigation.findings.length) gaps.add("insufficient-structured-evidence");
    for (const finding of investigation.findings) {
      if (finding.scanId !== hypothesis.scanId) { gaps.add("investigation-scan-mismatch"); continue; }
      if (finding.contract !== investigation.primaryContract || finding.filePath !== investigation.primaryFilePath) {
        gaps.add("ambiguous-primary-contract"); continue;
      }
      const rule = finding.detectorId && scannerRequirementRules[`${finding.source}:${finding.detectorId}`];
      if (!rule) { gaps.add("unmapped-scanner-rule"); continue; }
      for (const requirement of rule) facts.add(requirement);
    }
  }
  if (contracts.size > 1 || paths.size > 1) gaps.add("ambiguous-primary-contract");
  // Without a stable target identity, even a known rule cannot certify a route.
  if (gaps.has("primary-contract-unresolved") || gaps.has("ambiguous-primary-contract") || gaps.has("investigation-scan-mismatch") || gaps.has("missing-investigation")) {
    return assessVerificationRequirements([], [...gaps]);
  }
  return assessVerificationRequirements([...facts], [...gaps]);
}
