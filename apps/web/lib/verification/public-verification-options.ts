import { verificationCapabilityProfiles, type AssessmentReason, type VerificationRequirement, type VerificationStrategy, type VerificationStrategyAssessment } from "@contracthunter/core";

const strategyLabels: Record<VerificationStrategy, string> = {
  "structured-verification": "Structured verification",
  "foundry-fuzz-property": "Foundry fuzz property",
  "foundry-stateful-invariant": "Foundry stateful invariant",
  "echidna-stateful-invariant": "Echidna stateful invariant",
};

const requirementMessages: Record<VerificationRequirement, string> = {
  "explicit-caller": "Explicit caller semantics are not supported by this strategy.",
  "multiple-actors": "Multiple symbolic actors are not supported by this strategy.",
  "address-argument": "Address arguments are not supported by this strategy.",
  "uint-argument": "Uint256 arguments are not supported by this strategy.",
  "bool-argument": "Boolean arguments are not supported by this strategy.",
  "setup-call": "Setup calls are not supported by this strategy.",
  funding: "Contract funding is not supported by this strategy.",
  "uint-observation": "Uint observations are not supported by this strategy.",
  "address-observation": "Address observations are not supported by this strategy.",
  "balance-observation": "Balance observations are not supported by this strategy.",
  "state-sequence": "Stateful action sequences are not supported by this strategy.",
  "fuzzed-inputs": "Fuzzed inputs are not supported by this strategy.",
  "block-timestamp": "Block timestamp control is not supported by this strategy.",
  "tx-origin": "tx.origin semantics are not supported by this strategy.",
  "external-return-value": "External return-value observation is not supported by this strategy.",
  "reentrant-callback": "Reentrant callbacks are not supported by this strategy.",
};

const unknownMessages: Record<Exclude<AssessmentReason["code"], "unsupported-requirement">, string> = {
  "invalid-assessment-input": "Structured evidence could not be assessed.",
  "missing-investigation": "A linked static investigation is unavailable.",
  "investigation-scan-mismatch": "Linked investigation evidence does not match this scan.",
  "primary-contract-unresolved": "The primary contract could not be resolved from structured evidence.",
  "ambiguous-primary-contract": "The structured evidence does not identify one primary contract.",
  "insufficient-structured-evidence": "There is insufficient structured evidence for an assessment.",
  "unmapped-scanner-rule": "The available scanner rule has no verified capability mapping yet.",
};

export type PublicVerificationOptionReason = {
  code: AssessmentReason["code"];
  requirement: VerificationRequirement | null;
  message: string;
};
export type PublicVerificationOption = {
  strategy: VerificationStrategy;
  label: string;
  engine: "foundry" | "echidna" | null;
  planMode: "fuzz-property" | "stateful-invariant" | null;
  compatibility: "compatible" | "incompatible" | "unknown";
  reasons: PublicVerificationOptionReason[];
  selectionAvailable: boolean;
};

function publicReason(reason: AssessmentReason): PublicVerificationOptionReason {
  return reason.code === "unsupported-requirement"
    ? { code: reason.code, requirement: reason.requirement, message: requirementMessages[reason.requirement] }
    : { code: reason.code, requirement: null, message: unknownMessages[reason.code] };
}

/** Only closed enums and server-owned text cross the public boundary. */
export function toPublicVerificationOptions(assessment: VerificationStrategyAssessment): PublicVerificationOption[] {
  return verificationCapabilityProfiles.map((profile) => {
    const result = assessment.strategies.find((item) => item.strategy === profile.strategy);
    const compatibility = result?.compatibility ?? "unknown";
    const reasons = result?.reasons.length ? result.reasons.slice(0, 16).map(publicReason) : compatibility === "unknown"
      ? [{ code: "insufficient-structured-evidence" as const, requirement: null, message: unknownMessages["insufficient-structured-evidence"] }]
      : [];
    return {
      strategy: profile.strategy,
      label: strategyLabels[profile.strategy],
      engine: profile.engine,
      planMode: profile.planMode,
      compatibility,
      reasons,
      selectionAvailable: compatibility === "compatible",
    };
  });
}
