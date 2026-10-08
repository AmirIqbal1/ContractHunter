import type { VerificationPlanGenerationResult, VerificationPlanReuseResult, VerificationStrategy } from "@contracthunter/core";

export const strategyNames: Record<VerificationStrategy, string> = {
  "structured-verification": "Structured verification",
  "foundry-fuzz-property": "Foundry fuzz property",
  "foundry-stateful-invariant": "Foundry stateful invariant",
  "echidna-stateful-invariant": "Echidna stateful invariant",
};

export type PublicVerificationPlanAttempt = { id: string; selectedStrategy: "structured-verification"; status: VerificationPlanGenerationResult["status"]; failureCode: VerificationPlanGenerationResult["failureCode"];
  origin: "generated" | "legacy" | "reused"; reuseSourceArtifactId: string | null; reuseTargetId: string | null;
  result: VerificationPlanGenerationResult | VerificationPlanReuseResult; sourceClosureFingerprint: { schema: string; sha256: string; fileCount: number; totalBytes: number } | null; createdAt: string };

export const planningFailureMessages: Record<string, string> = {
  strategy_not_compatible: "Current structured evidence no longer supports this strategy. Review the updated verification options.",
  strategy_compatibility_unknown: "Compatibility cannot be determined from current structured evidence.",
  strategy_plan_mode_mismatch: "The generated plan used a mode outside the selected strategy.",
  strategy_concrete_plan_incompatible: "The concrete plan did not pass the selected strategy's compatibility checks.",
  plan_generation_failed: "The planning provider could not produce a proposal.",
  invariant_generation_unavailable: "The planning provider could not produce a proposal.",
  invalid_provider_proposal: "The provider response did not match the planning schema.",
  invalid_invariant_provider_proposal: "The provider response did not match the planning schema.",
  ambiguous_trusted_compiler: "The trusted compiler could not be selected unambiguously.",
  invalid_plan_source: "The generated plan did not match trusted source evidence.",
  invalid_invariant_source: "The generated plan did not match trusted source evidence.",
  invalid_function_signature: "The generated function signature did not match trusted source.",
  invalid_invariant_function_signature: "The generated function signature did not match trusted source.",
  unsupported_function_signature: "The generated function signature is outside supported verification capabilities.",
  unsupported_invariant_semantics: "The generated invariant semantics are outside supported capabilities.",
  invalid_harness_plan: "The generated verification plan failed schema or harness validation.",
  invalid_invariant_plan: "The generated invariant plan failed schema or harness validation.",
  strategy_generation_unavailable: "Strategy planning is currently unavailable.",
  strategy_generation_failed: "Strategy planning failed safely.",
  invalid_state: "Current scan or hypothesis state does not permit planning.",
  missing_context: "Trusted source context is unavailable for planning.",
};
export function planningFailureMessage(code: string | null | undefined) { return code ? planningFailureMessages[code] ?? "Strategy planning failed safely." : "Strategy planning failed safely."; }
