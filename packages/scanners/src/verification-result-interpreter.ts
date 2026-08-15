import { dynamicEvidenceSchema, verificationHarnessPlanSchema, type DynamicEvidence, type VerificationHarnessPlan, type VerificationOutcome } from "@contracthunter/core";
import type { FoundryVerificationResult } from "./foundry-verification-runner";

export type VerificationAssertionObservation = {
  assertionId: string;
  assertionIndex: number;
  result: "satisfied" | "contradicted" | "not-observed";
};

export type VerificationInterpretation = {
  outcome: VerificationOutcome;
  resultSummary: string;
  observations: VerificationAssertionObservation[];
  dynamicEvidence: DynamicEvidence[];
};

function observations(plan: VerificationHarnessPlan, result: FoundryVerificationResult): VerificationAssertionObservation[] {
  const unknown = () => plan.assertions.map((assertion, assertionIndex) => ({ assertionId: assertion.id, assertionIndex, result: "not-observed" as const }));
  if (result.outputTruncated || result.stdoutTruncated || result.stderrTruncated || result.timedOut || result.testCount !== 1) return unknown();
  if (result.status === "completed" && result.exitCode === 0 && result.errorCode === null && result.passedCount === 1 && result.failedCount === 0) {
    return plan.assertions.map((assertion, assertionIndex) => ({ assertionId: assertion.id, assertionIndex, result: "satisfied" }));
  }
  if (result.status !== "failed" || result.errorCode !== "forge_failed" || result.failedCount !== 1 || result.passedCount !== 0) return unknown();
  const markers = [...new Set(`${result.stdoutSummary}\n${result.stderrSummary}`.match(/\bCH_ASSERT_(\d+)\b/g) ?? [])];
  if (markers.length !== 1) return unknown();
  const failedIndex = Number(markers[0].slice("CH_ASSERT_".length));
  if (!Number.isInteger(failedIndex) || failedIndex < 0 || failedIndex >= plan.assertions.length) return unknown();
  return plan.assertions.map((assertion, assertionIndex) => ({
    assertionId: assertion.id,
    assertionIndex,
    result: assertionIndex < failedIndex ? "satisfied" : assertionIndex === failedIndex ? "contradicted" : "not-observed",
  }));
}

export function interpretVerificationResult(rawPlan: VerificationHarnessPlan, result: FoundryVerificationResult): VerificationInterpretation {
  const plan = verificationHarnessPlanSchema.parse(rawPlan);
  const assertionObservations = observations(plan, result);
  const dynamicEvidence = assertionObservations.map((observation) => {
    const assertion = plan.assertions[observation.assertionIndex];
    const satisfiedSupports = assertion.expectedOutcome === "hypothesis-supported";
    const direction = observation.result === "not-observed" ? "neutral"
      : observation.result === "satisfied" ? (satisfiedSupports ? "supports" : "contradicts")
        : satisfiedSupports ? "contradicts" : "supports";
    const read = plan.operations.find((operation): operation is Extract<(typeof plan.operations)[number], { kind: "read-uint" }> => operation.kind === "read-uint" && operation.resultName === assertion.actual);
    return dynamicEvidenceSchema.parse({
      assertionId: assertion.id,
      assertionName: assertion.description,
      expectedBehavior: `${assertion.description} (${assertion.expectedOutcome}).`,
      observedBehavior: observation.result === "satisfied" ? "The generated assertion condition was satisfied."
        : observation.result === "contradicted" ? "The generated assertion condition was contradicted."
          : "The assertion did not produce a complete deterministic observation.",
      direction,
      contract: plan.primaryContract,
      functionName: read?.functionName ?? null,
      details: `ContractHunter assertion ${assertion.id} mapped controlled marker CH_ASSERT_${observation.assertionIndex} to ${observation.result}.`,
    });
  });
  const directions = new Set(dynamicEvidence.filter((item) => item.direction !== "neutral").map((item) => item.direction));
  const outcome: VerificationOutcome = directions.size !== 1 ? "inconclusive" : directions.has("supports") ? "confirmed" : "refuted";
  const resultSummary = outcome === "confirmed" ? "Structured assertion observations support the hypothesis."
    : outcome === "refuted" ? "Structured assertion observations contradict the hypothesis."
      : "Structured assertion observations were incomplete, ambiguous, or mixed.";
  return { outcome, resultSummary, observations: assertionObservations, dynamicEvidence };
}
