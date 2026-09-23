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
    const read = plan.operations.find((operation) => (operation.kind === "read-uint" || operation.kind === "read-address" || operation.kind === "read-balance") && operation.resultName === assertion.actual);
    const addressExpected = assertion.kind === "address-eq" || assertion.kind === "address-not-eq" ? assertion.expected : null;
    const actorMutation = addressExpected?.source === "actor" ? plan.operations.find((operation) => operation.kind === "call" && operation.caller === addressExpected.name && (operation.args ?? []).some((argument) => argument.kind === "address" && argument.source === "actor" && argument.name === addressExpected.name)) : null;
    const actorRole = addressExpected?.name === "deployer" ? "deployer actor" : "non-deployer actor";
    const readIndex = read ? plan.operations.indexOf(read) : -1;
    const precedingActorCall = read?.kind === "read-balance" ? plan.operations.slice(0, readIndex).reverse().find((operation) => operation.kind === "call" && Boolean(operation.caller)) : null;
    const observedBehavior = observation.result === "not-observed" ? "The assertion did not produce a complete deterministic observation."
      : observation.result === "contradicted" ? "The generated local assertion condition was contradicted."
        : read?.kind === "read-address" && addressExpected?.source === "actor" && actorMutation?.kind === "call"
          ? `Local ${actorRole} ${addressExpected.name} called ${actorMutation.functionName} and the subsequent ${read.functionName}() observation matched that actor.`
          : read?.kind === "read-address" && addressExpected
            ? `The local ${read.functionName}() address observation satisfied the structured ${assertion.kind} condition for ${addressExpected.source} ${addressExpected.name}.`
            : read?.kind === "read-balance" && precedingActorCall?.kind === "call" && precedingActorCall.caller
              ? `Local actor ${precedingActorCall.caller} successfully called ${precedingActorCall.functionName}(); the subsequent native balance observation for ${read.target.kind} ${read.target.name} satisfied the structured ${assertion.kind} condition.`
            : read?.kind === "read-balance"
              ? `The local native balance observation for ${read.target.kind} ${read.target.name} satisfied the structured ${assertion.kind} condition.`
              : "The generated local assertion condition was satisfied.";
    return dynamicEvidenceSchema.parse({
      assertionId: assertion.id,
      assertionName: assertion.description,
      expectedBehavior: `${assertion.description} (${assertion.expectedOutcome}).`,
      observedBehavior,
      direction,
      contract: plan.primaryContract,
      functionName: read && "functionName" in read ? read.functionName : precedingActorCall?.kind === "call" ? precedingActorCall.functionName : actorMutation?.kind === "call" ? actorMutation.functionName : null,
      details: `ContractHunter mapped assertion ${assertion.id} over a ${read?.kind ?? "structured"} observation using controlled marker CH_ASSERT_${observation.assertionIndex} to ${observation.result}.`,
    });
  });
  const directions = new Set(dynamicEvidence.filter((item) => item.direction !== "neutral").map((item) => item.direction));
  const outcome: VerificationOutcome = directions.size !== 1 ? "inconclusive" : directions.has("supports") ? "confirmed" : "refuted";
  const resultSummary = outcome === "confirmed" ? "Structured assertion observations support the hypothesis."
    : outcome === "refuted" ? "Structured assertion observations contradict the hypothesis."
      : "Structured assertion observations were incomplete, ambiguous, or mixed.";
  return { outcome, resultSummary, observations: assertionObservations, dynamicEvidence };
}
