import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { VerificationTargetSection } from "./verification-target-section";
import type { PublicVerificationTargetSummary } from "@/lib/verification/verification-target-discovery";

const first = "11111111-1111-4111-8111-111111111111";
const second = "22222222-2222-4222-8222-222222222222";
const target: PublicVerificationTargetSummary = { targetId: "opaque", rootCauseFamily: "access-control", familyLabel: "Access control", representativeHypothesisId: first,
  currentHypothesisIsRepresentative: false, relatedHypotheses: [first], relatedHypothesisCount: 1, representativeReason: "stable-id-tiebreak", reason: "Stable identifier tie-break", groupingConfidence: "exact",
  strategyReadiness: { compatible: ["structured-verification"], incompatible: ["echidna-stateful-invariant"], unknown: ["foundry-fuzz-property", "foundry-stateful-invariant"] },
  candidates: [{ artifactId: second, artifactType: "invariant-proposal", hypothesisId: first, strategy: "foundry-stateful-invariant", propertyTargetIds: ["property"], eligibility: "eligible", reasons: ["matching-persisted-validation"], validationState: "validated-at-execution", executionHistoryExists: true, createdAt: "2026-01-01T00:00:00.000Z" }], candidateCount: 1 };

describe("advisory verification target UI", () => {
  it("shows a navigation link without redirecting or exposing internal target hashes", () => {
    const html = renderToStaticMarkup(<VerificationTargetSection target={target} />);
    expect(html).toContain("View representative target");
    expect(html).toContain(`/hypotheses/${first}`);
    expect(html).toContain("Eligible for future explicit reuse");
    expect(html).toContain("Planning readiness: 1 compatible, 1 incompatible, 2 unknown");
    expect(html).not.toContain("opaque");
    expect(html).not.toContain("property");
    expect(html).not.toContain("Run with");
  });
  it("shows representative status without navigation to itself", () => {
    const html = renderToStaticMarkup(<VerificationTargetSection target={{ ...target, currentHypothesisIsRepresentative: true, relatedHypotheses: [second] }} />);
    expect(html).toContain("Representative planning target");
    expect(html).not.toContain("View representative target");
  });
});
