import { isValidElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { VerificationTargetSection } from "./verification-target-section";
import type { PublicVerificationTargetSummary } from "@/lib/verification/verification-target-discovery";

const first = "11111111-1111-4111-8111-111111111111";
const second = "22222222-2222-4222-8222-222222222222";
const target: PublicVerificationTargetSummary = { targetId: "opaque", rootCauseFamily: "access-control", familyLabel: "Access control", representativeHypothesisId: first,
  currentHypothesisIsRepresentative: false, relatedHypotheses: [first], relatedHypothesisCount: 1, representativeReason: "stable-id-tiebreak", reason: "Stable identifier tie-break", groupingConfidence: "exact",
  strategyReadiness: { compatible: ["structured-verification"], incompatible: ["echidna-stateful-invariant"], unknown: ["foundry-fuzz-property", "foundry-stateful-invariant"] },
  candidates: [{ artifactId: second, artifactType: "invariant-proposal", hypothesisId: first, strategy: "foundry-stateful-invariant", propertyTargetIds: ["property"], eligibility: "eligible", reasons: ["matching-persisted-validation"], validationState: "validated-at-execution", executionHistoryExists: true, sourceClosureFingerprintRecorded: true, createdAt: "2026-01-01T00:00:00.000Z" }], candidateCount: 1 };

describe("advisory verification target UI", () => {
  it("shows a navigation link without redirecting or exposing internal target hashes", () => {
    const html = renderToStaticMarkup(<VerificationTargetSection target={target} />);
    expect(html).toContain("View representative target");
    expect(html).toContain(`/hypotheses/${first}`);
    expect(html).toContain("Eligible for explicit reuse");
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
  it("shows one explicit action per eligible candidate, including related and same-hypothesis sources", () => {
    const same = { ...target.candidates[0], artifactId: "33333333-3333-4333-8333-333333333333", hypothesisId: second };
    const html = renderToStaticMarkup(<VerificationTargetSection target={{ ...target, candidates: [target.candidates[0], same], candidateCount: 2 }} requestedHypothesisId={second} onReuse={() => undefined} />);
    expect((html.match(/>Reuse plan<\/button>/g) ?? [])).toHaveLength(2);
    expect(html).toContain("From related hypothesis");
    expect(html).toContain("From this hypothesis");
    expect(html).not.toContain("Auto reuse");
  });
  it.each(["stale-source", "stale-compiler", "strategy-not-compatible", "property-target-unproven", "source-fingerprint-unavailable", "stale-commit", "invalid-plan"] as const)("hides reuse for %s", (reason) => {
    const html = renderToStaticMarkup(<VerificationTargetSection target={{ ...target, candidates: [{ ...target.candidates[0], eligibility: reason.startsWith("stale-") ? "stale" : "incompatible", reasons: [reason], sourceClosureFingerprintRecorded: reason !== "source-fingerprint-unavailable" }] }} requestedHypothesisId={second} onReuse={() => undefined} />);
    expect(html).not.toContain(">Reuse plan</button>");
  });
  it("disables the active control and shows candidate-specific accessible failure", () => {
    const candidate = target.candidates[0];
    const html = renderToStaticMarkup(<VerificationTargetSection target={target} requestedHypothesisId={second} onReuse={() => undefined} reusingId={candidate.artifactId} reuseFeedback={{ artifactId: candidate.artifactId, message: "The verification target changed.", failed: true }} />);
    expect(html).toContain("disabled");
    expect(html).toContain("REUSING…");
    expect(html).toContain('role="alert"');
    expect(html).toContain(`aria-describedby="reuse-feedback-${candidate.artifactId}"`);
    expect(html).toContain("The verification target changed.");
  });
  it("binds the candidate button click to that exact artifact selector", () => {
    const selected = vi.fn(), tree = VerificationTargetSection({ target, requestedHypothesisId: second, onReuse: selected });
    const clickHandlers: Array<() => void> = [];
    const visit = (value: unknown): void => {
      if (Array.isArray(value)) { value.forEach(visit); return; }
      if (!isValidElement(value)) return;
      const props = value.props as { children?: unknown; onClick?: () => void };
      if (value.type === "button" && props.onClick) clickHandlers.push(props.onClick);
      else if (typeof value.type === "function" && value.type.name === "Candidate") visit((value.type as (props: unknown) => unknown)(value.props));
      else visit(props.children);
    };
    visit(tree);
    expect(clickHandlers).toHaveLength(1);
    clickHandlers[0]();
    expect(selected).toHaveBeenCalledExactlyOnceWith(target.candidates[0]);
  });
});
