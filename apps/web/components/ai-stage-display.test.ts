import { describe, expect, it } from "vitest";
import { protocolStageDisplay, reviewStageDisplay } from "./ai-stage-display";

describe("AI stage presentation", () => {
  it.each([
    [{ status: "disabled", enabled: true, configured: true, hasAnalysis: false, partialCoverage: false }, "ready / not run"],
    [{ status: "disabled", enabled: false, configured: false, hasAnalysis: false, partialCoverage: false }, "disabled"],
    [{ status: "disabled", enabled: true, configured: false, hasAnalysis: false, partialCoverage: false }, "not configured"],
    [{ status: "pending", enabled: true, configured: true, hasAnalysis: false, partialCoverage: false }, "queued"],
    [{ status: "running", enabled: true, configured: true, hasAnalysis: false, partialCoverage: false }, "running"],
    [{ status: "failed", enabled: true, configured: true, hasAnalysis: false, partialCoverage: false }, "failed"],
    [{ status: "completed", enabled: true, configured: true, hasAnalysis: true, partialCoverage: false }, "complete"],
    [{ status: "completed", enabled: true, configured: true, hasAnalysis: true, partialCoverage: true }, "partial coverage"],
  ] as const)("maps protocol state to %s", (options, label) => {
    expect(protocolStageDisplay(options).label).toBe(label);
  });

  it.each([
    [{ status: "disabled", hasProtocolAnalysis: false, hasReview: false }, "requires AI analysis"],
    [{ status: "disabled", hasProtocolAnalysis: true, hasReview: false }, "ready / not run"],
    [{ status: "pending", hasProtocolAnalysis: true, hasReview: false }, "queued"],
    [{ status: "running", hasProtocolAnalysis: true, hasReview: true }, "running"],
    [{ status: "failed", hasProtocolAnalysis: true, hasReview: true }, "failed"],
    [{ status: "completed", hasProtocolAnalysis: true, hasReview: true }, "complete"],
    [{ status: "completed-with-warnings", hasProtocolAnalysis: true, hasReview: true }, "completed with warnings"],
  ] as const)("maps review state to %s", (options, label) => {
    expect(reviewStageDisplay(options).label).toBe(label);
  });
});
