import { describe, expect, it } from "vitest";
import { aiConflictResponse, protocolAnalysisConflict, protocolAnalysisPrerequisite, securityReviewConflict, securityReviewPrerequisite } from "./manual-ai-guards";

describe("manual AI duplicate guards", () => {
  it("rejects duplicate pending/running protocol requests and allows terminal reruns", () => {
    expect(protocolAnalysisConflict("pending")).toBe("AI protocol analysis is already running.");
    expect(protocolAnalysisConflict("running")).toBe("AI protocol analysis is already running.");
    expect(protocolAnalysisConflict("completed")).toBeNull();
    expect(protocolAnalysisConflict("failed")).toBeNull();
  });

  it("rejects duplicate current review requests and allows terminal reruns", () => {
    expect(securityReviewConflict("running", null)).toBe("AI security review is already running.");
    expect(securityReviewConflict("completed", "pending")).toBe("AI security review is already running.");
    expect(securityReviewConflict("failed", "failed")).toBeNull();
  });

  it("also rejects an active in-memory job before persisted state catches up", () => {
    expect(protocolAnalysisConflict("completed", true)).not.toBeNull();
    expect(securityReviewConflict("completed", "completed", true)).not.toBeNull();
  });

  it("returns duplicate requests as HTTP 409 conflicts", async () => {
    const response = aiConflictResponse(protocolAnalysisConflict("running")!);
    expect(response.status).toBe(409);
    expect(await response.json()).toEqual({ error: "AI protocol analysis is already running." });
  });

  it("allows manual AI only after static completion and gates review on protocol analysis", () => {
    expect(protocolAnalysisPrerequisite("scanning")).toBe("AI analysis requires a completed static scan.");
    expect(protocolAnalysisPrerequisite("completed")).toBeNull();
    expect(securityReviewPrerequisite("completed", false)).toBe("Protocol analysis is required before security review.");
    expect(securityReviewPrerequisite("completed", true)).toBeNull();
  });
});
