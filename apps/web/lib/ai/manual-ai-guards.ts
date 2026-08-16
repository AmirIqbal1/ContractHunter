import type { AIAnalysisStatus, ReviewStageStatus } from "@contracthunter/core";
import { NextResponse } from "next/server";

export function aiConflictResponse(error: string): NextResponse {
  return NextResponse.json({ error }, { status: 409 });
}

export function protocolAnalysisPrerequisite(status: string): string | null {
  return status === "completed" ? null : "AI analysis requires a completed static scan.";
}

export function securityReviewPrerequisite(status: string, hasProtocolAnalysis: boolean): string | null {
  if (status !== "completed") return "Security review requires a completed static scan.";
  return hasProtocolAnalysis ? null : "Protocol analysis is required before security review.";
}

export function protocolAnalysisConflict(status: AIAnalysisStatus, runnerActive = false): string | null {
  return runnerActive || status === "pending" || status === "running" ? "AI protocol analysis is already running." : null;
}

export function securityReviewConflict(status: ReviewStageStatus, currentPlanStatus: ReviewStageStatus | null, runnerActive = false): string | null {
  return runnerActive || status === "pending" || status === "running" || currentPlanStatus === "pending" || currentPlanStatus === "running"
    ? "AI security review is already running."
    : null;
}
