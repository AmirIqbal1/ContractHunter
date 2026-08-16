import type { AIAnalysisStatus, ReviewStageStatus, ScanStatus } from "@contracthunter/core";

export function shouldPollHunt(status: ScanStatus, aiStatus: AIAnalysisStatus, reviewStatus: ReviewStageStatus): boolean {
  return !["completed", "failed"].includes(status)
    || aiStatus === "pending"
    || aiStatus === "running"
    || reviewStatus === "pending"
    || reviewStatus === "running";
}
