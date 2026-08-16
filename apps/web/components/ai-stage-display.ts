import type { AIAnalysisStatus, ReviewStageStatus } from "@contracthunter/core";

export type StageDisplay = { label: string; tone: "gray" | "purple" | "red" | "green" | "amber" };

export function protocolStageDisplay(options: { status: AIAnalysisStatus; enabled: boolean; configured: boolean; hasAnalysis: boolean; partialCoverage: boolean }): StageDisplay {
  if (options.status === "pending") return { label: "queued", tone: "purple" };
  if (options.status === "running") return { label: "running", tone: "purple" };
  if (options.status === "failed") return { label: "failed", tone: "red" };
  if (options.status === "completed" || options.hasAnalysis) return options.partialCoverage ? { label: "partial coverage", tone: "amber" } : { label: "complete", tone: "green" };
  if (!options.enabled) return { label: "disabled", tone: "gray" };
  if (!options.configured) return { label: "not configured", tone: "gray" };
  return { label: "ready / not run", tone: "gray" };
}

export function reviewStageDisplay(options: { status: ReviewStageStatus; hasProtocolAnalysis: boolean; hasReview: boolean }): StageDisplay {
  if (!options.hasProtocolAnalysis) return { label: "requires AI analysis", tone: "gray" };
  if (options.status === "pending") return { label: "queued", tone: "purple" };
  if (options.status === "running") return { label: "running", tone: "purple" };
  if (options.status === "failed") return { label: "failed", tone: "red" };
  if (options.status === "completed-with-warnings") return { label: "completed with warnings", tone: "amber" };
  if (options.status === "completed") return { label: "complete", tone: "green" };
  if (!options.hasReview) return { label: "ready / not run", tone: "gray" };
  return { label: options.status, tone: "gray" };
}
