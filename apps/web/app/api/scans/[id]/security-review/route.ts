import { estimateSecurityReviewAICost, formatAICost, loadConfig } from "@contracthunter/core";
import { getCurrentProtocolAnalysis, getCurrentSecurityReviewPlan, getDatabase, getScan, updateSecurityReviewState } from "@contracthunter/db";
import { NextResponse } from "next/server";
import { idSchema } from "@/lib/api";
import { enqueueSecurityReview, isSecurityReviewActive } from "@/lib/ai/security-review-job-runner";
import { previewSecurityReview } from "@/lib/ai/security-review-service";
import { aiConflictResponse, securityReviewConflict, securityReviewPrerequisite } from "@/lib/ai/manual-ai-guards";

export async function GET(_request: Request, context: { params: Promise<{ id: string }> }) {
  const id = idSchema.safeParse((await context.params).id); if (!id.success) return NextResponse.json({ error: "Invalid scan identifier." }, { status: 400 });
  try { const config = loadConfig(); const preview = previewSecurityReview({ scanId: id.data }); const estimate = estimateSecurityReviewAICost(preview.approximateSourceBytes, preview.plan.selected.length, { inputCostPerMillionUsd: config.AI_INPUT_COST_PER_MILLION_USD, outputCostPerMillionUsd: config.AI_OUTPUT_COST_PER_MILLION_USD }); return NextResponse.json({ selectedReviewers: preview.plan.selected, skippedReviewers: preview.plan.skipped, approximateSourceBytes: preview.approximateSourceBytes, approximateRequestCount: preview.approximateRequestCount, approximateInputTokens: estimate.inputTokens, expectedOutputTokens: estimate.outputTokens, estimatedCostUsd: estimate.costUsd, estimatedCostDisplay: formatAICost(estimate.costUsd) }); }
  catch (error) { return NextResponse.json({ error: error instanceof Error ? error.message : "Unable to preview security review." }, { status: 409 }); }
}
export async function POST(_request: Request, context: { params: Promise<{ id: string }> }) {
  const id = idSchema.safeParse((await context.params).id); if (!id.success) return NextResponse.json({ error: "Invalid scan identifier." }, { status: 400 }); const config = loadConfig();
  if (!config.AI_ENABLED) return NextResponse.json({ error: "AI security review is disabled." }, { status: 409 }); if (!config.OPENAI_API_KEY) return NextResponse.json({ error: "OpenAI is not configured." }, { status: 409 });
  const database = getDatabase(); const scan = getScan(database, id.data); if (!scan) return NextResponse.json({ error: "Scan not found." }, { status: 404 }); const analysis = getCurrentProtocolAnalysis(database, scan.id); const prerequisite = securityReviewPrerequisite(scan.status, Boolean(analysis)); if (prerequisite) return aiConflictResponse(prerequisite);
  const currentPlan = getCurrentSecurityReviewPlan(database, scan.id); const conflict = securityReviewConflict(scan.reviewStatus, currentPlan?.status ?? null, isSecurityReviewActive(scan.id)); if (conflict) return aiConflictResponse(conflict);
  updateSecurityReviewState(database, scan.id, "pending"); const enqueued = enqueueSecurityReview(scan.id); if (!enqueued) return aiConflictResponse("AI security review is already running."); return NextResponse.json({ status: "pending" }, { status: 202 });
}
