import { loadConfig } from "@contracthunter/core";
import { getCurrentProtocolAnalysis, getDatabase, getScan, updateSecurityReviewState } from "@contracthunter/db";
import { NextResponse } from "next/server";
import { idSchema } from "@/lib/api";
import { enqueueSecurityReview } from "@/lib/ai/security-review-job-runner";
import { previewSecurityReview } from "@/lib/ai/security-review-service";

export async function GET(_request: Request, context: { params: Promise<{ id: string }> }) {
  const id = idSchema.safeParse((await context.params).id); if (!id.success) return NextResponse.json({ error: "Invalid scan identifier." }, { status: 400 });
  try { const preview = previewSecurityReview({ scanId: id.data }); return NextResponse.json({ selectedReviewers: preview.plan.selected, skippedReviewers: preview.plan.skipped, approximateSourceBytes: preview.approximateSourceBytes, approximateRequestCount: preview.approximateRequestCount }); }
  catch (error) { return NextResponse.json({ error: error instanceof Error ? error.message : "Unable to preview security review." }, { status: 409 }); }
}
export async function POST(_request: Request, context: { params: Promise<{ id: string }> }) {
  const id = idSchema.safeParse((await context.params).id); if (!id.success) return NextResponse.json({ error: "Invalid scan identifier." }, { status: 400 }); const config = loadConfig();
  if (!config.AI_ENABLED) return NextResponse.json({ error: "AI security review is disabled." }, { status: 409 }); if (!config.OPENAI_API_KEY) return NextResponse.json({ error: "OpenAI is not configured." }, { status: 409 });
  const database = getDatabase(); const scan = getScan(database, id.data); if (!scan) return NextResponse.json({ error: "Scan not found." }, { status: 404 }); if (scan.status !== "completed") return NextResponse.json({ error: "Security review requires a completed static scan." }, { status: 409 }); if (!getCurrentProtocolAnalysis(database, scan.id)) return NextResponse.json({ error: "Protocol analysis is required before security review." }, { status: 409 });
  updateSecurityReviewState(database, scan.id, "pending"); const enqueued = enqueueSecurityReview(scan.id); return NextResponse.json({ status: enqueued ? "pending" : "running" }, { status: 202 });
}
