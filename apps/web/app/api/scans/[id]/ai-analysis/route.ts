import { loadConfig } from "@contracthunter/core";
import { getDatabase, getScan, updateAIState } from "@contracthunter/db";
import { NextResponse } from "next/server";
import { idSchema } from "@/lib/api";
import { enqueueProtocolAnalysis, isProtocolAnalysisActive } from "@/lib/ai/job-runner";
import { aiConflictResponse, protocolAnalysisConflict, protocolAnalysisPrerequisite } from "@/lib/ai/manual-ai-guards";

export async function POST(_request: Request, context: { params: Promise<{ id: string }> }) {
  const parsed = idSchema.safeParse((await context.params).id);
  if (!parsed.success) return NextResponse.json({ error: "Invalid scan identifier." }, { status: 400 });
  const config = loadConfig();
  if (!config.AI_ENABLED) return NextResponse.json({ error: "AI analysis is disabled." }, { status: 409 });
  if (!config.OPENAI_API_KEY) return NextResponse.json({ error: "OpenAI is not configured." }, { status: 409 });
  const database = getDatabase(); const scan = getScan(database, parsed.data);
  if (!scan) return NextResponse.json({ error: "Scan not found." }, { status: 404 });
  const prerequisite = protocolAnalysisPrerequisite(scan.status);
  if (prerequisite) return aiConflictResponse(prerequisite);
  const conflict = protocolAnalysisConflict(scan.aiStatus, isProtocolAnalysisActive(scan.id));
  if (conflict) return aiConflictResponse(conflict);
  updateAIState(database, scan.id, "pending");
  const enqueued = enqueueProtocolAnalysis(scan.id);
  if (!enqueued) return aiConflictResponse("AI protocol analysis is already running.");
  return NextResponse.json({ status: "pending" }, { status: 202 });
}
