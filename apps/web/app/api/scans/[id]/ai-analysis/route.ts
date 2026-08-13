import { loadConfig } from "@contracthunter/core";
import { getDatabase, getScan, updateAIState } from "@contracthunter/db";
import { NextResponse } from "next/server";
import { idSchema } from "@/lib/api";
import { enqueueProtocolAnalysis } from "@/lib/ai/job-runner";

export async function POST(_request: Request, context: { params: Promise<{ id: string }> }) {
  const parsed = idSchema.safeParse((await context.params).id);
  if (!parsed.success) return NextResponse.json({ error: "Invalid scan identifier." }, { status: 400 });
  const config = loadConfig();
  if (!config.AI_ENABLED) return NextResponse.json({ error: "AI analysis is disabled." }, { status: 409 });
  if (!config.OPENAI_API_KEY) return NextResponse.json({ error: "OpenAI is not configured." }, { status: 409 });
  const database = getDatabase(); const scan = getScan(database, parsed.data);
  if (!scan) return NextResponse.json({ error: "Scan not found." }, { status: 404 });
  if (scan.status !== "completed") return NextResponse.json({ error: "AI analysis requires a completed static scan." }, { status: 409 });
  updateAIState(database, scan.id, "pending");
  const enqueued = enqueueProtocolAnalysis(scan.id);
  return NextResponse.json({ status: enqueued ? "pending" : "running" }, { status: 202 });
}
