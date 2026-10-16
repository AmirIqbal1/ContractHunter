import { NextResponse } from "next/server";
import { getDatabase } from "@contracthunter/db";
import { idSchema } from "@/lib/api";
import { readReplayResult } from "@/lib/impact-scenario-replay";

export const runtime = "nodejs";
type Context = { params: Promise<{ id: string; executionId: string; scenarioId: string; planId: string; runId: string }> };
export async function GET(_request: Request, context: Context) {
  const { id, executionId, scenarioId, planId, runId } = await context.params;
  if (![id, executionId, scenarioId, planId, runId].every((value) => idSchema.safeParse(value).success))
    return NextResponse.json({ error: "Invalid identifier." }, { status: 400 });
  try { return NextResponse.json(readReplayResult(getDatabase(), id, executionId, scenarioId, planId, runId)); }
  catch { return NextResponse.json({ error: "Replay result unavailable." }, { status: 409 }); }
}
