import { NextResponse } from "next/server";
import { z } from "zod";
import { getDatabase } from "@contracthunter/db";
import { idSchema } from "@/lib/api";
import { boundedImpactJson } from "@/lib/impact-poc-http";
import { replayPlanView, startReplayRun } from "@/lib/impact-scenario-replay";

export const runtime = "nodejs";
type Context = { params: Promise<{ id: string; executionId: string; scenarioId: string; planId: string }> };
export async function GET(_request: Request, context: Context) {
  const { id, executionId, scenarioId, planId } = await context.params;
  if (![id, executionId, scenarioId, planId].every((value) => idSchema.safeParse(value).success))
    return NextResponse.json({ error: "Invalid identifier." }, { status: 400 });
  try { return NextResponse.json({ runs: replayPlanView(getDatabase(), id, executionId, scenarioId, planId).runs }); }
  catch { return NextResponse.json({ error: "Replay runs unavailable." }, { status: 404 }); }
}
export async function POST(request: Request, context: Context) {
  const { id, executionId, scenarioId, planId } = await context.params;
  if (![id, executionId, scenarioId, planId].every((value) => idSchema.safeParse(value).success))
    return NextResponse.json({ error: "Invalid identifier." }, { status: 400 });
  try { const { revisionId } = z.object({ revisionId: z.string().uuid() }).strict()
    .parse(await boundedImpactJson(request, 1024));
    return NextResponse.json({ run: await startReplayRun(getDatabase(), id, executionId, scenarioId,
      planId, revisionId) }, { status: 202 }); }
  catch { return NextResponse.json({ error: "Replay start refused." }, { status: 409 }); }
}
