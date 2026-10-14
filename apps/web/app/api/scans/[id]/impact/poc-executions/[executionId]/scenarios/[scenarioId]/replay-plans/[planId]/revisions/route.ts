import { NextResponse } from "next/server";
import { z } from "zod";
import { getDatabase } from "@contracthunter/db";
import { idSchema } from "@/lib/api";
import { boundedImpactJson } from "@/lib/impact-poc-http";
import { reviseReplayPlan } from "@/lib/impact-scenario-replay";

export const runtime = "nodejs";
type Context = { params: Promise<{ id: string; executionId: string; scenarioId: string; planId: string }> };
export async function POST(request: Request, context: Context) {
  const { id, executionId, scenarioId, planId } = await context.params;
  if (![id, executionId, scenarioId, planId].every((value) => idSchema.safeParse(value).success))
    return NextResponse.json({ error: "Invalid identifier." }, { status: 400 });
  try { const { revisionId } = z.object({ revisionId: z.string().uuid() }).strict()
    .parse(await boundedImpactJson(request, 1024));
    return NextResponse.json({ plan: reviseReplayPlan(getDatabase(), id, executionId, scenarioId,
      planId, revisionId) }, { status: 201 }); }
  catch { return NextResponse.json({ error: "Replay plan revision refused." }, { status: 409 }); }
}
