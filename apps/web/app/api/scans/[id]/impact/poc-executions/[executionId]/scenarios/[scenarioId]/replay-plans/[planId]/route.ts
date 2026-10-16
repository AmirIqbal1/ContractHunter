import { NextResponse } from "next/server";
import { z } from "zod";
import { getDatabase } from "@contracthunter/db";
import { idSchema } from "@/lib/api";
import { boundedImpactJson } from "@/lib/impact-poc-http";
import { replayPlanView, updateReplayPlan } from "@/lib/impact-scenario-replay";

export const runtime = "nodejs";
type Context = { params: Promise<{ id: string; executionId: string; scenarioId: string; planId: string }> };
const update = z.object({ revisionId: z.string().uuid(), mode: z.enum(["independent-replay", "cumulative-replay"]),
  iterationCount: z.number().int() }).strict();
export async function GET(_request: Request, context: Context) {
  const { id, executionId, scenarioId, planId } = await context.params;
  if (![id, executionId, scenarioId, planId].every((value) => idSchema.safeParse(value).success))
    return NextResponse.json({ error: "Invalid identifier." }, { status: 400 });
  try { return NextResponse.json(replayPlanView(getDatabase(), id, executionId, scenarioId, planId)); }
  catch { return NextResponse.json({ error: "Replay plan unavailable." }, { status: 404 }); }
}
export async function PATCH(request: Request, context: Context) {
  const { id, executionId, scenarioId, planId } = await context.params;
  if (![id, executionId, scenarioId, planId].every((value) => idSchema.safeParse(value).success))
    return NextResponse.json({ error: "Invalid identifier." }, { status: 400 });
  try { const input = update.parse(await boundedImpactJson(request, 1024));
    return NextResponse.json({ plan: await updateReplayPlan(getDatabase(), id, executionId, scenarioId,
      planId, input.revisionId, { mode: input.mode, iterationCount: input.iterationCount }) }); }
  catch { return NextResponse.json({ error: "Replay draft update refused." }, { status: 409 }); }
}
