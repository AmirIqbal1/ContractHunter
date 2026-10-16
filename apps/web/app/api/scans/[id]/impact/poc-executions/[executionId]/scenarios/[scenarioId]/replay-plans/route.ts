import { NextResponse } from "next/server";
import { getDatabase } from "@contracthunter/db";
import { idSchema } from "@/lib/api";
import { boundedImpactJson } from "@/lib/impact-poc-http";
import { createReplayPlan, listReplayPlans } from "@/lib/impact-scenario-replay";

export const runtime = "nodejs";
type Context = { params: Promise<{ id: string; executionId: string; scenarioId: string }> };
export async function GET(_request: Request, context: Context) {
  const { id, executionId, scenarioId } = await context.params;
  if (![id, executionId, scenarioId].every((value) => idSchema.safeParse(value).success))
    return NextResponse.json({ error: "Invalid identifier." }, { status: 400 });
  try { return NextResponse.json({ plans: listReplayPlans(getDatabase(), id, executionId, scenarioId) }); }
  catch { return NextResponse.json({ error: "Scenario replay evidence unavailable." }, { status: 409 }); }
}
export async function POST(request: Request, context: Context) {
  const { id, executionId, scenarioId } = await context.params;
  if (![id, executionId, scenarioId].every((value) => idSchema.safeParse(value).success))
    return NextResponse.json({ error: "Invalid identifier." }, { status: 400 });
  try { return NextResponse.json({ plan: await createReplayPlan(getDatabase(), id, executionId, scenarioId,
    await boundedImpactJson(request, 1024)) }, { status: 201 }); }
  catch { return NextResponse.json({ error: "Replay plan refused." }, { status: 409 }); }
}
