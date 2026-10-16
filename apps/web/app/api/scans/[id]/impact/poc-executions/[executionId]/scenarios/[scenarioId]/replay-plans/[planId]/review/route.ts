import { NextResponse } from "next/server";
import { z } from "zod";
import { getDatabase } from "@contracthunter/db";
import { idSchema } from "@/lib/api";
import { boundedImpactJson } from "@/lib/impact-poc-http";
import { reviewReplayPlan } from "@/lib/impact-scenario-replay";

export const runtime = "nodejs";
type Context = { params: Promise<{ id: string; executionId: string; scenarioId: string; planId: string }> };
const inputSchema = z.object({ revisionId: z.string().uuid(), decision: z.enum(["reviewed", "rejected"]) }).strict();
export async function POST(request: Request, context: Context) {
  const { id, executionId, scenarioId, planId } = await context.params;
  if (![id, executionId, scenarioId, planId].every((value) => idSchema.safeParse(value).success))
    return NextResponse.json({ error: "Invalid identifier." }, { status: 400 });
  try { const input = inputSchema.parse(await boundedImpactJson(request, 1024));
    return NextResponse.json({ plan: await reviewReplayPlan(getDatabase(), id, executionId, scenarioId,
      planId, input.revisionId, input.decision) }); }
  catch { return NextResponse.json({ error: "Replay plan review refused." }, { status: 409 }); }
}
