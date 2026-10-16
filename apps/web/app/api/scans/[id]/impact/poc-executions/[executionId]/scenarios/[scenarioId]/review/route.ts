import { NextResponse } from "next/server";
import { getDatabase } from "@contracthunter/db";
import { z } from "zod";
import { idSchema } from "@/lib/api";
import { boundedImpactJson } from "@/lib/impact-poc-http";
import { decideScenario } from "@/lib/impact-scenario-server";

export const runtime = "nodejs";
type Context = { params: Promise<{ id: string; executionId: string; scenarioId: string }> };
const decisionSchema = z.object({ revisionId: z.string().uuid(), decision: z.enum(["reviewed", "rejected"]) }).strict();
export async function POST(request: Request, context: Context) {
  const { id, executionId, scenarioId } = await context.params;
  if (![id, executionId, scenarioId].every((item) => idSchema.safeParse(item).success))
    return NextResponse.json({ error: "Invalid identifier." }, { status: 400 });
  try {
    const input = decisionSchema.parse(await boundedImpactJson(request, 1024));
    const scenario = decideScenario(getDatabase(), id, executionId, scenarioId, input.revisionId, input.decision);
    return NextResponse.json({ scenario });
  } catch { return NextResponse.json({ error: "Scenario review rejected." }, { status: 409 }); }
}
