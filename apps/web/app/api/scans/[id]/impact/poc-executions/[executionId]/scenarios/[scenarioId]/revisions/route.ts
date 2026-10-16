import { NextResponse } from "next/server";
import { getDatabase } from "@contracthunter/db";
import { z } from "zod";
import { idSchema } from "@/lib/api";
import { boundedImpactJson } from "@/lib/impact-poc-http";
import { createScenarioRevision } from "@/lib/impact-scenario-server";

export const runtime = "nodejs";
type Context = { params: Promise<{ id: string; executionId: string; scenarioId: string }> };
const inputSchema = z.object({ revisionId: z.string().uuid() }).strict();
export async function POST(request: Request, context: Context) {
  const { id, executionId, scenarioId } = await context.params;
  if (![id, executionId, scenarioId].every((item) => idSchema.safeParse(item).success))
    return NextResponse.json({ error: "Invalid identifier." }, { status: 400 });
  try {
    const input = inputSchema.parse(await boundedImpactJson(request, 1024));
    const scenario = createScenarioRevision(getDatabase(), id, executionId, scenarioId, input.revisionId);
    return NextResponse.json({ scenario }, { status: 201 });
  } catch { return NextResponse.json({ error: "Scenario revision could not be created." }, { status: 409 }); }
}
