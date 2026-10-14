import { NextResponse } from "next/server";
import { getDatabase } from "@contracthunter/db";
import { z } from "zod";
import { idSchema } from "@/lib/api";
import { boundedImpactJson } from "@/lib/impact-poc-http";
import { loadScenarioView, updateScenario } from "@/lib/impact-scenario-server";

export const runtime = "nodejs";
type Context = { params: Promise<{ id: string; executionId: string; scenarioId: string }> };
const updateSchema = z.object({ revisionId: z.string().uuid(), assignments: z.array(z.object({
  participantId: z.string(), role: z.string() }).strict()).max(512), note: z.string().max(1000) }).strict();
async function ids(context: Context) {
  const value = await context.params;
  return [value.id, value.executionId, value.scenarioId].every((item) => idSchema.safeParse(item).success) ? value : null;
}
export async function GET(_request: Request, context: Context) {
  const value = await ids(context);
  if (!value) return NextResponse.json({ error: "Invalid identifier." }, { status: 400 });
  try {
    const view = loadScenarioView(getDatabase(), value.id, value.executionId, value.scenarioId);
    return view ? NextResponse.json({ scenario: view.scenario, stale: view.stale, impact: view.impact }) :
      NextResponse.json({ error: "Scenario not found." }, { status: 404 });
  } catch { return NextResponse.json({ error: "Scenario evidence unavailable." }, { status: 409 }); }
}
export async function PATCH(request: Request, context: Context) {
  const value = await ids(context);
  if (!value) return NextResponse.json({ error: "Invalid identifier." }, { status: 400 });
  try {
    const input = updateSchema.parse(await boundedImpactJson(request, 65536));
    const scenario = updateScenario(getDatabase(), value.id, value.executionId, value.scenarioId,
      input.revisionId, { assignments: input.assignments, note: input.note });
    return NextResponse.json({ scenario });
  } catch { return NextResponse.json({ error: "Draft update rejected." }, { status: 409 }); }
}
