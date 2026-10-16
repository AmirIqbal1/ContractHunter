import { NextResponse } from "next/server";
import { getDatabase } from "@contracthunter/db";
import { idSchema } from "@/lib/api";
import { loadScenarioView } from "@/lib/impact-scenario-server";

export const runtime = "nodejs";
type Context = { params: Promise<{ id: string; executionId: string; scenarioId: string }> };
export async function GET(_request: Request, context: Context) {
  const { id, executionId, scenarioId } = await context.params;
  if (![id, executionId, scenarioId].every((item) => idSchema.safeParse(item).success))
    return NextResponse.json({ error: "Invalid identifier." }, { status: 400 });
  try {
    const view = loadScenarioView(getDatabase(), id, executionId, scenarioId);
    if (!view) return NextResponse.json({ error: "Scenario not found." }, { status: 404 });
    if (view.stale) return NextResponse.json({ error: "Scenario is bound to an earlier asset-accounting result." }, { status: 409 });
    if (view.scenario.status !== "reviewed") return NextResponse.json({ error: "Reviewed scenario required." }, { status: 409 });
    return NextResponse.json(view.impact);
  } catch { return NextResponse.json({ error: "Scenario impact unavailable." }, { status: 409 }); }
}
