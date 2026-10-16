import { NextResponse } from "next/server";
import { getDatabase } from "@contracthunter/db";
import { idSchema } from "@/lib/api";
import { boundedImpactJson } from "@/lib/impact-poc-http";
import { createScenario, listScenarioViews } from "@/lib/impact-scenario-server";

export const runtime = "nodejs";
type Context = { params: Promise<{ id: string; executionId: string }> };
async function ids(context: Context) {
  const value = await context.params;
  return idSchema.safeParse(value.id).success && idSchema.safeParse(value.executionId).success ? value : null;
}
export async function GET(_request: Request, context: Context) {
  const value = await ids(context);
  if (!value) return NextResponse.json({ error: "Invalid identifier." }, { status: 400 });
  try {
    const scenarios = listScenarioViews(getDatabase(), value.id, value.executionId);
    return scenarios ? NextResponse.json({ scenarios }) : NextResponse.json({ error: "Execution not found." }, { status: 404 });
  } catch { return NextResponse.json({ error: "Scenario evidence unavailable." }, { status: 409 }); }
}
export async function POST(request: Request, context: Context) {
  const value = await ids(context);
  if (!value) return NextResponse.json({ error: "Invalid identifier." }, { status: 400 });
  try {
    const scenario = createScenario(getDatabase(), value.id, value.executionId, await boundedImpactJson(request, 65536));
    return scenario ? NextResponse.json({ scenario }, { status: 201 }) :
      NextResponse.json({ error: "Execution not found." }, { status: 404 });
  } catch { return NextResponse.json({ error: "Scenario draft could not be created." }, { status: 400 }); }
}
