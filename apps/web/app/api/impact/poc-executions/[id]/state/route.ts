import { NextResponse } from "next/server";
import { getManualPoCExecutionState } from "@/lib/impact-poc";
import { getDatabase } from "@contracthunter/db";
import { requestedImpactScan, scopedImpactExecution } from "@/lib/impact-api-scope";
export const runtime = "nodejs";
type Context = { params: Promise<{ id: string }> };
export async function GET(request: Request, context: Context) {
  const { id } = await context.params;
  if (!/^[0-9a-f-]{36}$/i.test(id)) return NextResponse.json({ error: "Invalid execution ID." }, { status: 400 });
  const scanId = requestedImpactScan(request);
  if (!scanId) return NextResponse.json({ error: "Invalid scan ID." }, { status: 400 });
  try {
    if (!scopedImpactExecution(getDatabase(), scanId, id))
      return NextResponse.json({ error: "Execution not found." }, { status: 404 });
    const state = getManualPoCExecutionState(id);
    return state ? NextResponse.json({ state }) : NextResponse.json({ error: "Execution not found." }, { status: 404 });
  } catch { return NextResponse.json({ error: "State integrity check failed." }, { status: 409 }); }
}
