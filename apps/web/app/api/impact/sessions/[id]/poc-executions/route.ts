import { NextResponse } from "next/server";
import { executeManualPoC } from "@/lib/impact-poc";
import { boundedImpactJson } from "@/lib/impact-poc-http";
import { getDatabase } from "@contracthunter/db";
import { publicImpactExecution, requestedImpactScan, scopedImpactSession } from "@/lib/impact-api-scope";
export const runtime = "nodejs";
type Context = { params: Promise<{ id: string }> };
export async function POST(request: Request, context: Context) {
  const scanId = requestedImpactScan(request), { id } = await context.params;
  if (!scanId || !/^[0-9a-f-]{36}$/i.test(id)) return NextResponse.json({ error: "Invalid identifier." }, { status: 400 });
  if (!scopedImpactSession(getDatabase(), scanId, id)) return NextResponse.json({ error: "Session not found." }, { status: 404 });
  try { return NextResponse.json({ execution: publicImpactExecution(await executeManualPoC(id,
    await boundedImpactJson(request, 16 * 1024))) }, { status: 201 }); }
  catch { return NextResponse.json({ error: "PoC execution was refused." }, { status: 400 }); }
}
