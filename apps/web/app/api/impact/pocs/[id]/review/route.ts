import { NextResponse } from "next/server";
import { reviewManualPoC } from "@/lib/impact-poc";
import { boundedImpactJson } from "@/lib/impact-poc-http";
import { getDatabase } from "@contracthunter/db";
import { publicImpactPoC, requestedImpactScan, scopedImpactPoC } from "@/lib/impact-api-scope";
export const runtime = "nodejs";
type Context = { params: Promise<{ id: string }> };
export async function POST(request: Request, context: Context) {
  const scanId = requestedImpactScan(request), { id } = await context.params;
  if (!scanId || !/^[0-9a-f-]{36}$/i.test(id)) return NextResponse.json({ error: "Invalid identifier." }, { status: 400 });
  if (!scopedImpactPoC(getDatabase(), scanId, id)) return NextResponse.json({ error: "PoC not found." }, { status: 404 });
  try { return NextResponse.json({ poc: publicImpactPoC(reviewManualPoC(id, await boundedImpactJson(request, 1024))) }); }
  catch { return NextResponse.json({ error: "PoC review could not be recorded." }, { status: 400 }); }
}
