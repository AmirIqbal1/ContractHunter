import { NextResponse } from "next/server";
import { reviewManualPoC } from "@/lib/impact-poc";
import { boundedImpactJson } from "@/lib/impact-poc-http";
export const runtime = "nodejs";
type Context = { params: Promise<{ id: string }> };
export async function POST(request: Request, context: Context) {
  try { return NextResponse.json({ poc: reviewManualPoC((await context.params).id, await boundedImpactJson(request, 1024)) }); }
  catch { return NextResponse.json({ error: "PoC review could not be recorded." }, { status: 400 }); }
}
