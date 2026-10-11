import { NextResponse } from "next/server";
import { executeManualPoC } from "@/lib/impact-poc";
import { boundedImpactJson } from "@/lib/impact-poc-http";
export const runtime = "nodejs";
type Context = { params: Promise<{ id: string }> };
export async function POST(request: Request, context: Context) {
  try { return NextResponse.json({ execution: await executeManualPoC((await context.params).id,
    await boundedImpactJson(request, 1024)) }, { status: 201 }); }
  catch { return NextResponse.json({ error: "PoC execution was refused." }, { status: 400 }); }
}
