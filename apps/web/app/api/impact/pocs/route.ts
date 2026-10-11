import { NextResponse } from "next/server";
import { submitManualPoC } from "@/lib/impact-poc";
import { boundedImpactJson } from "@/lib/impact-poc-http";
export const runtime = "nodejs";
export async function POST(request: Request) {
  try { return NextResponse.json({ poc: submitManualPoC(await boundedImpactJson(request)) }, { status: 201 }); }
  catch { return NextResponse.json({ error: "Manual PoC could not be created." }, { status: 400 }); }
}
