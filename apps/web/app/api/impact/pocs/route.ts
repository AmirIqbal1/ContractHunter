import { NextResponse } from "next/server";
import { submitManualPoC } from "@/lib/impact-poc";
import { boundedImpactJson } from "@/lib/impact-poc-http";
import { impactPoCCreateSchema } from "@contracthunter/core";
import { getDatabase } from "@contracthunter/db";
import { impactSubjectInScan, publicImpactPoC, requestedImpactScan } from "@/lib/impact-api-scope";
export const runtime = "nodejs";
export async function POST(request: Request) {
  try {
    const scanId = requestedImpactScan(request);
    if (!scanId) return NextResponse.json({ error: "Invalid scan ID." }, { status: 400 });
    const input = impactPoCCreateSchema.parse(await boundedImpactJson(request));
    if (!impactSubjectInScan(getDatabase(), scanId, input.findingId ?? null, input.hypothesisId ?? null))
      return NextResponse.json({ error: "Subject not found." }, { status: 404 });
    return NextResponse.json({ poc: publicImpactPoC(submitManualPoC(input)) }, { status: 201 });
  }
  catch { return NextResponse.json({ error: "Manual PoC could not be created." }, { status: 400 }); }
}
