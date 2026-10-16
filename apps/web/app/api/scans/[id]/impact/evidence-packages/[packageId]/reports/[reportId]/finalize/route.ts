import { NextResponse } from "next/server";
import { getDatabase, readBountyReport } from "@contracthunter/db";
import { idSchema } from "@/lib/api";
import { finalizeReportDraft } from "@/lib/bounty-report-server";

export const runtime = "nodejs";
export async function POST(_request: Request, context: { params: Promise<{ id: string; packageId: string; reportId: string }> }) {
  const { id, packageId, reportId } = await context.params;
  if (![id, packageId, reportId].every((value) => idSchema.safeParse(value).success))
    return NextResponse.json({ error: "Invalid identifier." }, { status: 400 });
  try {
    const current = readBountyReport(getDatabase(), id, reportId);
    if (!current || current.evidencePackageId !== packageId) return NextResponse.json({ error: "Report not found." }, { status: 404 });
    const value = finalizeReportDraft(getDatabase(), id, reportId);
    return NextResponse.json({ reportId: value.reportId, status: value.status, contentHash: value.contentHash });
  } catch { return NextResponse.json({ error: "Report cannot be finalized." }, { status: 409 }); }
}
