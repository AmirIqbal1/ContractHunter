import { NextResponse } from "next/server";
import { z } from "zod";
import { getDatabase, readBountyReport } from "@contracthunter/db";
import { BOUNTY_REPORT_FIELD_LIMITS } from "@contracthunter/core";
import { idSchema } from "@/lib/api";
import { boundedImpactJson } from "@/lib/impact-poc-http";
import { saveReportDraft } from "@/lib/bounty-report-server";

export const runtime = "nodejs";
const fields = z.object({ title: z.string().max(BOUNTY_REPORT_FIELD_LIMITS.title),
  summary: z.string().max(BOUNTY_REPORT_FIELD_LIMITS.summary),
  impactStatement: z.string().max(BOUNTY_REPORT_FIELD_LIMITS.impactStatement),
  reproductionNote: z.string().max(BOUNTY_REPORT_FIELD_LIMITS.reproductionNote),
  additionalContext: z.string().max(BOUNTY_REPORT_FIELD_LIMITS.additionalContext) }).strict();
type Params = { params: Promise<{ id: string; packageId: string; reportId: string }> };
export async function PATCH(request: Request, context: Params) {
  const { id, packageId, reportId } = await context.params;
  if (![id, packageId, reportId].every((value) => idSchema.safeParse(value).success))
    return NextResponse.json({ error: "Invalid identifier." }, { status: 400 });
  try {
    const current = readBountyReport(getDatabase(), id, reportId);
    if (!current || current.evidencePackageId !== packageId) return NextResponse.json({ error: "Report not found." }, { status: 404 });
    const value = saveReportDraft(getDatabase(), id, reportId, fields.parse(await boundedImpactJson(request, 32_768)));
    return NextResponse.json({ reportId: value.reportId, status: value.status, contentHash: value.contentHash });
  } catch { return NextResponse.json({ error: "Draft fields are invalid or report is immutable." }, { status: 409 }); }
}
