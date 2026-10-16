import { NextResponse } from "next/server";
import { z } from "zod";
import { getDatabase } from "@contracthunter/db";
import { BOUNTY_REPORT_FIELD_LIMITS } from "@contracthunter/core";
import { idSchema } from "@/lib/api";
import { boundedImpactJson } from "@/lib/impact-poc-http";
import { createReportDraft } from "@/lib/bounty-report-server";

export const runtime = "nodejs";
const fields = z.object({ title: z.string().max(BOUNTY_REPORT_FIELD_LIMITS.title),
  summary: z.string().max(BOUNTY_REPORT_FIELD_LIMITS.summary),
  impactStatement: z.string().max(BOUNTY_REPORT_FIELD_LIMITS.impactStatement),
  reproductionNote: z.string().max(BOUNTY_REPORT_FIELD_LIMITS.reproductionNote),
  additionalContext: z.string().max(BOUNTY_REPORT_FIELD_LIMITS.additionalContext) }).strict();
const input = z.object({ revisionOf: z.string().uuid().nullable().optional(), fields: fields.optional() }).strict();
export async function POST(request: Request, context: { params: Promise<{ id: string; packageId: string }> }) {
  const { id, packageId } = await context.params;
  if (!idSchema.safeParse(id).success || !idSchema.safeParse(packageId).success)
    return NextResponse.json({ error: "Invalid identifier." }, { status: 400 });
  try {
    const { revisionOf, fields: authorFields } = input.parse(await boundedImpactJson(request, 32_768));
    const value = createReportDraft(getDatabase(), id, packageId, revisionOf ?? null, authorFields);
    return NextResponse.json({ reportId: value.reportId, status: value.status }, { status: 201 });
  } catch { return NextResponse.json({ error: "Report draft could not be created from this finalized package." }, { status: 409 }); }
}
