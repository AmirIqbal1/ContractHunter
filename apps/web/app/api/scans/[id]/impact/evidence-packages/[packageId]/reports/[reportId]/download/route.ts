import { getDatabase, readBountyReport } from "@contracthunter/db";
import { renderBountyReportMarkdown } from "@contracthunter/core";
import { idSchema } from "@/lib/api";

export const runtime = "nodejs";
export async function GET(_request: Request, context: { params: Promise<{ id: string; packageId: string; reportId: string }> }) {
  const { id, packageId, reportId } = await context.params;
  if (![id, packageId, reportId].every((value) => idSchema.safeParse(value).success))
    return new Response("Invalid identifier.", { status: 400 });
  try {
    const report = readBountyReport(getDatabase(), id, reportId);
    if (!report || report.evidencePackageId !== packageId || report.status !== "finalized")
      return new Response("Finalized report not found.", { status: 404 });
    return new Response(renderBountyReportMarkdown(report), { headers: {
      "content-type": "text/markdown; charset=utf-8",
      "content-disposition": `attachment; filename="contracthunter-report-${reportId}.md"`,
      "cache-control": "no-store", "x-content-type-options": "nosniff" } });
  } catch { return new Response("Report integrity unavailable.", { status: 409 }); }
}
