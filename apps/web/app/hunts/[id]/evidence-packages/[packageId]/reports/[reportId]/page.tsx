import { notFound } from "next/navigation";
import { bountyReportRevision, getDatabase, readBountyReport } from "@contracthunter/db";
import { BOUNTY_REPORT_FIELD_LIMITS } from "@contracthunter/core";
import { BountyReportView } from "@/components/bounty-report-view";
import { idSchema } from "@/lib/api";

export const dynamic = "force-dynamic";
export default async function ReportPage({ params }: {
  params: Promise<{ id: string; packageId: string; reportId: string }> }) {
  const { id, packageId, reportId } = await params;
  if (![id, packageId, reportId].every((value) => idSchema.safeParse(value).success)) notFound();
  let report: ReturnType<typeof readBountyReport>, revision = 1;
  try {
    report = readBountyReport(getDatabase(), id, reportId);
    if (report) revision = bountyReportRevision(getDatabase(), id, report);
  } catch { return <main className="io-page"><section className="card" role="alert"><h1>Report integrity failure</h1>
    <p>The bound Evidence Package or report failed current integrity verification. Finalized export is unavailable.</p></section></main>; }
  if (!report || report.evidencePackageId !== packageId) notFound();
  return <main className="io-page"><BountyReportView value={report} scanId={id} fieldLimits={BOUNTY_REPORT_FIELD_LIMITS} revision={revision} /></main>;
}
