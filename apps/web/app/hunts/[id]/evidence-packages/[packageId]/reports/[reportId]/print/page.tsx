import { notFound } from "next/navigation";
import { getDatabase, readBountyReport } from "@contracthunter/db";
import { BountyReportPaper } from "@/components/bounty-report-paper";
import { idSchema } from "@/lib/api";

export const dynamic = "force-dynamic";
export default async function ReportPrintPage({ params }: {
  params: Promise<{ id: string; packageId: string; reportId: string }> }) {
  const { id, packageId, reportId } = await params;
  if (![id, packageId, reportId].every((value) => idSchema.safeParse(value).success)) notFound();
  let report: ReturnType<typeof readBountyReport>;
  try { report = readBountyReport(getDatabase(), id, reportId); }
  catch { return <main className="io-page"><section className="card" role="alert"><h1>Report integrity failure</h1>
    <p>The bound Evidence Package or report failed current integrity verification. Printing is unavailable.</p></section></main>; }
  if (!report || report.evidencePackageId !== packageId || report.status !== "finalized") notFound();
  return <main className="io-page bounty-print-page"><BountyReportPaper value={report} /></main>;
}
