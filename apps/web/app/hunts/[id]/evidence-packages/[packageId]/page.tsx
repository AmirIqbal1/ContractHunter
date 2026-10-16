import { notFound } from "next/navigation";
import { getDatabase, readEvidencePackage, listBountyReports } from "@contracthunter/db";
import { EvidencePackageView } from "@/components/evidence-package-view";
import { idSchema } from "@/lib/api";

export const dynamic = "force-dynamic";
export default async function EvidencePackagePage({ params }: { params: Promise<{ id: string; packageId: string }> }) {
  const { id, packageId } = await params;
  if (!idSchema.safeParse(id).success || !idSchema.safeParse(packageId).success) notFound();
  let value: ReturnType<typeof readEvidencePackage>;
  try { value = readEvidencePackage(getDatabase(), id, packageId); }
  catch { notFound(); }
  if (!value) notFound();
  const reports = value.status === "finalized" ? listBountyReports(getDatabase(), id, packageId) : [];
  return <main className="io-page"><EvidencePackageView value={value} persisted reports={reports} /></main>;
}
