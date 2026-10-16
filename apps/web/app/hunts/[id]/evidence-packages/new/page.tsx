import { notFound } from "next/navigation";
import { getDatabase, listEvidencePackages } from "@contracthunter/db";
import { EvidencePackageView } from "@/components/evidence-package-view";
import { idSchema } from "@/lib/api";
import { composeEvidencePackage, type EvidencePackageSelection } from "@/lib/evidence-package-server";

export const dynamic = "force-dynamic";
export default async function NewEvidencePackagePage({ params, searchParams }: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ subjectType?: string; subjectId?: string; executionId?: string;
    scenarioRevisionId?: string; replayRunId?: string }>;
}) {
  const { id } = await params, query = await searchParams;
  if (!idSchema.safeParse(id).success || !idSchema.safeParse(query.subjectId).success ||
    !["finding", "investigation", "hypothesis"].includes(query.subjectType ?? "")) notFound();
  const selection: EvidencePackageSelection = { subjectType: query.subjectType as EvidencePackageSelection["subjectType"],
    subjectId: query.subjectId!, executionId: query.executionId ?? null,
    scenarioRevisionId: query.scenarioRevisionId ?? null, replayRunId: query.replayRunId ?? null };
  let value: ReturnType<typeof composeEvidencePackage>;
  try { value = composeEvidencePackage(getDatabase(), id, selection,
    { id: "00000000-0000-4000-8000-000000000000", createdAt: 0, status: "draft", finalizedAt: null }); }
  catch { notFound(); }
  const history = listEvidencePackages(getDatabase(), id, selection.subjectType, selection.subjectId);
  return <main className="io-page"><EvidencePackageView value={value} persisted={false} history={history} /></main>;
}
