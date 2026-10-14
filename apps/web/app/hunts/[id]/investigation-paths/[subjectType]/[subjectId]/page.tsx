import { investigationSubjectTypes } from "@contracthunter/core";
import { getDatabase, getFinding, getInvestigation, getScan, getVulnerabilityHypothesis,
  readStaticProtocolGraph } from "@contracthunter/db";
import { notFound } from "next/navigation";
import { InvestigationPathView } from "@/components/investigation-path-view";
import { idSchema } from "@/lib/api";
import { loadInvestigationPaths, type PathSubjectType } from "@/lib/investigation-path-server";
import { investigationPathNodeDetails } from "@/lib/investigation-path-view";
import { listImpactExecutionIds, selectImpactOverlay } from "@/lib/impact-overlay-selection";
import { investigationImpactComparison } from "@/lib/investigation-impact-comparison";

export const dynamic = "force-dynamic";

export default async function InvestigationPathPage({ params, searchParams }: {
  params: Promise<{ id: string; subjectType: string; subjectId: string }>;
  searchParams?: Promise<{ mode?: string; path?: string; edge?: string; execution?: string; view?: string; tx?: string; call?: string; state?: string }>;
}) {
  const { id, subjectType, subjectId } = await params;
  if (!idSchema.safeParse(id).success || !idSchema.safeParse(subjectId).success ||
    !investigationSubjectTypes.includes(subjectType as PathSubjectType)) notFound();
  const database = getDatabase(), scan = getScan(database, id);
  if (!scan) notFound();
  const type = subjectType as PathSubjectType;
  const subject = type === "finding" ? getFinding(database, subjectId) :
    type === "investigation" ? getInvestigation(database, subjectId) : getVulnerabilityHypothesis(database, subjectId);
  if (!subject || subject.scanId !== id) notFound();
  const title = subject.title, status = subject.status;
  const confidence = type === "finding" ? null : type === "investigation" ?
    "confidenceScore" in subject ? subject.confidenceScore : null : "confidence" in subject ? subject.confidence : null;
  let loaded: ReturnType<typeof loadInvestigationPaths> = null;
  let artifact: ReturnType<typeof readStaticProtocolGraph> = null;
  try {
    artifact = readStaticProtocolGraph(database, id);
    if (artifact) loaded = loadInvestigationPaths(database, id, type, subjectId, artifact);
  } catch {
    return <div className="card ip-state" role="alert"><h1>Investigation Path unavailable</h1>
      <p>The static graph or path result could not be validated. Return to the subject and try again after reviewing the scan.</p></div>;
  }
  if (!artifact || !loaded) return <div className="card ip-state"><h1>Investigation Path unavailable</h1>
    <p>This hunt has no finalized static ProtocolGraph for this subject.</p></div>;
  const query = await (searchParams ?? Promise.resolve({} as { mode?: string; path?: string; edge?: string; execution?: string; view?: string; tx?: string; call?: string; state?: string }));
  const executionIds = listImpactExecutionIds(database, id, { type, id: subjectId });
  let overlay: ReturnType<typeof selectImpactOverlay> = null;
  try { overlay = selectImpactOverlay(database, id, executionIds, query.execution); }
  catch { overlay = null; }
  return <InvestigationPathView result={loaded} nodes={investigationPathNodeDetails(artifact, loaded)}
    title={title} status={status} confidence={confidence} repositoryName={scan.repositoryName}
    initialMode={query.mode === "researcher" ? "researcher" : "beginner"}
    initialPathId={loaded.paths.some((path) => path.id === query.path) ? query.path! : null}
    initialEdgeId={query.edge ?? null} overlay={overlay} artifact={artifact} executionIds={executionIds}
    displayComparisons={overlay && type === "investigation" ? investigationImpactComparison(loaded, overlay) : overlay?.pathComparisons ?? []}
    initialView={query.view === "observed" || query.view === "compare" ? query.view : "static"}
    initialTx={Number.isInteger(Number(query.tx)) && Number(query.tx) >= 0 ? Number(query.tx) : 0}
    initialCall={query.call ?? null} initialState={query.state ?? "changed"} />;
}
