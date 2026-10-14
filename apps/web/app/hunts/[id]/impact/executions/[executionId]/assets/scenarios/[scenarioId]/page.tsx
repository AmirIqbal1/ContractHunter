import Link from "next/link";
import { notFound } from "next/navigation";
import { deriveScenarioImpact, scenarioParticipantId } from "@contracthunter/core";
import { getDatabase, getScan, listImpactScenarioRevisions, readStaticProtocolGraph } from "@contracthunter/db";
import { idSchema } from "@/lib/api";
import { loadScenarioView } from "@/lib/impact-scenario-server";
import { ScenarioReviewView } from "@/components/scenario-review-view";

export const dynamic = "force-dynamic";
export default async function ScenarioPage({ params, searchParams }: {
  params: Promise<{ id: string; executionId: string; scenarioId: string }>;
  searchParams?: Promise<{ revision?: string }> }) {
  const { id, executionId, scenarioId } = await params;
  if (![id, executionId, scenarioId].every((value) => idSchema.safeParse(value).success)) notFound();
  const database = getDatabase(), scan = getScan(database, id);
  if (!scan) notFound();
  let view: ReturnType<typeof loadScenarioView> = null;
  let artifact: ReturnType<typeof readStaticProtocolGraph> = null;
  try { view = loadScenarioView(database, id, executionId, scenarioId); artifact = readStaticProtocolGraph(database, id); }
  catch { return <main className="card"><h1>Scenario evidence unavailable</h1></main>; }
  if (!view) notFound();
  const query = await (searchParams ?? Promise.resolve({} as { revision?: string }));
  const revisions = listImpactScenarioRevisions(database, id, executionId, scenarioId);
  const selected = revisions.find((item) => item.id === query.revision) ?? view.scenario;
  const historical = selected.id !== view.scenario.id;
  const stale = selected.assetFlowContentSha256 !== view.flow.contentSha256 ||
    selected.assetAccountingRulesetVersion !== view.flow.rulesetVersion;
  const impact = historical && !stale && selected.status === "reviewed" ?
    deriveScenarioImpact(view.flow, selected) : historical ? null : view.impact;
  const labels = Object.fromEntries((artifact?.graph.nodes ?? []).map((node) => [node.id,
    node.kind === "function" ? node.signature : node.name]));
  return <main className="io-page"><nav className="ce-breadcrumb"><Link href={`/hunts/${encodeURIComponent(id)}/impact/executions/${encodeURIComponent(executionId)}/assets`}>Asset Flow</Link><span>/</span><strong>Scenario Analysis</strong></nav>
    <ScenarioReviewView flow={view.flow} labels={labels}
      participantIds={Object.fromEntries(view.flow.participants.map((item) => [item.address, scenarioParticipantId(view.flow, item.address)]))}
      scenario={selected}
      impact={impact}
      stale={stale} historical={historical}
      revisions={revisions} />
  </main>;
}
