import Link from "next/link";
import { notFound } from "next/navigation";
import { scenarioParticipantId } from "@contracthunter/core";
import { getDatabase, getScan, readStaticProtocolGraph } from "@contracthunter/db";
import { idSchema } from "@/lib/api";
import { loadAssetFlow } from "@/lib/asset-flow-server";
import { ScenarioReviewView } from "@/components/scenario-review-view";

export const dynamic = "force-dynamic";
export default async function NewScenarioPage({ params }: { params: Promise<{ id: string; executionId: string }> }) {
  const { id, executionId } = await params;
  if (!idSchema.safeParse(id).success || !idSchema.safeParse(executionId).success) notFound();
  const database = getDatabase(), scan = getScan(database, id);
  if (!scan) notFound();
  let flow: ReturnType<typeof loadAssetFlow> = null;
  let artifact: ReturnType<typeof readStaticProtocolGraph> = null;
  try { flow = loadAssetFlow(database, id, executionId); artifact = readStaticProtocolGraph(database, id); }
  catch { return <main className="card"><h1>Scenario evidence unavailable</h1></main>; }
  if (!flow) notFound();
  const labels = Object.fromEntries((artifact?.graph.nodes ?? []).map((node) => [node.id,
    node.kind === "function" ? node.signature : node.name]));
  return <main className="io-page"><nav className="ce-breadcrumb"><Link href={`/hunts/${encodeURIComponent(id)}/impact/executions/${encodeURIComponent(executionId)}/assets`}>Asset Flow</Link><span>/</span><strong>New Scenario</strong></nav>
    <ScenarioReviewView flow={flow} labels={labels}
      participantIds={Object.fromEntries(flow.participants.map((item) => [item.address, scenarioParticipantId(flow, item.address)]))}
      scenario={null} impact={null} stale={false} />
  </main>;
}
