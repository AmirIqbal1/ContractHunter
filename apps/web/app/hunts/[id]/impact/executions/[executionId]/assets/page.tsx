import Link from "next/link";
import { notFound } from "next/navigation";
import { assetFlowPositionsForTransaction } from "@contracthunter/core";
import { getDatabase, getScan, listImpactScenarios, readStaticProtocolGraph } from "@contracthunter/db";
import { AssetFlowView } from "@/components/asset-flow-view";
import { idSchema } from "@/lib/api";
import { loadAssetFlow } from "@/lib/asset-flow-server";
import { loadImpactOverlay } from "@/lib/impact-overlay-server";
import { listImpactExecutionIds } from "@/lib/impact-overlay-selection";

export const dynamic = "force-dynamic";

export default async function AssetFlowPage({ params, searchParams }: {
  params: Promise<{ id: string; executionId: string }>;
  searchParams?: Promise<{ tx?: string; asset?: string; participant?: string; status?: string; mode?: string; entry?: string }>;
}) {
  const { id, executionId } = await params;
  if (!idSchema.safeParse(id).success || !idSchema.safeParse(executionId).success) notFound();
  const database = getDatabase(), scan = getScan(database, id);
  if (!scan) notFound();
  let flow: ReturnType<typeof loadAssetFlow> = null;
  let artifact: ReturnType<typeof readStaticProtocolGraph> = null;
  let overlay: ReturnType<typeof loadImpactOverlay> = null;
  try { flow = loadAssetFlow(database, id, executionId); artifact = readStaticProtocolGraph(database, id);
    overlay = loadImpactOverlay(database, id, executionId); }
  catch { return <main className="card"><h1>Asset accounting unavailable</h1><p>Persisted evidence failed validation.</p></main>; }
  if (!flow) notFound();
  const query = await (searchParams ?? Promise.resolve({} as { tx?: string; asset?: string; participant?: string; status?: string; mode?: string; entry?: string }));
  const listedIds = listImpactExecutionIds(database, id);
  const executionIds = listedIds.includes(executionId) ? listedIds : [executionId, ...listedIds];
  const txPositions = Object.fromEntries(flow.transactions.map((tx) => [tx.ordinal,
    assetFlowPositionsForTransaction(flow, tx.ordinal)]));
  const labels = Object.fromEntries((artifact?.graph.nodes ?? []).filter((node) =>
    ["contract", "interface", "library", "function"].includes(node.kind)).map((node) => [node.id,
    node.kind === "function" ? node.signature : node.name]));
  return <main className="io-page"><nav className="ce-breadcrumb" aria-label="Breadcrumb">
    <Link href={`/hunts/${encodeURIComponent(id)}`}>{scan.repositoryName}</Link><span>/</span>
    <Link href={`/hunts/${encodeURIComponent(id)}/impact/executions/${encodeURIComponent(executionId)}`}>Observed Local Execution</Link><span>/</span><strong>Asset Flow</strong></nav>
    <AssetFlowView flow={flow} executionIds={executionIds} txPositions={txPositions} labels={labels}
      scenarios={listImpactScenarios(database, id, executionId)}
      initialTx={query.tx} initialAsset={query.asset} initialParticipant={query.participant}
      initialStatus={query.status} initialMode={query.mode} initialEntry={query.entry}
      investigationHref={overlay?.investigationPathResultId ? `/hunts/${encodeURIComponent(id)}/investigation-paths/${overlay.subject.type}/${encodeURIComponent(overlay.subject.id)}?execution=${encodeURIComponent(executionId)}` : null} />
  </main>;
}

