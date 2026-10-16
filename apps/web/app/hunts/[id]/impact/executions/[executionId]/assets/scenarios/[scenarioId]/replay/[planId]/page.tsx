import { notFound } from "next/navigation";
import { deriveScenarioImpact } from "@contracthunter/core";
import { getDatabase, readImpactExecutionState, readImpactPoCExecution,
  readImpactScenarioRevision } from "@contracthunter/db";
import { idSchema } from "@/lib/api";
import { readReplayResult, replayPlanView } from "@/lib/impact-scenario-replay";
import { loadAssetFlow } from "@/lib/asset-flow-server";
import { ScenarioReplayView } from "@/components/scenario-replay-view";

export const dynamic = "force-dynamic";
export default async function ReplayPlanPage({ params, searchParams }: {
  params: Promise<{ id: string; executionId: string; scenarioId: string; planId: string }>;
  searchParams?: Promise<{ run?: string }> }) {
  const { id, executionId, scenarioId, planId } = await params;
  if (![id, executionId, scenarioId, planId].every((value) => idSchema.safeParse(value).success)) notFound();
  const database = getDatabase();
  let planView: ReturnType<typeof replayPlanView> | null = null;
  try { planView = replayPlanView(database, id, executionId, scenarioId, planId); } catch { notFound(); }
  if (!planView) notFound();
  const sourceScenario = readImpactScenarioRevision(database, planView.plan.scenarioRevisionId);
  let flow: ReturnType<typeof loadAssetFlow> = null;
  try { flow = loadAssetFlow(database, id, executionId); } catch { /* stale evidence is shown below */ }
  const reference = sourceScenario?.status === "reviewed" && flow &&
    sourceScenario.assetFlowContentSha256 === flow.contentSha256 ? deriveScenarioImpact(flow, sourceScenario) : null;
  const execution = readImpactPoCExecution(database, executionId);
  if (!execution) notFound();
  const state = readImpactExecutionState(database, executionId);
  const query = await (searchParams ?? Promise.resolve({} as { run?: string }));
  const activeRun = planView.runs.find((item) => item.id === query.run) ?? planView.runs[0] ?? null;
  let result = null;
  if (activeRun) try { result = readReplayResult(database, id, executionId, scenarioId, planId, activeRun.id).result; }
  catch { /* read-only result remains unavailable if evidence changed */ }
  return <main className="io-page"><ScenarioReplayView scanId={id} executionId={executionId} scenarioId={scenarioId}
    plan={planView.plan} runs={planView.runs} activeRun={activeRun} result={result} stale={planView.stale}
    reference={reference}
    source={{ artifactId: execution.artifactId, sourceSha256: execution.sourceSha256,
      chainId: execution.chainId, forkBlock: execution.forkBlock, forkBlockHash: execution.forkBlockHash,
      forgeVersion: execution.forgeVersion, assets: flow?.assets.map((item) => item.id) ?? [],
      startingObservations: state?.pre?.observations.map((item) => ({ id: item.id,
        status: item.status, value: item.value })) ?? [] }} /></main>;
}
