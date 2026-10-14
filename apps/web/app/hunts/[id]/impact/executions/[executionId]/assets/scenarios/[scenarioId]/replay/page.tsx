import { notFound } from "next/navigation";
import { getDatabase, readImpactExecutionState, readImpactPoCExecution } from "@contracthunter/db";
import { idSchema } from "@/lib/api";
import { listReplayPlans } from "@/lib/impact-scenario-replay";
import { loadScenarioView } from "@/lib/impact-scenario-server";
import { ScenarioReplayView } from "@/components/scenario-replay-view";

export const dynamic = "force-dynamic";
export default async function ReplayPage({ params }: {
  params: Promise<{ id: string; executionId: string; scenarioId: string }> }) {
  const { id, executionId, scenarioId } = await params;
  if (![id, executionId, scenarioId].every((value) => idSchema.safeParse(value).success)) notFound();
  const database = getDatabase();
  let view: ReturnType<typeof loadScenarioView> = null;
  try { view = loadScenarioView(database, id, executionId, scenarioId); } catch { notFound(); }
  if (!view || view.stale || view.scenario.status !== "reviewed" || !view.impact) notFound();
  const execution = readImpactPoCExecution(database, executionId);
  if (!execution) notFound();
  const state = readImpactExecutionState(database, executionId);
  let plans: ReturnType<typeof listReplayPlans> = [];
  try { plans = listReplayPlans(database, id, executionId, scenarioId); } catch { /* creation still reports its exact refusal */ }
  return <main className="io-page"><ScenarioReplayView scanId={id} executionId={executionId} scenarioId={scenarioId}
    plan={null} plans={plans} reference={view.impact}
    source={{ artifactId: execution.artifactId, sourceSha256: execution.sourceSha256,
      chainId: execution.chainId, forkBlock: execution.forkBlock, forkBlockHash: execution.forkBlockHash,
      forgeVersion: execution.forgeVersion, assets: view.flow.assets.map((item) => item.id),
      startingObservations: state?.pre?.observations.map((item) => ({ id: item.id,
        status: item.status, value: item.value })) ?? [] }} /></main>;
}
