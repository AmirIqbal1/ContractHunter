import { notFound } from "next/navigation";
import { replayMovementSteps } from "@contracthunter/core";
import { getDatabase, readImpactForkSession, readImpactPoCExecution,
  readImpactScenarioRevision, readScenarioReplayPlan, readScenarioReplayRun } from "@contracthunter/db";
import { idSchema } from "@/lib/api";
import { readReplayResult, replayPlanView } from "@/lib/impact-scenario-replay";
import { loadAssetFlow } from "@/lib/asset-flow-server";
import { ScenarioReplayResultView, type ReplayIterationEvidence } from "@/components/scenario-replay-result-view";

export const dynamic = "force-dynamic";
export default async function ReplayRunPage({ params }: { params: Promise<{
  id: string; executionId: string; scenarioId: string; planId: string; runId: string }> }) {
  const { id, executionId, scenarioId, planId, runId } = await params;
  if (![id, executionId, scenarioId, planId, runId].every((value) => idSchema.safeParse(value).success)) notFound();
  const database = getDatabase();
  try { replayPlanView(database, id, executionId, scenarioId, planId); } catch { notFound(); }
  const run = readScenarioReplayRun(database, runId);
  if (!run) notFound();
  const plan = readScenarioReplayPlan(database, run.planRevisionId);
  if (!plan || plan.planId !== planId || plan.scanId !== id || plan.executionId !== executionId ||
    plan.scenarioId !== scenarioId) notFound();
  let result: ReturnType<typeof readReplayResult>["result"] = null;
  try { result = readReplayResult(database, id, executionId, scenarioId, planId, runId).result; }
  catch { /* Historical or tampered evidence has an explicit unavailable result below. */ }
  const scenario = readImpactScenarioRevision(database, plan.scenarioRevisionId);
  const fork = readImpactForkSession(database, plan.sessionId);
  const evidence: ReplayIterationEvidence[] = (result?.iterations ?? []).map(({ iteration }) => {
    let execution: ReturnType<typeof readImpactPoCExecution> = null;
    try { execution = iteration.executionId ? readImpactPoCExecution(database, iteration.executionId) : null; }
    catch { /* Exact execution integrity failed; retain bounded unavailable metadata. */ }
    let flow: ReturnType<typeof loadAssetFlow> = null;
    if (execution && iteration.assetFlowContentSha256) try {
      flow = loadAssetFlow(database, id, execution.id);
      if (flow?.contentSha256 !== iteration.assetFlowContentSha256) flow = null;
    } catch { flow = null; }
    const mappedContracts = flow?.participants.flatMap((item) => item.contractNodeId ?
      [{ address: item.address, contractNodeId: item.contractNodeId }] : []) ?? [];
    const mappedFunctions = [...new Map((flow?.ledgerEntries.flatMap((item) =>
      item.mappedContractNodeId && item.mappedFunctionNodeId ?
        [[`${item.mappedContractNodeId}:${item.mappedFunctionNodeId}`,
          { contractNodeId: item.mappedContractNodeId, functionNodeId: item.mappedFunctionNodeId }] as const] : []) ?? []))]
      .map(([, value]) => value);
    return { index: iteration.index, executionId: execution?.id ?? null,
      executionStatus: execution?.status ?? null, errorCode: execution?.errorCode ?? null,
      transactionHashes: execution?.transactionHashes ?? [], traceCaptureStatus: execution?.traceCaptureStatus ?? null,
      traceIds: execution?.traceIds ?? [], stateCaptureAvailable: execution?.stateCaptureAvailable ?? false,
      stateChangeCount: execution?.stateChangeCount ?? null, mappedContracts, mappedFunctions };
  });
  let movementSteps: ReturnType<typeof replayMovementSteps> = [];
  try { if (result) movementSteps = replayMovementSteps(result); }
  catch { result = null; }
  return <main className="io-page"><ScenarioReplayResultView scanId={id} executionId={executionId}
    scenarioId={scenarioId} plan={plan} run={run} result={result}
    movementSteps={movementSteps} evidence={evidence} subject={scenario?.subject ?? null}
    forkStatus={fork?.status ?? null} /></main>;
}
