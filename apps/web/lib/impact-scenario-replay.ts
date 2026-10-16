import { createHash } from "node:crypto";
import { deriveReplayIterationAccounting, deriveScenarioImpact, deriveScenarioReplayResult, planHash,
  replayPlanInputSchema, type ImpactStateSnapshot, type ScenarioReplayPlan,
  type ScenarioReplayIteration, type ScenarioReplayResult } from "@contracthunter/core";
import { createScenarioReplayIteration, createScenarioReplayPlan, createScenarioReplayRun,
  decideScenarioReplayPlan, finishScenarioReplayIteration, listScenarioReplayPlans,
  listScenarioReplayPlanRuns, readCurrentScenarioReplayPlan, readImpactExecutionState,
  readImpactForkSession, readImpactPoCArtifact, readImpactPoCExecution, readScenarioReplayIterations,
  readImpactScenarioRevision, readScenarioReplayPlan, readScenarioReplayRun, requestScenarioReplayCancel,
  reviseScenarioReplayPlan, updateScenarioReplayDraft, updateScenarioReplayRun,
  type DatabaseClient } from "@contracthunter/db";
import { createImpactForkService, resolveImpactHandle } from "./impact-lab";
import { executeManualPoC, reserveImpactReplayController, transferImpactReplayController } from "./impact-poc";
import { loadAssetFlow } from "./asset-flow-server";
import { loadScenarioView } from "./impact-scenario-server";

const TOTAL_RUN_MS = 10 * 60_000;
function tokenHash(token: string) { return createHash("sha256").update(token).digest("hex"); }
function observationFrame(snapshot: ImpactStateSnapshot | null): string | null {
  return snapshot ? JSON.stringify(snapshot.observations.map((item) =>
    [item.id, item.kind, item.status, item.value, item.errorCode])) : null;
}
function binding(database: DatabaseClient, scanId: string, executionId: string, scenarioId: string) {
  const view = loadScenarioView(database, scanId, executionId, scenarioId);
  if (!view || view.stale || view.scenario.status !== "reviewed" || !view.impact)
    throw Error("replay_scenario_not_current_reviewed");
  const execution = readImpactPoCExecution(database, executionId);
  const artifact = execution && readImpactPoCArtifact(database, execution.artifactId);
  const session = execution && readImpactForkSession(database, execution.sessionId);
  if (!execution || !artifact || !session || artifact.reviewState !== "reviewed" ||
    !execution.executed || !["completed", "failed"].includes(execution.status) ||
    execution.status === "failed" && (execution.errorCode !== "forge_failed" ||
      !view.flow.transactions.some((item) => item.status === "reverted")) ||
    execution.sourceSha256 !== artifact.sourceSha256 || execution.observationPlan === null ||
    execution.observationPlanSha256 !== planHash(execution.observationPlan) ||
    execution.forgeVersion === null || execution.forgeSha256 === null ||
    artifact.findingId !== session.findingId || artifact.hypothesisId !== session.hypothesisId ||
    execution.chainId !== session.chainId || execution.forkBlock !== session.resolvedForkBlock ||
    execution.forkBlockHash !== session.forkBlockHash ||
    JSON.stringify(execution.targetCodeHashes) !== JSON.stringify(session.targetCodeHashes))
    throw Error("replay_source_execution_invalid");
  return { view, execution, artifact, session };
}
function matchesPlan(plan: ScenarioReplayPlan, bound: ReturnType<typeof binding>): boolean {
  const { scenario, flow } = bound.view;
  const { execution, artifact } = bound;
  return plan.scanId === flow.scanId && plan.scenarioId === scenario.scenarioId &&
    plan.scenarioRevisionId === scenario.id && plan.executionId === execution.id &&
    plan.sessionId === execution.sessionId && plan.artifactId === artifact.id &&
    plan.sourceSha256 === artifact.sourceSha256 && plan.assetFlowContentSha256 === flow.contentSha256 &&
    plan.scenarioContentSha256 === scenario.contentSha256 &&
    plan.observationPlanSha256 === execution.observationPlanSha256 &&
    plan.forgeVersion === execution.forgeVersion && plan.forgeSha256 === execution.forgeSha256 &&
    plan.chainId === execution.chainId && plan.forkBlock === execution.forkBlock &&
    plan.forkBlockHash === execution.forkBlockHash && plan.runtimeTokenSha256 === execution.runtimeTokenSha256 &&
    JSON.stringify(plan.targetCodeHashes) === JSON.stringify(execution.targetCodeHashes);
}
async function liveSession(bound: ReturnType<typeof binding>) {
  const handle = resolveImpactHandle(bound.session.id);
  if (!handle || tokenHash(handle.token) !== bound.execution.runtimeTokenSha256)
    throw Error("replay_runtime_identity_changed");
  const session = await createImpactForkService().assertSafeImpactExecutionEndpoint(handle);
  if (session.status !== "ready" || session.chainId !== bound.execution.chainId ||
    session.resolvedForkBlock !== bound.execution.forkBlock || session.forkBlockHash !== bound.execution.forkBlockHash ||
    JSON.stringify(session.targetCodeHashes) !== JSON.stringify(bound.execution.targetCodeHashes))
    throw Error("replay_fork_identity_changed");
  return handle;
}
export async function createReplayPlan(database: DatabaseClient, scanId: string, executionId: string,
  scenarioId: string, raw: unknown) {
  const input = replayPlanInputSchema.parse(raw), bound = binding(database, scanId, executionId, scenarioId);
  await liveSession(bound);
  const { execution } = bound;
  return createScenarioReplayPlan(database, { scanId, scenarioId, scenarioRevisionId: bound.view.scenario.id,
    executionId, sessionId: execution.sessionId, artifactId: execution.artifactId,
    sourceSha256: execution.sourceSha256, assetFlowContentSha256: bound.view.flow.contentSha256,
    scenarioContentSha256: bound.view.scenario.contentSha256,
    observationPlanSha256: execution.observationPlanSha256!, forgeVersion: execution.forgeVersion!,
    forgeSha256: execution.forgeSha256!, chainId: execution.chainId, forkBlock: execution.forkBlock,
    forkBlockHash: execution.forkBlockHash, targetCodeHashes: execution.targetCodeHashes,
    runtimeTokenSha256: execution.runtimeTokenSha256 }, input);
}
export function listReplayPlans(database: DatabaseClient, scanId: string, executionId: string, scenarioId: string) {
  const bound = binding(database, scanId, executionId, scenarioId);
  return listScenarioReplayPlans(database, scanId, bound.view.scenario.id);
}
export function replayPlanView(database: DatabaseClient, scanId: string, executionId: string,
  scenarioId: string, planId: string) {
  const plan = readCurrentScenarioReplayPlan(database, planId);
  if (!plan || plan.scanId !== scanId || plan.executionId !== executionId || plan.scenarioId !== scenarioId)
    throw Error("replay_plan_not_found");
  let stale = true;
  try { stale = !matchesPlan(plan, binding(database, scanId, executionId, scenarioId)); }
  catch { /* Historical plan remains readable without current E1. */ }
  return { plan, stale, runs: listScenarioReplayPlanRuns(database, plan.planId) };
}
export async function updateReplayPlan(database: DatabaseClient, scanId: string, executionId: string,
  scenarioId: string, planId: string, revisionId: string, raw: unknown) {
  const view = replayPlanView(database, scanId, executionId, scenarioId, planId);
  if (view.stale || view.plan.id !== revisionId) throw Error("replay_plan_stale");
  await liveSession(binding(database, scanId, executionId, scenarioId));
  return updateScenarioReplayDraft(database, view.plan, raw);
}
export async function reviewReplayPlan(database: DatabaseClient, scanId: string, executionId: string,
  scenarioId: string, planId: string, revisionId: string, decision: "reviewed" | "rejected") {
  const view = replayPlanView(database, scanId, executionId, scenarioId, planId);
  if (view.plan.id !== revisionId || decision === "reviewed" && view.stale) throw Error("replay_plan_stale");
  if (decision === "reviewed") await liveSession(binding(database, scanId, executionId, scenarioId));
  return decideScenarioReplayPlan(database, view.plan, decision);
}
export function reviseReplayPlan(database: DatabaseClient, scanId: string, executionId: string,
  scenarioId: string, planId: string, revisionId: string) {
  const view = replayPlanView(database, scanId, executionId, scenarioId, planId);
  if (view.stale || view.plan.id !== revisionId) throw Error("replay_plan_stale");
  return reviseScenarioReplayPlan(database, view.plan);
}

async function runLoop(database: DatabaseClient, plan: ScenarioReplayPlan, runId: string,
  bound: ReturnType<typeof binding>, release: () => void) {
  const service = createImpactForkService(), handle = resolveImpactHandle(plan.sessionId);
  let status: "completed" | "failed" | "cancelled" = "failed", stopReason: string | null = null;
  const deadline = Date.now() + TOTAL_RUN_MS;
  let timedOut = false;
  let forcedStop: Promise<unknown> | null = null;
  const timeout = setTimeout(() => {
    timedOut = true;
    // Stop the only mutable endpoint if a bounded stage is still in progress.
    if (handle) forcedStop = service.stopForkSession(handle).catch(() => undefined);
  }, TOTAL_RUN_MS);
  let lastPost: string | null = null;
  try {
    const originalState = readImpactExecutionState(database, plan.executionId);
    const referenceStart = observationFrame(originalState?.pre ?? null);
    const referenceTx = bound.view.flow.transactions.map((item) => item.status);
    if (!handle || referenceStart === null) throw Error("replay_reference_state_unavailable");
    updateScenarioReplayRun(database, runId, "running");
    await service.resetForkSession(handle);
    for (let index = 1; index <= plan.iterationCount; index++) {
      if (readScenarioReplayRun(database, runId)?.cancelRequested) { status = "cancelled"; stopReason = "cancel_requested"; break; }
      if (timedOut || Date.now() >= deadline) { stopReason = "replay_total_timeout"; break; }
      if (plan.mode === "independent-replay" && index > 1) await service.resetForkSession(handle);
      await liveSession(bound);
      const iteration = createScenarioReplayIteration(database, runId, index);
      let execution: Awaited<ReturnType<typeof executeManualPoC>> | null = null;
      let iterationStatus: ScenarioReplayIteration["status"] = "failed";
      let iterationReason: string | null = null, flowHash: string | null = null;
      try {
        execution = await executeManualPoC(plan.sessionId, { pocArtifactId: plan.artifactId }, {
          database, service, resolveHandle: resolveImpactHandle, replayLeaseId: runId,
          resetBefore: false, resetAfter: false, reviewedObservationPlan: bound.execution.observationPlan! });
        const state = readImpactExecutionState(database, execution.id);
        const preFrame = observationFrame(state?.pre ?? null), postFrame = observationFrame(state?.post ?? null);
        if (!preFrame || !postFrame) iterationReason = "replay_state_capture_unavailable";
        else if ((index === 1 || plan.mode === "independent-replay") && preFrame !== referenceStart)
          iterationReason = "replay_baseline_observation_changed";
        else if (plan.mode === "cumulative-replay" && index > 1 && preFrame !== lastPost)
          iterationReason = "replay_state_continuity_failed";
        lastPost = postFrame;
        if (execution.forgeVersion !== plan.forgeVersion || execution.forgeSha256 !== plan.forgeSha256)
          iterationReason = "replay_worker_identity_changed";
        let flow = null;
        try { flow = loadAssetFlow(database, plan.scanId, execution.id); }
        catch { iterationReason ??= "replay_accounting_unavailable"; }
        if (flow) {
          flowHash = flow.contentSha256;
          try { deriveReplayIterationAccounting(bound.view.flow, bound.view.scenario, flow); }
          catch { iterationReason ??= "replay_role_accounting_unavailable"; }
          const txStatus = flow.transactions.map((item) => item.status);
          if (JSON.stringify(txStatus) !== JSON.stringify(referenceTx))
            iterationReason ??= "replay_transaction_outcome_changed";
          iterationStatus = txStatus.some((item) => item === "reverted") ? "reverted" :
            execution.status === "completed" ? "completed" : "failed";
          if (iterationStatus === "failed") iterationReason ??= execution.errorCode ?? "replay_execution_failed";
        } else {
          iterationStatus = execution.status === "completed" ? "completed" : "failed";
          iterationReason ??= "replay_accounting_unavailable";
        }
      } catch { iterationReason = "replay_execution_failed"; }
      if (timedOut) { iterationStatus = "failed"; iterationReason = "replay_total_timeout"; }
      const state = execution ? readImpactExecutionState(database, execution.id) : null;
      finishScenarioReplayIteration(database, iteration.id, iterationStatus, {
        executionId: execution?.id ?? null, preSnapshotId: state?.pre?.id ?? null,
        postSnapshotId: state?.post?.id ?? null, assetFlowContentSha256: flowHash, stopReason: iterationReason });
      if (timedOut) { stopReason = "replay_total_timeout"; break; }
      if (iterationReason) { stopReason = iterationReason; break; }
      if (iterationStatus === "failed") { stopReason = "replay_execution_failed"; break; }
      if (index === plan.iterationCount) status = "completed";
    }
  } catch { stopReason ??= timedOut ? "replay_total_timeout" : "replay_controller_failure"; }
  finally {
    clearTimeout(timeout);
    if (forcedStop) await forcedStop;
    try { if (!handle) throw Error("replay_handle_missing"); await service.resetForkSession(handle); }
    catch { status = "failed"; stopReason = timedOut ? "replay_total_timeout" : "replay_final_reset_failed";
      if (handle) await service.stopForkSession(handle).catch(() => undefined); }
    try { updateScenarioReplayRun(database, runId, status, stopReason); }
    finally { release(); }
  }
}

export async function startReplayRun(database: DatabaseClient, scanId: string, executionId: string,
  scenarioId: string, planId: string, revisionId: string) {
  const view = replayPlanView(database, scanId, executionId, scenarioId, planId);
  if (view.stale || view.plan.id !== revisionId || view.plan.status !== "reviewed") throw Error("replay_plan_not_reviewed");
  const bound = binding(database, scanId, executionId, scenarioId);
  await liveSession(bound);
  const release = reserveImpactReplayController(view.plan.id);
  try {
    const run = createScenarioReplayRun(database, view.plan);
    // Transfer the same lease without opening an execution gap.
    const releaseRun = transferImpactReplayController(view.plan.id, run.id);
    void runLoop(database, view.plan, run.id, bound, releaseRun).catch(() => {
      releaseRun();
      try { updateScenarioReplayRun(database, run.id, "failed", "replay_controller_failure"); }
      catch { /* persisted failure handling is retried by restart recovery */ }
    });
    return run;
  } catch (error) { release(); throw error; }
}
export function cancelReplayRun(database: DatabaseClient, scanId: string, executionId: string,
  scenarioId: string, planId: string, runId: string) {
  const view = replayPlanView(database, scanId, executionId, scenarioId, planId);
  const run = readScenarioReplayRun(database, runId);
  const runPlan = run && readScenarioReplayPlan(database, run.planRevisionId);
  if (!run || !runPlan || runPlan.planId !== view.plan.planId) throw Error("replay_run_not_found");
  return requestScenarioReplayCancel(database, runId);
}
export function readReplayResult(database: DatabaseClient, scanId: string, executionId: string,
  scenarioId: string, planId: string, runId: string): { run: ReturnType<typeof readScenarioReplayRun>;
    result: ScenarioReplayResult | null } {
  const view = replayPlanView(database, scanId, executionId, scenarioId, planId);
  const run = readScenarioReplayRun(database, runId);
  const runPlan = run && readScenarioReplayPlan(database, run.planRevisionId);
  if (!run || !runPlan || runPlan.planId !== view.plan.planId || runPlan.scanId !== scanId ||
    runPlan.executionId !== executionId || runPlan.scenarioId !== scenarioId) throw Error("replay_run_not_found");
  const sourceScenario = readImpactScenarioRevision(database, runPlan.scenarioRevisionId);
  const originalFlow = loadAssetFlow(database, scanId, executionId);
  if (!sourceScenario || sourceScenario.status !== "reviewed" || !originalFlow ||
    sourceScenario.assetFlowContentSha256 !== runPlan.assetFlowContentSha256 ||
    originalFlow.contentSha256 !== runPlan.assetFlowContentSha256 ||
    sourceScenario.contentSha256 !== runPlan.scenarioContentSha256) return { run, result: null };
  const reference = deriveScenarioImpact(originalFlow, sourceScenario);
  const iterations = readScenarioReplayIterations(database, run.id).map((iteration) => {
    let accounting = null, assetFlowStatus = null;
    if (iteration.executionId && iteration.assetFlowContentSha256) {
      const flow = loadAssetFlow(database, scanId, iteration.executionId);
      if (flow?.contentSha256 !== iteration.assetFlowContentSha256) throw Error("replay_iteration_evidence_changed");
      if (flow) { assetFlowStatus = flow.status;
        accounting = deriveReplayIterationAccounting(originalFlow, sourceScenario, flow); }
    }
    return { iteration, accounting, assetFlowStatus };
  });
  return { run, result: deriveScenarioReplayResult(runPlan, run, reference, iterations) };
}
