import { z } from "zod";
import { canonicalImpactHash } from "./impact-state";
import { deriveScenarioImpact, scenarioContentHash, scenarioParticipantId,
  type ImpactScenario, type ScenarioImpact, type ScenarioRole } from "./impact-scenario";
import type { AssetFlow } from "./asset-flow";

export const SCENARIO_REPLAY_PLAN_SCHEMA = "contracthunter-scenario-replay-plan-v1" as const;
export const SCENARIO_REPLAY_RESULT_SCHEMA = "contracthunter-scenario-replay-result-v1" as const;
export const SCENARIO_REPLAY_RULESET = "contracthunter-scenario-replay-ruleset-v1" as const;
export const REPLAY_MIN_ITERATIONS = 2;
export const REPLAY_MAX_ITERATIONS = 5;
export const replayPlanInputSchema = z.object({ mode: z.enum(["independent-replay", "cumulative-replay"]),
  iterationCount: z.number().int().min(REPLAY_MIN_ITERATIONS).max(REPLAY_MAX_ITERATIONS) }).strict();
export type ReplayMode = z.infer<typeof replayPlanInputSchema>["mode"];
export type ReplayPlanStatus = "draft" | "reviewed" | "rejected";
export type ScenarioReplayPlan = Readonly<{ schema: typeof SCENARIO_REPLAY_PLAN_SCHEMA;
  id: string; planId: string; revision: number; revisionOf: string | null; scanId: string;
  scenarioId: string; scenarioRevisionId: string; executionId: string; sessionId: string;
  artifactId: string; sourceSha256: string; assetFlowContentSha256: string;
  scenarioContentSha256: string; observationPlanSha256: string; forgeVersion: string; forgeSha256: string;
  chainId: number; forkBlock: number; forkBlockHash: string; targetCodeHashes: Record<string, string>;
  runtimeTokenSha256: string; mode: ReplayMode; iterationCount: number; status: ReplayPlanStatus;
  createdAt: number; reviewedAt: number | null; rejectedAt: number | null; contentSha256: string }>;
export type ReplayRunStatus = "queued" | "running" | "completed" | "failed" | "cancelled";
export type ReplayIterationStatus = "queued" | "running" | "completed" | "reverted" | "failed" | "cancelled";
export type ScenarioReplayRun = Readonly<{ id: string; planRevisionId: string; status: ReplayRunStatus;
  createdAt: number; startedAt: number | null; completedAt: number | null; stopReason: string | null;
  cancelRequested: boolean }>;
export type ScenarioReplayIteration = Readonly<{ id: string; runId: string; index: number;
  status: ReplayIterationStatus; executionId: string | null; startedAt: number;
  completedAt: number | null; stopReason: string | null; preSnapshotId: string | null;
  postSnapshotId: string | null; assetFlowContentSha256: string | null }>;
export type ReplayAccounting = Readonly<{ iteration: ScenarioReplayIteration; accounting: ScenarioImpact | null;
  matchedReference: boolean | null; variation: string[]; assetFlowStatus: AssetFlow["status"] | null }>;
export type ReplayCumulativePosition = Readonly<{ assetId: string; role: ScenarioRole;
  incoming: string; outgoing: string; netObservedMovement: string; iterationIndexes: number[] }>;
export type ReplayCumulativeDirect = Readonly<{ assetId: string;
  direction: "protocol-to-subject" | "subject-to-protocol"; amount: string; iterationIndexes: number[] }>;
export type ScenarioReplayResult = Readonly<{ schema: typeof SCENARIO_REPLAY_RESULT_SCHEMA;
  rulesetVersion: typeof SCENARIO_REPLAY_RULESET; planRevisionId: string; runId: string;
  mode: ReplayMode; requestedIterations: number; completedIterations: number;
  matchingIterations: number; repeatability: "reproduced-consistently" | "reproduced-with-variation" |
    "stopped-after-state-change" | "not-reproduced" | "partial" | "unavailable";
  stopReason: string | null; iterations: ReplayAccounting[];
  cumulativePositions: ReplayCumulativePosition[]; cumulativeDirect: ReplayCumulativeDirect[];
  warnings: string[]; contentSha256: string }>;

export function replayPlanContentHash(value: Pick<ScenarioReplayPlan, "planId" | "revision" | "revisionOf" |
  "scanId" | "scenarioId" | "scenarioRevisionId" | "executionId" | "sessionId" | "artifactId" |
  "sourceSha256" | "assetFlowContentSha256" | "scenarioContentSha256" | "observationPlanSha256" |
  "forgeVersion" | "forgeSha256" |
  "chainId" | "forkBlock" | "forkBlockHash" | "targetCodeHashes" | "runtimeTokenSha256" | "mode" |
  "iterationCount">): string {
  return canonicalImpactHash(SCENARIO_REPLAY_PLAN_SCHEMA, [SCENARIO_REPLAY_RULESET, value.planId, value.revision,
    value.revisionOf, value.scanId, value.scenarioId, value.scenarioRevisionId, value.executionId,
    value.sessionId, value.artifactId, value.sourceSha256, value.assetFlowContentSha256,
    value.scenarioContentSha256, value.observationPlanSha256, value.forgeVersion, value.forgeSha256,
    value.chainId, value.forkBlock,
    value.forkBlockHash, Object.entries(value.targetCodeHashes).sort(([a], [b]) => a.localeCompare(b)),
    value.runtimeTokenSha256, value.mode, value.iterationCount]);
}

/** Apply only the exact addresses selected by the F1 review to a new, local replay E1 result. */
export function deriveReplayIterationAccounting(original: AssetFlow, scenario: ImpactScenario,
  replay: AssetFlow): ScenarioImpact {
  if (scenario.status !== "reviewed" || scenario.executionId !== original.executionId ||
    scenario.scanId !== original.scanId || scenario.assetFlowContentSha256 !== original.contentSha256 ||
    replay.scanId !== original.scanId) throw Error("replay_scenario_binding_invalid");
  const originalParticipants = new Map(original.participants.map((item) =>
    [scenarioParticipantId(original, item.address), item.address]));
  const replayAddresses = new Set(replay.participants.map((item) => item.address));
  const assignments = scenario.assignments.flatMap((item) => {
    const address = originalParticipants.get(item.participantId);
    if (!address) throw Error("replay_role_participant_invalid");
    return replayAddresses.has(address) ? [{ participantId: scenarioParticipantId(replay, address), role: item.role }] : [];
  });
  const projection = { ...scenario, executionId: replay.executionId, assetFlowContentSha256: replay.contentSha256,
    assetAccountingRulesetVersion: replay.rulesetVersion, assignments };
  return deriveScenarioImpact(replay, { ...projection, contentSha256: scenarioContentHash(projection) });
}

/** Transaction hashes and local block numbers are intentionally excluded from semantic comparison. */
export function replaySemanticFrame(accounting: ScenarioImpact): unknown {
  return [accounting.status,
    accounting.rolePositions.filter((item) => item.transactionOrdinal === null).map((item) =>
      [item.assetId, item.role, item.incoming, item.outgoing, item.netObservedMovement]),
    accounting.directRoleTransfers.filter((item) => item.transactionOrdinal === null).map((item) =>
      [item.assetId, item.direction, item.amount]),
    accounting.reconciliation.map((item) => [item.assetId, item.participant, item.kind,
      item.status, item.observedDelta, item.difference])];
}
function replayVariation(reference: ScenarioImpact, observed: ScenarioImpact): string[] {
  const differences: string[] = [];
  const positions = (impact: ScenarioImpact) => new Map(impact.rolePositions
    .filter((item) => item.transactionOrdinal === null)
    .map((item) => [`${item.assetId}|${item.role}`, item]));
  const expected = positions(reference), actual = positions(observed);
  for (const key of [...new Set([...expected.keys(), ...actual.keys()])].sort()) {
    const before = expected.get(key), after = actual.get(key);
    if (before?.incoming !== after?.incoming || before?.outgoing !== after?.outgoing ||
      before?.netObservedMovement !== after?.netObservedMovement)
      differences.push(`${key}: incoming ${before?.incoming ?? "UNAVAILABLE"} → ${after?.incoming ?? "UNAVAILABLE"}, ` +
        `outgoing ${before?.outgoing ?? "UNAVAILABLE"} → ${after?.outgoing ?? "UNAVAILABLE"}, ` +
        `net ${before?.netObservedMovement ?? "UNAVAILABLE"} → ${after?.netObservedMovement ?? "UNAVAILABLE"}`);
  }
  const transfers = (impact: ScenarioImpact) => new Map(impact.directRoleTransfers
    .filter((item) => item.transactionOrdinal === null)
    .map((item) => [`${item.assetId}|${item.direction}`, item.amount]));
  const expectedTransfers = transfers(reference), actualTransfers = transfers(observed);
  for (const key of [...new Set([...expectedTransfers.keys(), ...actualTransfers.keys()])].sort())
    if (expectedTransfers.get(key) !== actualTransfers.get(key))
      differences.push(`${key}: direct ${expectedTransfers.get(key) ?? "UNAVAILABLE"} → ${actualTransfers.get(key) ?? "UNAVAILABLE"}`);
  const reconciliation = (impact: ScenarioImpact) => new Map(impact.reconciliation.map((item) =>
    [`${item.assetId}|${item.participant}|${item.kind}`, `${item.status}:${item.observedDelta ?? "UNAVAILABLE"}:${item.difference ?? "UNAVAILABLE"}`]));
  const expectedRecon = reconciliation(reference), actualRecon = reconciliation(observed);
  for (const key of [...new Set([...expectedRecon.keys(), ...actualRecon.keys()])].sort())
    if (expectedRecon.get(key) !== actualRecon.get(key))
      differences.push(`${key}: reconciliation ${expectedRecon.get(key) ?? "UNAVAILABLE"} → ${actualRecon.get(key) ?? "UNAVAILABLE"}`);
  if (reference.status !== observed.status) differences.push(`evidence status ${reference.status} → ${observed.status}`);
  return differences;
}

export function deriveScenarioReplayResult(plan: ScenarioReplayPlan, run: ScenarioReplayRun,
  reference: ScenarioImpact, values: Array<{ iteration: ScenarioReplayIteration;
    accounting: ScenarioImpact | null; assetFlowStatus: AssetFlow["status"] | null }>): ScenarioReplayResult {
  if (plan.status !== "reviewed" || run.planRevisionId !== plan.id ||
    reference.revisionId !== plan.scenarioRevisionId || reference.assetFlowContentSha256 !== plan.assetFlowContentSha256 ||
    values.length > plan.iterationCount) throw Error("replay_result_binding_invalid");
  const referenceFrame = JSON.stringify(replaySemanticFrame(reference));
  const iterations = values.map(({ iteration, accounting, assetFlowStatus }, index): ReplayAccounting => {
    if (iteration.runId !== run.id || iteration.index !== index + 1 ||
      (accounting && (accounting.executionId !== iteration.executionId ||
        accounting.assetFlowContentSha256 !== iteration.assetFlowContentSha256))) throw Error("replay_iteration_binding_invalid");
    const frame = accounting ? JSON.stringify(replaySemanticFrame(accounting)) : null;
    return { iteration, accounting, assetFlowStatus,
      matchedReference: frame === null ? null : frame === referenceFrame,
      variation: frame === null || frame === referenceFrame ? [] : replayVariation(reference, accounting!) };
  });
  const completed = iterations.filter((item) =>
    (item.iteration.status === "completed" || item.iteration.status === "reverted" && item.iteration.stopReason === null) &&
    item.accounting);
  const matchingIterations = completed.filter((item) => item.matchedReference).length;
  const partial = iterations.some((item) =>
    (item.iteration.status === "completed" || item.iteration.status === "reverted") && !item.accounting) ||
    completed.some((item) => item.accounting?.status !== "complete-within-evidence");
  const positions = new Map<string, { assetId: string; role: ScenarioRole; incoming: bigint;
    outgoing: bigint; indexes: number[] }>();
  const direct = new Map<string, { assetId: string; direction: ReplayCumulativeDirect["direction"];
    amount: bigint; indexes: number[] }>();
  if (plan.mode === "cumulative-replay") for (const item of completed) {
    for (const row of item.accounting!.rolePositions.filter((value) =>
      value.transactionOrdinal === null && !value.assetId.startsWith("erc721:"))) {
      const key = `${row.assetId}|${row.role}`;
      const current = positions.get(key) ?? { assetId: row.assetId, role: row.role, incoming: 0n, outgoing: 0n, indexes: [] };
      current.incoming += BigInt(row.incoming); current.outgoing += BigInt(row.outgoing);
      current.indexes.push(item.iteration.index); positions.set(key, current);
    }
    for (const row of item.accounting!.directRoleTransfers.filter((value) =>
      value.transactionOrdinal === null && !value.assetId.startsWith("erc721:"))) {
      const key = `${row.assetId}|${row.direction}`;
      const current = direct.get(key) ?? { assetId: row.assetId, direction: row.direction, amount: 0n, indexes: [] };
      current.amount += BigInt(row.amount); current.indexes.push(item.iteration.index); direct.set(key, current);
    }
  }
  const cumulativePositions = [...positions.values()].sort((a, b) => a.assetId.localeCompare(b.assetId) ||
    a.role.localeCompare(b.role)).map((item) => ({ assetId: item.assetId, role: item.role,
    incoming: item.incoming.toString(), outgoing: item.outgoing.toString(),
    netObservedMovement: (item.incoming - item.outgoing).toString(), iterationIndexes: item.indexes }));
  const cumulativeDirect = [...direct.values()].sort((a, b) => a.assetId.localeCompare(b.assetId) ||
    a.direction.localeCompare(b.direction)).map((item) => ({ assetId: item.assetId, direction: item.direction,
    amount: item.amount.toString(), iterationIndexes: item.indexes }));
  const referenceHasMovement = reference.rolePositions.some((item) => item.transactionOrdinal === null &&
    (item.incoming !== "0" || item.outgoing !== "0"));
  const observedHasMovement = completed.some((item) => item.accounting!.rolePositions.some((row) =>
    row.transactionOrdinal === null && (row.incoming !== "0" || row.outgoing !== "0")));
  const repeatability: ScenarioReplayResult["repeatability"] = partial ? "partial" : completed.length === 0 ? "unavailable" :
    run.status !== "completed" ? plan.mode === "cumulative-replay" &&
      ["replay_transaction_outcome_changed", "replay_state_continuity_failed", "replay_baseline_observation_changed"]
        .includes(run.stopReason ?? "") ? "stopped-after-state-change" : "partial" :
    completed.length !== plan.iterationCount ? "partial" : matchingIterations === plan.iterationCount ?
      "reproduced-consistently" : referenceHasMovement && !observedHasMovement ?
        "not-reproduced" : "reproduced-with-variation";
  const warnings = [...new Set(completed.flatMap((item) => item.accounting?.warnings ?? []))].sort();
  const content = { schema: SCENARIO_REPLAY_RESULT_SCHEMA, rulesetVersion: SCENARIO_REPLAY_RULESET,
    planRevisionId: plan.id, runId: run.id, mode: plan.mode, requestedIterations: plan.iterationCount,
    completedIterations: completed.length, matchingIterations, repeatability, stopReason: run.stopReason,
    iterations, cumulativePositions, cumulativeDirect, warnings };
  return { ...content, contentSha256: canonicalImpactHash(SCENARIO_REPLAY_RESULT_SCHEMA,
    [SCENARIO_REPLAY_RULESET, plan.contentSha256, reference.contentSha256, content]) };
}
