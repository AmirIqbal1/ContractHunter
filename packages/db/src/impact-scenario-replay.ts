import { randomUUID } from "node:crypto";
import { replayPlanContentHash, replayPlanInputSchema, SCENARIO_REPLAY_PLAN_SCHEMA,
  type ScenarioReplayPlan, type ScenarioReplayRun, type ScenarioReplayIteration,
  type ReplayIterationStatus, type ReplayRunStatus } from "@contracthunter/core";
import type { DatabaseClient } from "./index";

type PlanBase = Pick<ScenarioReplayPlan, "scanId" | "scenarioId" | "scenarioRevisionId" | "executionId" |
  "sessionId" | "artifactId" | "sourceSha256" | "assetFlowContentSha256" | "scenarioContentSha256" |
  "observationPlanSha256" | "forgeVersion" | "forgeSha256" | "chainId" | "forkBlock" | "forkBlockHash" | "targetCodeHashes" |
  "runtimeTokenSha256">;
function parsePlan(row: Record<string, unknown>): ScenarioReplayPlan {
  const item = JSON.parse(String(row.plan_json)) as ScenarioReplayPlan;
  if (item.schema !== SCENARIO_REPLAY_PLAN_SCHEMA || item.id !== row.id || item.planId !== row.plan_id ||
    item.revision !== row.revision || item.status !== row.status || item.scanId !== row.scan_id ||
    item.scenarioRevisionId !== row.scenario_revision_id || item.contentSha256 !== row.content_sha256 ||
    item.contentSha256 !== replayPlanContentHash(item) ||
    !replayPlanInputSchema.safeParse({ mode: item.mode, iterationCount: item.iterationCount }).success)
    throw Error("scenario_replay_plan_integrity_invalid");
  return item;
}
function persistPlan(database: DatabaseClient, item: ScenarioReplayPlan): ScenarioReplayPlan {
  database.sqlite.prepare(`INSERT INTO impact_scenario_replay_plans
    (id,plan_id,revision,revision_of,scan_id,scenario_revision_id,status,plan_json,content_sha256,
     created_at,reviewed_at,rejected_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`).run(item.id, item.planId,
    item.revision, item.revisionOf, item.scanId, item.scenarioRevisionId, item.status,
    JSON.stringify(item), item.contentSha256, item.createdAt, item.reviewedAt, item.rejectedAt);
  return item;
}
export function createScenarioReplayPlan(database: DatabaseClient, base: PlanBase, raw: unknown): ScenarioReplayPlan {
  const input = replayPlanInputSchema.parse(raw), id = randomUUID(), createdAt = Date.now();
  const content = { ...base, planId: id, revision: 1, revisionOf: null, ...input };
  return persistPlan(database, { schema: SCENARIO_REPLAY_PLAN_SCHEMA, id, ...content, status: "draft",
    createdAt, reviewedAt: null, rejectedAt: null, contentSha256: replayPlanContentHash(content) });
}
export function readScenarioReplayPlan(database: DatabaseClient, id: string): ScenarioReplayPlan | null {
  const row = database.sqlite.prepare("SELECT * FROM impact_scenario_replay_plans WHERE id=?")
    .get(id) as Record<string, unknown> | undefined;
  return row ? parsePlan(row) : null;
}
export function readCurrentScenarioReplayPlan(database: DatabaseClient, planId: string): ScenarioReplayPlan | null {
  const row = database.sqlite.prepare(`SELECT * FROM impact_scenario_replay_plans WHERE plan_id=?
    ORDER BY revision DESC LIMIT 1`).get(planId) as Record<string, unknown> | undefined;
  return row ? parsePlan(row) : null;
}
export function listScenarioReplayPlans(database: DatabaseClient, scanId: string, scenarioRevisionId: string): ScenarioReplayPlan[] {
  const rows = database.sqlite.prepare(`SELECT p.* FROM impact_scenario_replay_plans p
    WHERE p.scan_id=? AND p.scenario_revision_id=? AND p.revision=(SELECT MAX(r.revision)
      FROM impact_scenario_replay_plans r WHERE r.plan_id=p.plan_id)
    ORDER BY p.created_at DESC LIMIT 32`).all(scanId, scenarioRevisionId) as Record<string, unknown>[];
  return rows.map(parsePlan);
}
export function updateScenarioReplayDraft(database: DatabaseClient, current: ScenarioReplayPlan, raw: unknown): ScenarioReplayPlan {
  if (current.status !== "draft" || readCurrentScenarioReplayPlan(database, current.planId)?.id !== current.id)
    throw Error("scenario_replay_plan_not_current_draft");
  const input = replayPlanInputSchema.parse(raw);
  const next = { ...current, ...input, contentSha256: replayPlanContentHash({ ...current, ...input }) };
  if (!database.sqlite.prepare(`UPDATE impact_scenario_replay_plans SET plan_json=?,content_sha256=?
    WHERE id=? AND status='draft'`).run(JSON.stringify(next), next.contentSha256, current.id).changes)
    throw Error("scenario_replay_plan_not_current_draft");
  return next;
}
export function decideScenarioReplayPlan(database: DatabaseClient, current: ScenarioReplayPlan,
  decision: "reviewed" | "rejected"): ScenarioReplayPlan {
  if (current.status !== "draft" || readCurrentScenarioReplayPlan(database, current.planId)?.id !== current.id)
    throw Error("scenario_replay_plan_not_current_draft");
  const now = Date.now(), next: ScenarioReplayPlan = { ...current, status: decision,
    reviewedAt: decision === "reviewed" ? now : null, rejectedAt: decision === "rejected" ? now : null };
  if (!database.sqlite.prepare(`UPDATE impact_scenario_replay_plans SET status=?,plan_json=?,reviewed_at=?,rejected_at=?
    WHERE id=? AND status='draft'`).run(decision, JSON.stringify(next), next.reviewedAt, next.rejectedAt,
    current.id).changes) throw Error("scenario_replay_plan_not_current_draft");
  return next;
}
export function reviseScenarioReplayPlan(database: DatabaseClient, current: ScenarioReplayPlan): ScenarioReplayPlan {
  if (current.status === "draft" || readCurrentScenarioReplayPlan(database, current.planId)?.id !== current.id)
    throw Error("scenario_replay_plan_revision_invalid");
  const id = randomUUID(), content = { ...current, revision: current.revision + 1, revisionOf: current.id };
  return persistPlan(database, { ...content, id, status: "draft", createdAt: Date.now(),
    reviewedAt: null, rejectedAt: null, contentSha256: replayPlanContentHash(content) });
}
function parseRun(row: Record<string, unknown>): ScenarioReplayRun {
  return { id: String(row.id), planRevisionId: String(row.plan_revision_id), status: row.status as ReplayRunStatus,
    createdAt: Number(row.created_at), startedAt: row.started_at as number | null,
    completedAt: row.completed_at as number | null, stopReason: row.stop_reason as string | null,
    cancelRequested: Boolean(row.cancel_requested) };
}
export function createScenarioReplayRun(database: DatabaseClient, plan: ScenarioReplayPlan): ScenarioReplayRun {
  if (plan.status !== "reviewed" || readCurrentScenarioReplayPlan(database, plan.planId)?.id !== plan.id)
    throw Error("scenario_replay_plan_not_reviewed");
  const id = randomUUID();
  database.sqlite.transaction(() => {
    if (database.sqlite.prepare(`SELECT 1 FROM impact_poc_executions
      WHERE status IN ('created','queued','running') LIMIT 1`).get()) throw Error("impact_execution_busy");
    database.sqlite.prepare(`INSERT INTO impact_scenario_replay_runs
      (id,plan_revision_id,status,created_at) VALUES (?,?,'queued',?)`).run(id, plan.id, Date.now());
  })();
  return readScenarioReplayRun(database, id)!;
}
export function readScenarioReplayRun(database: DatabaseClient, id: string): ScenarioReplayRun | null {
  const row = database.sqlite.prepare("SELECT * FROM impact_scenario_replay_runs WHERE id=?")
    .get(id) as Record<string, unknown> | undefined;
  return row ? parseRun(row) : null;
}
export function listScenarioReplayRuns(database: DatabaseClient, planRevisionId: string): ScenarioReplayRun[] {
  return (database.sqlite.prepare(`SELECT * FROM impact_scenario_replay_runs WHERE plan_revision_id=?
    ORDER BY created_at DESC LIMIT 32`).all(planRevisionId) as Record<string, unknown>[]).map(parseRun);
}
export function listScenarioReplayPlanRuns(database: DatabaseClient, planId: string): ScenarioReplayRun[] {
  return (database.sqlite.prepare(`SELECT r.* FROM impact_scenario_replay_runs r
    JOIN impact_scenario_replay_plans p ON p.id=r.plan_revision_id WHERE p.plan_id=?
    ORDER BY r.created_at DESC LIMIT 32`).all(planId) as Record<string, unknown>[]).map(parseRun);
}
export function updateScenarioReplayRun(database: DatabaseClient, id: string, status: ReplayRunStatus,
  stopReason: string | null = null): ScenarioReplayRun {
  const now = Date.now();
  if (!database.sqlite.prepare(`UPDATE impact_scenario_replay_runs SET status=?,
    started_at=CASE WHEN ?='running' THEN COALESCE(started_at,?) ELSE started_at END,
    completed_at=CASE WHEN ? IN ('completed','failed','cancelled') THEN ? ELSE NULL END,
    stop_reason=? WHERE id=? AND status IN ('queued','running')`)
    .run(status, status, now, status, now, stopReason, id).changes) throw Error("scenario_replay_run_state_invalid");
  return readScenarioReplayRun(database, id)!;
}
export function requestScenarioReplayCancel(database: DatabaseClient, id: string): ScenarioReplayRun {
  if (!database.sqlite.prepare(`UPDATE impact_scenario_replay_runs SET cancel_requested=1
    WHERE id=? AND status IN ('queued','running')`).run(id).changes) throw Error("scenario_replay_run_not_active");
  return readScenarioReplayRun(database, id)!;
}
function parseIteration(row: Record<string, unknown>): ScenarioReplayIteration {
  return { id: String(row.id), runId: String(row.run_id), index: Number(row.iteration_index),
    status: row.status as ReplayIterationStatus, executionId: row.execution_id as string | null,
    startedAt: Number(row.started_at), completedAt: row.completed_at as number | null,
    stopReason: row.stop_reason as string | null, preSnapshotId: row.pre_snapshot_id as string | null,
    postSnapshotId: row.post_snapshot_id as string | null,
    assetFlowContentSha256: row.asset_flow_content_sha256 as string | null };
}
export function createScenarioReplayIteration(database: DatabaseClient, runId: string, index: number): ScenarioReplayIteration {
  const id = randomUUID();
  database.sqlite.prepare(`INSERT INTO impact_scenario_replay_iterations
    (id,run_id,iteration_index,status,started_at) VALUES (?,?,?,'running',?)`).run(id, runId, index, Date.now());
  return readScenarioReplayIterations(database, runId).find((item) => item.id === id)!;
}
export function finishScenarioReplayIteration(database: DatabaseClient, id: string, status: ReplayIterationStatus,
  values: { executionId: string | null; preSnapshotId: string | null; postSnapshotId: string | null;
    assetFlowContentSha256: string | null; stopReason: string | null }): void {
  if (!database.sqlite.prepare(`UPDATE impact_scenario_replay_iterations SET status=?,execution_id=?,
    pre_snapshot_id=?,post_snapshot_id=?,asset_flow_content_sha256=?,stop_reason=?,completed_at=?
    WHERE id=? AND status='running'`).run(status, values.executionId, values.preSnapshotId,
    values.postSnapshotId, values.assetFlowContentSha256, values.stopReason, Date.now(), id).changes)
    throw Error("scenario_replay_iteration_state_invalid");
}
export function readScenarioReplayIterations(database: DatabaseClient, runId: string): ScenarioReplayIteration[] {
  return (database.sqlite.prepare(`SELECT * FROM impact_scenario_replay_iterations WHERE run_id=?
    ORDER BY iteration_index LIMIT 5`).all(runId) as Record<string, unknown>[]).map(parseIteration);
}
