import { randomUUID } from "node:crypto";
import { IMPACT_SCENARIO_SCHEMA, scenarioAssignmentInputSchema, scenarioContentHash, scenarioDraftInputSchema,
  validateScenarioAssignments, type AssetFlow, type ImpactScenario, type ScenarioAssignment } from "@contracthunter/core";
import type { DatabaseClient } from "./index";

type Subject = ImpactScenario["subject"];
function rowToScenario(row: Record<string, unknown>): ImpactScenario {
  if (row.schema !== IMPACT_SCENARIO_SCHEMA) throw Error("impact_scenario_schema_invalid");
  const scenario: ImpactScenario = { schema: IMPACT_SCENARIO_SCHEMA, id: String(row.id),
    scenarioId: String(row.scenario_id), revision: Number(row.revision), revisionOf: row.revision_of as string | null,
    scanId: String(row.scan_id), executionId: String(row.execution_id),
    subject: { type: row.subject_type as Subject["type"], id: String(row.subject_id) },
    assetFlowContentSha256: String(row.asset_flow_content_sha256),
    assetAccountingRulesetVersion: String(row.accounting_ruleset_version),
    status: row.status as ImpactScenario["status"],
    assignments: scenarioAssignmentInputSchema.array().max(512).parse(JSON.parse(String(row.assignments_json))),
    note: String(row.note),
    createdAt: Number(row.created_at), reviewedAt: row.reviewed_at as number | null,
    rejectedAt: row.rejected_at as number | null, contentSha256: String(row.content_sha256) };
  if (scenario.contentSha256 !== scenarioContentHash(scenario)) throw Error("impact_scenario_content_invalid");
  return scenario;
}
function insert(database: DatabaseClient, item: ImpactScenario): ImpactScenario {
  database.sqlite.prepare(`INSERT INTO impact_scenario_revisions
    (id,scenario_id,revision,revision_of,scan_id,execution_id,subject_type,subject_id,
     asset_flow_content_sha256,accounting_ruleset_version,schema,status,assignments_json,note,
     content_sha256,created_at,reviewed_at,rejected_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
    item.id, item.scenarioId, item.revision, item.revisionOf, item.scanId, item.executionId,
    item.subject.type, item.subject.id, item.assetFlowContentSha256, item.assetAccountingRulesetVersion,
    item.schema, item.status, JSON.stringify(item.assignments), item.note, item.contentSha256,
    item.createdAt, item.reviewedAt, item.rejectedAt);
  return item;
}
function draft(flow: AssetFlow, subject: Subject, scenarioId: string, revision: number,
  revisionOf: string | null, assignments: readonly ScenarioAssignment[], note: string): ImpactScenario {
  const id = randomUUID(), createdAt = Date.now(), sorted = validateScenarioAssignments(flow, assignments);
  const content = { scenarioId, revision, revisionOf, scanId: flow.scanId, executionId: flow.executionId,
    subject, assetFlowContentSha256: flow.contentSha256,
    assetAccountingRulesetVersion: flow.rulesetVersion, assignments: sorted, note };
  return { schema: IMPACT_SCENARIO_SCHEMA, id, ...content, status: "draft", createdAt,
    reviewedAt: null, rejectedAt: null, contentSha256: scenarioContentHash(content) };
}
export function createImpactScenarioDraft(database: DatabaseClient, flow: AssetFlow, subject: Subject,
  raw: unknown): ImpactScenario {
  if (!flow.capabilities.assetAccountingAvailable || flow.status === "unavailable")
    throw Error("impact_scenario_asset_accounting_unavailable");
  const input = scenarioDraftInputSchema.parse(raw);
  const id = randomUUID();
  return insert(database, draft(flow, subject, id, 1, null, input.assignments, input.note));
}
export function readImpactScenarioRevision(database: DatabaseClient, id: string): ImpactScenario | null {
  const row = database.sqlite.prepare("SELECT * FROM impact_scenario_revisions WHERE id=?").get(id) as Record<string, unknown> | undefined;
  return row ? rowToScenario(row) : null;
}
export function readCurrentImpactScenario(database: DatabaseClient, scenarioId: string): ImpactScenario | null {
  const row = database.sqlite.prepare(`SELECT * FROM impact_scenario_revisions WHERE scenario_id=?
    ORDER BY revision DESC LIMIT 1`).get(scenarioId) as Record<string, unknown> | undefined;
  return row ? rowToScenario(row) : null;
}
export function listImpactScenarios(database: DatabaseClient, scanId: string, executionId: string): ImpactScenario[] {
  const rows = database.sqlite.prepare(`SELECT r.* FROM impact_scenario_revisions r
    WHERE r.scan_id=? AND r.execution_id=? AND r.revision=(SELECT MAX(x.revision)
      FROM impact_scenario_revisions x WHERE x.scenario_id=r.scenario_id)
    ORDER BY r.created_at DESC,r.id DESC LIMIT 32`).all(scanId, executionId) as Record<string, unknown>[];
  return rows.map(rowToScenario);
}
export function listImpactScenarioRevisions(database: DatabaseClient, scanId: string, executionId: string,
  scenarioId: string): ImpactScenario[] {
  const rows = database.sqlite.prepare(`SELECT * FROM impact_scenario_revisions
    WHERE scan_id=? AND execution_id=? AND scenario_id=? ORDER BY revision DESC LIMIT 256`)
    .all(scanId, executionId, scenarioId) as Record<string, unknown>[];
  return rows.map(rowToScenario);
}
export function updateImpactScenarioDraft(database: DatabaseClient, flow: AssetFlow, revisionId: string,
  raw: unknown): ImpactScenario {
  const current = readImpactScenarioRevision(database, revisionId);
  if (!current || current.status !== "draft" || current.scanId !== flow.scanId ||
    current.executionId !== flow.executionId) throw Error("impact_scenario_draft_unavailable");
  if (current.assetFlowContentSha256 !== flow.contentSha256) throw Error("scenario_asset_flow_stale");
  const input = scenarioDraftInputSchema.parse(raw), assignments = validateScenarioAssignments(flow, input.assignments);
  const contentSha256 = scenarioContentHash({ ...current, assignments, note: input.note });
  if (!database.sqlite.prepare(`UPDATE impact_scenario_revisions SET assignments_json=?,note=?,content_sha256=?
    WHERE id=? AND status='draft'`).run(JSON.stringify(assignments), input.note, contentSha256, revisionId).changes)
    throw Error("impact_scenario_draft_unavailable");
  return readImpactScenarioRevision(database, revisionId)!;
}
export function reviewImpactScenarioDraft(database: DatabaseClient, flow: AssetFlow, revisionId: string): ImpactScenario {
  const current = readImpactScenarioRevision(database, revisionId);
  if (!current || current.status !== "draft" || current.scanId !== flow.scanId ||
    current.executionId !== flow.executionId) throw Error("impact_scenario_draft_unavailable");
  if (current.assetFlowContentSha256 !== flow.contentSha256 ||
    current.assetAccountingRulesetVersion !== flow.rulesetVersion) throw Error("scenario_asset_flow_stale");
  const assignments = validateScenarioAssignments(flow, current.assignments);
  if (!assignments.some((item) => item.role === "scenario-subject")) throw Error("scenario_subject_required");
  if (!database.sqlite.prepare(`UPDATE impact_scenario_revisions SET status='reviewed',reviewed_at=?
    WHERE id=? AND status='draft'`).run(Date.now(), revisionId).changes) throw Error("impact_scenario_draft_unavailable");
  return readImpactScenarioRevision(database, revisionId)!;
}
export function rejectImpactScenario(database: DatabaseClient, current: ImpactScenario): ImpactScenario {
  if (current.status === "draft") {
    if (!database.sqlite.prepare(`UPDATE impact_scenario_revisions SET status='rejected',rejected_at=?
      WHERE id=? AND status='draft'`).run(Date.now(), current.id).changes) throw Error("impact_scenario_draft_unavailable");
    return readImpactScenarioRevision(database, current.id)!;
  }
  if (current.status !== "reviewed") throw Error("impact_scenario_already_rejected");
  const next = { ...current, id: randomUUID(), revision: current.revision + 1, revisionOf: current.id,
    status: "rejected" as const, createdAt: Date.now(), reviewedAt: null, rejectedAt: Date.now(),
    contentSha256: scenarioContentHash({ ...current, revision: current.revision + 1, revisionOf: current.id }) };
  return insert(database, next);
}
export function reviseImpactScenario(database: DatabaseClient, flow: AssetFlow, current: ImpactScenario): ImpactScenario {
  if (current.status === "draft" || current.scanId !== flow.scanId || current.executionId !== flow.executionId)
    throw Error("impact_scenario_revision_invalid");
  const sameEvidence = current.assetFlowContentSha256 === flow.contentSha256 &&
    current.assetAccountingRulesetVersion === flow.rulesetVersion;
  return insert(database, draft(flow, current.subject, current.scenarioId, current.revision + 1,
    current.id, sameEvidence ? current.assignments : [], sameEvidence ? current.note : ""));
}
