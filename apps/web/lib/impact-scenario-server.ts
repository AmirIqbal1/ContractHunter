import { deriveScenarioImpact, type ImpactScenario } from "@contracthunter/core";
import { createImpactScenarioDraft, listImpactScenarios, readCurrentImpactScenario,
  rejectImpactScenario, reviseImpactScenario, reviewImpactScenarioDraft, updateImpactScenarioDraft,
  type DatabaseClient } from "@contracthunter/db";
import { loadAssetFlow } from "./asset-flow-server";
import { loadImpactOverlay } from "./impact-overlay-server";

function evidence(database: DatabaseClient, scanId: string, executionId: string) {
  const flow = loadAssetFlow(database, scanId, executionId);
  if (!flow) return null;
  const overlay = loadImpactOverlay(database, scanId, executionId);
  if (!overlay || overlay.scanId !== flow.scanId || overlay.executionId !== flow.executionId)
    throw Error("impact_scenario_evidence_invalid");
  return { flow, subject: overlay.subject };
}
function current(database: DatabaseClient, scanId: string, executionId: string,
  scenarioId: string): ImpactScenario | null {
  const item = readCurrentImpactScenario(database, scenarioId);
  return item?.scanId === scanId && item.executionId === executionId ? item : null;
}
export function listScenarioViews(database: DatabaseClient, scanId: string, executionId: string) {
  const bound = evidence(database, scanId, executionId);
  return bound ? listImpactScenarios(database, scanId, executionId) : null;
}
export function createScenario(database: DatabaseClient, scanId: string, executionId: string, raw: unknown) {
  const bound = evidence(database, scanId, executionId);
  if (!bound) return null;
  return createImpactScenarioDraft(database, bound.flow, bound.subject, raw);
}
export function loadScenarioView(database: DatabaseClient, scanId: string, executionId: string, scenarioId: string) {
  const bound = evidence(database, scanId, executionId), scenario = current(database, scanId, executionId, scenarioId);
  if (!bound || !scenario || scenario.subject.type !== bound.subject.type ||
    scenario.subject.id !== bound.subject.id) return null;
  const stale = scenario.assetFlowContentSha256 !== bound.flow.contentSha256 ||
    scenario.assetAccountingRulesetVersion !== bound.flow.rulesetVersion;
  return { flow: bound.flow, scenario, stale, impact: stale || scenario.status === "rejected" ? null :
    deriveScenarioImpact(bound.flow, scenario, { preview: scenario.status === "draft" }) };
}
export function updateScenario(database: DatabaseClient, scanId: string, executionId: string,
  scenarioId: string, revisionId: string, raw: unknown) {
  const view = loadScenarioView(database, scanId, executionId, scenarioId);
  if (!view || view.scenario.id !== revisionId || view.stale) throw Error("impact_scenario_current_revision_invalid");
  return updateImpactScenarioDraft(database, view.flow, revisionId, raw);
}
export function decideScenario(database: DatabaseClient, scanId: string, executionId: string,
  scenarioId: string, revisionId: string, decision: "reviewed" | "rejected") {
  const view = loadScenarioView(database, scanId, executionId, scenarioId);
  if (!view || view.scenario.id !== revisionId) throw Error("impact_scenario_current_revision_invalid");
  if (decision === "reviewed") {
    if (view.stale) throw Error("scenario_asset_flow_stale");
    return reviewImpactScenarioDraft(database, view.flow, revisionId);
  }
  return rejectImpactScenario(database, view.scenario);
}
export function createScenarioRevision(database: DatabaseClient, scanId: string, executionId: string,
  scenarioId: string, revisionId: string) {
  const view = loadScenarioView(database, scanId, executionId, scenarioId);
  if (!view || view.scenario.id !== revisionId) throw Error("impact_scenario_current_revision_invalid");
  return reviseImpactScenario(database, view.flow, view.scenario);
}
