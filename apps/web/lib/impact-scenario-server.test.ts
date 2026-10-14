import { beforeEach, describe, expect, it, vi } from "vitest";

const calls = vi.hoisted(() => ({ flow: vi.fn(), overlay: vi.fn(), current: vi.fn(), list: vi.fn(),
  create: vi.fn(), update: vi.fn(), review: vi.fn(), revise: vi.fn(), reject: vi.fn(), derive: vi.fn() }));
vi.mock("./asset-flow-server", () => ({ loadAssetFlow: calls.flow }));
vi.mock("./impact-overlay-server", () => ({ loadImpactOverlay: calls.overlay }));
vi.mock("@contracthunter/db", () => ({ createImpactScenarioDraft: calls.create, listImpactScenarios: calls.list,
  readCurrentImpactScenario: calls.current, rejectImpactScenario: calls.reject,
  reviseImpactScenario: calls.revise, reviewImpactScenarioDraft: calls.review,
  updateImpactScenarioDraft: calls.update }));
vi.mock("@contracthunter/core", () => ({ deriveScenarioImpact: calls.derive }));
import { createScenario, loadScenarioView, decideScenario, updateScenario } from "./impact-scenario-server";

const scanId = "scan", executionId = "execution", scenarioId = "scenario";
const flow = { scanId, executionId, contentSha256: "hash", rulesetVersion: "ruleset" };
const subject = { type: "finding", id: "finding" };
const scenario = { id: "revision", scenarioId, scanId, executionId, subject,
  assetFlowContentSha256: "hash", assetAccountingRulesetVersion: "ruleset", status: "reviewed" };
beforeEach(() => { vi.resetAllMocks(); calls.flow.mockReturnValue(flow); calls.overlay.mockReturnValue({ scanId, executionId, subject });
  calls.current.mockReturnValue(scenario); calls.derive.mockReturnValue({ contentSha256: "result" }); });
describe("exact scenario server binding", () => {
  it("rejects a cross-hunt execution before draft persistence or role interpretation", () => {
    calls.flow.mockReturnValueOnce(null);
    expect(createScenario({} as never, "other-scan", executionId, { assignments: [], note: "" })).toBeNull();
    expect(calls.create).not.toHaveBeenCalled();
    calls.flow.mockReturnValueOnce(null);
    expect(loadScenarioView({} as never, "other-scan", executionId, scenarioId)).toBeNull();
    expect(calls.derive).not.toHaveBeenCalled();
  });
  it("accepts only current same-hunt revision and inherits exact subject", () => {
    expect(createScenario({} as never, scanId, executionId, { assignments: [], note: "" })).toBeUndefined();
    expect(calls.create).toHaveBeenCalledWith({}, flow, subject, { assignments: [], note: "" });
    expect(loadScenarioView({} as never, scanId, executionId, scenarioId)?.impact).toEqual({ contentSha256: "result" });
    expect(() => updateScenario({} as never, scanId, executionId, scenarioId, "older", {})).toThrow();
    expect(() => decideScenario({} as never, scanId, executionId, scenarioId, "older", "reviewed")).toThrow();
  });
  it("does not derive current impact from stale E1 evidence", () => {
    calls.current.mockReturnValueOnce({ ...scenario, assetFlowContentSha256: "old" });
    expect(loadScenarioView({} as never, scanId, executionId, scenarioId)).toMatchObject({ stale: true, impact: null });
    expect(calls.derive).not.toHaveBeenCalled();
  });
});
