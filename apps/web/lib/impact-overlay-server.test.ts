import { beforeEach, describe, expect, it, vi } from "vitest";

const calls = vi.hoisted(() => ({ scan: vi.fn(), execution: vi.fn(), artifact: vi.fn(), session: vi.fn(),
  finding: vi.fn(), hypothesis: vi.fn(), state: vi.fn(), traces: vi.fn(), graph: vi.fn(), path: vi.fn(), derive: vi.fn() }));
vi.mock("@contracthunter/db", () => ({ getScan: calls.scan, readImpactPoCExecution: calls.execution,
  readImpactPoCArtifact: calls.artifact, readImpactForkSession: calls.session, getFinding: calls.finding,
  getVulnerabilityHypothesis: calls.hypothesis, readImpactExecutionState: calls.state,
  readImpactExecutionTraces: calls.traces, readStaticProtocolGraph: calls.graph }));
vi.mock("@contracthunter/core", () => ({ deriveImpactOverlay: calls.derive }));
vi.mock("./investigation-path-server", () => ({ loadInvestigationPaths: calls.path }));
import { loadImpactOverlay } from "./impact-overlay-server";

const scanId = "11111111-1111-4111-8111-111111111111";
const executionId = "22222222-2222-4222-8222-222222222222";
const findingId = "33333333-3333-4333-8333-333333333333";
beforeEach(() => {
  vi.resetAllMocks();
  calls.scan.mockReturnValue({ id: scanId });
  calls.execution.mockReturnValue({ id: executionId, artifactId: "artifact", sessionId: "session", traceCaptureStatus: null });
  calls.artifact.mockReturnValue({ id: "artifact", findingId, hypothesisId: null, reviewState: "reviewed" });
  calls.session.mockReturnValue({ id: "session", findingId, hypothesisId: null });
  calls.finding.mockReturnValue({ id: findingId, scanId });
  calls.state.mockReturnValue({ pre: null, post: null, diff: null });
  calls.traces.mockReturnValue({ status: null, traces: [] });
  calls.graph.mockReturnValue(null);
  calls.derive.mockReturnValue({ schema: "contracthunter-impact-overlay-v1" });
});
describe("Impact Overlay exact server binding", () => {
  it("rejects cross-scan finding membership before reading evidence", () => {
    calls.finding.mockReturnValue({ id: findingId, scanId: "other" });
    expect(loadImpactOverlay({} as never, scanId, executionId)).toBeNull();
    expect(calls.state).not.toHaveBeenCalled();
    expect(calls.derive).not.toHaveBeenCalled();
  });
  it("rejects artifact/session subject mismatch and unreviewed source", () => {
    calls.session.mockReturnValueOnce({ id: "session", findingId: "other", hypothesisId: null });
    expect(loadImpactOverlay({} as never, scanId, executionId)).toBeNull();
    calls.artifact.mockReturnValueOnce({ id: "artifact", findingId, hypothesisId: null, reviewState: "draft" });
    expect(loadImpactOverlay({} as never, scanId, executionId)).toBeNull();
    expect(calls.derive).not.toHaveBeenCalled();
  });
  it("passes only persisted evidence and no invented deployment bindings", () => {
    const result = loadImpactOverlay({} as never, scanId, executionId);
    expect(result?.schema).toBe("contracthunter-impact-overlay-v1");
    expect(calls.derive).toHaveBeenCalledWith(expect.objectContaining({ scanId, traces: [],
      trustedDeploymentBindings: [] }));
  });
});
