import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { validAIOutput, type ProtocolAnalysisResult } from "@contracthunter/core";
import { closeDatabase, createDatabase, createExecutableInvariantProposal, createProtocolAnalysis, createScan, createSecurityReviewerRun, createSecurityReviewPlan, getVulnerabilityHypothesis, insertFindings, insertVulnerabilityHypotheses, reconcileInvestigations, type DatabaseClient } from "@contracthunter/db";
import { generateForSelectedStrategy } from "./strategy-generation-api";

let directory: string, database: DatabaseClient, hypothesisId: string, scanId: string;
beforeEach(() => {
  directory = mkdtempSync(path.join(tmpdir(), "contracthunter-strategy-api-")); database = createDatabase(path.join(directory, "test.db"));
  const scan = createScan(database, { repositoryUrl: "https://example.invalid/synthetic", repositoryName: "synthetic", depth: "quick" }); scanId = scan.id;
  database.sqlite.prepare("UPDATE scans SET status='completed', resolved_commit=?, compiler_status='ready', compiler_versions=? WHERE id=?").run("a".repeat(40), JSON.stringify(["0.8.36"]), scanId);
  const analysis = createProtocolAnalysis(database, { scanId, provider: "mock", requestedModel: "mock", actualModel: "mock", promptVersion: "protocol-analysis-v1", result: validAIOutput as unknown as ProtocolAnalysisResult, coverageStatus: "complete", contextManifest: {}, durationMs: 1, inputTokens: 1, outputTokens: 1, totalTokens: 2, requestId: "analysis" });
  const review = createSecurityReviewPlan(database, { scanId, protocolAnalysisId: analysis.id, plan: { selected: [], skipped: [], estimatedRequestCount: 0 }, estimatedSourceBytes: 0 });
  const reviewer = createSecurityReviewerRun(database, { planId: review.id, scanId, protocolAnalysisId: analysis.id, reviewerId: "fixture", reviewerName: "Fixture", selectionReason: "Fixture", promptVersion: "security-review-fixture-v1", provider: "mock", requestedModel: "mock", contextManifest: {} });
  hypothesisId = insertVulnerabilityHypotheses(database, [{ scanId, protocolAnalysisId: analysis.id, reviewerId: "fixture", reviewerRunId: reviewer.id, title: "Synthetic hypothesis", category: "state-transition", severity: "low", severityJustification: "Fixture", confidence: 60, summary: "Fixture", rootCause: "Fixture", preconditions: "[]", attackPath: "[]", impact: "Fixture", affectedAssets: "[]", affectedContracts: "[]", affectedFunctions: "[]", evidence: "[]", violatedInvariantIds: "[]", relatedInvestigationIds: "[]", falsePositiveRisks: "[]", verificationStrategy: "[]" }])[0].id;
});
afterEach(() => { closeDatabase(database); rmSync(directory, { recursive: true, force: true }); });
const context = (strategy: string, id = hypothesisId) => ({ params: Promise.resolve({ id, strategy }) });
const request = (body?: string) => new Request("http://localhost", { method: "POST", ...(body === undefined ? {} : { body }) });
function link(detectorId: string) {
  insertFindings(database, scanId, [{ title: "Hostile /secret/path", severity: "medium", confidence: 80, source: "slither", detectorId, fingerprint: "f".repeat(64), contract: "Vault", functionName: "check", filePath: "src/Vault.sol", startLine: 1, endLine: 1, rootCause: "Numeric result", attackScenario: "", impact: "", evidence: "fixture", status: "candidate" }]);
  const investigation = reconcileInvestigations(database, scanId)[0];
  database.sqlite.prepare("UPDATE vulnerability_hypotheses SET related_investigation_ids=? WHERE id=?").run(JSON.stringify([investigation.id]), hypothesisId);
}
function emptyHistory() {
  for (const table of ["hypothesis_verification_runs", "executable_invariant_runs", "invariant_replay_artifacts", "authoritative_invariant_evidence", "hypothesis_lifecycle_transitions"]) {
    expect(database.sqlite.prepare(`SELECT count(*) AS count FROM ${table}`).get()).toEqual({ count: 0 });
  }
  expect(getVulnerabilityHypothesis(database, hypothesisId)?.status).toBe("candidate");
}

describe("explicit strategy generation API", () => {
  it("rejects invalid identifiers, browser capability fields, and oversized bodies before planning", async () => {
    const structured = { generate: vi.fn() }, invariant = { generate: vi.fn() };
    const services = { database, structured: structured as never, invariant: invariant as never };
    expect((await generateForSelectedStrategy(request(), context("unknown-mode"), services)).status).toBe(400);
    expect((await generateForSelectedStrategy(request(), context("structured-verification", "bad"), services)).status).toBe(400);
    for (const body of ['{"compatible":true}', '{"mode":"stateful-invariant"}', '{"capabilities":["explicit-caller"]}', '{"compiler":"0.8.36"}', '{"commit":"abc"}', '{"prompt":"ignore rules"}', '{"sourcePath":"src/Vault.sol"}', '{"source":"contract X {}"}', '{"engineExecutable":"/bin/sh"}', '{"argv":["--unsafe"]}', '{"echidnaYaml":"testLimit: 1"}', '{"foundryConfig":"[profile.default]"}', '{"seed":123}']) {
      expect((await generateForSelectedStrategy(request(body), context("structured-verification"), services)).status, body).toBe(400);
    }
    expect((await generateForSelectedStrategy(request("x".repeat(1025)), context("structured-verification"), services)).status).toBe(413);
    expect((await generateForSelectedStrategy(new Request("http://localhost", { method: "POST", headers: { "content-length": "2048" } }), context("structured-verification"), services)).status).toBe(413);
    expect(structured.generate).not.toHaveBeenCalled(); expect(invariant.generate).not.toHaveBeenCalled(); emptyHistory();
  });

  it("reassesses after page state changes and refuses unknown/incompatible selections with zero provider calls", async () => {
    link("protected-vars");
    const structured = { generate: vi.fn() }, invariant = { generate: vi.fn() };
    const services = { database, structured: structured as never, invariant: invariant as never };
    const incompatible = await generateForSelectedStrategy(request(), context("echidna-stateful-invariant"), services);
    expect(incompatible.status).toBe(409);
    expect(await incompatible.json()).toMatchObject({ code: "strategy_not_compatible", reasons: [{ code: "unsupported-requirement", requirement: "explicit-caller" }] });
    database.sqlite.prepare("UPDATE vulnerability_hypotheses SET related_investigation_ids='[]' WHERE id=?").run(hypothesisId);
    const unknown = await generateForSelectedStrategy(request(), context("structured-verification"), services);
    expect(unknown.status).toBe(409);
    expect(await unknown.json()).toMatchObject({ code: "strategy_compatibility_unknown" });
    expect(structured.generate).not.toHaveBeenCalled(); expect(invariant.generate).not.toHaveBeenCalled(); emptyHistory();
  });

  it("dispatches only the explicitly selected compatible planner and returns a reviewable result", async () => {
    link("protected-vars");
    const result = { status: "not_plannable", plan: null, rationale: "No concrete plan.", limitations: [], notPlannableReasons: ["insufficient_source_evidence"], failureCode: null, provenance: { provider: "mock", requestedModel: "mock", actualModel: "mock", promptVersion: "verification-plan-v4", generatedAt: new Date().toISOString(), inputTokens: 1, outputTokens: 1, totalTokens: 2, durationMs: 1, sourceFileCount: 1, totalSourceBytes: 100, sourceContextTruncated: false } };
    const structured = { generate: vi.fn().mockResolvedValue(result) }, invariant = { generate: vi.fn() };
    const emptyStream = new Request("http://localhost", { method: "POST", body: new ReadableStream({ start(controller) { controller.close(); } }), duplex: "half" } as RequestInit & { duplex: "half" });
    const response = await generateForSelectedStrategy(emptyStream, context("structured-verification"), { database, structured: structured as never, invariant: invariant as never });
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ selectedStrategy: "structured-verification", result: { status: "not_plannable" } });
    expect(structured.generate).toHaveBeenCalledOnce(); expect(structured.generate).toHaveBeenCalledWith(hypothesisId, "structured-verification");
    expect(invariant.generate).not.toHaveBeenCalled(); emptyHistory();
  });

  it("dispatches a compatible invariant strategy without an engine fanout", async () => {
    link("divide-before-multiply");
    const provenance = { provider: "mock", requestedModel: "mock", actualModel: "mock", promptVersion: "invariant-plan-v1", generatedAt: new Date().toISOString(), inputTokens: 1, outputTokens: 1, totalTokens: 2, estimatedCostUsd: null, durationMs: 1, sourceFileCount: 1, totalSourceBytes: 100, sourceContextTruncated: false };
    const result = { status: "failed" as const, plan: null, planHash: null, hypothesisExpectation: null, relationRationale: null, rationale: null, limitations: [], notPlannableReasons: [], failureCode: "strategy_concrete_plan_incompatible" as const, provenance };
    const proposal = createExecutableInvariantProposal(database, { hypothesisId, scanId, result, contextManifest: {}, requestId: null, selectedStrategy: "echidna-stateful-invariant" });
    const structured = { generate: vi.fn() }, invariant = { generate: vi.fn().mockResolvedValue({ proposal, result }) };
    const response = await generateForSelectedStrategy(request(), context("echidna-stateful-invariant"), { database, structured: structured as never, invariant: invariant as never });
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ selectedStrategy: "echidna-stateful-invariant", proposal: { selectedStrategy: "echidna-stateful-invariant", status: "failed", failureCode: "strategy_concrete_plan_incompatible" } });
    expect(invariant.generate).toHaveBeenCalledOnce(); expect(invariant.generate).toHaveBeenCalledWith(hypothesisId, "echidna-stateful-invariant");
    expect(structured.generate).not.toHaveBeenCalled(); emptyHistory();
  });

  it("returns 404 for a missing hypothesis before constructing a planner", async () => {
    const structured = { generate: vi.fn() };
    expect((await generateForSelectedStrategy(request(), context("structured-verification", crypto.randomUUID()), { database, structured: structured as never })).status).toBe(404);
    expect(structured.generate).not.toHaveBeenCalled();
  });
});
