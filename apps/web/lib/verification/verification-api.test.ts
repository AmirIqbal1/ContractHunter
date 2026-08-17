import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { validAIOutput, verificationHarnessPlanSchema, type ProtocolAnalysisResult } from "@contracthunter/core";
import {
  closeDatabase, completeHypothesisVerificationRun, createDatabase, createHypothesisVerificationRun, createProtocolAnalysis, createScan,
  createSecurityReviewerRun, createSecurityReviewPlan, failHypothesisVerificationRun, insertVulnerabilityHypotheses,
  markHypothesisVerificationRunRunning, type DatabaseClient, type HypothesisVerificationRunRow,
} from "@contracthunter/db";
import { HypothesisVerificationRequestError } from "./hypothesis-verification-service";
import { generateVerificationPlan, readVerificationHistory, startVerification } from "./verification-api";
import { VerificationPlanGenerationError } from "./verification-plan-generation-service";

const commit = "a".repeat(40);
let directory: string; let database: DatabaseClient; let hypothesisId: string; let scanId: string;

beforeEach(() => {
  directory = mkdtempSync(path.join(tmpdir(), "contracthunter-verification-api-")); database = createDatabase(path.join(directory, "test.db"));
  const scan = createScan(database, { repositoryUrl: "https://github.com/example/fixture", repositoryName: "example/fixture", depth: "quick" }); scanId = scan.id;
  database.sqlite.prepare("UPDATE scans SET status = 'completed', resolved_commit = ?, compiler_status = 'ready', compiler_versions = ? WHERE id = ?").run(commit, JSON.stringify(["0.8.24"]), scan.id);
  const analysis = createProtocolAnalysis(database, { scanId, provider: "mock", requestedModel: "mock", actualModel: "mock", promptVersion: "protocol-analysis-v1", result: validAIOutput as unknown as ProtocolAnalysisResult, coverageStatus: "complete", contextManifest: {}, durationMs: 1, inputTokens: 1, outputTokens: 1, totalTokens: 2, requestId: "analysis" });
  const reviewPlan = createSecurityReviewPlan(database, { scanId, protocolAnalysisId: analysis.id, plan: { selected: [], skipped: [], estimatedRequestCount: 0 }, estimatedSourceBytes: 0 });
  const reviewer = createSecurityReviewerRun(database, { planId: reviewPlan.id, scanId, protocolAnalysisId: analysis.id, reviewerId: "accounting", reviewerName: "Accounting", selectionReason: "Fixture", promptVersion: "security-review-accounting-v1", provider: "mock", requestedModel: "mock", contextManifest: {} });
  hypothesisId = insertVulnerabilityHypotheses(database, [{ scanId, protocolAnalysisId: analysis.id, reviewerId: "accounting", reviewerRunId: reviewer.id, title: "Counter transition", category: "state-transition", severity: "low", severityJustification: "Fixture", confidence: 60, summary: "Fixture", rootCause: "Fixture", preconditions: "[]", attackPath: "[]", impact: "Fixture", affectedAssets: "[]", affectedContracts: "[]", affectedFunctions: "[]", evidence: "[]", violatedInvariantIds: "[]", relatedInvestigationIds: "[]", falsePositiveRisks: "[]", verificationStrategy: "[\"Run locally.\"]" }])[0].id;
});
afterEach(() => { closeDatabase(database); rmSync(directory, { recursive: true, force: true }); });

function plan(overrides: Record<string, unknown> = {}) {
  return { scanId, hypothesisId, resolvedCommit: commit, compilerVersion: "0.8.24", primaryContract: "Counter", primarySourcePath: "contracts/Counter.sol", relevantFunctions: ["increment", "count"], sourceFiles: ["contracts/Counter.sol"], verificationGoal: "Check a deterministic counter transition.", expectedProperty: "The count becomes one.", verificationSteps: ["Deploy, increment, and read."], operations: [{ kind: "deploy", contractName: "Counter", instanceName: "target" }, { kind: "call", instanceName: "target", functionName: "increment" }, { kind: "read-uint", instanceName: "target", functionName: "count", resultName: "observed" }], assertions: [{ id: "count-is-one", kind: "uint-eq", actual: "observed", expected: "1", expectedOutcome: "hypothesis-supported", description: "Count is one." }], ...overrides };
}
function request(value: unknown, headers: Record<string, string> = {}) { return new Request(`http://localhost/api/hypotheses/${hypothesisId}/verify`, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(value) }); }
const context = (id = hypothesisId) => ({ params: Promise.resolve({ id }) });
function queued(): HypothesisVerificationRunRow { const value = verificationHarnessPlanSchema.parse(plan()); return createHypothesisVerificationRun(database, { hypothesisId, scanId, resolvedCommit: commit, compilerVersion: "0.8.24", verificationPlan: value, verifierId: "local-verifier", toolName: "forge", toolVersion: null, verificationStrategy: value.verificationSteps }); }
function completed(): HypothesisVerificationRunRow { const run = queued(); markHypothesisVerificationRunRunning(database, run.id); return completeHypothesisVerificationRun(database, run.id, { outcome: "inconclusive", resultSummary: "No sufficient evidence.", durationMs: 12, testCount: 1, passedTestCount: 1, failedTestCount: 0, stdoutSummary: "secret-looking bounded output", stderrSummary: "internal/path", dynamicEvidence: [], contentFingerprint: "b".repeat(64), isolationBackend: "linux-bubblewrap", executionExitCode: 0, timedOut: false }); }

describe("explicit local verification API", () => {
  it("rejects malformed plans, URL mismatches, unknown fields, and executable injection fields", async () => {
    expect((await startVerification(request({ nope: true }), context())).status).toBe(400);
    expect((await startVerification(request(plan({ hypothesisId: crypto.randomUUID() })), context())).status).toBe(400);
    for (const field of ["command", "repositoryPath", "forgeArgs", "soliditySource", "environment", "rpcUrl", "privateKey", "status"]) {
      const value = field === "status" ? "verified" : "attacker-controlled";
      expect((await startVerification(request(plan({ [field]: value })), context())).status, field).toBe(400);
    }
  });

  it("requires JSON, bounds the body, maps unknown hypotheses, and reaches the service for a valid request", async () => {
    expect((await startVerification(new Request("http://localhost", { method: "POST", body: "{}" }), context())).status).toBe(415);
    expect((await startVerification(request(plan(), { "content-length": "70000" }), context())).status).toBe(413);
    expect((await startVerification(request({ payload: "x".repeat(70_000) }), context())).status).toBe(413);
    const unknownService = { run: vi.fn().mockRejectedValue(new HypothesisVerificationRequestError("unknown_hypothesis", "Vulnerability hypothesis not found.")) };
    expect((await startVerification(request(plan()), context(), unknownService as never)).status).toBe(404);
    const run = completed(); const service = { run: vi.fn().mockResolvedValue({ status: "completed", run }) };
    const response = await startVerification(request(plan()), context(), service as never);
    expect(response.status).toBe(200); expect(service.run).toHaveBeenCalledWith(hypothesisId, verificationHarnessPlanSchema.parse(plan()));
  });

  it("returns 409 for an active-run conflict", async () => {
    const run = queued(); const service = { run: vi.fn().mockResolvedValue({ status: "conflict", run }) };
    const response = await startVerification(request(plan()), context(), service as never);
    expect(response.status).toBe(409); expect((await response.json()).verification.status).toBe("queued");
  });
});

describe("verification history API", () => {
  it("returns 404 for an unknown hypothesis", async () => { expect((await readVerificationHistory(new Request("http://localhost"), context(crypto.randomUUID()), database)).status).toBe(404); });

  it("returns newest first with bounded structured evidence and sanitised output", async () => {
    const first = completed(); const second = queued(); markHypothesisVerificationRunRunning(database, second.id);
    failHypothesisVerificationRun(database, second.id, { error: "arbitrary /internal/path secret prose", durationMs: 3, stdoutSummary: "do not publish", stderrSummary: "do not publish", contentFingerprint: null, isolationBackend: null, executionExitCode: null, timedOut: false });
    const response = await readVerificationHistory(new Request("http://localhost"), context(), database); const body = await response.json();
    expect(body.verifications.map((run: { id: string }) => run.id)).toEqual([second.id, first.id]);
    expect(body.verifications[0]).toMatchObject({ failureCode: "verification_failed", verifier: "local-verifier", compiler: "0.8.24", testCounts: { total: 0, passed: 0, failed: 0 } });
    expect(JSON.stringify(body)).not.toContain("stdout"); expect(JSON.stringify(body)).not.toContain("internal/path"); expect(JSON.stringify(body)).not.toContain("verificationPlan");
  });
});

describe("verification plan preview API", () => {
  const preview = { status: "not_plannable", plan: null, rationale: "Unsupported setup.", limitations: [], notPlannableReasons: ["unsupported_state_setup"], failureCode: null, provenance: { provider: "fake", requestedModel: "model", actualModel: "model", promptVersion: "verification-plan-v1", generatedAt: "2026-08-16T10:00:00.000Z", inputTokens: 1, outputTokens: 1, totalTokens: 2, durationMs: 1, sourceFileCount: 1, totalSourceBytes: 100, sourceContextTruncated: false } };
  it("accepts POST requests with no bytes, including an empty body stream", async () => {
    const service = { generate: vi.fn().mockResolvedValue(preview) };
    const noBody = await generateVerificationPlan(new Request("http://localhost", { method: "POST" }), context(), service as never);
    const emptyStream = await generateVerificationPlan(new Request("http://localhost", { method: "POST", body: new ReadableStream({ start(controller) { controller.close(); } }), duplex: "half" } as RequestInit & { duplex: "half" }), context(), service as never);
    expect(noBody.status).toBe(200); expect(emptyStream.status).toBe(200);
    expect(service.generate).toHaveBeenCalledTimes(2); expect(service.generate).toHaveBeenNthCalledWith(1, hypothesisId); expect(service.generate).toHaveBeenNthCalledWith(2, hypothesisId);
  });

  it.each(["{}", "text payload"]) ("rejects actual request data (%s) without invoking generation", async (body) => {
    const service = { generate: vi.fn().mockResolvedValue(preview) };
    const response = await generateVerificationPlan(new Request("http://localhost", { method: "POST", body }), context(), service as never);
    expect(response.status).toBe(400); expect(await response.json()).toEqual({ error: "Verification plan generation does not accept request data." }); expect(service.generate).not.toHaveBeenCalled();
  });

  it("rejects oversized request data before generation", async () => {
    const service = { generate: vi.fn().mockResolvedValue(preview) };
    const response = await generateVerificationPlan(new Request("http://localhost", { method: "POST", body: "x".repeat(65_537) }), context(), service as never);
    expect(response.status).toBe(413); expect(service.generate).not.toHaveBeenCalled();
  });

  it("preserves disabled and missing-key checks", async () => {
    vi.stubEnv("AI_ENABLED", "false");
    expect((await generateVerificationPlan(new Request("http://localhost", { method: "POST" }), context())).status).toBe(409);
    vi.stubEnv("AI_ENABLED", "true"); vi.stubEnv("OPENAI_API_KEY", "");
    expect((await generateVerificationPlan(new Request("http://localhost", { method: "POST" }), context())).status).toBe(409);
    vi.unstubAllEnvs();
  });
  it("maps unknown hypotheses and rejected/missing state consistently", async () => {
    expect((await generateVerificationPlan(new Request("http://localhost", { method: "POST" }), context(), { generate: vi.fn().mockRejectedValue(new VerificationPlanGenerationError("unknown_hypothesis", "Not found.")) } as never)).status).toBe(404);
    expect((await generateVerificationPlan(new Request("http://localhost", { method: "POST" }), context(), { generate: vi.fn().mockRejectedValue(new VerificationPlanGenerationError("invalid_state", "Rejected.")) } as never)).status).toBe(409);
  });
});
