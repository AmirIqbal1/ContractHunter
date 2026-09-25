import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { executableInvariantPlanSchema, invariantPlanHash, validAIOutput, type ProtocolAnalysisResult } from "@contracthunter/core";
import { closeDatabase, createDatabase, createExecutableInvariantProposal, createExecutableInvariantRun, createProtocolAnalysis, createScan, createSecurityReviewerRun, createSecurityReviewPlan, getVulnerabilityHypothesis, insertVulnerabilityHypotheses, type DatabaseClient } from "@contracthunter/db";
import { generateInvariantProposal, generateInvariantReplay, readInvariantHistory, reviewInvariantReplay, runInvariantProposal, runInvariantReplay, validateInvariantProposal } from "./invariant-api";
import { InvariantReplayRequestError } from "./invariant-replay-service";

let directory: string, database: DatabaseClient, hypothesisId: string, scanId: string;
const commit = "a".repeat(40);
beforeEach(() => {
  directory = mkdtempSync(path.join(tmpdir(), "ch-invariant-api-")); database = createDatabase(path.join(directory, "test.db"));
  const scan = createScan(database, { repositoryUrl: "https://example.invalid/synthetic", repositoryName: "synthetic", depth: "quick" }); scanId = scan.id;
  database.sqlite.prepare("UPDATE scans SET status='completed', resolved_commit=?, compiler_status='ready', compiler_versions=? WHERE id=?").run(commit, JSON.stringify(["0.8.36"]), scanId);
  const analysis = createProtocolAnalysis(database, { scanId, provider: "mock", requestedModel: "mock", actualModel: "mock", promptVersion: "protocol-analysis-v1", result: validAIOutput as unknown as ProtocolAnalysisResult, coverageStatus: "complete", contextManifest: {}, durationMs: 1, inputTokens: 1, outputTokens: 1, totalTokens: 2, requestId: "analysis" });
  const review = createSecurityReviewPlan(database, { scanId, protocolAnalysisId: analysis.id, plan: { selected: [], skipped: [], estimatedRequestCount: 0 }, estimatedSourceBytes: 0 });
  const reviewer = createSecurityReviewerRun(database, { planId: review.id, scanId, protocolAnalysisId: analysis.id, reviewerId: "fixture", reviewerName: "Fixture", selectionReason: "Fixture", promptVersion: "security-review-fixture-v1", provider: "mock", requestedModel: "mock", contextManifest: {} });
  hypothesisId = insertVulnerabilityHypotheses(database, [{ scanId, protocolAnalysisId: analysis.id, reviewerId: "fixture", reviewerRunId: reviewer.id, title: "Synthetic hypothesis", category: "state-transition", severity: "low", severityJustification: "Fixture", confidence: 60, summary: "Fixture", rootCause: "Fixture", preconditions: "[]", attackPath: "[]", impact: "Fixture", affectedAssets: "[]", affectedContracts: "[]", affectedFunctions: "[]", evidence: "[]", violatedInvariantIds: "[]", relatedInvestigationIds: "[]", falsePositiveRisks: "[]", verificationStrategy: "[]" }])[0].id;
});
afterEach(() => { closeDatabase(database); rmSync(directory, { recursive: true, force: true }); vi.unstubAllEnvs(); });
const context = (proposalId?: string) => ({ params: Promise.resolve({ id: hypothesisId, ...(proposalId ? { proposalId } : {}) }) });
const replayContext = (proposalId: string, runId: string, replayId?: string) => ({ params: Promise.resolve({ id: hypothesisId, proposalId, runId, ...(replayId ? { replayId } : {}) }) });
const post = (body?: string, headers?: Record<string, string>) => new Request("http://localhost", { method: "POST", ...(body === undefined ? {} : { body }), headers });
function plan() { return executableInvariantPlanSchema.parse({ schemaVersion: "contracthunter-invariant-plan-v1", mode: "fuzz-property", scanId, hypothesisId, resolvedCommit: commit, compilerVersion: "0.8.36", primaryContract: "VulnerableAccounting", primarySourcePath: "contracts/VulnerableAccounting.sol", sourceFiles: ["contracts/VulnerableAccounting.sol"], actors: ["deployer", "attacker"], setup: [{ kind: "deploy", contractName: "VulnerableAccounting", instanceName: "target" }], property: { name: "accounting", observations: [{ kind: "read-uint", instanceName: "target", functionName: "totalRecordedBalance", resultName: "recorded" }, { kind: "read-balance", target: { kind: "instance", name: "target" }, resultName: "balance" }], assertions: [{ id: "equal", kind: "uint-eq", actual: "recorded", expected: { kind: "result", name: "balance" } }] }, fuzzAction: { instanceName: "target", functionName: "record", caller: "attacker", parameters: [{ name: "amount", type: "uint256" }], args: [{ kind: "parameter", name: "amount" }] } }); }
function proposalRow() { const value = plan(); return createExecutableInvariantProposal(database, { hypothesisId, scanId, result: { status: "generated", plan: value, planHash: invariantPlanHash(value), hypothesisExpectation: "hypothesis-predicts-property-violation", relationRationale: "The hypothesis predicts a property violation.", rationale: "Fixture", limitations: [], notPlannableReasons: [], failureCode: null, provenance: { provider: "mock", requestedModel: "model", actualModel: "model", promptVersion: "invariant-plan-v1", generatedAt: new Date().toISOString(), inputTokens: 1, outputTokens: 1, totalTokens: 2, estimatedCostUsd: 0.0001, durationMs: 1, sourceFileCount: 1, totalSourceBytes: 100, sourceContextTruncated: false } }, contextManifest: { files: [], totalSourceBytes: 0, truncated: false }, requestId: "request" }); }

describe("manual invariant API", () => {
  it("accepts bodyless generation, including an empty stream, without starting execution", async () => {
    const row = proposalRow(), generation = { generate: vi.fn().mockResolvedValue({ proposal: row, result: null }) }, execution = vi.fn();
    expect((await generateInvariantProposal(post(), context(), generation as never)).status).toBe(200);
    const empty = post(); Object.defineProperty(empty, "body", { value: new ReadableStream({ start(controller) { controller.close(); } }) });
    expect((await generateInvariantProposal(empty, context(), generation as never)).status).toBe(200);
    expect(generation.generate).toHaveBeenCalledTimes(2); expect(execution).not.toHaveBeenCalled(); expect(getVulnerabilityHypothesis(database, hypothesisId)?.status).toBe("candidate");
  });
  it("rejects unexpected or oversized request bytes before provider use", async () => {
    const generation = { generate: vi.fn() };
    expect((await generateInvariantProposal(post("{}"), context(), generation as never)).status).toBe(400);
    expect((await generateInvariantProposal(post("x".repeat(1025)), context(), generation as never)).status).toBe(413);
    expect((await generateInvariantProposal(post(undefined, { "content-length": "10000" }), context(), generation as never)).status).toBe(413);
    expect(generation.generate).not.toHaveBeenCalled();
  });
  it("reports unavailable AI without contacting a provider", async () => {
    vi.stubEnv("AI_ENABLED", "false");
    const response = await generateInvariantProposal(post(), context());
    expect(response.status).toBe(409); expect((await response.json()).error).toContain("disabled");
  });
  it("requires separate validation and run requests and never accepts a plan body", async () => {
    const proposal = proposalRow(), validated = { validate: vi.fn().mockResolvedValue({ plan: plan(), planHash: proposal.planHash }) }, runRow = createExecutableInvariantRun(database, { plan: plan() });
    const execution = { run: vi.fn().mockResolvedValue({ status: "completed", run: runRow }) };
    const validation = await validateInvariantProposal(post(), context(proposal.id), validated as never);
    expect(validation.status).toBe(200); expect(execution.run).not.toHaveBeenCalled();
    expect((await runInvariantProposal(post("{}"), context(proposal.id), validated as never, execution as never)).status).toBe(400);
    expect(execution.run).not.toHaveBeenCalled();
    expect((await runInvariantProposal(post(), context(proposal.id), validated as never, execution as never)).status).toBe(200);
    expect(execution.run).toHaveBeenCalledWith(hypothesisId, plan()); expect(getVulnerabilityHypothesis(database, hypothesisId)?.status).toBe("candidate");
  });
  it("returns bounded history without raw worker output", async () => {
    proposalRow(); createExecutableInvariantRun(database, { plan: plan() });
    const response = await readInvariantHistory(new Request("http://localhost"), context(), database), body = await response.json();
    expect(response.status).toBe(200); expect(body.proposals).toHaveLength(1); expect(body.runs).toHaveLength(1);
    expect(JSON.stringify(body)).not.toMatch(/stdout|stderr|isolationMetadata|request-id/);
  });
  it("accepts bodyless replay/review actions and rejects unexpected or oversized bytes before service use", async () => {
    const proposal = proposalRow(), run = createExecutableInvariantRun(database, { plan: plan() }), replayId = crypto.randomUUID();
    const generate = { generate: vi.fn().mockRejectedValue(new InvariantReplayRequestError("replay_unavailable", "No replay.")) }, execute = { execute: vi.fn().mockRejectedValue(new InvariantReplayRequestError("unknown_replay", "Missing.")) }, review = { review: vi.fn().mockImplementation(() => { throw new InvariantReplayRequestError("unknown_replay", "Missing."); }) };
    expect((await generateInvariantReplay(post(), replayContext(proposal.id, run.id), generate)).status).toBe(409); expect(generate.generate).toHaveBeenCalledTimes(1);
    expect((await runInvariantReplay(post(), replayContext(proposal.id, run.id, replayId), execute)).status).toBe(404); expect(execute.execute).toHaveBeenCalledTimes(1);
    expect((await reviewInvariantReplay(post(), replayContext(proposal.id, run.id, replayId), review)).status).toBe(404); expect(review.review).toHaveBeenCalledTimes(1);
    expect((await generateInvariantReplay(post("{}"), replayContext(proposal.id, run.id), generate)).status).toBe(400); expect((await reviewInvariantReplay(post("x".repeat(1025)), replayContext(proposal.id, run.id, replayId), review)).status).toBe(413);
    expect(generate.generate).toHaveBeenCalledTimes(1); expect(review.review).toHaveBeenCalledTimes(1);
  });
});
