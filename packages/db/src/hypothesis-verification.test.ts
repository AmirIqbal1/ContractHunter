import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { validAIOutput, type DynamicEvidence, type ProtocolAnalysisResult, type VerificationOutcome } from "@contracthunter/core";
import {
  closeDatabase, completeHypothesisVerificationRun, createDatabase, createHypothesisVerificationRun, createProtocolAnalysis, createScan,
  createSecurityReviewerRun, createSecurityReviewPlan, failHypothesisVerificationRun, getHypothesisVerificationRun, getLatestHypothesisVerificationRun,
  getVulnerabilityHypothesis, insertVulnerabilityHypotheses, listHypothesisVerificationRuns, markHypothesisVerificationRunRunning,
  updateVulnerabilityHypothesisStatus, verifyHypothesisFromDynamicEvidence, type DatabaseClient, type HypothesisVerificationRunRow,
} from "./index";

const commit = "a".repeat(40);
let directory: string;
let database: DatabaseClient;
let scanId: string;
let hypothesisId: string;

beforeEach(() => {
  directory = mkdtempSync(path.join(tmpdir(), "contracthunter-hypothesis-verification-"));
  database = createDatabase(path.join(directory, "test.db"));
  const scan = createScan(database, { repositoryUrl: "https://github.com/example/fixture", repositoryName: "example/fixture", depth: "quick" }); scanId = scan.id;
  database.sqlite.prepare("UPDATE scans SET status = 'completed', resolved_commit = ? WHERE id = ?").run(commit, scan.id);
  const analysis = createProtocolAnalysis(database, { scanId, provider: "mock", requestedModel: "mock", actualModel: "mock", promptVersion: "protocol-analysis-v1", result: validAIOutput as unknown as ProtocolAnalysisResult, coverageStatus: "complete", contextManifest: {}, durationMs: 1, inputTokens: 1, outputTokens: 1, totalTokens: 2, requestId: "analysis" });
  const plan = createSecurityReviewPlan(database, { scanId, protocolAnalysisId: analysis.id, plan: { selected: [], skipped: [], estimatedRequestCount: 0 }, estimatedSourceBytes: 0 });
  const reviewerRun = createSecurityReviewerRun(database, { planId: plan.id, scanId, protocolAnalysisId: analysis.id, reviewerId: "accounting", reviewerName: "Accounting", selectionReason: "Fixture", promptVersion: "security-review-accounting-v1", provider: "mock", requestedModel: "mock", contextManifest: {} });
  const hypothesis = insertVulnerabilityHypotheses(database, [{ scanId, protocolAnalysisId: analysis.id, reviewerId: "accounting", reviewerRunId: reviewerRun.id, title: "Post-transfer denominator dilutes shares", category: "share-accounting", severity: "high", severityJustification: "Existing depositors may gain value.", confidence: 78, summary: "Share minting may use the post-transfer asset balance.", rootCause: "Assets are transferred before the share conversion denominator is read.", preconditions: "[]", attackPath: "[]", impact: "Depositors may receive too few shares.", affectedAssets: "[]", affectedContracts: "[]", affectedFunctions: "[]", evidence: "[]", violatedInvariantIds: "[]", relatedInvestigationIds: "[]", falsePositiveRisks: "[]", verificationStrategy: JSON.stringify(["Compare bounded local deposit assertions."]) }])[0];
  hypothesisId = hypothesis.id;
});

afterEach(() => { closeDatabase(database); rmSync(directory, { recursive: true, force: true }); });

const supportingEvidence: DynamicEvidence = { assertionName: "share conversion", expectedBehavior: "Shares use the pre-deposit exchange rate.", observedBehavior: "Shares used the post-deposit exchange rate.", direction: "supports", contract: "Vault", functionName: "deposit", details: "The bounded assertion observed fewer shares than expected." };
const neutralEvidence: DynamicEvidence = { ...supportingEvidence, direction: "neutral", observedBehavior: "The harness could not represent the required initial state." };

function createRun(): HypothesisVerificationRunRow {
  return createHypothesisVerificationRun(database, { hypothesisId, scanId, resolvedCommit: commit, verifierId: "local-test-harness", toolName: "foundation-fixture", toolVersion: "1", verificationStrategy: ["Compare bounded local deposit assertions."] });
}

function complete(run: HypothesisVerificationRunRow, outcome: VerificationOutcome, dynamicEvidence: DynamicEvidence[] = []): HypothesisVerificationRunRow {
  markHypothesisVerificationRunRunning(database, run.id);
  return completeHypothesisVerificationRun(database, run.id, { outcome, resultSummary: `Verification was ${outcome}.`, durationMs: 12, testCount: 1, passedTestCount: outcome === "refuted" ? 1 : 0, failedTestCount: outcome === "confirmed" ? 1 : 0, stdoutSummary: "bounded stdout", stderrSummary: "", dynamicEvidence });
}

describe("hypothesis verification persistence", () => {
  it("creates a queued run and permits only queued -> running", () => {
    const run = createRun();
    expect(run).toMatchObject({ hypothesisId, scanId, resolvedCommit: commit, status: "queued", outcome: null, dynamicEvidence: "[]" });
    expect(markHypothesisVerificationRunRunning(database, run.id)).toMatchObject({ status: "running", startedAt: expect.any(Date) });
    expect(() => markHypothesisVerificationRunRunning(database, run.id)).toThrow("Invalid verification run transition");
  });

  it.each(["confirmed", "refuted", "inconclusive"] as const)("records a completed %s outcome", (outcome) => {
    const run = complete(createRun(), outcome, outcome === "confirmed" ? [supportingEvidence] : [neutralEvidence]);
    expect(run).toMatchObject({ status: "completed", outcome, completedAt: expect.any(Date), durationMs: 12, testCount: 1 });
    if (outcome === "confirmed") expect(getVulnerabilityHypothesis(database, hypothesisId)?.status).toBe("verified");
    else expect(getVulnerabilityHypothesis(database, hypothesisId)?.status).toBe("candidate");
    expect(() => markHypothesisVerificationRunRunning(database, run.id)).toThrow("Invalid verification run transition");
  });

  it("records running -> failed without verifying the hypothesis", () => {
    const run = createRun(); markHypothesisVerificationRunRunning(database, run.id);
    const failed = failHypothesisVerificationRun(database, run.id, { error: "Harness setup failed.", durationMs: 4, stdoutSummary: "", stderrSummary: "bounded error" });
    expect(failed).toMatchObject({ status: "failed", outcome: null, error: "Harness setup failed.", completedAt: expect.any(Date) });
    expect(() => verifyHypothesisFromDynamicEvidence(database, run.id)).toThrow("completed, confirmed");
    expect(getVulnerabilityHypothesis(database, hypothesisId)?.status).toBe("candidate");
  });

  it("rejects queued -> completed and terminal-state rewrites", () => {
    const queued = createRun();
    expect(() => completeHypothesisVerificationRun(database, queued.id, { outcome: "inconclusive", resultSummary: "No result.", durationMs: 0, testCount: 0, passedTestCount: 0, failedTestCount: 0, stdoutSummary: "", stderrSummary: "", dynamicEvidence: [] })).toThrow("Invalid verification run transition");
    markHypothesisVerificationRunRunning(database, queued.id); failHypothesisVerificationRun(database, queued.id, { error: "Failed safely.", durationMs: 1, stdoutSummary: "", stderrSummary: "" });
    expect(() => completeHypothesisVerificationRun(database, queued.id, { outcome: "confirmed", resultSummary: "Late result.", durationMs: 1, testCount: 1, passedTestCount: 0, failedTestCount: 1, stdoutSummary: "", stderrSummary: "", dynamicEvidence: [supportingEvidence] })).toThrow("Invalid verification run transition");
  });

  it("preserves history and returns the newest rerun without overwriting the old run", () => {
    const first = complete(createRun(), "refuted", [{ ...supportingEvidence, direction: "contradicts" }]);
    const second = complete(createRun(), "inconclusive", [neutralEvidence]);
    expect(listHypothesisVerificationRuns(database, hypothesisId).map((run) => run.id)).toEqual([second.id, first.id]);
    expect(getLatestHypothesisVerificationRun(database, hypothesisId)?.id).toBe(second.id);
    expect(getHypothesisVerificationRun(database, first.id)).toMatchObject({ status: "completed", outcome: "refuted", dynamicEvidence: first.dynamicEvidence });
  });
});

describe("verified hypothesis safety", () => {
  it("requires supporting evidence even for a confirmed completed run", () => {
    const run = complete(createRun(), "confirmed", [neutralEvidence]);
    expect(getVulnerabilityHypothesis(database, hypothesisId)?.status).toBe("candidate");
    expect(() => verifyHypothesisFromDynamicEvidence(database, run.id)).toThrow("supporting dynamic evidence");
  });

  it.each(["refuted", "inconclusive"] as const)("does not verify a %s result", (outcome) => {
    const run = complete(createRun(), outcome, [supportingEvidence]);
    expect(() => verifyHypothesisFromDynamicEvidence(database, run.id)).toThrow("completed, confirmed");
    expect(getVulnerabilityHypothesis(database, hypothesisId)?.status).toBe("candidate");
  });

  it("blocks manual verified status and keeps AI-created hypotheses candidate", () => {
    expect(getVulnerabilityHypothesis(database, hypothesisId)?.status).toBe("candidate");
    expect(() => updateVulnerabilityHypothesisStatus(database, hypothesisId, "verified" as "candidate")).toThrow("confirmed dynamic evidence");
    expect(getVulnerabilityHypothesis(database, hypothesisId)?.status).toBe("candidate");
  });
});
