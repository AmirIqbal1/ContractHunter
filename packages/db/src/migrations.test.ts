import Database from "better-sqlite3";
import { copyFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { counterexampleHash, executableInvariantPlanSchema, invariantPlanHash, invariantReplayPlanSchema, validAIOutput, type DynamicEvidence, type ProtocolAnalysisResult } from "@contracthunter/core";
import {
  closeDatabase, completeExecutableInvariantRun, completeHypothesisVerificationRun, createDatabase, createExecutableInvariantProposal, createExecutableInvariantRun,
  createHypothesisVerificationRun, createInvariantReplayArtifact, createInvariantReplayRun, createProtocolAnalysis, createScan, createSecurityReviewerRun,
  createSecurityReviewPlan, finishInvariantReplayRun, getVulnerabilityHypothesis, insertVulnerabilityHypotheses, markExecutableInvariantRunRunning,
  markHypothesisVerificationRunRunning, markInvariantReplayRunRunning,
  getExecutableInvariantRun, getInvariantReplayArtifact, reviewReproducedInvariantEvidence,
  executableInvariantProposals,
} from "./index";

const commit = "a".repeat(40);
const directories: string[] = [];
afterEach(() => {
  if (process.env.CONTRACTHUNTER_KEEP_UPGRADE_PROBE === "1") return;
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function verificationPlan(scanId: string, hypothesisId: string) {
  return {
    scanId, hypothesisId, resolvedCommit: commit, compilerVersion: "0.8.24", primaryContract: "BrokenAccessControl", primarySourcePath: "contracts/BrokenAccessControl.sol",
    actors: ["deployer", "attacker"],
    relevantFunctions: ["setOwner", "owner"], sourceFiles: ["contracts/BrokenAccessControl.sol"], verificationGoal: "Confirm that an unprivileged caller can replace the owner.", expectedProperty: "Only the current owner can replace the owner.", verificationSteps: ["Deploy, call as attacker, and read owner."],
    operations: [{ kind: "deploy" as const, contractName: "BrokenAccessControl", instanceName: "target" }, { kind: "call" as const, instanceName: "target", functionName: "setOwner", caller: "attacker" as const, args: [{ kind: "address" as const, source: "actor" as const, name: "attacker" }] }, { kind: "read-address" as const, instanceName: "target", functionName: "owner", resultName: "observed" }],
    assertions: [{ id: "attacker-became-owner", kind: "address-eq" as const, actual: "observed", expected: { kind: "address" as const, source: "actor" as const, name: "attacker" }, expectedOutcome: "hypothesis-supported" as const, description: "The attacker becomes owner." }],
  };
}

function invariantPlan(scanId: string, hypothesisId: string) {
  return executableInvariantPlanSchema.parse({
    schemaVersion: "contracthunter-invariant-plan-v1", mode: "fuzz-property", scanId, hypothesisId, resolvedCommit: commit, compilerVersion: "0.8.24", primaryContract: "BrokenAccessControl", primarySourcePath: "contracts/BrokenAccessControl.sol", sourceFiles: ["contracts/BrokenAccessControl.sol"], actors: ["deployer", "attacker"],
    setup: [{ kind: "deploy", contractName: "BrokenAccessControl", instanceName: "target" }],
    fuzzAction: { instanceName: "target", functionName: "setOwner", caller: "attacker", parameters: [{ name: "newOwner", type: "bool" }], args: [{ kind: "parameter", name: "newOwner" }] },
    property: { name: "ownerStable", observations: [{ kind: "read-address", instanceName: "target", functionName: "owner", resultName: "observed" }], assertions: [{ id: "owner", kind: "address-eq", actual: "observed", expected: { kind: "address", source: "actor", name: "deployer" } }] },
  });
}

function seedV019Shape(databasePath: string) {
  const database = createDatabase(databasePath);
  const scan = createScan(database, { repositoryUrl: "https://example.invalid/broken-access", repositoryName: "fixture/broken-access", depth: "deep" });
  database.sqlite.prepare("UPDATE scans SET status='completed', resolved_commit=?, compiler_status='ready', compiler_versions=?, ai_status='completed', review_status='completed' WHERE id=?").run(commit, JSON.stringify(["0.8.24"]), scan.id);
  const analysis = createProtocolAnalysis(database, { scanId: scan.id, provider: "mock", requestedModel: "historical-model", actualModel: "historical-model", promptVersion: "protocol-analysis-v1", result: validAIOutput as unknown as ProtocolAnalysisResult, coverageStatus: "complete", contextManifest: { historical: true }, durationMs: 2, inputTokens: 10, outputTokens: 20, totalTokens: 30, requestId: "historical-analysis" });
  const review = createSecurityReviewPlan(database, { scanId: scan.id, protocolAnalysisId: analysis.id, plan: { selected: [], skipped: [], estimatedRequestCount: 1 }, estimatedSourceBytes: 100 });
  const reviewer = createSecurityReviewerRun(database, { planId: review.id, scanId: scan.id, protocolAnalysisId: analysis.id, reviewerId: "access-control", reviewerName: "Access control", selectionReason: "Historical fixture", promptVersion: "security-review-access-control-v1", provider: "mock", requestedModel: "historical-model", contextManifest: { historical: true } });
  const hypothesis = insertVulnerabilityHypotheses(database, [{ scanId: scan.id, protocolAnalysisId: analysis.id, reviewerId: reviewer.reviewerId, reviewerRunId: reviewer.id, title: "Broken access control permits ownership replacement", category: "access-control", severity: "high", severityJustification: "An attacker can take ownership.", confidence: 95, summary: "Unprivileged ownership replacement.", rootCause: "setOwner lacks authorization.", preconditions: "[]", attackPath: "[]", impact: "Administrative compromise.", affectedAssets: "[]", affectedContracts: "[]", affectedFunctions: "[]", evidence: "[]", violatedInvariantIds: "[]", relatedInvestigationIds: "[]", falsePositiveRisks: "[]", verificationStrategy: "[]" }])[0];
  const supporting: DynamicEvidence = { assertionId: "attacker-became-owner", assertionName: "attacker became owner", expectedBehavior: "Only the owner can replace the owner.", observedBehavior: "The attacker replaced the owner.", direction: "supports", contract: "BrokenAccessControl", functionName: "setOwner", details: "Historical bounded structured verification." };
  const first = createHypothesisVerificationRun(database, { hypothesisId: hypothesis.id, scanId: scan.id, resolvedCommit: commit, compilerVersion: "0.8.24", verificationPlan: verificationPlan(scan.id, hypothesis.id), verifierId: "local-test-harness", toolName: "forge", toolVersion: "1.7.1", verificationStrategy: ["Historical structured verification"] });
  markHypothesisVerificationRunRunning(database, first.id);
  completeHypothesisVerificationRun(database, first.id, { outcome: "confirmed", resultSummary: "Historical BrokenAccessControl behavior confirmed.", durationMs: 12, testCount: 1, passedTestCount: 0, failedTestCount: 1, stdoutSummary: "historical stdout", stderrSummary: "", dynamicEvidence: [supporting], contentFingerprint: "b".repeat(64), isolationBackend: "docker-verification-worker-v1", executionExitCode: 1, timedOut: false });
  const failed = createHypothesisVerificationRun(database, { hypothesisId: hypothesis.id, scanId: scan.id, resolvedCommit: commit, compilerVersion: "0.8.24", verificationPlan: verificationPlan(scan.id, hypothesis.id), verifierId: "local-test-harness", toolName: "forge", toolVersion: "1.7.1", verificationStrategy: ["Historical retry"] });
  database.sqlite.prepare("UPDATE hypothesis_verification_runs SET status='failed', error='Historical failed retry.', completed_at=?, duration_ms=4 WHERE id=?").run(Date.now(), failed.id);
  closeDatabase(database);

  const raw = new Database(databasePath);
  raw.exec(`
    DROP TABLE invariant_evidence_reviews;
    DROP TABLE authoritative_invariant_evidence;
    DROP TABLE invariant_replay_runs;
    DROP TABLE invariant_replay_artifacts;
    DROP TABLE executable_invariant_proposals;
    DROP TABLE executable_invariant_runs;
    DROP TABLE hypothesis_lifecycle_transitions;
    DROP TABLE schema_migrations;
  `);
  raw.close();
  return { scanId: scan.id, hypothesisId: hypothesis.id, verificationIds: [first.id, failed.id] };
}

function snapshot(databasePath: string) {
  const raw = new Database(databasePath, { readonly: true });
  const result = Object.fromEntries(["scans", "protocol_analyses", "security_review_plans", "security_reviewer_runs", "vulnerability_hypotheses", "hypothesis_verification_runs"].map((table) => [table, raw.prepare(`SELECT * FROM ${table} ORDER BY rowid`).all()]));
  raw.close();
  return result;
}

describe("v0.1.9 to v0.2.0 migration", () => {
  it("upgrades a copy transactionally without changing historical rows, then accepts new invariant and replay history", () => {
    const directory = mkdtempSync(path.join(tmpdir(), "contracthunter-upgrade-")); directories.push(directory);
    const sourcePath = path.join(directory, "v0.1.9.db"), copyPath = path.join(directory, "v0.2.0-upgrade.db");
    const ids = seedV019Shape(sourcePath), before = snapshot(sourcePath); copyFileSync(sourcePath, copyPath);
    const upgraded = createDatabase(copyPath);
    expect(snapshot(copyPath)).toEqual(before);
    expect(getVulnerabilityHypothesis(upgraded, ids.hypothesisId)?.status).toBe("verified");
    expect(upgraded.sqlite.prepare("SELECT id, status, error FROM hypothesis_verification_runs ORDER BY created_at").all()).toEqual([
      { id: ids.verificationIds[0], status: "completed", error: null },
      { id: ids.verificationIds[1], status: "failed", error: "Historical failed retry." },
    ]);
    expect((upgraded.sqlite.prepare("SELECT id FROM schema_migrations").pluck().all() as string[])).toEqual(["0001_v0_2_0_release_schema", "0002_v0_2_1_echidna_public", "0003_v0_2_1_run_proposal_binding"]);

    const plan = invariantPlan(ids.scanId, ids.hypothesisId), planHash = invariantPlanHash(plan);
    expect(() => createExecutableInvariantRun(upgraded, { plan, proposalId: crypto.randomUUID() })).toThrow("Invariant plan does not match persisted scan identity");
    const proposal = createExecutableInvariantProposal(upgraded, { hypothesisId: ids.hypothesisId, scanId: ids.scanId, result: { status: "generated", plan, planHash, hypothesisExpectation: "hypothesis-predicts-property-violation", relationRationale: "The hypothesis predicts ownership instability.", rationale: "Upgrade probe.", limitations: [], notPlannableReasons: [], failureCode: null, provenance: { provider: "mock", requestedModel: "mock", actualModel: "mock", promptVersion: "invariant-plan-v1", generatedAt: new Date().toISOString(), inputTokens: 1, outputTokens: 1, totalTokens: 2, estimatedCostUsd: 0, durationMs: 1, sourceFileCount: 1, totalSourceBytes: 100, sourceContextTruncated: false } }, contextManifest: { sourceHashes: {} }, requestId: "upgrade-probe" });
    const run = createExecutableInvariantRun(upgraded, { plan, proposalId: proposal.id }); markExecutableInvariantRunRunning(upgraded, run.id);
    const counterexample = { kind: "single" as const, parserVersion: "foundry-1.7.1-json-v1" as const, parameterValues: [{ name: "newOwner", type: "bool" as const, value: true }], summary: "Upgrade probe counterexample." };
    completeExecutableInvariantRun(upgraded, run.id, { evidence: [{ planHash, mode: "fuzz-property", propertyName: "ownerStable", configuredRuns: 128, configuredDepth: null, runsExecuted: 1, propertyOutcome: "counterexample-found", hypothesisRelation: "unreviewed", compilerVersion: "0.8.24", isolationProvider: "docker-verification-worker-v1", counterexample, summary: "Counterexample found." }], testCount: 1, passedCount: 0, failedCount: 1, runsExecuted: 1, stdoutSummary: "bounded", stderrSummary: "", contentFingerprint: "c".repeat(64), isolationMetadata: "{}", exitCode: 1, durationMs: 2 });
    const replayPlan = invariantReplayPlanSchema.parse({ schemaVersion: "contracthunter-invariant-replay-v1", scanId: ids.scanId, hypothesisId: ids.hypothesisId, resolvedCommit: commit, compilerVersion: "0.8.24", proposalId: proposal.id, invariantRunId: run.id, invariantPlanHash: planHash, propertyName: "ownerStable", hypothesisExpectation: "hypothesis-predicts-property-violation", counterexample, counterexampleHash: counterexampleHash(counterexample) });
    const otherProposalId = crypto.randomUUID(); upgraded.orm.insert(executableInvariantProposals).values({ ...proposal, id: otherProposalId }).run();
    expect(() => createInvariantReplayArtifact(upgraded, { id: crypto.randomUUID(), proposalId: otherProposalId, invariantRunId: run.id, replayPlan: { ...replayPlan, proposalId: otherProposalId }, harnessHash: "d".repeat(64), contentFingerprint: "e".repeat(64) })).toThrow("Replay artifact identity is invalid");
    const artifact = createInvariantReplayArtifact(upgraded, { id: crypto.randomUUID(), proposalId: proposal.id, invariantRunId: run.id, replayPlan, harnessHash: "d".repeat(64), contentFingerprint: "e".repeat(64) });
    expect(() => createInvariantReplayArtifact(upgraded, { id: crypto.randomUUID(), proposalId: proposal.id, invariantRunId: run.id, replayPlan: { ...replayPlan, sourceEngine: "echidna" }, harnessHash: "d".repeat(64), contentFingerprint: "e".repeat(64) })).toThrow("Replay artifact identity is invalid");
    const replayRun = createInvariantReplayRun(upgraded, artifact.id); markInvariantReplayRunRunning(upgraded, replayRun.id); finishInvariantReplayRun(upgraded, replayRun.id, { outcome: "reproduced", exitCode: 0, timedOut: false, errorCode: null, isolationMetadata: "{}", durationMs: 1 });
    reviewReproducedInvariantEvidence(upgraded, { hypothesisId: ids.hypothesisId, proposalId: proposal.id, invariantRunId: run.id, replayRunId: replayRun.id });
    expect(upgraded.sqlite.prepare("SELECT count(*) AS count FROM executable_invariant_proposals").get()).toEqual({ count: 2 });
    expect(upgraded.sqlite.prepare("SELECT count(*) AS count FROM executable_invariant_runs").get()).toEqual({ count: 1 });
    expect(upgraded.sqlite.prepare("SELECT count(*) AS count FROM invariant_replay_runs").get()).toEqual({ count: 1 });
    closeDatabase(upgraded);

    // Model an existing v0.2.0 installation with its invariant/replay/review history.
    const v020Path = path.join(directory, "v0.2.0-shaped.db"); copyFileSync(copyPath, v020Path);
    const old = new Database(v020Path);
    old.exec("DROP INDEX executable_invariant_runs_proposal_idx; ALTER TABLE executable_invariant_runs DROP COLUMN proposal_id; ALTER TABLE executable_invariant_runs DROP COLUMN engine_metadata; ALTER TABLE executable_invariant_runs DROP COLUMN engine; ALTER TABLE invariant_replay_artifacts DROP COLUMN source_engine; DELETE FROM schema_migrations WHERE id IN ('0002_v0_2_1_echidna_public', '0003_v0_2_1_run_proposal_binding')");
    old.close();
    const migrated = createDatabase(v020Path);
    expect(getExecutableInvariantRun(migrated, run.id)?.engine).toBe("foundry");
    expect(getInvariantReplayArtifact(migrated, artifact.id)?.sourceEngine).toBe("foundry");
    expect(migrated.sqlite.prepare("SELECT count(*) AS count FROM invariant_evidence_reviews").get()).toEqual({ count: 1 });
    expect(migrated.sqlite.prepare("SELECT count(*) AS count FROM authoritative_invariant_evidence").get()).toEqual({ count: 1 });
    expect(getVulnerabilityHypothesis(migrated, ids.hypothesisId)?.status).toBe("verified");
    if (plan.mode !== "fuzz-property") throw new Error("Fixture requires a fuzz plan.");
    const { property, fuzzAction, ...base } = plan;
    void fuzzAction;
    const stateful = executableInvariantPlanSchema.parse({ ...base, mode: "stateful-invariant", handlerActions: [{ name: "replaceOwner", instanceName: "target", functionName: "setOwner", parameters: [{ name: "newOwner", type: "bool" }], args: [{ kind: "parameter", name: "newOwner" }] }], properties: [property] });
    const echidnaRun = createExecutableInvariantRun(migrated, { plan: stateful, engine: "echidna" });
    expect(echidnaRun.engine).toBe("echidna"); markExecutableInvariantRunRunning(migrated, echidnaRun.id);
    expect(() => completeExecutableInvariantRun(migrated, echidnaRun.id, { evidence: [{ engine: "foundry", planHash: invariantPlanHash(stateful), mode: "stateful-invariant", propertyName: "ownerStable", configuredRuns: 128, configuredDepth: 32, runsExecuted: 128, propertyOutcome: "held-within-bounds", hypothesisRelation: "neutral", compilerVersion: "0.8.24", isolationProvider: "test", counterexample: null, summary: "Bounded" }], testCount: 1, passedCount: 1, failedCount: 0, runsExecuted: 128, stdoutSummary: "", stderrSummary: "", contentFingerprint: "c".repeat(64), isolationMetadata: "{}", exitCode: 0, durationMs: 1 })).toThrow("Invariant evidence does not match the run");
    const unmappable = completeExecutableInvariantRun(migrated, echidnaRun.id, { evidence: [{ engine: "echidna", planHash: invariantPlanHash(stateful), mode: "stateful-invariant", propertyName: "ownerStable", configuredRuns: 128, configuredDepth: 32, runsExecuted: 128, propertyOutcome: "counterexample-found", hypothesisRelation: "unreviewed", compilerVersion: "0.8.24", isolationProvider: "test", counterexample: null, replayAvailable: false, replayUnavailableReason: "sequence-not-exactly-mappable", summary: "Bounded Echidna observation." }], testCount: 1, passedCount: 0, failedCount: 1, runsExecuted: 128, stdoutSummary: "", stderrSummary: "", contentFingerprint: "c".repeat(64), isolationMetadata: "{}", exitCode: 1, durationMs: 1 });
    expect(unmappable.outcome).toBe("counterexample-found"); expect(JSON.parse(unmappable.dynamicEvidence)[0].replayAvailable).toBe(false);
    closeDatabase(migrated);
    const reopened = createDatabase(v020Path);
    expect((reopened.sqlite.prepare("SELECT id FROM schema_migrations ORDER BY id").pluck().all() as string[])).toEqual(["0001_v0_2_0_release_schema", "0002_v0_2_1_echidna_public", "0003_v0_2_1_run_proposal_binding"]);
    expect(getExecutableInvariantRun(reopened, run.id)?.engine).toBe("foundry"); closeDatabase(reopened);

    expect(snapshot(sourcePath)).toEqual(before);
    const untouched = new Database(sourcePath, { readonly: true });
    expect(untouched.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations'").get()).toBeUndefined(); untouched.close();
  });
});
