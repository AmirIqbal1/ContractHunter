import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { executableInvariantPlanSchema, invariantPlanHash, validAIOutput, verificationHarnessPlanSchema, type ProtocolAnalysisResult, type VerificationHarnessPlan } from "@contracthunter/core";
import {
  closeDatabase, createDatabase, createProtocolAnalysis, createScan, createSecurityReviewerRun, createSecurityReviewPlan,
  getActiveHypothesisVerificationRun, getVulnerabilityHypothesis, insertVulnerabilityHypotheses, listExecutableInvariantRuns, listHypothesisVerificationRuns,
  updateVulnerabilityHypothesisStatus, type DatabaseClient,
} from "@contracthunter/db";
import {
  VerificationWorkspaceBuilder, interpretVerificationResult, validateVerificationWorkspaceIntegrity,
  type ExecutableInvariantWorkerResult, type FoundryVerificationResult, type VerificationIsolationMetadata,
} from "@contracthunter/scanners";
import { HypothesisVerificationRequestError, HypothesisVerificationService } from "./hypothesis-verification-service";
import { ExecutableInvariantService } from "./executable-invariant-service";

const commit = "a".repeat(40);
const fingerprint = "b".repeat(64);
const fixture = path.resolve("packages/scanners/fixtures/verification");
let directory: string; let repositoryRoot: string; let repository: string; let verificationRoot: string;
let database: DatabaseClient; let scanId: string; let hypothesisId: string;

const isolation: VerificationIsolationMetadata = {
  providerId: "test-isolation", isolationVersion: "1", networkAccess: "disabled", networkIsolated: true, processIsolated: true,
  resourceLimitsApplied: { maxCpuTimeSeconds: 10, maxVirtualMemoryBytes: 536_870_912, maxProcesses: 16, maxOpenFiles: 64, maxFileSizeBytes: 1_048_576 },
  wallClockTimeoutMs: 5_000, maxOutputBytes: 8_192, writableProjectPath: "/controlled/workspace",
};

function runnerResult(overrides: Partial<FoundryVerificationResult> = {}): FoundryVerificationResult {
  return { status: "completed", exitCode: 0, durationMs: 12, timedOut: false, testCount: 1, passedCount: 1, failedCount: 0, stdoutSummary: "1 passed; 0 failed;", stderrSummary: "", stdoutTruncated: false, stderrTruncated: false, outputTruncated: false, errorCode: null, errorMessage: null, isolation, ...overrides };
}

beforeEach(async () => {
  directory = await mkdtemp(path.join(tmpdir(), "contracthunter-verification-service-")); repositoryRoot = path.join(directory, "repositories"); verificationRoot = path.join(directory, "verifications");
  await mkdir(repositoryRoot); database = createDatabase(path.join(directory, "test.db"));
  const scan = createScan(database, { repositoryUrl: "https://github.com/example/fixture", repositoryName: "example/fixture", depth: "quick" }); scanId = scan.id; repository = path.join(repositoryRoot, scanId);
  await cp(fixture, repository, { recursive: true });
  database.sqlite.prepare("UPDATE scans SET status = 'completed', resolved_commit = ?, compiler_status = 'ready', compiler_versions = ? WHERE id = ?").run(commit, JSON.stringify(["0.8.24"]), scanId);
  const analysis = createProtocolAnalysis(database, { scanId, provider: "mock", requestedModel: "mock", actualModel: "mock", promptVersion: "protocol-analysis-v1", result: validAIOutput as unknown as ProtocolAnalysisResult, coverageStatus: "complete", contextManifest: {}, durationMs: 1, inputTokens: 1, outputTokens: 1, totalTokens: 2, requestId: "analysis" });
  const reviewPlan = createSecurityReviewPlan(database, { scanId, protocolAnalysisId: analysis.id, plan: { selected: [], skipped: [], estimatedRequestCount: 0 }, estimatedSourceBytes: 0 });
  const reviewer = createSecurityReviewerRun(database, { planId: reviewPlan.id, scanId, protocolAnalysisId: analysis.id, reviewerId: "accounting", reviewerName: "Accounting", selectionReason: "Fixture", promptVersion: "security-review-accounting-v1", provider: "mock", requestedModel: "mock", contextManifest: {} });
  hypothesisId = insertVulnerabilityHypotheses(database, [{ scanId, protocolAnalysisId: analysis.id, reviewerId: "accounting", reviewerRunId: reviewer.id, title: "Counter transition hypothesis", category: "state-transition", severity: "low", severityJustification: "The fixture tests deterministic state semantics.", confidence: 60, summary: "A benign counter should move through its expected state.", rootCause: "The selected public function controls the counter transition under test.", preconditions: "[]", attackPath: "[]", impact: "This is a benign orchestration fixture.", affectedAssets: "[]", affectedContracts: JSON.stringify(["Counter"]), affectedFunctions: JSON.stringify(["increment", "count"]), evidence: JSON.stringify([{ filePath: "contracts/Counter.sol", contract: "Counter", functionName: "increment", startLine: 9, endLine: 11, explanation: "Fixture evidence.", valid: true, validationError: null }]), violatedInvariantIds: "[]", relatedInvestigationIds: "[]", falsePositiveRisks: "[]", verificationStrategy: JSON.stringify(["Deploy, increment, and read count."]) }])[0].id;
});

describe("executable invariant history without hypothesis status transitions", () => {
  function invariantPlan() {
    return executableInvariantPlanSchema.parse({ schemaVersion: "contracthunter-invariant-plan-v1", mode: "fuzz-property", scanId, hypothesisId, resolvedCommit: commit, compilerVersion: "0.8.24", primaryContract: "VulnerableAccounting", primarySourcePath: "contracts/VulnerableAccounting.sol", sourceFiles: ["contracts/VulnerableAccounting.sol"], actors: ["deployer", "attacker"], setup: [{ kind: "deploy", contractName: "VulnerableAccounting", instanceName: "target" }], fuzzAction: { instanceName: "target", functionName: "record", caller: "attacker", parameters: [{ name: "amount", type: "uint256" }], args: [{ kind: "parameter", name: "amount" }] }, property: { name: "accounting", observations: [{ kind: "read-uint", instanceName: "target", functionName: "totalRecordedBalance", resultName: "recorded" }, { kind: "read-balance", target: { kind: "instance", name: "target" }, resultName: "nativeBalance" }], assertions: [{ id: "conservation", kind: "uint-eq", actual: "recorded", expected: { kind: "result", name: "nativeBalance" } }] } });
  }
  function instance(run: (input: { planHash: string; mode: "fuzz-property" | "stateful-invariant" }) => Promise<ExecutableInvariantWorkerResult>) {
    return new ExecutableInvariantService({ database, repositoryRoot, runner: { run }, workspaceBuilder: (compilers) => new VerificationWorkspaceBuilder({ verificationRoot, repositoryRoot, acceptedCompilerVersions: compilers, approvedSourceRoots: ["contracts"], generatorVersion: "0.2.0" }) });
  }
  async function fixture() { await writeFile(path.join(repository, "contracts/VulnerableAccounting.sol"), await readFile(path.resolve("packages/scanners/fixtures/invariants/contracts/VulnerableAccounting.sol"))); }
  it("persists bounded support and counterexamples as immutable separate runs", async () => {
    await fixture(); const plan = invariantPlan(), hash = invariantPlanHash(plan);
    const pass = async (input: { planHash: string; mode: "fuzz-property" | "stateful-invariant" }): Promise<ExecutableInvariantWorkerResult> => ({ ...runnerResult(), compilerIdentity: { version: "0.8.24", executablePath: "/trusted/solc" }, mode: input.mode, planHash: input.planHash, runsExecuted: 128, tests: [{ propertyName: "accounting", testName: "testFuzz_accounting(uint256)", status: "passed", runsExecuted: 128, reason: null, counterexample: null }] });
    const first = await instance(pass).run(hypothesisId, plan);
    expect(first).toMatchObject({ status: "completed", run: { outcome: "held-within-bounds", planHash: hash, configuredRuns: 128, configuredDepth: null } });
    expect(JSON.parse(first.run.dynamicEvidence)).toMatchObject([{ direction: "supports", summary: "No counterexample found within configured runs." }]);
    expect(getVulnerabilityHypothesis(database, hypothesisId)?.status).toBe("candidate");
    const fail = async (input: { planHash: string; mode: "fuzz-property" | "stateful-invariant" }): Promise<ExecutableInvariantWorkerResult> => ({ ...await pass(input), exitCode: 1, passedCount: 0, failedCount: 1, runsExecuted: 0, tests: [{ propertyName: "accounting", testName: "testFuzz_accounting(uint256)", status: "failed", runsExecuted: 0, reason: "CH_ASSERT_0", counterexample: { kind: "single", fuzzArguments: ["436"], actionSequence: [], summary: "436" } }] });
    const second = await instance(fail).run(hypothesisId, plan);
    expect(second).toMatchObject({ status: "completed", run: { outcome: "counterexample-found" } });
    expect(JSON.parse(second.run.dynamicEvidence)).toMatchObject([{ direction: "contradicts", counterexample: { fuzzArguments: ["436"] } }]);
    expect(listExecutableInvariantRuns(database, hypothesisId)).toHaveLength(2);
    expect(listExecutableInvariantRuns(database, hypothesisId).find((item) => item.id === first.run.id)?.dynamicEvidence).toBe(first.run.dynamicEvidence);
    expect(getVulnerabilityHypothesis(database, hypothesisId)?.status).toBe("candidate");
  });
  it("records worker refusal and never tries a web execution fallback", async () => {
    await fixture(); const runner = vi.fn(async (input: { planHash: string; mode: "fuzz-property" | "stateful-invariant" }): Promise<ExecutableInvariantWorkerResult> => ({ ...runnerResult({ status: "refused", exitCode: null, testCount: null, passedCount: null, failedCount: null, isolation: null, errorCode: "invariant_worker_isolation_unavailable" }), mode: input.mode, planHash: input.planHash, runsExecuted: null, tests: [] }));
    expect(await instance(runner).run(hypothesisId, invariantPlan())).toMatchObject({ status: "failed", run: { status: "failed", errorCode: "invariant_worker_isolation_unavailable" } });
    expect(runner).toHaveBeenCalledTimes(1); expect(getVulnerabilityHypothesis(database, hypothesisId)?.status).toBe("candidate");
  });
  it("does not persist evidence from timed out or truncated worker output", async () => {
    await fixture(); const plan = invariantPlan();
    const timedOut = async (input: { planHash: string; mode: "fuzz-property" | "stateful-invariant" }): Promise<ExecutableInvariantWorkerResult> => ({ ...runnerResult({ status: "failed", exitCode: -1, timedOut: true, testCount: null, passedCount: null, failedCount: null, errorCode: "invariant_execution_timeout" }), mode: input.mode, planHash: input.planHash, runsExecuted: null, tests: [] });
    const first = await instance(timedOut).run(hypothesisId, plan);
    expect(first).toMatchObject({ status: "failed", run: { errorCode: "invariant_execution_timeout", timedOut: true, dynamicEvidence: "[]" } });
    const truncated = async (input: { planHash: string; mode: "fuzz-property" | "stateful-invariant" }): Promise<ExecutableInvariantWorkerResult> => ({ ...runnerResult({ stdoutTruncated: true, outputTruncated: true }), mode: input.mode, planHash: input.planHash, runsExecuted: 128, tests: [{ propertyName: "accounting", testName: "testFuzz_accounting(uint256)", status: "passed", runsExecuted: 128, reason: null, counterexample: null }] });
    const second = await instance(truncated).run(hypothesisId, plan);
    expect(second).toMatchObject({ status: "failed", run: { errorCode: "invariant_result_unparseable", dynamicEvidence: "[]" } });
    expect(listExecutableInvariantRuns(database, hypothesisId)).toHaveLength(2);
  });
});

afterEach(async () => { closeDatabase(database); await rm(directory, { recursive: true, force: true }); });

function plan(overrides: Partial<VerificationHarnessPlan> = {}): VerificationHarnessPlan {
  return verificationHarnessPlanSchema.parse({
    scanId, hypothesisId, resolvedCommit: commit, compilerVersion: "0.8.24", primaryContract: "Counter", primarySourcePath: "contracts/Counter.sol",
    relevantFunctions: ["increment", "count"], sourceFiles: ["contracts/Counter.sol"], verificationGoal: "Check a benign deterministic counter transition.", expectedProperty: "Increment changes count from zero to one.", verificationSteps: ["Deploy Counter.", "Call increment.", "Read count."],
    operations: [{ kind: "deploy", contractName: "Counter", instanceName: "target" }, { kind: "call", instanceName: "target", functionName: "increment" }, { kind: "read-uint", instanceName: "target", functionName: "count", resultName: "observed" }],
    assertions: [{ id: "count-is-one", kind: "uint-eq", actual: "observed", expected: "1", expectedOutcome: "hypothesis-supported", description: "Count equals one." }], ...overrides,
  });
}

function accessControlPlan(contractName = "BrokenAccessControl"): VerificationHarnessPlan {
  return verificationHarnessPlanSchema.parse({
    scanId, hypothesisId, resolvedCommit: commit, compilerVersion: "0.8.24", primaryContract: contractName, primarySourcePath: `contracts/${contractName}.sol`, sourceFiles: [`contracts/${contractName}.sol`],
    relevantFunctions: ["setOwner", "owner", "withdraw"], actors: ["deployer", "attacker"], verificationGoal: "Observe unauthorized ownership replacement and withdrawal.", expectedProperty: "Only the owner can replace owner.", verificationSteps: ["Deploy and fund.", "Call as attacker.", "Read owner and balance."],
    operations: [{ kind: "deploy", contractName, instanceName: "target" }, { kind: "fund", target: { kind: "instance", name: "target" }, amountWei: "1000000000000000000" }, { kind: "call", instanceName: "target", functionName: "setOwner", caller: "attacker", args: [{ kind: "address", source: "actor", name: "attacker" }] }, { kind: "read-address", instanceName: "target", functionName: "owner", resultName: "ownerAfter" }, { kind: "call", instanceName: "target", functionName: "withdraw", caller: "attacker", args: [] }, { kind: "read-balance", target: { kind: "instance", name: "target" }, resultName: "targetBalance" }],
    assertions: [{ id: "attacker-is-owner", kind: "address-eq", actual: "ownerAfter", expected: { kind: "address", source: "actor", name: "attacker" }, expectedOutcome: "hypothesis-supported", description: "The unauthorized attacker becomes the observed owner." }, { id: "target-drained", kind: "uint-eq", actual: "targetBalance", expected: "0", expectedOutcome: "hypothesis-supported", description: "The target native balance is zero after attacker withdrawal." }],
  });
}

function service(result: FoundryVerificationResult | (() => Promise<FoundryVerificationResult>) = runnerResult(), overrides: Partial<ConstructorParameters<typeof HypothesisVerificationService>[0]> = {}) {
  const run = typeof result === "function" ? result : async () => result;
  return new HypothesisVerificationService({
    database, repositoryRoot, timeoutMs: 5_000, maxOutputBytes: 8_192, runner: { run },
    workspaceBuilder: (compilers) => new VerificationWorkspaceBuilder({ verificationRoot, repositoryRoot, acceptedCompilerVersions: compilers, approvedSourceRoots: ["contracts", "lib"], generatorVersion: "0.1.0" }),
    ...overrides,
  });
}

describe("verification result interpretation", () => {
  it("maps controlled assertion semantics to supporting and contradicting evidence", () => {
    const supporting = interpretVerificationResult(plan(), runnerResult());
    expect(supporting).toMatchObject({ outcome: "confirmed", dynamicEvidence: [{ assertionId: "count-is-one", direction: "supports" }] });
    const contradicting = interpretVerificationResult(plan({ assertions: [{ ...plan().assertions[0], expectedOutcome: "hypothesis-contradicted" }] }), runnerResult());
    expect(contradicting).toMatchObject({ outcome: "refuted", dynamicEvidence: [{ direction: "contradicts" }] });
  });

  it("does not confirm from process success alone and treats incomplete output as inconclusive", () => {
    expect(interpretVerificationResult(plan(), runnerResult({ testCount: null, passedCount: null, failedCount: null })).outcome).toBe("inconclusive");
    expect(interpretVerificationResult(plan(), runnerResult({ outputTruncated: true })).dynamicEvidence[0].direction).toBe("neutral");
  });

  it("recognises only controlled assertion markers and handles mixed evidence conservatively", () => {
    const failed = runnerResult({ status: "failed", exitCode: 1, passedCount: 0, failedCount: 1, stdoutSummary: "0 passed; 1 failed;", stderrSummary: "[FAIL: CH_ASSERT_0]", errorCode: "forge_failed", errorMessage: "Forge failed." });
    expect(interpretVerificationResult(plan(), failed)).toMatchObject({ outcome: "refuted", dynamicEvidence: [{ direction: "contradicts" }] });
    const mixedPlan = plan({ assertions: [{ ...plan().assertions[0], id: "supports" }, { ...plan().assertions[0], id: "contradicts", expectedOutcome: "hypothesis-contradicted" }] });
    expect(interpretVerificationResult(mixedPlan, runnerResult()).outcome).toBe("inconclusive");
    expect(interpretVerificationResult(plan(), { ...failed, stderrSummary: "arbitrary failure prose" }).outcome).toBe("inconclusive");
  });

  it("describes observed actor ownership precisely and does not confirm a remediated revert", () => {
    const vulnerable = interpretVerificationResult(accessControlPlan(), runnerResult());
    expect(vulnerable.outcome).toBe("confirmed");
    expect(vulnerable.dynamicEvidence[0]).toMatchObject({ direction: "supports", functionName: "owner" });
    expect(vulnerable.dynamicEvidence[0].observedBehavior).toContain("Local non-deployer actor attacker called setOwner");
    expect(vulnerable.dynamicEvidence[1]).toMatchObject({ direction: "supports", functionName: "withdraw" });
    expect(vulnerable.dynamicEvidence[1].observedBehavior).toContain("Local actor attacker successfully called withdraw()");
    const remediatedRevert = runnerResult({ status: "failed", exitCode: 1, passedCount: 0, failedCount: 1, stdoutSummary: "0 passed; 1 failed;", stderrSummary: "[FAIL: Not owner]", errorCode: "forge_failed", errorMessage: "Forge failed." });
    const remediated = interpretVerificationResult(accessControlPlan("RemediatedAccessControl"), remediatedRevert);
    expect(remediated.outcome).toBe("inconclusive"); expect(remediated.dynamicEvidence.every((item) => item.direction === "neutral")).toBe(true);
  });
});

describe("explicit hypothesis verification orchestration", () => {
  it("runs the generated BrokenAccessControl workspace through the result interpretation boundary", async () => {
    const result = await service(runnerResult(), { runner: { run: async (input) => { await validateVerificationWorkspaceIntegrity(input.workspacePath); return runnerResult({ stdoutSummary: "Ran 1 test suite: 1 test passed, 0 failed, 0 skipped" }); } } }).run(hypothesisId, accessControlPlan());
    expect(result).toMatchObject({ status: "completed", run: { outcome: "confirmed", compilerVersion: "0.8.24" } });
    expect(JSON.parse(result.run.dynamicEvidence)).toEqual([expect.objectContaining({ direction: "supports", functionName: "owner" }), expect.objectContaining({ direction: "supports", functionName: "withdraw" })]);
  });

  it("binds persisted state, runs queued -> running -> completed, audits execution, and verifies only with support", async () => {
    let observedStatus: string | undefined;
    const result = await service(async () => { observedStatus = getActiveHypothesisVerificationRun(database, hypothesisId)?.status; return runnerResult(); }).run(hypothesisId, plan());
    expect(observedStatus).toBe("running"); expect(result).toMatchObject({ status: "completed", run: { status: "completed", outcome: "confirmed", compilerVersion: "0.8.24", contentFingerprint: expect.any(String), isolationBackend: "test-isolation", executionExitCode: 0, timedOut: false } });
    expect(result.run.contentFingerprint).not.toBe(fingerprint); expect(JSON.parse(result.run.verificationPlan)).toEqual(plan());
    expect(JSON.parse(result.run.dynamicEvidence)).toEqual([expect.objectContaining({ assertionId: "count-is-one", direction: "supports" })]);
    expect(getVulnerabilityHypothesis(database, hypothesisId)?.status).toBe("verified");
  });

  it.each([
    ["refuted", "hypothesis-contradicted", "refuted"],
    ["inconclusive", "hypothesis-supported", "inconclusive"],
  ] as const)("persists a %s completion without verifying", async (_label, expectedOutcome, outcome) => {
    const execution = outcome === "inconclusive" ? runnerResult({ testCount: null, passedCount: null, failedCount: null }) : runnerResult();
    const result = await service(execution).run(hypothesisId, plan({ assertions: [{ ...plan().assertions[0], expectedOutcome }] }));
    expect(result).toMatchObject({ status: "completed", run: { outcome } }); expect(getVulnerabilityHypothesis(database, hypothesisId)?.status).toBe("candidate");
  });

  it("fails closed for isolation unavailability and timeout", async () => {
    const unavailable = runnerResult({ status: "refused", exitCode: null, testCount: null, passedCount: null, failedCount: null, errorCode: "verification_worker_isolation_unavailable", errorMessage: "Unavailable.", isolation: null });
    expect(await service(unavailable).run(hypothesisId, plan())).toMatchObject({ status: "failed", run: { status: "failed", outcome: null, error: "verification_worker_isolation_unavailable" } });
    expect(getVulnerabilityHypothesis(database, hypothesisId)?.status).toBe("candidate");
    const second = runnerResult({ status: "failed", exitCode: -1, timedOut: true, testCount: null, passedCount: null, failedCount: null, errorCode: "verification_worker_timeout", errorMessage: "Timed out." });
    expect(await service(second).run(hypothesisId, plan())).toMatchObject({ status: "failed", run: { error: "verification_worker_timeout", timedOut: true } });
    const compilerUnavailable = runnerResult({ status: "refused", exitCode: null, testCount: null, passedCount: null, failedCount: null, errorCode: "trusted_compiler_unavailable", errorMessage: "Unavailable.", isolation: null });
    expect(await service(compilerUnavailable).run(hypothesisId, plan())).toMatchObject({ status: "failed", run: { error: "trusted_compiler_unavailable" } });
  });

  it("revalidates immediately before execution and records tampering as failure", async () => {
    const runner = vi.fn(async () => runnerResult());
    const instance = service(runnerResult(), { runner: { run: runner }, validateIntegrity: async (workspacePath) => {
      await writeFile(path.join(workspacePath, "test/ContractHunterVerification.t.sol"), "contract Tampered {}");
      return validateVerificationWorkspaceIntegrity(workspacePath);
    } });
    expect(await instance.run(hypothesisId, plan())).toMatchObject({ status: "failed", run: { error: "workspace_integrity_or_execution_failed" } });
    expect(runner).not.toHaveBeenCalled();
  });

  it("fails when the on-disk manifest no longer matches the builder expectation", async () => {
    const runner = vi.fn(async () => runnerResult());
    const instance = service(runnerResult(), { runner: { run: runner }, validateIntegrity: async (workspacePath) => {
      const filename = path.join(workspacePath, ".contracthunter-verification.json");
      const manifest = JSON.parse(await readFile(filename, "utf8")) as Record<string, unknown>;
      manifest.createdAt = "2026-08-16T00:00:00.000Z"; await writeFile(filename, JSON.stringify(manifest));
      return validateVerificationWorkspaceIntegrity(workspacePath);
    } });
    expect(await instance.run(hypothesisId, plan())).toMatchObject({ status: "failed", run: { error: "workspace_integrity_or_execution_failed" } });
    expect(runner).not.toHaveBeenCalled();
  });

  it("preserves rerun history and refuses a simultaneous duplicate", async () => {
    await service().run(hypothesisId, plan());
    updateVulnerabilityHypothesisStatus(database, hypothesisId, "candidate");
    await service().run(hypothesisId, plan());
    expect(listHypothesisVerificationRuns(database, hypothesisId)).toHaveLength(2);
    updateVulnerabilityHypothesisStatus(database, hypothesisId, "candidate");
    let release!: () => void; const gate = new Promise<void>((resolve) => { release = resolve; });
    const first = service(async () => { await gate; return runnerResult(); }).run(hypothesisId, plan());
    await vi.waitFor(() => expect(getActiveHypothesisVerificationRun(database, hypothesisId)?.status).toBe("running"));
    const conflict = await service().run(hypothesisId, plan()); expect(conflict).toMatchObject({ status: "conflict", run: { status: "running" } });
    release(); await first;
  });

  it("rejects untrusted bindings and request-shaped executable fields before creating a run", async () => {
    const invalid = [
      plan({ scanId: crypto.randomUUID() }), plan({ hypothesisId: crypto.randomUUID() }), plan({ resolvedCommit: "c".repeat(40) }), plan({ compilerVersion: "0.8.25" }),
      { ...plan(), repositoryPath: "/tmp/attacker" }, { ...plan(), command: "forge test" }, { ...plan(), forgeArgs: ["--ffi"] }, { ...plan(), soliditySource: "contract Arbitrary {}" },
    ];
    for (const candidate of invalid) await expect(service().run(hypothesisId, candidate)).rejects.toBeInstanceOf(HypothesisVerificationRequestError);
    expect(listHypothesisVerificationRuns(database, hypothesisId)).toHaveLength(0);
    await expect(service().run(crypto.randomUUID(), plan({ hypothesisId: crypto.randomUUID() }))).rejects.toMatchObject({ code: "unknown_hypothesis" });
    updateVulnerabilityHypothesisStatus(database, hypothesisId, "rejected");
    await expect(service().run(hypothesisId, plan())).rejects.toMatchObject({ code: "invalid_state" });
  });

  it("does not start verification when scans or hypotheses are created", () => {
    expect(listHypothesisVerificationRuns(database, hypothesisId)).toEqual([]);
  });
});
