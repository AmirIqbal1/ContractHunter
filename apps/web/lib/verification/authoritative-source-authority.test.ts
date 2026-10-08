import { createHash, randomUUID } from "node:crypto";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { COMPILATION_MANIFEST_SCHEMA, SOURCE_CLOSURE_FINGERPRINT_SCHEMA, counterexampleHash, executableInvariantPlanSchema, invariantPlanHash, invariantReplayPlanSchema, validAIOutput, type ProtocolAnalysisResult, type VerificationPlanProvider, type InvariantProposalProvider, type VerificationHarnessPlan } from "@contracthunter/core";
import { closeDatabase, createDatabase, createProtocolAnalysis, createScan, createSecurityReviewPlan, createSecurityReviewerRun, createVerificationPlanAttempt, finalizeScanCompilation, finalizeScanSourceSnapshot, getVulnerabilityHypothesis, insertFindings, insertScannerAlignment, insertVulnerabilityHypotheses, listVerificationPlanAttempts, listExecutableInvariantProposals, reconcileInvestigations, type DatabaseClient } from "@contracthunter/db";
import { VerificationWorkspaceBuilder } from "@contracthunter/scanners";
import { InvariantProposalService } from "./invariant-proposal-service";
import { VerificationPlanGenerationService } from "./verification-plan-generation-service";
import { requireAuthoritativeSourceClosureForHypothesis, sourceAuthorityForHypothesis } from "./authoritative-source-authority";

const commit = "a".repeat(40);
const original = 'pragma solidity 0.8.24; import "./Math.sol"; contract Counter { uint256 public count; function increment() external { count = Math.plusOne(count); } }';
const dependency = 'pragma solidity 0.8.24; library Math { function plusOne(uint256 value) internal pure returns (uint256) { return value + 1; } }';
const bytes = (name: string, content: string | Buffer) => { const rawBytes = Buffer.isBuffer(content) ? content : Buffer.from(content); return { sourceKey: name, rawBytes, rawSha256: createHash("sha256").update(rawBytes).digest("hex"), byteLength: rawBytes.length }; };
let root: string, repositoryRoot: string, repository: string, database: DatabaseClient, scanId: string, hypothesisId: string, findingId: string;
let sourceRows: ReturnType<typeof bytes>[];

function setup(content: string | Buffer = original, aligned = true) {
  sourceRows = [bytes("contracts/Counter.sol", content), bytes("contracts/Math.sol", dependency)];
  for (const file of sourceRows) writeFileSync(path.join(repository, path.basename(file.sourceKey)), file.rawBytes);
  const scan = createScan(database, { repositoryUrl: "https://example.invalid/counter", repositoryName: "counter", depth: "quick" }); scanId = scan.id;
  database.sqlite.prepare("UPDATE scans SET status='preparing_dependencies',resolved_commit=?,dependency_status='ready' WHERE id=?").run(commit, scanId);
  finalizeScanSourceSnapshot(database, scanId, commit, sourceRows);
  finalizeScanCompilation(database, scanId, commit, { status: "supported", manifest: { schema: COMPILATION_MANIFEST_SCHEMA, scanId, resolvedCommit: commit, compilationProfileKind: "plain-solidity-exact-pragma-v1", compiler: { version: "0.8.24", artifactSha256: "b".repeat(64) }, sourceRoots: ["contracts"], libraryRoots: [], remappings: [], sourceUnits: sourceRows.map((file) => ({ sourceUnitName: file.sourceKey, snapshotSourceKey: file.sourceKey, rawSha256: file.rawSha256, byteLength: file.byteLength, contractNames: file.sourceKey.includes("Counter") ? ["Counter", ...(String(content).includes("contract Other") ? ["Other"] : [])] : ["Math"] })) } });
  database.sqlite.prepare("UPDATE scans SET status='completed',compiler_status='ready',compiler_versions=? WHERE id=?").run(JSON.stringify(["0.8.24"]), scanId);
  const analysis = createProtocolAnalysis(database, { scanId, provider: "mock", requestedModel: "mock", actualModel: "mock", promptVersion: "protocol-analysis-v1", result: validAIOutput as unknown as ProtocolAnalysisResult, coverageStatus: "complete", contextManifest: {}, durationMs: 1, inputTokens: 1, outputTokens: 1, totalTokens: 2, requestId: "analysis" });
  const review = createSecurityReviewPlan(database, { scanId, protocolAnalysisId: analysis.id, plan: { selected: [], skipped: [], estimatedRequestCount: 0 }, estimatedSourceBytes: 0 });
  const reviewer = createSecurityReviewerRun(database, { planId: review.id, scanId, protocolAnalysisId: analysis.id, reviewerId: "counter", reviewerName: "Counter", selectionReason: "Fixture", promptVersion: "security-review-counter-v1", provider: "mock", requestedModel: "mock", contextManifest: {} });
  const [finding] = insertFindings(database, scanId, [{ title: "Counter rule", severity: "medium", confidence: 80, source: "slither", detectorId: "divide-before-multiply", fingerprint: randomUUID().replaceAll("-", "").padEnd(64, "0"), contract: "Counter", functionName: "increment", filePath: "contracts/Counter.sol", startLine: 1, endLine: 1, rootCause: "Counter transition", attackScenario: "", impact: "", evidence: "fixture", status: "candidate" }]);
  findingId = finding.id;
  const investigation = reconcileInvestigations(database, scanId)[0];
  hypothesisId = insertVulnerabilityHypotheses(database, [{ scanId, protocolAnalysisId: analysis.id, reviewerId: "counter", reviewerRunId: reviewer.id, title: "Counter transition", category: "state-transition", severity: "low", severityJustification: "Fixture", confidence: 60, summary: "Counter changes after increment.", rootCause: "Counter transition under review.", preconditions: "[]", attackPath: "[]", impact: "Fixture", affectedAssets: "[]", affectedContracts: JSON.stringify(["Counter"]), affectedFunctions: JSON.stringify(["increment", "count"]), evidence: JSON.stringify([{ filePath: "contracts/Counter.sol", contract: "Counter", functionName: "increment", startLine: 1, endLine: 1 }]), violatedInvariantIds: "[]", relatedInvestigationIds: JSON.stringify([investigation.id]), falsePositiveRisks: "[]", verificationStrategy: "[]" }])[0].id;
  insertScannerAlignment(database, scanId, { findingId, scannerId: "slither", scannerVersion: "0.11.0", detectorId: "divide-before-multiply", reportedSourceIdentity: "contracts/Counter.sol", status: aligned ? "aligned" : "unaligned", sourceUnitName: aligned ? "contracts/Counter.sol" : null, snapshotSourceKey: aligned ? "contracts/Counter.sol" : null, targetResolved: aligned });
}
function structuredProvider() { const calls: unknown[] = []; const provider: VerificationPlanProvider = { id: "fixture", async generateVerificationPlan(input) { calls.push(input); return { proposal: { status: "not_plannable", plan: null, rationale: "Fixture", limitations: [], notPlannableReasons: ["insufficient_source_evidence"] }, actualModel: "fixture", requestId: "fixture", inputTokens: 1, outputTokens: 1, totalTokens: 2, durationMs: 1 }; } }; return { calls, provider }; }
function invariantProvider() { const calls: unknown[] = []; const provider: InvariantProposalProvider = { id: "fixture", async generateInvariantProposal(input) { calls.push(input); return { proposal: { status: "not_plannable", semantics: null, hypothesisExpectation: null, relationRationale: null, rationale: "Fixture", limitations: [], notPlannableReasons: ["insufficient_source_evidence"] }, actualModel: "fixture", requestId: "fixture", inputTokens: 1, outputTokens: 1, totalTokens: 2, durationMs: 1 }; } }; return { calls, provider }; }
function planners() { const structured = structuredProvider(), invariant = invariantProvider(); return { structured, invariant,
  plan: new VerificationPlanGenerationService({ database, repositoryRoot, provider: structured.provider, requestedModel: "fixture", timeoutMs: 1000, maxSourceBytes: 10_000, maxFiles: 5, maxFileBytes: 5_000 }),
  propose: new InvariantProposalService({ database, repositoryRoot, provider: invariant.provider, requestedModel: "fixture", timeoutMs: 1000, maxSourceBytes: 10_000, maxFiles: 5, maxFileBytes: 5_000 }) }; }
function structuredPlan(): VerificationHarnessPlan { return { scanId, hypothesisId, resolvedCommit: commit, compilerVersion: "0.8.24", primaryContract: "Counter", primarySourcePath: "contracts/Counter.sol", relevantFunctions: ["increment", "count"], sourceFiles: ["contracts/Counter.sol", "contracts/Math.sol"], verificationGoal: "Check the counter transition.", expectedProperty: "Increment changes count to one.", verificationSteps: ["Deploy", "Increment", "Read"], actors: ["deployer"], operations: [{ kind: "deploy", contractName: "Counter", instanceName: "target" }, { kind: "call", instanceName: "target", functionName: "increment", args: [] }, { kind: "read-uint", instanceName: "target", functionName: "count", resultName: "observed" }], assertions: [{ id: "count-is-one", kind: "uint-eq", actual: "observed", expected: "1", expectedOutcome: "hypothesis-supported", description: "The counter becomes one after increment." }] }; }
function invariantPlan() { return executableInvariantPlanSchema.parse({ schemaVersion: "contracthunter-invariant-plan-v1", mode: "stateful-invariant", scanId, hypothesisId, resolvedCommit: commit, compilerVersion: "0.8.24", primaryContract: "Counter", primarySourcePath: "contracts/Counter.sol", sourceFiles: ["contracts/Counter.sol"], actors: ["deployer"], setup: [{ kind: "deploy", contractName: "Counter", instanceName: "target" }], handlerActions: [{ name: "incrementCounter", instanceName: "target", functionName: "increment", parameters: [], args: [] }], properties: [{ name: "counterProperty", observations: [{ kind: "read-uint", instanceName: "target", functionName: "count", resultName: "observed" }], assertions: [{ id: "nonzero", kind: "uint-not-eq", actual: "observed", expected: "0" }] }] }); }

beforeEach(() => { root = mkdtempSync(path.join(tmpdir(), "ch-closure-consumer-")); repositoryRoot = path.join(root, "repositories"); repository = path.join(repositoryRoot, "checkout"); mkdirSync(repository, { recursive: true }); database = createDatabase(path.join(root, "test.db")); });
afterEach(() => { closeDatabase(database); rmSync(root, { recursive: true, force: true }); });

describe("authoritative source consumers", () => {
  it("persists the same verified closure fingerprint across both planners and all invariant strategies", async () => {
    setup(); rmSync(repository, { recursive: true, force: true });
    const p = planners();
    await p.plan.generate(hypothesisId);
    await p.plan.generate(hypothesisId, "structured-verification");
    await p.propose.generate(hypothesisId);
    for (const strategy of ["foundry-fuzz-property", "foundry-stateful-invariant", "echidna-stateful-invariant"] as const)
      await p.propose.generate(hypothesisId, strategy);
    const attempts = listVerificationPlanAttempts(database, hypothesisId), proposals = listExecutableInvariantProposals(database, hypothesisId);
    expect(attempts).toHaveLength(2); expect(proposals).toHaveLength(4);
    expect(p.structured.calls).toHaveLength(2); expect(p.invariant.calls).toHaveLength(4);
    const hashes = [...attempts, ...proposals].map((row) => row.sourceClosureFingerprintSha256);
    expect(new Set(hashes).size).toBe(1);
    expect(hashes[0]).toMatch(/^[a-f0-9]{64}$/);
    for (const row of [...attempts, ...proposals]) {
      expect(row).toMatchObject({ sourceClosureFingerprintSchema: SOURCE_CLOSURE_FINGERPRINT_SCHEMA, sourceClosureFingerprintFileCount: 2,
        sourceClosureFingerprintTotalBytes: sourceRows.reduce((sum, file) => sum + file.byteLength, 0) });
      expect(() => database.sqlite.prepare(`UPDATE ${"result" in row ? "verification_plan_attempts" : "executable_invariant_proposals"} SET source_closure_fingerprint_sha256=? WHERE id=?`).run("f".repeat(64), row.id)).toThrow("immutable");
    }
    expect(database.sqlite.prepare("SELECT count(*) AS count FROM hypothesis_verification_runs").get()).toEqual({ count: 0 });
    expect(database.sqlite.prepare("SELECT count(*) AS count FROM executable_invariant_runs").get()).toEqual({ count: 0 });
    expect(database.sqlite.prepare("SELECT count(*) AS count FROM hypothesis_lifecycle_transitions").get()).toEqual({ count: 0 });
  });
  it("retains attempt A when a later authoritative scan has changed source bytes", async () => {
    setup(); const firstHypothesis = hypothesisId; const first = planners();
    await first.plan.generate(firstHypothesis); await first.propose.generate(firstHypothesis);
    const a = listVerificationPlanAttempts(database, firstHypothesis)[0].sourceClosureFingerprintSha256;
    setup(`${original} `); const secondHypothesis = hypothesisId; const second = planners();
    await second.plan.generate(secondHypothesis); await second.propose.generate(secondHypothesis);
    const b = listVerificationPlanAttempts(database, secondHypothesis)[0].sourceClosureFingerprintSha256;
    expect(a).not.toBe(b);
    expect(listVerificationPlanAttempts(database, firstHypothesis)[0].sourceClosureFingerprintSha256).toBe(a);
    expect(listExecutableInvariantProposals(database, firstHypothesis)[0].sourceClosureFingerprintSha256).toBe(a);
    expect(listExecutableInvariantProposals(database, secondHypothesis)[0].sourceClosureFingerprintSha256).toBe(b);
  });
  it("stores authoritative provider failures with the precomputed fingerprint and rejects a null insert", async () => {
    setup();
    const failedStructured = new VerificationPlanGenerationService({ database, repositoryRoot, provider: { id: "rejecting", async generateVerificationPlan() { throw new Error("provider failed"); } }, requestedModel: "fixture", timeoutMs: 1000, maxSourceBytes: 10_000, maxFiles: 5, maxFileBytes: 5_000 });
    const failedInvariant = new InvariantProposalService({ database, repositoryRoot, provider: { id: "rejecting", async generateInvariantProposal() { throw new Error("provider failed"); } }, requestedModel: "fixture", timeoutMs: 1000, maxSourceBytes: 10_000, maxFiles: 5, maxFileBytes: 5_000 });
    const structuredResult = await failedStructured.generate(hypothesisId);
    const invariantResult = await failedInvariant.generate(hypothesisId);
    expect(structuredResult.failureCode).toBe("plan_generation_failed");
    expect(invariantResult.result.failureCode).toBe("invariant_generation_unavailable");
    const attempt = listVerificationPlanAttempts(database, hypothesisId)[0], proposal = listExecutableInvariantProposals(database, hypothesisId)[0];
    expect(attempt.sourceClosureFingerprintSha256).toBe(proposal.sourceClosureFingerprintSha256);
    expect(attempt.sourceClosureFingerprintSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(() => createVerificationPlanAttempt(database, { hypothesisId, scanId, selectedStrategy: "structured-verification", result: structuredResult })).toThrow("fingerprint");
    expect(() => database.sqlite.prepare("INSERT INTO verification_plan_attempts (id,hypothesis_id,scan_id,selected_strategy,status,plan,failure_code,result,created_at) SELECT ?,hypothesis_id,scan_id,selected_strategy,status,plan,failure_code,result,created_at FROM verification_plan_attempts WHERE id=?").run(randomUUID(), attempt.id)).toThrow("invalid planning source closure fingerprint");
    expect(database.sqlite.prepare("SELECT count(*) AS count FROM verification_plan_attempts").get()).toEqual({ count: 1 });
  });
  it("uses identical snapshot source context for both planners after checkout deletion and materializes exact bytes", async () => {
    setup(); rmSync(repository, { recursive: true, force: true });
    const p = planners();
    await p.plan.generate(hypothesisId); await p.propose.generate(hypothesisId);
    expect(p.structured.calls).toHaveLength(1); expect(p.invariant.calls).toHaveLength(1);
    const structuredContext = (p.structured.calls[0] as { context: { content: string; manifest: { files: Array<{ path: string }> } } }).context;
    const invariantContext = (p.invariant.calls[0] as { context: { content: string; manifest: { files: Array<{ path: string }> } } }).context;
    expect(structuredContext.content).toContain(JSON.stringify(original)); expect(invariantContext.content).toContain(JSON.stringify(original));
    expect(structuredContext.manifest.files.map((file) => file.path)).toEqual(invariantContext.manifest.files.map((file) => file.path));
    const authority = sourceAuthorityForHypothesis(database, getVulnerabilityHypothesis(database, hypothesisId)!);
    expect(authority.kind).toBe("authoritative"); if (authority.kind !== "authoritative") return;
    expect(authority.closure.files.map((file) => file.rawSha256)).toEqual(sourceRows.map((file) => file.rawSha256).sort((a, b) => sourceRows.find((x) => x.rawSha256 === a)!.sourceKey < sourceRows.find((x) => x.rawSha256 === b)!.sourceKey ? -1 : 1));
    const builder = new VerificationWorkspaceBuilder({ verificationRoot: path.join(root, "workspaces"), repositoryRoot, acceptedCompilerVersions: ["0.8.24"], approvedSourceRoots: ["contracts"], generatorVersion: "0.2.2" });
    const built = await builder.build({ verificationRunId: randomUUID(), repositoryPath: repository, plan: structuredPlan(), authoritativeClosure: authority.closure });
    for (const file of authority.closure.files) expect(readFileSync(path.join(built.workspacePath, file.sourceUnitName))).toEqual(file.rawBytes);
    expect(built.manifest.sourceLayout).toBe("authoritative-source-unit-v1");
    const invariant = await builder.buildInvariant({ workspaceId: randomUUID(), repositoryPath: repository, plan: invariantPlan(), authoritativeClosure: authority.closure });
    expect(invariant.manifest.sourceLayout).toBe("authoritative-source-unit-v1");
    for (const file of authority.closure.files) expect(readFileSync(path.join(invariant.workspacePath, file.sourceUnitName))).toEqual(file.rawBytes);
    const echidnaPlan = executableInvariantPlanSchema.parse({ ...invariantPlan(), actors: [] });
    const echidna = await builder.buildEchidnaInvariant({ workspaceId: randomUUID(), repositoryPath: repository, plan: echidnaPlan, authoritativeClosure: authority.closure });
    expect(echidna.manifest.sourceLayout).toBe("authoritative-source-unit-v1");
    for (const file of authority.closure.files) expect(readFileSync(path.join(echidna.workspacePath, file.sourceUnitName))).toEqual(file.rawBytes);
    const counterexample = { kind: "sequence", parserVersion: "foundry-1.7.1-json-v1", actions: [{ actionName: "incrementCounter", parameterValues: [] }], summary: "Counter sequence." };
    const replayPlan = invariantReplayPlanSchema.parse({ schemaVersion: "contracthunter-invariant-replay-v1", scanId, hypothesisId, resolvedCommit: commit, compilerVersion: "0.8.24", proposalId: randomUUID(), invariantRunId: randomUUID(), invariantPlanHash: invariantPlanHash(invariantPlan()), propertyName: "counterProperty", hypothesisExpectation: "hypothesis-predicts-property-violation", counterexample, counterexampleHash: counterexampleHash(counterexample) });
    const replay = await builder.buildInvariantReplay({ workspaceId: randomUUID(), repositoryPath: repository, replayPlan, invariantPlan: invariantPlan(), authoritativeClosure: authority.closure });
    expect(replay.manifest.sourceLayout).toBe("authoritative-source-unit-v1");
    for (const file of authority.closure.files) expect(readFileSync(path.join(replay.workspacePath, file.sourceUnitName))).toEqual(file.rawBytes);
  });
  it("ignores checkout mutation for planning and workspace bytes", async () => {
    setup(); writeFileSync(path.join(repository, "Counter.sol"), "pragma solidity 0.8.24; contract Poison {}");
    const p = planners(); await p.plan.generate(hypothesisId); await p.propose.generate(hypothesisId);
    expect((p.structured.calls[0] as { context: { content: string } }).context.content).toContain(JSON.stringify(original));
    expect((p.invariant.calls[0] as { context: { content: string } }).context.content).not.toContain("Poison");
    const authority = sourceAuthorityForHypothesis(database, getVulnerabilityHypothesis(database, hypothesisId)!);
    if (authority.kind !== "authoritative") throw new Error("fixture authority unavailable");
    const built = await new VerificationWorkspaceBuilder({ verificationRoot: path.join(root, "workspaces"), repositoryRoot, acceptedCompilerVersions: ["0.8.24"], approvedSourceRoots: ["contracts"], generatorVersion: "0.2.2" }).build({ verificationRunId: randomUUID(), repositoryPath: repository, plan: structuredPlan(), authoritativeClosure: authority.closure });
    expect(readFileSync(path.join(built.workspacePath, "contracts/Counter.sol"), "utf8")).toBe(original);
  });
  it("rejects unaligned findings before either provider request", async () => {
    setup(original, false); const p = planners(); await expect(p.plan.generate(hypothesisId)).rejects.toMatchObject({ code: "missing_context" });
    await expect(p.propose.generate(hypothesisId)).rejects.toMatchObject({ code: "invalid_state" });
    expect(p.structured.calls).toHaveLength(0); expect(p.invariant.calls).toHaveLength(0);
  });
  it("rejects a hypothesis with two different aligned contracts in one source", async () => {
    setup(`${original} contract Other {}`);
    const [other] = insertFindings(database, scanId, [{ title: "Other rule", severity: "medium", confidence: 80, source: "aderyn", detectorId: "other-rule", fingerprint: "f".repeat(64), contract: "Other", functionName: null, filePath: "contracts/Counter.sol", startLine: 1, endLine: 1, rootCause: "Other contract", attackScenario: "", impact: "", evidence: "fixture", status: "candidate" }]);
    insertScannerAlignment(database, scanId, { findingId: other.id, scannerId: "aderyn", scannerVersion: "0.6.0", detectorId: "other-rule", reportedSourceIdentity: "contracts/Counter.sol", status: "aligned", sourceUnitName: "contracts/Counter.sol", snapshotSourceKey: "contracts/Counter.sol", targetResolved: true });
    reconcileInvestigations(database, scanId);
    const investigationIds = (database.sqlite.prepare("SELECT id FROM investigations WHERE scan_id=?").all(scanId) as Array<{ id: string }>).map((row) => row.id);
    database.sqlite.prepare("UPDATE vulnerability_hypotheses SET related_investigation_ids=?,evidence=? WHERE id=?").run(JSON.stringify(investigationIds), JSON.stringify([{ filePath: "contracts/Counter.sol", contract: "Counter", functionName: null, startLine: 1, endLine: 1 }, { filePath: "contracts/Counter.sol", contract: "Other", functionName: null, startLine: 1, endLine: 1 }]), hypothesisId);
    const p = planners(); await expect(p.plan.generate(hypothesisId)).rejects.toMatchObject({ code: "missing_context" });
    await expect(p.propose.generate(hypothesisId)).rejects.toMatchObject({ code: "invalid_state" });
    expect(p.structured.calls).toHaveLength(0); expect(p.invariant.calls).toHaveLength(0);
  });
  it("rejects missing and changed snapshot rows before either provider request", async () => {
    setup();
    for (const mutation of ["missing", "changed"] as const) {
      database.sqlite.prepare("DROP TRIGGER IF EXISTS scan_source_snapshot_file_immutable").run();
      database.sqlite.prepare("DROP TRIGGER IF EXISTS scan_source_snapshot_file_no_delete").run();
      database.sqlite.prepare("DROP TRIGGER IF EXISTS scan_source_snapshot_file_closed").run();
      if (mutation === "missing") { database.sqlite.pragma("foreign_keys = OFF"); database.sqlite.prepare("DELETE FROM scan_source_snapshot_files WHERE scan_id=? AND source_key=?").run(scanId, "contracts/Math.sol"); database.sqlite.pragma("foreign_keys = ON"); }
      else database.sqlite.prepare("UPDATE scan_source_snapshot_files SET raw_bytes=? WHERE scan_id=? AND source_key=?").run(Buffer.from("poison"), scanId, "contracts/Counter.sol");
      const p = planners(); await expect(p.plan.generate(hypothesisId)).rejects.toMatchObject({ code: "missing_context" });
      await expect(p.propose.generate(hypothesisId)).rejects.toMatchObject({ code: "invalid_state" });
      expect(p.structured.calls).toHaveLength(0); expect(p.invariant.calls).toHaveLength(0);
      if (mutation === "missing") database.sqlite.prepare("INSERT INTO scan_source_snapshot_files (scan_id,source_key,raw_bytes,raw_sha256,byte_length) VALUES (?,?,?,?,?)").run(scanId, sourceRows[1].sourceKey, sourceRows[1].rawBytes, sourceRows[1].rawSha256, sourceRows[1].byteLength);
    }
  });
  it("rejects invalid UTF-8 and unsupported imports before either provider request", async () => {
    for (const content of [Buffer.from([0xff]), 'pragma solidity 0.8.24; import "forge-std/Test.sol"; contract Counter {}']) {
      setup(content); const p = planners();
      await expect(p.plan.generate(hypothesisId)).rejects.toMatchObject({ code: "missing_context" });
      await expect(p.propose.generate(hypothesisId)).rejects.toMatchObject({ code: "invalid_state" });
      expect(p.structured.calls).toHaveLength(0); expect(p.invariant.calls).toHaveLength(0);
      database.sqlite.prepare("DELETE FROM scans WHERE id=?").run(scanId);
    }
  });
  it("reports absent and unsupported compilation to explicit authoritative callers", () => {
    const legacy = createScan(database, { repositoryUrl: "https://example.invalid/legacy", repositoryName: "legacy", depth: "quick" });
    const fake = { id: randomUUID(), scanId: legacy.id } as Parameters<typeof requireAuthoritativeSourceClosureForHypothesis>[1];
    expect(() => requireAuthoritativeSourceClosureForHypothesis(database, fake)).toThrow("authority_unavailable");
    database.sqlite.prepare("UPDATE scans SET status='preparing_dependencies',resolved_commit=?,dependency_status='ready' WHERE id=?").run(commit, legacy.id);
    finalizeScanSourceSnapshot(database, legacy.id, commit, [bytes("contracts/Legacy.sol", "pragma solidity 0.8.24; contract Legacy {}")]);
    finalizeScanCompilation(database, legacy.id, commit, { status: "unsupported", reason: "dynamic_build_configuration" });
    expect(() => requireAuthoritativeSourceClosureForHypothesis(database, fake)).toThrow("unsupported_profile");
    setup();
    expect(requireAuthoritativeSourceClosureForHypothesis(database, getVulnerabilityHypothesis(database, hypothesisId)!).kind).toBe("authoritative");
  });
});
