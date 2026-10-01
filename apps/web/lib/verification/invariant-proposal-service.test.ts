import { cpSync, mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ECHIDNA_BINARY_SHA256, ECHIDNA_BUILD_ID, ECHIDNA_UPSTREAM_VERSION, echidnaSeed, invariantCapabilityProfile, invariantProposalSchema, validAIOutput, type InvariantProposalInput, type InvariantProposalProvider, type InvariantProposalProviderResult, type ProtocolAnalysisResult } from "@contracthunter/core";
import { closeDatabase, createDatabase, createProtocolAnalysis, createScan, createSecurityReviewerRun, createSecurityReviewPlan, getVulnerabilityHypothesis, insertVulnerabilityHypotheses, listExecutableInvariantProposals, listExecutableInvariantRuns, type DatabaseClient } from "@contracthunter/db";
import { VerificationWorkspaceBuilder } from "@contracthunter/scanners";
import { InvariantProposalService } from "./invariant-proposal-service";
import { EchidnaInvariantService } from "./echidna-invariant-service";
import { ExecutableInvariantService } from "./executable-invariant-service";

const commit = "a".repeat(40), fixtureRoot = path.resolve("packages/scanners/fixtures/invariants");
let root: string, repositoryRoot: string, repository: string, database: DatabaseClient, scanId: string, hypothesisId: string;
beforeEach(() => {
  root = mkdtempSync(path.join(tmpdir(), "ch-invariant-proposal-")); repositoryRoot = path.join(root, "repos"); mkdirSync(repositoryRoot);
  database = createDatabase(path.join(root, "test.db")); const scan = createScan(database, { repositoryUrl: "https://example.invalid/synthetic", repositoryName: "synthetic", depth: "quick" }); scanId = scan.id;
  repository = path.join(repositoryRoot, scanId); cpSync(fixtureRoot, repository, { recursive: true });
  database.sqlite.prepare("UPDATE scans SET status='completed', resolved_commit=?, compiler_status='ready', compiler_versions=? WHERE id=?").run(commit, JSON.stringify(["0.8.36"]), scanId);
  const analysis = createProtocolAnalysis(database, { scanId, provider: "mock", requestedModel: "mock", actualModel: "mock", promptVersion: "protocol-analysis-v1", result: validAIOutput as unknown as ProtocolAnalysisResult, coverageStatus: "complete", contextManifest: {}, durationMs: 1, inputTokens: 1, outputTokens: 1, totalTokens: 2, requestId: "analysis" });
  const review = createSecurityReviewPlan(database, { scanId, protocolAnalysisId: analysis.id, plan: { selected: [], skipped: [], estimatedRequestCount: 0 }, estimatedSourceBytes: 0 });
  const reviewer = createSecurityReviewerRun(database, { planId: review.id, scanId, protocolAnalysisId: analysis.id, reviewerId: "accounting", reviewerName: "Accounting", selectionReason: "Fixture", promptVersion: "security-review-accounting-v1", provider: "mock", requestedModel: "mock", contextManifest: {} });
  hypothesisId = insertVulnerabilityHypotheses(database, [{ scanId, protocolAnalysisId: analysis.id, reviewerId: "accounting", reviewerRunId: reviewer.id, title: "Accounting can diverge", category: "state-transition", severity: "low", severityJustification: "Fixture", confidence: 60, summary: "Recorded accounting should match native balance.", rootCause: "record may not transfer ether", preconditions: "[]", attackPath: "[]", impact: "Fixture", affectedAssets: "[]", affectedContracts: JSON.stringify(["VulnerableAccounting"]), affectedFunctions: JSON.stringify(["record", "totalRecordedBalance"]), evidence: JSON.stringify([{ filePath: "contracts/VulnerableAccounting.sol", contract: "VulnerableAccounting", functionName: "record", startLine: 5, endLine: 5 }]), violatedInvariantIds: "[]", relatedInvestigationIds: "[]", falsePositiveRisks: "[]", verificationStrategy: "[]" }])[0].id;
});
afterEach(() => { closeDatabase(database); rmSync(root, { recursive: true, force: true }); });
const property = { name: "accounting", observations: [{ kind: "read-uint", instanceName: "target", functionName: "totalRecordedBalance", resultName: "recorded" }, { kind: "read-balance", target: { kind: "instance", name: "target" }, resultName: "nativeBalance" }], assertions: [{ id: "conservation", kind: "uint-eq", actual: "recorded", expected: { kind: "result", name: "nativeBalance" } }] };
function fuzzSemantics() { return { mode: "fuzz-property", primaryContract: "VulnerableAccounting", actors: ["deployer", "attacker"], setup: [{ kind: "deploy", contractName: "VulnerableAccounting", instanceName: "target" }], property, fuzzAction: { instanceName: "target", functionName: "record", caller: "attacker", parameters: [{ name: "amount", type: "uint256" }], args: [{ kind: "parameter", name: "amount" }] } }; }
function statefulSemantics() { return { mode: "stateful-invariant", primaryContract: "StatefulAccessControl", actors: ["deployer", "attacker"], setup: [{ kind: "deploy", contractName: "StatefulAccessControl", instanceName: "target" }], handlerActions: [{ name: "takeOwnership", instanceName: "target", functionName: "transferOwnership", caller: "attacker", parameters: [], args: [{ kind: "address", source: "actor", name: "attacker" }] }, { name: "touch", instanceName: "target", functionName: "touch", caller: "attacker", parameters: [{ name: "flag", type: "bool" }], args: [{ kind: "parameter", name: "flag" }] }], properties: [{ name: "ownerStable", observations: [{ kind: "read-address", instanceName: "target", functionName: "owner", resultName: "observedOwner" }], assertions: [{ id: "owner", kind: "address-eq", actual: "observedOwner", expected: { kind: "address", source: "actor", name: "deployer" } }] }] }; }
const generated = (semantics: unknown) => ({ status: "generated", semantics, hypothesisExpectation: "hypothesis-predicts-property-violation", relationRationale: "The hypothesis predicts that this property can be broken.", rationale: "The property maps to bounded current-state observations.", limitations: [], notPlannableReasons: [] });
function fake(value: unknown | Error): InvariantProposalProvider & { calls: InvariantProposalInput[] } { const calls: InvariantProposalInput[] = []; return { id: "fixture-provider", calls, async generateInvariantProposal(input): Promise<InvariantProposalProviderResult> { calls.push(input); if (value instanceof Error) throw value; return { proposal: value, actualModel: "actual-model", requestId: "request-id", inputTokens: 80, outputTokens: 40, totalTokens: 120, durationMs: 7 }; } }; }
function service(provider: InvariantProposalProvider) { return new InvariantProposalService({ database, repositoryRoot, provider, requestedModel: "configured-model", timeoutMs: 1234, maxSourceBytes: 10_000, maxFiles: 5, maxFileBytes: 5_000, pricing: { inputCostPerMillionUsd: 1, outputCostPerMillionUsd: 2 }, logger: vi.fn() }); }

describe("reviewed invariant proposal boundary", () => {
  it("composes a canonical fuzz plan from trusted identity and builds a deterministic workspace", async () => {
    const provider = fake(generated(fuzzSemantics())), output = await service(provider).generate(hypothesisId);
    expect(output.result).toMatchObject({ status: "generated", plan: { hypothesisId, scanId, resolvedCommit: commit, compilerVersion: "0.8.36", primarySourcePath: "contracts/VulnerableAccounting.sol" }, provenance: { promptVersion: "invariant-plan-v1", totalTokens: 120, estimatedCostUsd: 0.00016 } });
    expect(output.result.planHash).toMatch(/^[a-f0-9]{64}$/);
    expect(provider.calls).toHaveLength(1); expect(provider.calls[0]).toMatchObject({ timeoutMs: 1234, model: "configured-model" });
    expect(provider.calls[0].context.content).toContain(JSON.stringify(invariantCapabilityProfile));
    for (const forbidden of [hypothesisId, scanId, commit, "trustedCompilerVersions"]) expect(provider.calls[0].context.content).not.toContain(forbidden);
    const validated = await service(provider).validate(hypothesisId, output.proposal.id); expect(validated.planHash).toBe(output.result.planHash);
    const built = await new VerificationWorkspaceBuilder({ verificationRoot: path.join(root, "workspaces"), repositoryRoot, acceptedCompilerVersions: ["0.8.36"], approvedSourceRoots: ["contracts"], generatorVersion: "0.2.0" }).buildInvariant({ workspaceId: crypto.randomUUID(), repositoryPath: repository, plan: validated.plan });
    expect(built.manifest.planHash).toBe(output.result.planHash); expect(listExecutableInvariantRuns(database, hypothesisId)).toEqual([]);
    expect(getVulnerabilityHypothesis(database, hypothesisId)?.status).toBe("candidate");
  });
  it("composes a stateful plan with bounded handler actions", async () => {
    database.sqlite.prepare("UPDATE vulnerability_hypotheses SET evidence=?, affected_contracts=? WHERE id=?").run(JSON.stringify([{ filePath: "contracts/StatefulAccessControl.sol", contract: "StatefulAccessControl", functionName: "transferOwnership", startLine: 6, endLine: 6 }]), JSON.stringify(["StatefulAccessControl"]), hypothesisId);
    const output = await service(fake(generated(statefulSemantics()))).generate(hypothesisId);
    expect(output.result).toMatchObject({ status: "generated", plan: { mode: "stateful-invariant", compilerVersion: "0.8.36", handlerActions: [{ name: "takeOwnership" }, { name: "touch" }] } });
    expect(await service(fake(null)).validate(hypothesisId, output.proposal.id)).toMatchObject({ planHash: output.result.planHash });
  });
  it("preserves immutable generation history including not-plannable and provider failure", async () => {
    const first = await service(fake(generated(fuzzSemantics()))).generate(hypothesisId);
    const second = await service(fake({ status: "not_plannable", semantics: null, hypothesisExpectation: null, relationRationale: null, rationale: "A bytes argument is required.", limitations: [], notPlannableReasons: ["unsupported_function_type"] })).generate(hypothesisId);
    const third = await service(fake(new Error("secret /tmp/path"))).generate(hypothesisId);
    expect(second.result).toMatchObject({ status: "not_plannable", plan: null }); expect(third.result).toMatchObject({ status: "failed", failureCode: "invariant_generation_unavailable" });
    expect(listExecutableInvariantProposals(database, hypothesisId)).toHaveLength(3);
    expect(listExecutableInvariantProposals(database, hypothesisId).find((item) => item.id === first.proposal.id)?.planHash).toBe(first.result.planHash);
    expect(JSON.stringify(listExecutableInvariantProposals(database, hypothesisId))).not.toContain("secret /tmp/path");
    expect(listExecutableInvariantRuns(database, hypothesisId)).toEqual([]);
  });
  it("rejects authoritative identity, arbitrary execution inputs, raw addresses, unsupported fuzz types, and excessive handlers", async () => {
    const invalid = [
      ...["hypothesisId", "scanId", "resolvedCommit", "compilerVersion", "sourceFiles", "primarySourcePath", "solidity", "imports", "cheatcode", "foundry", "forgeArgs", "rpcUrl", "ffi", "command"].map((field) => ({ ...fuzzSemantics(), [field]: "attacker" })),
      { ...fuzzSemantics(), fuzzAction: { ...fuzzSemantics().fuzzAction, parameters: [{ name: "amount", type: "string" }] } },
      { ...fuzzSemantics(), fuzzAction: { ...fuzzSemantics().fuzzAction, parameters: [{ name: "amount", type: "bytes" }] } },
      { ...fuzzSemantics(), fuzzAction: { ...fuzzSemantics().fuzzAction, args: [{ kind: "address", value: "0x1234" }] } },
      { ...statefulSemantics(), handlerActions: Array.from({ length: 17 }, (_, index) => ({ ...statefulSemantics().handlerActions[0], name: `action${index}` })) },
    ];
    for (const semantics of invalid) expect(invariantProposalSchema.safeParse(generated(semantics)).success).toBe(false);
    const output = await service(fake(generated(invalid[0]))).generate(hypothesisId);
    expect(output.result).toMatchObject({ status: "failed", failureCode: "invalid_invariant_provider_proposal", plan: null });
    expect(listExecutableInvariantRuns(database, hypothesisId)).toEqual([]);
  });
  it("fails closed on unsupported semantics, missing function, and ambiguous compiler without provider retry", async () => {
    const unsupported = await service(fake(generated({ ...fuzzSemantics(), fuzzAction: { ...fuzzSemantics().fuzzAction, parameters: [{ name: "amount", type: "string" }] } }))).generate(hypothesisId);
    expect(unsupported.result).toMatchObject({ status: "failed", failureCode: "unsupported_invariant_semantics" });
    const missing = await service(fake(generated({ ...fuzzSemantics(), fuzzAction: { ...fuzzSemantics().fuzzAction, functionName: "doesNotExist" } }))).generate(hypothesisId);
    expect(missing.result).toMatchObject({ status: "failed", failureCode: "invalid_invariant_function_signature" });
    database.sqlite.prepare("UPDATE scans SET compiler_versions=? WHERE id=?").run(JSON.stringify(["0.8.24", "0.8.36"]), scanId);
    const provider = fake(generated(fuzzSemantics())), ambiguous = await service(provider).generate(hypothesisId);
    expect(ambiguous.result).toMatchObject({ status: "failed", failureCode: "ambiguous_trusted_compiler" }); expect(provider.calls).toHaveLength(0);
  });
  it("refuses execution validation after the reviewed source changes", async () => {
    const output = await service(fake(generated(fuzzSemantics()))).generate(hypothesisId);
    expect(output.result.status).toBe("generated");
    writeFileSync(path.join(repository, "contracts/VulnerableAccounting.sol"), "pragma solidity ^0.8.24; contract VulnerableAccounting { uint256 public totalRecordedBalance; function record(uint256) external {} }");
    await expect(service(fake(null)).validate(hypothesisId, output.proposal.id)).rejects.toMatchObject({ code: "invalid_state" });
    expect(listExecutableInvariantRuns(database, hypothesisId)).toEqual([]);
  });
  it("generates without execution, reports both engines, then persists separate explicitly selected runs", async () => {
    cpSync(path.resolve("packages/scanners/fixtures/echidna/contracts/SafeAccounting.sol"), path.join(repository, "contracts/SafeAccounting.sol"));
    database.sqlite.prepare("UPDATE vulnerability_hypotheses SET evidence=?, affected_contracts=? WHERE id=?").run(JSON.stringify([{ filePath: "contracts/SafeAccounting.sol", contract: "SafeAccounting", functionName: "credit", startLine: 8, endLine: 8 }]), JSON.stringify(["SafeAccounting"]), hypothesisId);
    const semantics = { mode: "stateful-invariant", primaryContract: "SafeAccounting", actors: [], setup: [{ kind: "deploy", contractName: "SafeAccounting", instanceName: "target" }], handlerActions: [{ name: "credit", instanceName: "target", functionName: "credit", caller: null, parameters: [{ name: "amount", type: "uint256" }], args: [{ kind: "parameter", name: "amount" }] }], properties: [{ name: "balanced", observations: [{ kind: "read-uint", instanceName: "target", functionName: "recorded", resultName: "recordedValue" }, { kind: "read-uint", instanceName: "target", functionName: "mirror", resultName: "mirrorValue" }], assertions: [{ id: "same", kind: "uint-eq", actual: "recordedValue", expected: { kind: "result", name: "mirrorValue" } }] }] };
    const proposalService = service(fake(generated(semantics)));
    const output = await proposalService.generate(hypothesisId);
    expect(listExecutableInvariantRuns(database, hypothesisId)).toEqual([]);
    const validated = await proposalService.validate(hypothesisId, output.proposal.id);
    expect(validated.compatibility).toEqual({ foundry: { compatible: true, reasons: [] }, echidna: { compatible: true, reasons: [] } });
    const verificationRoot = path.join(root, "workspaces");
    const builder = (compilers: string[]) => new VerificationWorkspaceBuilder({ verificationRoot, repositoryRoot, acceptedCompilerVersions: compilers, approvedSourceRoots: ["contracts"], generatorVersion: "0.2.1" });
    const foundryRunner = vi.fn(async (input: { planHash: string; mode: string }) => ({ status: "completed", mode: input.mode, planHash: input.planHash, exitCode: 0, durationMs: 2, timedOut: false, outputTruncated: false, testCount: 1, passedCount: 1, failedCount: 0, runsExecuted: 64, tests: [{ propertyName: "balanced", testName: "invariant_balanced()", status: "passed", runsExecuted: 64, reason: null, counterexample: null }], stdoutSummary: "", stderrSummary: "", errorCode: null, isolation: { providerId: "mock-worker" } }));
    const foundry = new ExecutableInvariantService({ database, repositoryRoot, workspaceBuilder: builder, runner: { run: foundryRunner } as never });
    const foundryRun = (await foundry.run(hypothesisId, validated.plan, output.proposal.id)).run;
    expect(foundryRun).toMatchObject({ engine: "foundry", proposalId: output.proposal.id, status: "completed", outcome: "held-within-bounds" });
    expect(JSON.parse(foundryRun.engineMetadata ?? "null")).toMatchObject({ forgeVersion: "1.7.1", parserVersion: "foundry-1.7.1-json-v1", configHash: expect.stringMatching(/^[a-f0-9]{64}$/) });
    const echidnaRunner = vi.fn(async (input: { planHash: string }) => ({ engine: "echidna", status: "completed", planHash: input.planHash, exitCode: 0, durationMs: 3, timedOut: false, outputTruncated: false, errorCode: null, seed: echidnaSeed(input.planHash), executedCalls: 130, campaignStopReason: "test-limit-reached", tests: [{ propertyName: "balanced", outcome: "held-within-bounds", counterexample: null, replayAvailable: false }], stdoutSummary: "", stderrSummary: "", binaryHash: ECHIDNA_BINARY_SHA256, echidnaVersion: ECHIDNA_UPSTREAM_VERSION, compatibilityVersion: "2.3.3+contracthunter.1", buildId: ECHIDNA_BUILD_ID, isolation: { providerId: "mock-worker" } }));
    const echidna = new EchidnaInvariantService({ database, repositoryRoot, proposals: proposalService, workspaceBuilder: builder, runner: { run: echidnaRunner } as never });
    const echidnaRun = (await echidna.run(hypothesisId, output.proposal.id)).run;
    expect(echidnaRun).toMatchObject({ engine: "echidna", proposalId: output.proposal.id, status: "completed", outcome: "held-within-bounds", configuredRuns: 128 });
    expect(JSON.parse(echidnaRun.engineMetadata ?? "null")).toMatchObject({ binarySha256: ECHIDNA_BINARY_SHA256, compatibilityBuildId: ECHIDNA_BUILD_ID, seed: echidnaSeed(echidnaRun.planHash) });
    expect((await foundry.run(hypothesisId, validated.plan, output.proposal.id)).run.engine).toBe("foundry");
    expect(listExecutableInvariantRuns(database, hypothesisId).map((run) => run.engine)).toEqual(["foundry", "echidna", "foundry"]);
    expect(foundryRunner).toHaveBeenCalledTimes(2); expect(echidnaRunner).toHaveBeenCalledTimes(1);
    expect(getVulnerabilityHypothesis(database, hypothesisId)?.status).toBe("candidate");
  });
  it("keeps Foundry available while refusing explicit caller semantics before Echidna workspace or worker use", async () => {
    database.sqlite.prepare("UPDATE vulnerability_hypotheses SET evidence=?, affected_contracts=? WHERE id=?").run(JSON.stringify([{ filePath: "contracts/StatefulAccessControl.sol", contract: "StatefulAccessControl", functionName: "transferOwnership", startLine: 6, endLine: 6 }]), JSON.stringify(["StatefulAccessControl"]), hypothesisId);
    const proposals = service(fake(generated(statefulSemantics()))), output = await proposals.generate(hypothesisId);
    const validated = await proposals.validate(hypothesisId, output.proposal.id);
    expect(validated.compatibility).toMatchObject({ foundry: { compatible: true }, echidna: { compatible: false, reasons: expect.arrayContaining(["explicit-caller-unsupported"]) } });
    const builder = vi.fn(), runner = vi.fn();
    const echidna = new EchidnaInvariantService({ database, repositoryRoot, proposals, workspaceBuilder: builder as never, runner: { run: runner } as never });
    await expect(echidna.run(hypothesisId, output.proposal.id)).rejects.toMatchObject({ code: "echidna_plan_incompatible" });
    expect(builder).not.toHaveBeenCalled(); expect(runner).not.toHaveBeenCalled();
    expect(listExecutableInvariantRuns(database, hypothesisId)).toEqual([]);
  });
});
