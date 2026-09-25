import { cpSync, mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { invariantCapabilityProfile, invariantProposalSchema, validAIOutput, type InvariantProposalInput, type InvariantProposalProvider, type InvariantProposalProviderResult, type ProtocolAnalysisResult } from "@contracthunter/core";
import { closeDatabase, createDatabase, createProtocolAnalysis, createScan, createSecurityReviewerRun, createSecurityReviewPlan, getVulnerabilityHypothesis, insertVulnerabilityHypotheses, listExecutableInvariantProposals, listExecutableInvariantRuns, type DatabaseClient } from "@contracthunter/db";
import { VerificationWorkspaceBuilder } from "@contracthunter/scanners";
import { InvariantProposalService } from "./invariant-proposal-service";

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
});
