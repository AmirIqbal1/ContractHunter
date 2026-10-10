import { createHash, randomUUID } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { COMPILATION_MANIFEST_SCHEMA, executableInvariantPlanSchema, fingerprintAuthoritativeSourceClosure, invariantPlanHash,
  validAIOutput, verificationHarnessPlanSchema, type ProtocolAnalysisResult } from "@contracthunter/core";
import { closeDatabase, createDatabase, createExecutableInvariantProposal, createExecutableInvariantRun, createHypothesisVerificationRun,
  createProtocolAnalysis, createScan, createSecurityReviewPlan, createSecurityReviewerRun, createVerificationPlanAttempt,
  finalizeScanCompilation, finalizeScanSourceSnapshot, getExecutableInvariantProposal, getVerificationPlanAttempt,
  getVulnerabilityHypothesis, insertFindings, insertScannerAlignment, insertVulnerabilityHypotheses,
  listPersistedVerificationTargetGroups, reconcileInvestigations, type DatabaseClient } from "@contracthunter/db";
import { requireAuthoritativeSourceClosureForHypothesis } from "./authoritative-source-authority";
import { reuseInvariantPlanningArtifact, reuseStructuredPlanningArtifact } from "./planning-reuse-api";

const commit = "a".repeat(40), sourceKey = "contracts/Counter.sol";
const source = "pragma solidity 0.8.24; contract Counter { uint256 public count; function increment(uint256 value) external { count += value; } function decrement(uint256 value) external { count -= value; } }";
let directory: string, database: DatabaseClient, scanId: string, ids: string[], findingId: string;
const endpoint = (kind: "structured" | "invariant", id: string, artifactId: string, body?: string, query = "") =>
  new Request(`http://localhost/api/hypotheses/${id}/verification-target/reuse/${kind}/${artifactId}${query}`, { method: "POST", ...(body === undefined ? {} : { body }) });
const context = (id: string, artifactId: string) => ({ params: Promise.resolve({ id, artifactId }) });
const post = async (kind: "structured" | "invariant", id: string, artifactId: string, body?: string, query = "") => {
  const request = endpoint(kind, id, artifactId, body, query);
  const response = kind === "structured" ? await reuseStructuredPlanningArtifact(request, context(id, artifactId), database) :
    await reuseInvariantPlanningArtifact(request, context(id, artifactId), database);
  return { status: response.status, payload: await response.json() as { attempt?: { id: string }; proposal?: { id: string }; code?: string } };
};
const count = (table: string) => (database.sqlite.prepare(`SELECT count(*) AS count FROM ${table}`).get() as { count: number }).count;
const counts = () => Object.fromEntries(["verification_plan_attempts", "executable_invariant_proposals", "hypothesis_verification_runs", "executable_invariant_runs", "invariant_replay_artifacts", "authoritative_invariant_evidence", "hypothesis_lifecycle_transitions"].map((table) => [table, count(table)]));
const raw = (table: string, id: string) => database.sqlite.prepare(`SELECT * FROM ${table} WHERE id=?`).get(id);

function fixture() {
  const bytes = Buffer.from(source), hash = createHash("sha256").update(bytes).digest("hex");
  scanId = createScan(database, { repositoryUrl: "https://example.invalid/counter", repositoryName: "counter", depth: "quick" }).id;
  database.sqlite.prepare("UPDATE scans SET status='preparing_dependencies',resolved_commit=?,dependency_status='ready' WHERE id=?").run(commit, scanId);
  finalizeScanSourceSnapshot(database, scanId, commit, [{ sourceKey, rawBytes: bytes, rawSha256: hash, byteLength: bytes.length }]);
  finalizeScanCompilation(database, scanId, commit, { status: "supported", manifest: { schema: COMPILATION_MANIFEST_SCHEMA, scanId,
    resolvedCommit: commit, compilationProfileKind: "plain-solidity-exact-pragma-v1", compiler: { version: "0.8.24", artifactSha256: "b".repeat(64) },
    sourceRoots: ["contracts"], libraryRoots: [], remappings: [], sourceUnits: [{ sourceUnitName: sourceKey, snapshotSourceKey: sourceKey,
      rawSha256: hash, byteLength: bytes.length, contractNames: ["Counter"] }] } });
  database.sqlite.prepare("UPDATE scans SET status='completed',compiler_status='ready',compiler_versions=? WHERE id=?").run(JSON.stringify(["0.8.24"]), scanId);
  const analysis = createProtocolAnalysis(database, { scanId, provider: "mock", requestedModel: "mock", actualModel: "mock", promptVersion: "fixture",
    result: validAIOutput as unknown as ProtocolAnalysisResult, coverageStatus: "complete", contextManifest: {}, durationMs: 1, inputTokens: 1,
    outputTokens: 1, totalTokens: 2, requestId: "fixture" });
  const review = createSecurityReviewPlan(database, { scanId, protocolAnalysisId: analysis.id, plan: { selected: [], skipped: [], estimatedRequestCount: 0 }, estimatedSourceBytes: 0 });
  const reviewer = createSecurityReviewerRun(database, { planId: review.id, scanId, protocolAnalysisId: analysis.id, reviewerId: "fixture",
    reviewerName: "Fixture", selectionReason: "Fixture", promptVersion: "fixture", provider: "mock", requestedModel: "mock", contextManifest: {} });
  const [finding] = insertFindings(database, scanId, [{ title: "Counter rule", severity: "medium", confidence: 80, source: "slither",
    detectorId: "divide-before-multiply", fingerprint: randomUUID().replaceAll("-", "").padEnd(64, "0"), contract: "Counter",
    functionName: "increment", filePath: sourceKey, startLine: 1, endLine: 1, rootCause: "Counter transition", attackScenario: "",
    impact: "", evidence: "fixture", status: "candidate" }]);
  findingId = finding.id;
  const investigation = reconcileInvestigations(database, scanId)[0];
  ids = insertVulnerabilityHypotheses(database, Array.from({ length: 3 }, (_, i) => ({ scanId, protocolAnalysisId: analysis.id,
    reviewerId: "fixture", reviewerRunId: reviewer.id, title: `Counter transition ${i}`, category: "state-transition", severity: "low" as const,
    severityJustification: "Fixture", confidence: 60, summary: "Counter changes.", rootCause: "Counter transition under review.",
    preconditions: "[]", attackPath: "[]", impact: "Fixture", affectedAssets: "[]", affectedContracts: JSON.stringify(["Counter"]),
    affectedFunctions: JSON.stringify(["increment", "count"]), evidence: JSON.stringify([{ valid: true, filePath: sourceKey, contract: "Counter",
      functionName: "increment", startLine: 1, endLine: 1 }]), violatedInvariantIds: "[]", relatedInvestigationIds: JSON.stringify(i === 2 ? [] : [investigation.id]),
    falsePositiveRisks: "[]", verificationStrategy: "[]" }))).map((row) => row.id);
  insertScannerAlignment(database, scanId, { findingId, scannerId: "slither", scannerVersion: "0.11.0", detectorId: "divide-before-multiply",
    reportedSourceIdentity: sourceKey, status: "aligned", sourceUnitName: sourceKey, snapshotSourceKey: sourceKey, targetResolved: true });
  expect(listPersistedVerificationTargetGroups(database, scanId).find((group) => group.members.includes(ids[0]))?.members).toContain(ids[1]);
}
function fingerprint() {
  return fingerprintAuthoritativeSourceClosure(requireAuthoritativeSourceClosureForHypothesis(database, getVulnerabilityHypothesis(database, ids[0])!).closure);
}
function structuredPlan(hypothesisId = ids[0]) {
  return verificationHarnessPlanSchema.parse({ scanId, hypothesisId, resolvedCommit: commit, compilerVersion: "0.8.24", primaryContract: "Counter",
    primarySourcePath: sourceKey, relevantFunctions: ["increment", "count"], sourceFiles: [sourceKey], verificationGoal: "Check counter state.",
    expectedProperty: "Increment changes the count.", verificationSteps: ["Deploy", "Increment", "Read"], actors: ["deployer"],
    operations: [{ kind: "deploy", contractName: "Counter", instanceName: "target" }, { kind: "call", instanceName: "target", functionName: "increment",
      args: [{ kind: "uint", value: "1" }] }, { kind: "read-uint", instanceName: "target", functionName: "count", resultName: "observed" }],
    assertions: [{ id: "count-is-one", kind: "uint-eq", actual: "observed", expected: "1", expectedOutcome: "hypothesis-supported",
      description: "The counter becomes one after increment." }] });
}
type Strategy = "foundry-fuzz-property" | "foundry-stateful-invariant" | "echidna-stateful-invariant";
function invariantPlan(strategy: Strategy, hypothesisId = ids[0], expected = "0") {
  const fuzz = strategy === "foundry-fuzz-property";
  return executableInvariantPlanSchema.parse({ schemaVersion: "contracthunter-invariant-plan-v1", mode: fuzz ? "fuzz-property" : "stateful-invariant",
    scanId, hypothesisId, resolvedCommit: commit, compilerVersion: "0.8.24", primaryContract: "Counter", primarySourcePath: sourceKey,
    sourceFiles: [sourceKey], actors: [], setup: [{ kind: "deploy", contractName: "Counter", instanceName: "target" }],
    ...(fuzz ? { fuzzAction: { instanceName: "target", functionName: "increment", parameters: [{ name: "value", type: "uint256" }],
      args: [{ kind: "parameter", name: "value" }] }, property: { name: "countProperty", observations: [{ kind: "read-uint", instanceName: "target",
      functionName: "count", resultName: "observed" }], assertions: [{ id: "countCheck", kind: "uint-not-eq", actual: "observed", expected }] } } :
      { handlerActions: [{ name: "incrementCounter", instanceName: "target", functionName: "increment", parameters: [{ name: "value", type: "uint256" }],
        args: [{ kind: "parameter", name: "value" }] }], properties: [{ name: "countProperty", observations: [{ kind: "read-uint", instanceName: "target",
        functionName: "count", resultName: "observed" }], assertions: [{ id: "countCheck", kind: "uint-not-eq", actual: "observed", expected }] }] }) });
}
function sourceStructured(withFingerprint = true, witnessed = true) {
  const plan = structuredPlan();
  const row = createVerificationPlanAttempt(database, { hypothesisId: ids[0], scanId, selectedStrategy: "structured-verification",
    result: { status: "generated", plan, rationale: "fixture", limitations: [], notPlannableReasons: [], failureCode: null,
      provenance: { provider: "mock", requestedModel: "mock", actualModel: "mock", promptVersion: "fixture", generatedAt: new Date().toISOString(),
        inputTokens: 1, outputTokens: 1, totalTokens: 2, durationMs: 1, sourceFileCount: 1, totalSourceBytes: source.length,
        sourceContextTruncated: false } } as never, sourceClosureFingerprint: withFingerprint ? fingerprint() : undefined });
  if (witnessed) createHypothesisVerificationRun(database, { hypothesisId: ids[0], scanId, resolvedCommit: commit, compilerVersion: "0.8.24",
    verificationPlan: plan, verifierId: "local-verifier", toolName: "forge", toolVersion: null, verificationStrategy: plan.verificationSteps });
  return row;
}
function sourceInvariant(strategy: Strategy, expected = "0") {
  const plan = invariantPlan(strategy, ids[0], expected);
  const row = createExecutableInvariantProposal(database, { hypothesisId: ids[0], scanId, selectedStrategy: strategy, sourceClosureFingerprint: fingerprint(),
    result: { status: "generated", plan, planHash: invariantPlanHash(plan), hypothesisExpectation: "hypothesis-predicts-property-violation",
      relationRationale: "fixture", rationale: "fixture", limitations: [], notPlannableReasons: [], failureCode: null,
      provenance: { provider: "mock", requestedModel: "mock", actualModel: "mock", promptVersion: "fixture", generatedAt: new Date().toISOString(),
        inputTokens: 1, outputTokens: 1, totalTokens: 2, estimatedCostUsd: null, durationMs: 1, sourceFileCount: 1,
        totalSourceBytes: source.length, sourceContextTruncated: false } } as never,
    contextManifest: { sourceHashes: { [sourceKey]: createHash("sha256").update(source).digest("hex") } }, requestId: "fixture" });
  createExecutableInvariantRun(database, { plan, proposalId: row.id, engine: strategy === "echidna-stateful-invariant" ? "echidna" : "foundry" });
  return row;
}

beforeEach(() => { directory = mkdtempSync(path.join(tmpdir(), "ch-planning-reuse-")); database = createDatabase(path.join(directory, "test.db")); fixture(); });
afterEach(() => { closeDatabase(database); rmSync(directory, { recursive: true, force: true }); });

describe("explicit authoritative planning reuse API", () => {
  it("creates independent structured history for exact cross-hypothesis and repeated same-hypothesis requests", async () => {
    const original = sourceStructured(), prior = raw("verification_plan_attempts", original.id), before = counts();
    const first = await post("structured", ids[1], original.id), second = await post("structured", ids[1], original.id), own = await post("structured", ids[0], original.id);
    expect([first.status, second.status, own.status]).toEqual([201, 201, 201]);
    const newIds = [first, second, own].map((item) => item.payload.attempt!.id);
    expect(new Set([original.id, ...newIds]).size).toBe(4);
    for (const id of newIds) {
      const row = getVerificationPlanAttempt(database, id)!;
      expect(row).toMatchObject({ status: "generated", reuseSourceArtifactType: "structured-plan", reuseSourceArtifactId: original.id,
        sourceClosureFingerprintSha256: fingerprint().sha256, reuseCompilerArtifactSha256: "b".repeat(64) });
      expect(row.reuseTargetId).toMatch(/^[a-f0-9]{64}$/);
      expect(row.reuseCreatedAt).toBeInstanceOf(Date);
      expect(JSON.parse(row.result)).not.toHaveProperty("provenance");
      expect(() => database.sqlite.prepare("UPDATE verification_plan_attempts SET reuse_source_artifact_id=? WHERE id=?").run(randomUUID(), id)).toThrow("immutable");
    }
    expect(getVerificationPlanAttempt(database, newIds[0])!.hypothesisId).toBe(ids[1]);
    expect(raw("verification_plan_attempts", original.id)).toEqual(prior);
    expect(counts()).toMatchObject({ ...before, verification_plan_attempts: before.verification_plan_attempts + 3 });
  });
  it.each(["foundry-fuzz-property", "foundry-stateful-invariant", "echidna-stateful-invariant"] as const)("creates a fresh %s invariant proposal without inherited execution", async (strategy) => {
    const original = sourceInvariant(strategy), prior = raw("executable_invariant_proposals", original.id), before = counts();
    const response = await post("invariant", ids[1], original.id);
    expect(response.status).toBe(201);
    const row = getExecutableInvariantProposal(database, response.payload.proposal!.id)!;
    expect(row.id).not.toBe(original.id);
    expect(row).toMatchObject({ hypothesisId: ids[1], selectedStrategy: strategy, reuseSourceArtifactType: "invariant-proposal",
      reuseSourceArtifactId: original.id, sourceClosureFingerprintSha256: fingerprint().sha256, provider: "", requestedModel: "",
      actualModel: null, promptVersion: "", requestId: null });
    expect(row.reuseTargetId).toMatch(/^[a-f0-9]{64}$/);
    expect(row.reuseCreatedAt).toBeInstanceOf(Date);
    expect(() => database.sqlite.prepare("UPDATE executable_invariant_proposals SET reuse_source_artifact_id=? WHERE id=?").run(randomUUID(), row.id)).toThrow("immutable");
    expect(raw("executable_invariant_proposals", original.id)).toEqual(prior);
    expect(counts()).toMatchObject({ ...before, executable_invariant_proposals: before.executable_invariant_proposals + 1 });
  });
  it("rejects missing fingerprint, mismatched fingerprint, scan commit, compiler, and target state", async () => {
    const original = sourceStructured();
    const change = async (sql: string, args: unknown[], code: string) => { database.sqlite.prepare(sql).run(...args); const response = await post("structured", ids[1], original.id); expect(response).toMatchObject({ status: 409, payload: { code } }); };
    await change("UPDATE vulnerability_hypotheses SET related_investigation_ids='[]' WHERE id=?", [ids[1]], "reuse_target_changed");
    database.sqlite.prepare("UPDATE vulnerability_hypotheses SET related_investigation_ids=related_investigation_ids WHERE id=?").run(ids[0]);
    const links = getVulnerabilityHypothesis(database, ids[0])!.relatedInvestigationIds;
    database.sqlite.prepare("UPDATE vulnerability_hypotheses SET related_investigation_ids=? WHERE id=?").run(links, ids[1]);
    await change("UPDATE scans SET resolved_commit=? WHERE id=?", ["c".repeat(40), scanId], "reuse_commit_mismatch");
    database.sqlite.prepare("UPDATE scans SET resolved_commit=? WHERE id=?").run(commit, scanId);
    await change("UPDATE scans SET compiler_versions=? WHERE id=?", [JSON.stringify(["0.8.23"]), scanId], "reuse_compiler_mismatch");
    database.sqlite.prepare("UPDATE scans SET compiler_versions=? WHERE id=?").run(JSON.stringify(["0.8.24"]), scanId);
    const other = createVerificationPlanAttempt(database, { hypothesisId: ids[0], scanId, selectedStrategy: "structured-verification",
      result: JSON.parse(original.result) as never, sourceClosureFingerprint: { ...fingerprint(), sha256: "e".repeat(64) } });
    expect(await post("structured", ids[1], other.id)).toMatchObject({ status: 409, payload: { code: "reuse_source_changed" } });
  });
  it("rejects exact-target, strategy, mode, property, and alignment changes at POST", async () => {
    const structured = sourceStructured();
    expect(await post("structured", ids[2], structured.id)).toMatchObject({ status: 409, payload: { code: "reuse_target_changed" } });
    const stateful = sourceInvariant("foundry-stateful-invariant");
    database.sqlite.prepare("UPDATE executable_invariant_proposals SET selected_strategy='foundry-fuzz-property' WHERE id=?").run(stateful.id);
    expect(await post("invariant", ids[1], stateful.id)).toMatchObject({ status: 409, payload: { code: "reuse_mode_mismatch" } });
    database.sqlite.prepare("UPDATE executable_invariant_proposals SET selected_strategy='foundry-stateful-invariant' WHERE id=?").run(stateful.id);
    database.sqlite.prepare("UPDATE executable_invariant_runs SET status='completed' WHERE proposal_id=?").run(stateful.id);
    const incompatible = sourceInvariant("foundry-stateful-invariant", "1");
    expect(await post("invariant", ids[1], stateful.id)).toMatchObject({ status: 201 });
    expect(await post("invariant", ids[1], incompatible.id)).toMatchObject({ status: 409, payload: { code: "reuse_property_target_mismatch" } });
    database.sqlite.prepare("UPDATE vulnerability_hypotheses SET related_investigation_ids='[]' WHERE id=?").run(ids[1]);
    expect(await post("structured", ids[1], structured.id)).toMatchObject({ status: 409, payload: { code: "reuse_target_changed" } });
  });
  it("accepts selectors only and performs no provider, execution, evidence, or lifecycle work on success or failure", async () => {
    const original = sourceStructured(), before = counts();
    const network = vi.spyOn(globalThis, "fetch").mockImplementation(() => { throw new Error("Unexpected provider or worker request"); });
    try {
      expect((await post("structured", ids[1], original.id)).status).toBe(201);
      expect((await post("structured", ids[2], original.id)).status).toBe(409);
      for (const key of ["targetId", "rootCauseFamily", "representative", "fingerprint", "scanId", "commit", "compiler", "strategy", "mode", "sourcePath", "sourceBytes", "propertyTarget", "canonicalPlan", "providerPayload", "executable", "arguments", "config", "seed"])
        expect((await post("structured", ids[1], original.id, JSON.stringify({ [key]: "forged" }))).status).toBe(400);
      expect((await post("structured", ids[1], original.id, undefined, "?strategy=forged")).status).toBe(400);
      expect((await post("structured", ids[1], original.id, "x".repeat(1025))).status).toBe(413);
      expect(network).not.toHaveBeenCalled();
      expect(counts()).toMatchObject({ ...before, verification_plan_attempts: before.verification_plan_attempts + 1 });
      expect(getVulnerabilityHypothesis(database, ids[1])?.status).toBe("candidate");
    } finally { network.mockRestore(); }
  });
  it("rolls back a rejected insert without creating reuse provenance or any other artifact", async () => {
    const original = sourceStructured(), before = counts();
    database.sqlite.exec("CREATE TRIGGER reject_reuse BEFORE INSERT ON verification_plan_attempts WHEN NEW.reuse_source_artifact_id IS NOT NULL BEGIN SELECT RAISE(ABORT, 'fixture rollback'); END");
    expect(await post("structured", ids[1], original.id)).toMatchObject({ status: 500, payload: { code: "reuse_failed_safely" } });
    expect(counts()).toEqual(before);
  });
  it("rejects historical null fingerprints and unsupported compilation without checkout recovery", async () => {
    const original = sourceStructured();
    database.sqlite.exec("DROP TRIGGER verification_plan_attempts_source_fingerprint_immutable");
    database.sqlite.prepare("UPDATE verification_plan_attempts SET source_closure_fingerprint_schema=NULL,source_closure_fingerprint_sha256=NULL,source_closure_fingerprint_file_count=NULL,source_closure_fingerprint_total_bytes=NULL WHERE id=?").run(original.id);
    expect(await post("structured", ids[1], original.id)).toMatchObject({ status: 409, payload: { code: "reuse_source_identity_unprovable" } });
    database.sqlite.exec("DROP TRIGGER scan_compilation_provenance_immutable");
    database.sqlite.prepare("UPDATE scan_compilation_provenance SET status='unsupported',unsupported_reason='dynamic_build_configuration',schema=NULL,profile_kind=NULL,compiler_version=NULL,compiler_artifact_sha256=NULL,source_roots=NULL,library_roots=NULL,remappings=NULL WHERE scan_id=?").run(scanId);
    expect(await post("structured", ids[1], original.id)).toMatchObject({ status: 409, payload: { code: "reuse_authoritative_profile_unsupported" } });
  });
  it("rejects a newly unaligned source and current strategy incompatibility", async () => {
    const original = sourceStructured();
    database.sqlite.exec("DROP TRIGGER scan_scanner_alignment_immutable");
    database.sqlite.prepare("UPDATE scan_scanner_alignment SET status='unaligned',source_unit_name=NULL,snapshot_source_key=NULL,target_resolved=0 WHERE finding_id=?").run(findingId);
    expect(await post("structured", ids[1], original.id)).toMatchObject({ status: 409, payload: { code: "reuse_alignment_unavailable" } });
  });
  it("recomputes strategy requirements from current scanner facts", async () => {
    const original = sourceInvariant("echidna-stateful-invariant");
    database.sqlite.prepare("UPDATE findings SET detector_id='protected-vars' WHERE id=?").run(findingId);
    expect(await post("invariant", ids[1], original.id)).toMatchObject({ status: 409, payload: { code: "reuse_strategy_mismatch" } });
  });
  it("reruns concrete Echidna compatibility and refuses a currently incompatible semantic plan", async () => {
    const original = sourceInvariant("echidna-stateful-invariant"), oldPlan = JSON.parse(original.plan!) as Record<string, unknown>;
    const changed = executableInvariantPlanSchema.parse({ ...oldPlan, actors: ["attacker"] });
    const hash = invariantPlanHash(changed);
    database.sqlite.prepare("UPDATE executable_invariant_proposals SET plan=?,plan_hash=? WHERE id=?").run(JSON.stringify(changed), hash, original.id);
    database.sqlite.prepare("UPDATE executable_invariant_runs SET plan=?,plan_hash=? WHERE proposal_id=?").run(JSON.stringify(changed), hash, original.id);
    expect(await post("invariant", ids[1], original.id)).toMatchObject({ status: 409, payload: { code: "reuse_concrete_strategy_incompatible" } });
  });
  it("checks a reused source artifact's recorded compiler hash independently of source bytes", async () => {
    const original = sourceStructured(), first = await post("structured", ids[1], original.id);
    expect(first.status).toBe(201);
    const plan = structuredPlan(ids[1]);
    createHypothesisVerificationRun(database, { hypothesisId: ids[1], scanId, resolvedCommit: commit, compilerVersion: "0.8.24",
      verificationPlan: plan, verifierId: "local-verifier", toolName: "forge", toolVersion: null, verificationStrategy: plan.verificationSteps });
    database.sqlite.exec("DROP TRIGGER scan_compilation_provenance_immutable");
    database.sqlite.prepare("UPDATE scan_compilation_provenance SET compiler_artifact_sha256=? WHERE scan_id=?").run("c".repeat(64), scanId);
    expect(await post("structured", ids[1], first.payload.attempt!.id)).toMatchObject({ status: 409, payload: { code: "reuse_compiler_mismatch" } });
  });
  it("rejects missing or forged artifact selectors and keeps failed admission read only", async () => {
    const original = sourceStructured(), before = counts();
    expect(await post("structured", ids[1], randomUUID())).toMatchObject({ status: 404, payload: { code: "reuse_artifact_not_found" } });
    expect(await post("structured", ids[1], "../../secret")).toMatchObject({ status: 400, payload: { code: "reuse_request_invalid" } });
    expect(await post("structured", randomUUID(), original.id)).toMatchObject({ status: 404, payload: { code: "reuse_hypothesis_not_found" } });
    expect(counts()).toEqual(before);
  });
  it("requires a persisted source validation witness and rejects a rejected source hypothesis", async () => {
    const unwitnessed = sourceStructured(true, false), before = counts();
    expect(await post("structured", ids[1], unwitnessed.id)).toMatchObject({ status: 409, payload: { code: "reuse_candidate_not_eligible" } });
    expect(counts()).toEqual(before);
    const plan = structuredPlan();
    createHypothesisVerificationRun(database, { hypothesisId: ids[0], scanId, resolvedCommit: commit, compilerVersion: "0.8.24",
      verificationPlan: plan, verifierId: "local-verifier", toolName: "forge", toolVersion: null, verificationStrategy: plan.verificationSteps });
    database.sqlite.prepare("UPDATE vulnerability_hypotheses SET status='rejected' WHERE id=?").run(ids[0]);
    expect(await post("structured", ids[1], unwitnessed.id)).toMatchObject({ status: 409, payload: { code: "reuse_candidate_not_eligible" } });
  });
  it("rejects cross-scan reuse even when a later scan has the same canonical source bytes", async () => {
    const original = sourceStructured(), oldScanId = scanId;
    fixture();
    expect(scanId).not.toBe(oldScanId);
    expect(await post("structured", ids[1], original.id)).toMatchObject({ status: 409, payload: { code: "reuse_scan_mismatch" } });
    expect(raw("verification_plan_attempts", original.id)).toMatchObject({ scan_id: oldScanId, reuse_source_artifact_id: null });
  });
});
