import { describe, expect, it } from "vitest";
import { buildEvidencePackage, canonicalEvidenceJson, evidenceArtifact, verifyEvidencePackageIntegrity,
  type EvidenceArtifact, type EvidencePackage } from "./evidence-package";

const scanId = "11111111-1111-4111-8111-111111111111";
const subjectId = "22222222-2222-4222-8222-222222222222";
const executionId = "33333333-3333-4333-8333-333333333333";
function artifact(type: string, id: string, provenance: string[], data: unknown,
  status: EvidenceArtifact["status"] = "available") {
  return evidenceArtifact({ type, id, schemaVersion: `${type}-v1`, status,
    sourceContentHash: null, provenance, recordCount: 1, data });
}
function build(artifacts: EvidenceArtifact[], execution: string | null = null,
  scenarioRevisionId: string | null = null, replayRunId: string | null = null): EvidencePackage {
  return buildEvidencePackage({ packageId: "44444444-4444-4444-8444-444444444444", huntId: scanId,
    scanId, subject: { type: "finding", id: subjectId, title: "Observed issue", status: "investigating",
      existingSeverity: "medium", existingConfidence: 80 },
    selection: { executionId: execution, scenarioRevisionId, replayRunId }, status: "finalized",
    artifacts, warnings: [], createdAt: 1, finalizedAt: 2 });
}
const staticContext = artifact("static-context", subjectId, [], { findingIds: [subjectId] });
describe("deterministic evidence package", () => {
  it("builds a valid static-only package without invented dynamic evidence", () => {
    const value = build([staticContext, artifact("source", "snapshot:source", [subjectId],
      { sourceUnit: "src/Vault.sol", excerpt: "contract Vault {}" }),
    artifact("investigation-path", "path", [subjectId], { kind: "static" })]);
    expect(value.completeness).toBe("static-only");
    expect(value.capabilities.trace).toBe("unavailable");
    expect(value.executionEnvironment).toBeNull();
    expect(verifyEvidencePackageIntegrity(value)).toEqual({ status: "valid", reasons: [] });
  });
  it("marks partial trace/state explicitly in a dynamic package", () => {
    const value = build([staticContext,
      artifact("reviewed-poc", "poc", [subjectId], { sourceHash: "abc" }),
      artifact("fork-identity", "fork", ["poc"], { block: 100 }),
      artifact("execution", executionId, ["poc", "fork"], { status: "completed" }),
      artifact("trace", "trace", [executionId], { reason: "unavailable" }, "unavailable"),
      artifact("state", "state", [executionId], { pre: "available", post: null }, "partial")], executionId);
    expect(value.completeness).toBe("dynamic-partial");
    expect(value.capabilities.trace).toBe("unavailable");
    expect(value.capabilities.state).toBe("partial");
    expect(value.localExecutionStatement).toContain("No transaction was sent");
  });
  it("binds full reviewed scenario and bounded replay without an independent cumulative sum", () => {
    const run = "66666666-6666-4666-8666-666666666666", scenario = "55555555-5555-4555-8555-555555555555";
    const artifacts = [staticContext, artifact("reviewed-poc", "poc", [subjectId], {}),
      artifact("fork-identity", "fork", ["poc"], {}),
      artifact("execution", executionId, ["poc", "fork"], {}),
      artifact("trace", "trace", [executionId], {}), artifact("state", "state", [executionId], {}),
      artifact("asset-flow", "flow", [executionId], { amount: "900719925474099312345" }),
      artifact("reviewed-scenario", scenario, ["flow"], { roles: ["scenario-subject", "protocol"] }),
      artifact("replay", run, [scenario], { mode: "independent-replay", completed: 3,
        iterations: [{ net: "100" }, { net: "100" }, { net: "100" }], cumulative: [] })];
    const value = build(artifacts, executionId, scenario, run);
    expect(value.completeness).toBe("dynamic-complete-within-evidence");
    expect(value.limitations.join(" ")).toContain("unlimited repeatability");
    expect(canonicalEvidenceJson(value)).toContain("900719925474099312345");
    expect(verifyEvidencePackageIntegrity(value).status).toBe("valid");
  });
  it("keeps semantic hashes stable across DB identity and timestamps", () => {
    const first = build([staticContext]);
    const second = buildEvidencePackage({ packageId: "99999999-9999-4999-8999-999999999999",
      huntId: first.huntId, scanId: first.scanId, subject: first.subject, selection: first.selection,
      status: "draft", artifacts: [staticContext], warnings: [], createdAt: 999, finalizedAt: null });
    expect(second.manifestHash).toBe(first.manifestHash);
    expect(second.contentHash).toBe(first.contentHash);
  });
  it("detects changed evidence and tampered manifest or package fields", () => {
    const original = build([staticContext]);
    const changed = build([artifact("static-context", subjectId, [], { findingIds: [] })]);
    expect(changed.contentHash).not.toBe(original.contentHash);
    expect(changed.manifestHash).not.toBe(original.manifestHash);
    expect(verifyEvidencePackageIntegrity({ ...original, artifacts: changed.artifacts }).status).toBe("invalid");
    expect(verifyEvidencePackageIntegrity({ ...original, manifestHash: "sha256:bad" }).status).toBe("invalid");
    expect(verifyEvidencePackageIntegrity({ ...original, limitations: [] }).status).toBe("invalid");
  });
  it("rejects dangling provenance, unsafe numbers and oversized payloads", () => {
    expect(() => build([staticContext, artifact("trace", "trace", ["foreign-hunt"], {})])).toThrow("evidence_dangling_provenance");
    expect(() => canonicalEvidenceJson(Number.MAX_SAFE_INTEGER + 1)).toThrow("evidence_unsafe_number");
    expect(canonicalEvidenceJson(900719925474099312345n)).toBe('"900719925474099312345"');
    expect(artifact("asset-flow", "big", [], { amount: 900719925474099312345n }).data)
      .toEqual({ amount: "900719925474099312345" });
    expect(() => artifact("trace", "large", [], { bytes: "x".repeat(2_500_001) })).toThrow("evidence_artifact_size_limit");
  });
  it("keeps hostile text as JSON data", () => {
    const value = build([artifact("static-context", subjectId, [], { title: "<script>alert(1)</script>" })]);
    expect(canonicalEvidenceJson(value)).toContain("<script>alert(1)</script>");
    expect(verifyEvidencePackageIntegrity(value).status).toBe("valid");
  });
});
