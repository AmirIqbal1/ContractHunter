import { describe, expect, it } from "vitest";
import { buildEvidencePackage, evidenceArtifact } from "./evidence-package";
import { buildBountyReport, defaultBountyReportFields, renderBountyReportMarkdown,
  verifyBountyReport } from "./bounty-report";

const scanId = "11111111-1111-4111-8111-111111111111";
const subjectId = "22222222-2222-4222-8222-222222222222";
function fixture(dynamic = false) {
  const artifacts = [evidenceArtifact({ type: "static-context", id: subjectId,
    schemaVersion: "context-v1", status: "available", sourceContentHash: null, provenance: [], recordCount: 1,
    data: { findings: [{ id: subjectId, contract: "Vault|X", functionName: "withdraw", sourceUnit: "Vault.sol",
      startLine: 4, endLine: 5, scanner: "fixture", detectorId: "d", status: "candidate" }] } }),
  evidenceArtifact({ type: "source", id: "source", schemaVersion: "source-v1", status: "available",
    sourceContentHash: null, provenance: [subjectId], recordCount: 1,
    data: { sourceUnit: "Vault.sol", rawSha256: "abc", startLine: 4, endLine: 5,
      excerpt: "contract Vault {\n```\n<script>alert(1)</script>\n}" } })];
  if (dynamic) {
    artifacts.push(evidenceArtifact({ type: "reviewed-poc", id: "poc", schemaVersion: "poc-v1", status: "available",
      sourceContentHash: null, provenance: [subjectId], recordCount: 1,
      data: { id: "poc", sourceSha256: "def", source: "contract PoC {\n````\n}", forgeVersion: "1.7.1" } }));
    artifacts.push(evidenceArtifact({ type: "fork-identity", id: "fork", schemaVersion: "fork-v1", status: "available",
      sourceContentHash: null, provenance: ["poc"], recordCount: 1,
      data: { chainId: 1, forkBlock: 100, forkBlockHash: "0xabc", targetCodeHashes: { "0xabc": "def" } } }));
    artifacts.push(evidenceArtifact({ type: "execution", id: "execution", schemaVersion: "execution-v1", status: "available",
      sourceContentHash: null, provenance: ["poc", "fork"], recordCount: 1,
      data: { id: "execution", status: "completed", executed: true, transactionHashes: ["0xtx"] } }));
    artifacts.push(evidenceArtifact({ type: "asset-flow", id: "flow", schemaVersion: "flow-v1", status: "available",
      sourceContentHash: null, provenance: ["execution"], recordCount: 1,
      data: { ledgerEntries: [{ transactionOrdinal: 0, assetId: "TOKEN", from: "A", to: "B",
        amount: "900719925474099312345", movementKind: "erc20-transfer", evidenceId: "log" }],
        netPositions: [{ participant: "B", assetId: "TOKEN", incoming: "900719925474099312345",
          outgoing: "0", netObservedMovement: "900719925474099312345" }] } }));
  }
  return buildEvidencePackage({ packageId: "33333333-3333-4333-8333-333333333333", huntId: scanId, scanId,
    subject: { type: "finding", id: subjectId, title: "Issue <script>", status: "candidate",
      existingSeverity: "high", existingConfidence: 90 },
    selection: { executionId: dynamic ? "44444444-4444-4444-8444-444444444444" : null,
      scenarioRevisionId: null, replayRunId: null }, status: "finalized", artifacts, warnings: [],
    createdAt: 1, finalizedAt: 2 });
}
function report(dynamic = false) {
  const pkg = fixture(dynamic), fields = { ...defaultBountyReportFields(pkg), summary: "User | text\n<script>bad</script>" };
  return { pkg, value: buildBountyReport(pkg, fields, { reportId: "55555555-5555-4555-8555-555555555555",
    revisionOf: null, status: "finalized", createdAt: 3, finalizedAt: 4 }) };
}
describe("deterministic bounty report", () => {
  it("uses finalized G1 only, binds hashes and preserves exact raw integers", () => {
    const { pkg, value } = report(true), markdown = renderBountyReportMarkdown(value);
    expect(verifyBountyReport(value, pkg)).toBe(true);
    expect(value.evidencePackageContentHash).toBe(pkg.contentHash);
    expect(markdown).toContain("900719925474099312345");
    expect(markdown).toContain("No transaction was sent to the upstream/live network.");
    expect(markdown).toContain("Reported/Existing Severity");
    expect(markdown).not.toContain("profit");
  });
  it("escapes hostile prose and tables and uses a longer source fence", () => {
    const { value } = report(true), markdown = renderBountyReportMarkdown(value);
    expect(markdown).toContain("&lt;script&gt;bad&lt;/script&gt;");
    expect(markdown).toContain("Vault\\|X");
    expect(markdown).toContain("`````solidity");
    expect(markdown).toContain("````\n}");
    expect(markdown).toContain("&lt;script&gt;bad&lt;/script&gt;");
    expect(markdown).toContain("<script>alert(1)</script>"); // Exact source inside a safe code fence.
  });
  it("rejects draft packages, tampering and oversized researcher text", () => {
    const { pkg, value } = report();
    expect(verifyBountyReport({ ...value, fields: { ...value.fields, summary: "altered" } }, pkg)).toBe(false);
    expect(() => buildBountyReport({ ...pkg, status: "draft" }, value.fields,
      { reportId: value.reportId, revisionOf: null, status: "draft", createdAt: 3, finalizedAt: null })).toThrow();
    expect(() => buildBountyReport(pkg, { ...value.fields, summary: "x".repeat(4097) },
      { reportId: value.reportId, revisionOf: null, status: "draft", createdAt: 3, finalizedAt: null })).toThrow();
  });
  it("changes content hash only for semantic fields, not lifecycle timestamps", () => {
    const { pkg, value } = report();
    const later = buildBountyReport(pkg, value.fields, { reportId: "other", revisionOf: value.reportId,
      status: "draft", createdAt: 999, finalizedAt: null });
    expect(later.contentHash).toBe(value.contentHash);
    const edited = buildBountyReport(pkg, { ...value.fields, impactStatement: "Researcher claim" },
      { reportId: "other", revisionOf: value.reportId, status: "draft", createdAt: 999, finalizedAt: null });
    expect(edited.contentHash).not.toBe(value.contentHash);
  });
});
