import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { ImpactForkSession } from "@contracthunter/core";
import { closeDatabase, createDatabase, createImpactPoCArtifact, createImpactPoCExecution, createScan,
  getFinding, insertFindings, readEvidencePackage, recordImpactForkSession, reviewImpactPoCArtifact,
  updateImpactPoCExecution } from "@contracthunter/db";
import { composeEvidencePackage, createEvidencePackage, finalizeEvidencePackageFromCurrent } from "./evidence-package-server";

const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });
function fixture() {
  const dir = mkdtempSync(path.join(os.tmpdir(), "impact-g1-service-")); dirs.push(dir);
  const database = createDatabase(path.join(dir, "db.sqlite"));
  const scan = createScan(database, { repositoryUrl: "https://example.invalid/g1",
    repositoryName: "fixture/g1", depth: "quick" });
  const other = createScan(database, { repositoryUrl: "https://example.invalid/other",
    repositoryName: "fixture/other", depth: "quick" });
  const finding = insertFindings(database, scan.id, [{ title: "<script>plain data</script>",
    severity: "informational", confidence: 80, source: "slither", detectorId: "test",
    fingerprint: "a".repeat(64), contract: "Vault", functionName: "move",
    filePath: "/home/amir/Desktop/ContractHunter/private.sol", startLine: 1, endLine: 1,
    rootCause: "Fixture", attackScenario: "Fixture", impact: "Fixture", evidence: "Fixture",
    status: "candidate" }])[0]!;
  const selection = { subjectType: "finding" as const, subjectId: finding.id,
    executionId: null, scenarioRevisionId: null, replayRunId: null };
  return { database, scan, other, finding, selection };
}
describe("evidence composition authority", () => {
  it("builds static-only evidence without mutable source paths or execution calls", () => {
    const { database, scan, other, finding, selection } = fixture();
    try {
      const preview = composeEvidencePackage(database, scan.id, selection,
        { id: crypto.randomUUID(), createdAt: 0, status: "draft", finalizedAt: null });
      expect(preview.completeness).toBe("static-only");
      expect(JSON.stringify(preview)).not.toContain("/home/amir");
      expect(JSON.stringify(preview)).toContain("<script>plain data</script>");
      expect(preview.artifacts.map((item) => item.type)).toEqual(["static-context"]);
      const draft = createEvidencePackage(database, scan.id, selection);
      expect(readEvidencePackage(database, scan.id, draft.packageId)?.status).toBe("draft");
      expect(readEvidencePackage(database, other.id, draft.packageId)).toBeNull();
      const finalized = finalizeEvidencePackageFromCurrent(database, scan.id, draft.packageId);
      expect(finalized.status).toBe("finalized");
      expect(getFinding(database, finding.id)?.status).toBe("candidate");
      expect(() => finalizeEvidencePackageFromCurrent(database, scan.id, draft.packageId)).toThrow();
    } finally { closeDatabase(database); }
  });
  it("rejects wrong hunt, unknown execution and scenario without exact execution", () => {
    const { database, scan, other, selection } = fixture();
    try {
      expect(() => createEvidencePackage(database, other.id, selection)).toThrow("evidence_subject_not_found");
      expect(() => createEvidencePackage(database, scan.id, { ...selection,
        executionId: crypto.randomUUID() })).toThrow("evidence_execution_not_final");
      expect(() => createEvidencePackage(database, scan.id, { ...selection,
        scenarioRevisionId: crypto.randomUUID() })).toThrow("evidence_selection_invalid");
    } finally { closeDatabase(database); }
  });
  it("packages an exact reviewed local execution as partial without runtime secrets", () => {
    const { database, scan, finding, selection } = fixture();
    try {
      const target = `0x${"1".repeat(40)}`, blockHash = `0x${"a".repeat(64)}`;
      const session: ImpactForkSession = { id: crypto.randomUUID(), findingId: finding.id,
        hypothesisId: null, chainId: 1, network: "fixture", upstreamRpcRef: "IMPACT_RPC_SECRET",
        rpcConfigId: "fixture", targetContracts: [target],
        targetCodeHashes: { [target]: `sha256:${"b".repeat(64)}` }, resolvedForkBlock: 10,
        historicalTransactionHash: null, forkBlockHash: blockHash, status: "ready", localPort: 49001,
        localRpcEndpoint: "http://127.0.0.1:49001", anvilVersion: "1.7.1",
        anvilSha256: "c".repeat(64), processPid: 1234, baselineSnapshotId: "0x1",
        disposableAccounts: [], createdAt: 1, startedAt: 2, stoppedAt: null, failureCode: null };
      recordImpactForkSession(database, session);
      const poc = createImpactPoCArtifact(database, { findingId: finding.id,
        filename: "ImpactPoC.s.sol", source: "pragma solidity 0.8.36; contract ImpactPoC { function run() external {} }",
        entryContract: "ImpactPoC" });
      reviewImpactPoCArtifact(database, poc.id, "reviewed");
      const execution = createImpactPoCExecution(database, { id: crypto.randomUUID(), artifactId: poc.id,
        sourceSha256: poc.sourceSha256, sessionId: session.id,
        runtimeTokenSha256: `sha256:${"d".repeat(64)}`, chainId: 1, forkBlock: 10,
        forkBlockHash: blockHash, targetCodeHashes: session.targetCodeHashes,
        forgeVersion: "1.7.1", forgeSha256: "e".repeat(64) });
      updateImpactPoCExecution(database, execution.id, "completed", { exitCode: 0,
        compiled: true, executed: true, stdout: "worker secret=HIDDEN", stderr: "",
        transactionHashes: [], errorCode: null, forgeVersion: "1.7.1", forgeSha256: "e".repeat(64) });
      const value = createEvidencePackage(database, scan.id, { ...selection, executionId: execution.id });
      expect(value.completeness).toBe("dynamic-partial");
      expect(value.capabilities.state).toBe("unavailable");
      expect(value.capabilities.trace).toBe("unavailable");
      const json = JSON.stringify(value);
      for (const secret of ["IMPACT_RPC_SECRET", "127.0.0.1", "49001", "HIDDEN", "processPid", "/home/amir"])
        expect(json).not.toContain(secret);
      expect(value.localExecutionStatement).toContain("isolated local fork");
      expect(getFinding(database, finding.id)?.status).toBe("candidate");
      const other = insertFindings(database, scan.id, [{ title: "Other", severity: "informational",
        confidence: 80, source: "slither", detectorId: "other", fingerprint: "f".repeat(64),
        contract: "Other", functionName: "run", filePath: "contracts/Other.sol", startLine: 1,
        endLine: 1, rootCause: "Fixture", attackScenario: "Fixture", impact: "Fixture",
        evidence: "Fixture", status: "candidate" }])[0]!;
      expect(() => createEvidencePackage(database, scan.id, { ...selection,
        subjectId: other.id, executionId: execution.id })).toThrow("evidence_wrong_subject");
    } finally { closeDatabase(database); }
  });
});
