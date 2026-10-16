import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { closeDatabase, createDatabase, createImpactPoCArtifact, createImpactPoCExecution,
  createScan, insertFindings, recordImpactForkSession, type DatabaseClient } from "@contracthunter/db";
import type { ImpactForkSession } from "@contracthunter/core";
import { impactSubjectInScan, publicImpactExecution, publicImpactPoC, requestedImpactScan, scopedImpactExecution,
  scopedImpactPoC, scopedImpactSession } from "./impact-api-scope";

describe("Impact API scan scope and response projection", () => {
  it("rejects wrong scan bindings for subject, session, PoC, and execution", () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "impact-api-scope-"));
    const database: DatabaseClient = createDatabase(path.join(dir, "db.sqlite"));
    try {
      const scan = createScan(database, { repositoryUrl: "https://example.invalid/one",
        repositoryName: "one", depth: "quick" });
      const other = createScan(database, { repositoryUrl: "https://example.invalid/two",
        repositoryName: "two", depth: "quick" });
      const finding = insertFindings(database, scan.id, [{ title: "Test", severity: "informational",
        confidence: 80, source: "slither", detectorId: "test", fingerprint: "a".repeat(64),
        contract: "Vault", functionName: "run", filePath: "contracts/Vault.sol", startLine: 1,
        endLine: 1, rootCause: "Test", attackScenario: "Test", impact: "Test",
        evidence: "Test", status: "candidate" }])[0]!;
      const target = `0x${"1".repeat(40)}`;
      const session: ImpactForkSession = { id: crypto.randomUUID(), findingId: finding.id,
        hypothesisId: null, chainId: 1, network: "fixture", upstreamRpcRef: "IMPACT_RPC_SECRET",
        rpcConfigId: "fixture", targetContracts: [target],
        targetCodeHashes: { [target]: `sha256:${"b".repeat(64)}` }, resolvedForkBlock: 10,
        historicalTransactionHash: null, forkBlockHash: `0x${"a".repeat(64)}`, status: "ready",
        localPort: 49001, localRpcEndpoint: "http://127.0.0.1:49001", anvilVersion: "1.7.1",
        anvilSha256: "c".repeat(64), processPid: 1234, baselineSnapshotId: "0x1",
        disposableAccounts: [], createdAt: 1, startedAt: 2, stoppedAt: null, failureCode: null };
      recordImpactForkSession(database, session);
      const poc = createImpactPoCArtifact(database, { findingId: finding.id,
        filename: "ImpactPoC.s.sol", source: "pragma solidity 0.8.36; contract ImpactPoC { function run() external {} }",
        entryContract: "ImpactPoC" });
      const execution = createImpactPoCExecution(database, { id: crypto.randomUUID(), artifactId: poc.id,
        sourceSha256: poc.sourceSha256, sessionId: session.id, runtimeTokenSha256: `sha256:${"d".repeat(64)}`,
        chainId: 1, forkBlock: 10, forkBlockHash: session.forkBlockHash!, targetCodeHashes: session.targetCodeHashes,
        forgeVersion: "1.7.1", forgeSha256: "e".repeat(64) });
      expect(impactSubjectInScan(database, scan.id, finding.id, null)).toBe(true);
      expect(impactSubjectInScan(database, other.id, finding.id, null)).toBe(false);
      expect(scopedImpactSession(database, other.id, session.id)).toBeNull();
      expect(scopedImpactPoC(database, other.id, poc.id)).toBeNull();
      expect(scopedImpactExecution(database, other.id, execution.id)).toBeNull();
      expect(scopedImpactExecution(database, scan.id, execution.id)?.id).toBe(execution.id);
      const response = JSON.stringify(publicImpactExecution(execution));
      for (const forbidden of ["runtimeTokenSha256", "stdout", "stderr", "IMPACT_RPC_SECRET", "49001"])
        expect(response).not.toContain(forbidden);
      const historicalPoC = JSON.stringify(publicImpactPoC({ ...poc,
        source: "pragma solidity 0.8.36; // API_KEY=HISTORICAL_SECRET" }));
      expect(historicalPoC).not.toContain("HISTORICAL_SECRET");
      expect(historicalPoC).toContain('"sourceOmitted":true');
      expect(requestedImpactScan(new Request(`http://localhost/api/impact/pocs/${poc.id}?scanId=${scan.id}`)))
        .toBe(scan.id);
      expect(requestedImpactScan(new Request("http://localhost/api/impact/pocs?id=bad"))).toBeNull();
    } finally { closeDatabase(database); rmSync(dir, { recursive: true, force: true }); }
  });
});
