import { randomUUID } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { impactTraceHash, makeImpactObservationPlan, planHash, snapshotHash, type ImpactForkSession,
  type ImpactStateProvenance, type ImpactStateSnapshot, type ImpactTransactionTrace } from "@contracthunter/core";
import { closeDatabase, createDatabase, createScan, insertFindings, recordImpactForkSession } from "./index";
import { createImpactPoCArtifact, createImpactPoCExecution, readImpactPoCExecution,
  reviewImpactPoCArtifact, updateImpactPoCExecution } from "./impact-poc";
import { persistImpactStateArtifacts } from "./impact-state";
import { persistImpactTraceCapture, readImpactExecutionTraces, readImpactTransactionTrace } from "./impact-trace";

const directories: string[] = [];
afterEach(() => { for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true }); });
const target = `0x${"1".repeat(40)}`, sender = `0x${"2".repeat(40)}`,
  txHash = `0x${"3".repeat(64)}`, localHash = `0x${"4".repeat(64)}`;
function fixture() {
  const directory = mkdtempSync(path.join(os.tmpdir(), "impact-d1-db-")); directories.push(directory);
  const database = createDatabase(path.join(directory, "test.db"));
  const scan = createScan(database, { repositoryUrl: "https://example.invalid/d1", repositoryName: "fixture/d1", depth: "quick" });
  const finding = insertFindings(database, scan.id, [{ title: "D1 fixture", severity: "informational", confidence: 100,
    source: "slither", detectorId: "d1", fingerprint: "f".repeat(64), contract: "Fixture", functionName: "run",
    filePath: "Fixture.sol", startLine: 1, endLine: 1, rootCause: "Test", attackScenario: "Test",
    impact: "None", evidence: "Test", status: "candidate" }])[0]!;
  const session: ImpactForkSession = { id: randomUUID(), findingId: finding.id, hypothesisId: null,
    chainId: 31337, network: "anvil-test", upstreamRpcRef: "IMPACT_RPC_LOCAL_TEST", rpcConfigId: null,
    targetContracts: [target], targetCodeHashes: { [target]: `sha256:${"c".repeat(64)}` },
    resolvedForkBlock: 1, historicalTransactionHash: null, forkBlockHash: `0x${"b".repeat(64)}`,
    status: "stopped", localPort: null, localRpcEndpoint: null, anvilVersion: "anvil 1.7.1",
    anvilSha256: "d".repeat(64), processPid: null, baselineSnapshotId: null,
    disposableAccounts: [sender], createdAt: Date.now(), startedAt: Date.now(), stoppedAt: Date.now(), failureCode: null };
  recordImpactForkSession(database, session);
  const artifact = createImpactPoCArtifact(database, { findingId: finding.id, filename: "ImpactPoC.s.sol",
    source: "pragma solidity 0.8.36; contract ImpactPoC { function run() external {} }", entryContract: "ImpactPoC" });
  reviewImpactPoCArtifact(database, artifact.id, "reviewed");
  const execution = createImpactPoCExecution(database, { id: randomUUID(), artifactId: artifact.id,
    sourceSha256: artifact.sourceSha256, sessionId: session.id, runtimeTokenSha256: "a".repeat(64),
    chainId: 31337, forkBlock: 1, forkBlockHash: session.forkBlockHash!,
    targetCodeHashes: session.targetCodeHashes, forgeVersion: null, forgeSha256: null });
  updateImpactPoCExecution(database, execution.id, "running");
  const plan = makeImpactObservationPlan(sender, [target]);
  const provenance: ImpactStateProvenance = { executionId: execution.id, sessionId: session.id,
    runtimeTokenSha256: execution.runtimeTokenSha256, chainId: execution.chainId,
    forkBlock: execution.forkBlock, forkBlockHash: execution.forkBlockHash,
    targetCodeHashes: execution.targetCodeHashes, artifactId: artifact.id,
    sourceSha256: artifact.sourceSha256, planSha256: planHash(plan) };
  const preBase = { schema: "impact-state-snapshot-v1" as const, id: randomUUID(), phase: "pre" as const,
    provenance, observedAtBlock: 1, observedAtTimestamp: "100",
    observations: [target, sender].sort().map((address) => ({
      id: `native:${address}`, kind: "native" as const, status: "available" as const,
      value: "100", errorCode: null })) };
  const pre: ImpactStateSnapshot = { ...preBase, contentSha256: snapshotHash(preBase) };
  persistImpactStateArtifacts(database, plan, pre, null, null);
  const trace: ImpactTransactionTrace = (() => {
    const node = { ordinal: 0, parentOrdinal: null, depth: 0, callType: "CALL" as const,
      rawCallType: null, from: sender, to: target, valueWei: "1", gasSupplied: "1000", gasUsed: "100",
      outcome: "success" as const, error: null, inputSelector: null,
      input: { byteLength: 0, sha256: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        prefix: "0x", truncated: false }, output: null, revertKind: null, revertDetail: null, targetAddress: target };
    const base = { schema: "impact-transaction-trace-v1" as const, id: randomUUID(), provenance,
      transactionOrdinal: 0, localTransactionHash: txHash,
      receipt: { transactionHash: txHash, blockNumber: 2, blockHash: localHash, transactionIndex: 0,
        status: 1 as const, gasUsed: "100", contractAddress: null },
      nodes: [node], logs: [], stats: { nodeCount: 1, maxDepth: 0, revertedCallCount: 0,
        targetCallCount: 1, createdContractCount: 0, logCount: 0 } };
    return { ...base, contentSha256: impactTraceHash(base) };
  })();
  return { database, execution, trace, finding };
}

describe("Impact D1 immutable trace persistence", () => {
  it("binds and reads a finalized local transaction trace without changing authority", () => {
    const { database, execution, trace, finding } = fixture();
    try {
      expect(readImpactPoCExecution(database, execution.id)?.traceCaptureStatus).toBeNull();
      persistImpactTraceCapture(database, execution.id, [txHash], [trace]);
      expect(readImpactExecutionTraces(database, execution.id)?.traces[0]?.contentSha256).toBe(trace.contentSha256);
      expect(readImpactPoCExecution(database, execution.id)).toMatchObject({ transactionHashes: [txHash],
        traceCaptureStatus: "finalized", traceCount: 1, traceNodeCount: 1, traceAvailable: true, traceIds: [trace.id] });
      expect(() => database.sqlite.prepare("DELETE FROM impact_trace_nodes WHERE trace_id=?").run(trace.id)).toThrow("immutable");
      expect(() => database.sqlite.prepare("UPDATE impact_poc_executions SET transaction_hashes='[]' WHERE id=?")
        .run(execution.id)).toThrow("immutable");
      expect(() => database.sqlite.prepare("DELETE FROM impact_poc_executions WHERE id=?").run(execution.id)).toThrow();
      expect(database.sqlite.prepare("SELECT status FROM findings WHERE id=?").get(finding.id)).toEqual({ status: "candidate" });
      expect(database.sqlite.prepare("SELECT count(*) AS n FROM authoritative_invariant_evidence").get()).toEqual({ n: 0 });
    } finally { closeDatabase(database); }
  });

  it("rejects wrong hash, execution/session/token, malformed parent and duplicate transaction atomically", () => {
    const { database, execution, trace } = fixture();
    try {
      const bad: ImpactTransactionTrace[] = [
        { ...trace, localTransactionHash: localHash },
        { ...trace, provenance: { ...trace.provenance, sessionId: randomUUID() } },
        { ...trace, provenance: { ...trace.provenance, runtimeTokenSha256: "b".repeat(64) } },
        { ...trace, provenance: { ...trace.provenance, executionId: randomUUID() } },
        { ...trace, nodes: [{ ...trace.nodes[0]!, parentOrdinal: 2 }] },
      ];
      for (const value of bad) expect(() => persistImpactTraceCapture(database, execution.id, [txHash], [value])).toThrow();
      expect(() => persistImpactTraceCapture(database, execution.id, [txHash, txHash], [trace, trace])).toThrow();
      expect(database.sqlite.prepare("SELECT count(*) AS n FROM impact_transaction_traces").get()).toEqual({ n: 0 });
      expect(readImpactPoCExecution(database, execution.id)?.traceCaptureStatus).toBeNull();
    } finally { closeDatabase(database); }
  });

  it("detects a missing persisted node and preserves historical nulls and failed capture semantics", () => {
    const { database, execution, trace } = fixture();
    try {
      persistImpactTraceCapture(database, execution.id, [txHash], [trace]);
      database.sqlite.exec("DROP TRIGGER impact_trace_nodes_no_delete");
      database.sqlite.prepare("DELETE FROM impact_trace_nodes WHERE trace_id=?").run(trace.id);
      expect(() => readImpactTransactionTrace(database, trace.id)).toThrow("impact_trace_integrity_failed");
    } finally { closeDatabase(database); }
    const second = fixture();
    try {
      expect(readImpactExecutionTraces(second.database, second.execution.id))
        .toMatchObject({ status: null, traces: [] });
      persistImpactTraceCapture(second.database, second.execution.id, [txHash], null);
      expect(readImpactExecutionTraces(second.database, second.execution.id))
        .toMatchObject({ status: "failed", traces: [] });
    } finally { closeDatabase(second.database); }
    const third = fixture();
    try {
      persistImpactTraceCapture(third.database, third.execution.id, [], []);
      expect(readImpactExecutionTraces(third.database, third.execution.id))
        .toMatchObject({ status: "finalized", traces: [] });
    } finally { closeDatabase(third.database); }
  });

  it("detects a stored trace hash mismatch", () => {
    const { database, execution, trace } = fixture();
    try {
      persistImpactTraceCapture(database, execution.id, [txHash], [trace]);
      database.sqlite.exec("DROP TRIGGER impact_transaction_traces_immutable");
      database.sqlite.prepare("UPDATE impact_transaction_traces SET content_sha256=? WHERE id=?")
        .run(`sha256:${"0".repeat(64)}`, trace.id);
      expect(() => readImpactExecutionTraces(database, execution.id)).toThrow("impact_trace_integrity_failed");
    } finally { closeDatabase(database); }
  });
});
