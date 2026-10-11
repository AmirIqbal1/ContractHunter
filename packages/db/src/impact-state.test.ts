import { randomUUID } from "node:crypto";
import Database from "better-sqlite3";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { diffHash, makeImpactObservationPlan, planHash, snapshotHash,
  type ImpactForkSession, type ImpactStateDiff, type ImpactStateProvenance, type ImpactStateSnapshot } from "@contracthunter/core";
import { closeDatabase, createDatabase, createScan, insertFindings, recordImpactForkSession } from "./index";
import { createImpactPoCArtifact, createImpactPoCExecution, readImpactPoCExecution, reviewImpactPoCArtifact } from "./impact-poc";
import { persistImpactStateArtifacts, readImpactExecutionState, readImpactStateSnapshot } from "./impact-state";

const directories: string[] = [];
afterEach(() => { for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true }); });
const target = `0x${"1".repeat(40)}`, sender = `0x${"2".repeat(40)}`;
function fixture() {
  const directory = mkdtempSync(path.join(os.tmpdir(), "impact-c1-db-")); directories.push(directory);
  const file = path.join(directory, "test.db");
  const database = createDatabase(file);
  const scan = createScan(database, { repositoryUrl: "https://example.invalid/c1", repositoryName: "fixture/c1", depth: "quick" });
  const finding = insertFindings(database, scan.id, [{ title: "C1 fixture", severity: "informational", confidence: 100,
    source: "slither", detectorId: "c1", fingerprint: "e".repeat(64), contract: "Fixture", functionName: "run",
    filePath: "Fixture.sol", startLine: 1, endLine: 1, rootCause: "Test", attackScenario: "Test",
    impact: "None", evidence: "Test", status: "candidate" }])[0]!;
  const session: ImpactForkSession = { id: randomUUID(), findingId: finding.id, hypothesisId: null, chainId: 31337,
    network: "anvil-test", upstreamRpcRef: "IMPACT_RPC_LOCAL_TEST", rpcConfigId: null, targetContracts: [target],
    targetCodeHashes: { [target]: `sha256:${"c".repeat(64)}` }, resolvedForkBlock: 1, historicalTransactionHash: null,
    forkBlockHash: `0x${"b".repeat(64)}`, status: "stopped", localPort: null, localRpcEndpoint: null,
    anvilVersion: "anvil 1.7.1", anvilSha256: "d".repeat(64), processPid: null, baselineSnapshotId: null,
    disposableAccounts: [sender], createdAt: Date.now(), startedAt: Date.now(), stoppedAt: Date.now(), failureCode: null };
  recordImpactForkSession(database, session);
  const artifact = createImpactPoCArtifact(database, { findingId: finding.id, filename: "ImpactPoC.s.sol",
    source: "pragma solidity 0.8.36; contract ImpactPoC { function run() external {} }", entryContract: "ImpactPoC" });
  reviewImpactPoCArtifact(database, artifact.id, "reviewed");
  const execution = createImpactPoCExecution(database, { id: randomUUID(), artifactId: artifact.id,
    sourceSha256: artifact.sourceSha256, sessionId: session.id, runtimeTokenSha256: "a".repeat(64),
    chainId: 31337, forkBlock: 1, forkBlockHash: session.forkBlockHash!, targetCodeHashes: session.targetCodeHashes,
    forgeVersion: null, forgeSha256: null });
  const plan = makeImpactObservationPlan(sender, [target]);
  const provenance: ImpactStateProvenance = { executionId: execution.id, sessionId: session.id,
    runtimeTokenSha256: execution.runtimeTokenSha256, chainId: execution.chainId, forkBlock: execution.forkBlock,
    forkBlockHash: execution.forkBlockHash, targetCodeHashes: execution.targetCodeHashes,
    artifactId: artifact.id, sourceSha256: artifact.sourceSha256, planSha256: planHash(plan) };
  const snapshot = (phase: "pre" | "post", targetBalance: string): ImpactStateSnapshot => {
    const value = { schema: "impact-state-snapshot-v1" as const, id: randomUUID(), phase, provenance,
      observedAtBlock: phase === "pre" ? 1 : 2, observedAtTimestamp: phase === "pre" ? "100" : "101",
      observations: [
        { id: `native:${target}`, kind: "native" as const, status: "available" as const, value: targetBalance, errorCode: null },
        { id: `native:${sender}`, kind: "native" as const, status: "available" as const, value: "100", errorCode: null },
      ].sort((a, b) => a.id.localeCompare(b.id)) };
    return { ...value, contentSha256: snapshotHash(value) };
  };
  const pre = snapshot("pre", "10"), post = snapshot("post", "11");
  const diffBase = { schema: "impact-state-diff-v1" as const, id: randomUUID(), provenance,
    preSnapshotId: pre.id, postSnapshotId: post.id, preSnapshotSha256: pre.contentSha256,
    postSnapshotSha256: post.contentSha256, changes: [{ id: `native:${target}`, kind: "native" as const,
      type: "native_balance_changed" as const, beforeStatus: "available" as const, afterStatus: "available" as const,
      before: "10", after: "11", beforeErrorCode: null, afterErrorCode: null, delta: "1" }], changeCount: 1 };
  const diff: ImpactStateDiff = { ...diffBase, contentSha256: diffHash(diffBase) };
  return { database, file, execution, plan, pre, post, diff };
}

describe("Impact C1 immutable persistence", () => {
  it("links finalized snapshots and diff, retains historical nulls, and detects row tampering", () => {
    const { database, execution, plan, pre, post, diff } = fixture();
    try {
      expect(readImpactPoCExecution(database, execution.id)?.preSnapshotId).toBeNull();
      persistImpactStateArtifacts(database, plan, pre, post, diff);
      const state = readImpactExecutionState(database, execution.id)!;
      expect(state.diff?.changes[0]?.delta).toBe("1");
      expect(readImpactPoCExecution(database, execution.id)).toMatchObject({ stateCaptureAvailable: true,
        stateChangeCount: 1, preSnapshotId: pre.id, postSnapshotId: post.id, stateDiffId: diff.id });
      expect(() => database.sqlite.prepare("UPDATE impact_state_observations SET value='999' WHERE snapshot_id=?").run(pre.id)).toThrow("immutable");
      expect(() => database.sqlite.prepare("DELETE FROM impact_state_snapshots WHERE id=?").run(pre.id)).toThrow("immutable");
      expect(() => database.sqlite.prepare("DELETE FROM impact_poc_executions WHERE id=?").run(execution.id)).toThrow();
      expect(() => database.sqlite.prepare(`INSERT INTO impact_state_observations
        (snapshot_id,identity,kind,status,value) VALUES (?,?,?,?,?)`).run(pre.id, `native:${target}`, "native", "available", "9")).toThrow();
      database.sqlite.exec("DROP TRIGGER impact_state_observations_immutable");
      database.sqlite.prepare("UPDATE impact_state_observations SET value='999' WHERE snapshot_id=? AND identity=?")
        .run(pre.id, `native:${target}`);
      expect(() => readImpactStateSnapshot(database, pre.id)).toThrow("impact_state_integrity_failed");
    } finally { closeDatabase(database); }
  });

  it("rejects mismatched execution, phase, session, source snapshots and missing observations atomically", () => {
    const { database, execution, plan, pre, post, diff } = fixture();
    try {
      for (const bad of [
        () => persistImpactStateArtifacts(database, plan, { ...pre, phase: "post" }, post, diff),
        () => persistImpactStateArtifacts(database, plan, { ...pre, provenance: { ...pre.provenance, executionId: randomUUID() } }, post, diff),
        () => persistImpactStateArtifacts(database, plan, pre, { ...post, provenance: { ...post.provenance, sessionId: randomUUID() } }, diff),
        () => persistImpactStateArtifacts(database, plan, pre, post, { ...diff, preSnapshotId: randomUUID() }),
        () => persistImpactStateArtifacts(database, plan, { ...pre, observations: pre.observations.slice(1) }, post, diff),
      ]) expect(bad).toThrow();
      expect(database.sqlite.prepare("SELECT count(*) AS n FROM impact_state_snapshots").get()).toEqual({ n: 0 });
      expect(readImpactPoCExecution(database, execution.id)?.stateCaptureAvailable).toBe(false);
    } finally { closeDatabase(database); }
  });

  it("rejects a missing finalized observation even if a row is removed outside normal triggers", () => {
    const { database, plan, pre, post, diff } = fixture();
    try {
      persistImpactStateArtifacts(database, plan, pre, post, diff);
      database.sqlite.exec("DROP TRIGGER impact_state_observations_no_delete");
      database.sqlite.prepare("DELETE FROM impact_state_observations WHERE snapshot_id=? AND identity=?")
        .run(pre.id, "native:" + target);
      expect(() => readImpactExecutionState(database, pre.provenance.executionId)).toThrow("impact_state_integrity_failed");
    } finally { closeDatabase(database); }
  });

  it("upgrades a historical B1 execution without fabricating state artifacts", () => {
    const { database, file, execution } = fixture();
    closeDatabase(database);
    const old = new Database(file);
    old.exec(`DROP TRIGGER impact_execution_state_links_immutable;
      DROP TABLE impact_state_changes; DROP TABLE impact_state_diffs;
      DROP TABLE impact_state_observations; DROP TABLE impact_state_snapshots;
      ALTER TABLE impact_poc_executions DROP COLUMN observation_plan;
      ALTER TABLE impact_poc_executions DROP COLUMN observation_plan_sha256;
      ALTER TABLE impact_poc_executions DROP COLUMN pre_snapshot_id;
      ALTER TABLE impact_poc_executions DROP COLUMN post_snapshot_id;
      ALTER TABLE impact_poc_executions DROP COLUMN state_diff_id;
      ALTER TABLE impact_poc_executions DROP COLUMN state_change_count;
      DELETE FROM schema_migrations WHERE id='0012_v0_3_impact_state_capture';`);
    old.close();
    const upgraded = createDatabase(file);
    try {
      expect(readImpactPoCExecution(upgraded, execution.id)).toMatchObject({ preSnapshotId: null,
        postSnapshotId: null, stateDiffId: null, stateChangeCount: null, stateCaptureAvailable: false });
      expect(readImpactExecutionState(upgraded, execution.id)).toMatchObject({ pre: null, post: null, diff: null });
      expect(upgraded.sqlite.prepare("SELECT count(*) AS n FROM impact_state_snapshots").get()).toEqual({ n: 0 });
    } finally { closeDatabase(upgraded); }
  });
});
