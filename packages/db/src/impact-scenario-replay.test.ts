import { randomUUID } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { replayPlanContentHash, scenarioParticipantId, type AssetFlow,
  type ImpactForkSession } from "@contracthunter/core";
import { closeDatabase, createDatabase, createScan, insertFindings, recordImpactForkSession,
  createImpactPoCArtifact, reviewImpactPoCArtifact, createImpactPoCExecution, updateImpactPoCExecution,
  createImpactScenarioDraft, updateImpactScenarioDraft, reviewImpactScenarioDraft,
  recoverInterruptedImpactJobs } from "./index";
import { createScenarioReplayPlan, decideScenarioReplayPlan, readScenarioReplayPlan,
  reviseScenarioReplayPlan, updateScenarioReplayDraft, createScenarioReplayRun,
  updateScenarioReplayRun, createScenarioReplayIteration, finishScenarioReplayIteration,
  readScenarioReplayIterations, requestScenarioReplayCancel } from "./impact-scenario-replay";

const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });
const P = `0x${"1".repeat(40)}`, S = `0x${"2".repeat(40)}`, HASH = `0x${"a".repeat(64)}`;
function fixture() {
  const dir = mkdtempSync(path.join(os.tmpdir(), "impact-f2a-db-")); dirs.push(dir);
  const dbPath = path.join(dir, "test.db");
  const database = createDatabase(dbPath);
  const scan = createScan(database, { repositoryUrl: "https://example.invalid/f2a", repositoryName: "fixture/f2a", depth: "quick" });
  const finding = insertFindings(database, scan.id, [{ title: "F2A fixture", severity: "informational", confidence: 90,
    source: "slither", detectorId: "f2a", fingerprint: "b".repeat(64), contract: "Vault", functionName: "move",
    filePath: "Vault.sol", startLine: 1, endLine: 1, rootCause: "Fixture", attackScenario: "Fixture",
    impact: "Fixture", evidence: "Fixture", status: "candidate" }])[0]!;
  const session: ImpactForkSession = { id: randomUUID(), findingId: finding.id, hypothesisId: null,
    chainId: 1, network: "ethereum", upstreamRpcRef: "IMPACT_RPC_TEST", rpcConfigId: "test",
    targetContracts: [P], targetCodeHashes: { [P]: `sha256:${"c".repeat(64)}` },
    resolvedForkBlock: 1, historicalTransactionHash: null, forkBlockHash: HASH, status: "ready",
    localPort: 49001, localRpcEndpoint: "http://127.0.0.1:49001", anvilVersion: "1.7.1",
    anvilSha256: "d".repeat(64), processPid: 1234, baselineSnapshotId: "0x1",
    disposableAccounts: [S], createdAt: Date.now(), startedAt: Date.now(), stoppedAt: null, failureCode: null };
  recordImpactForkSession(database, session);
  const artifact = createImpactPoCArtifact(database, { findingId: finding.id, filename: "ImpactPoC.s.sol",
    source: "pragma solidity 0.8.36; contract ImpactPoC { function run() external {} }", entryContract: "ImpactPoC" });
  reviewImpactPoCArtifact(database, artifact.id, "reviewed");
  const executionId = randomUUID();
  createImpactPoCExecution(database, { id: executionId, artifactId: artifact.id,
    sourceSha256: artifact.sourceSha256, sessionId: session.id, runtimeTokenSha256: `sha256:${"e".repeat(64)}`,
    chainId: 1, forkBlock: 1, forkBlockHash: HASH, targetCodeHashes: session.targetCodeHashes,
    forgeVersion: "forge Version: 1.7.1", forgeSha256: "f".repeat(64) });
  updateImpactPoCExecution(database, executionId, "completed", { exitCode: 0, compiled: true,
    executed: true, stdout: "", stderr: "", transactionHashes: [], errorCode: null,
    forgeVersion: "forge Version: 1.7.1", forgeSha256: "f".repeat(64) });
  const flow = { schema: "contracthunter-asset-flow-v1", scanId: scan.id, executionId,
    contentSha256: `sha256:${"b".repeat(64)}`, rulesetVersion: "contracthunter-asset-accounting-v1",
    status: "partial", capabilities: { assetAccountingAvailable: true },
    participants: [{ address: P, label: "Mapped protocol contract", contractNodeId: null },
      { address: S, label: "Disposable PoC sender", contractNodeId: null }],
    ledgerEntries: [], attemptedFlows: [], transactions: [], reconciliation: [], warnings: [] } as unknown as AssetFlow;
  const draft = createImpactScenarioDraft(database, flow, { type: "finding", id: finding.id },
    { assignments: [], note: "" });
  updateImpactScenarioDraft(database, flow, draft.id, { assignments: [
    { participantId: scenarioParticipantId(flow, P), role: "protocol" },
    { participantId: scenarioParticipantId(flow, S), role: "scenario-subject" }], note: "" });
  const scenario = reviewImpactScenarioDraft(database, flow, draft.id);
  const base = { scanId: scan.id, scenarioId: scenario.scenarioId, scenarioRevisionId: scenario.id,
    executionId, sessionId: session.id, artifactId: artifact.id, sourceSha256: artifact.sourceSha256,
    assetFlowContentSha256: flow.contentSha256, scenarioContentSha256: scenario.contentSha256,
    observationPlanSha256: `sha256:${"e".repeat(64)}`, forgeVersion: "forge Version: 1.7.1",
    forgeSha256: "f".repeat(64), chainId: 1, forkBlock: 1, forkBlockHash: HASH,
    targetCodeHashes: session.targetCodeHashes, runtimeTokenSha256: `sha256:${"e".repeat(64)}` };
  return { database, dbPath, base, artifact, session };
}
describe("reviewed replay persistence", () => {
  it("adds migration 17 without guessing any historical replay", () => {
    const { database } = fixture();
    try { expect(database.sqlite.prepare("SELECT count(*) AS count FROM schema_migrations").get()).toEqual({ count: 18 });
      expect(database.sqlite.prepare("SELECT count(*) AS count FROM impact_scenario_replay_plans").get()).toEqual({ count: 0 });
      expect(database.sqlite.pragma("foreign_key_check")).toEqual([]); }
    finally { closeDatabase(database); }
  });
  it("freezes reviewed mode and count, makes a new draft revision, and preserves prior identity", () => {
    const { database, base } = fixture();
    try { const draft = createScenarioReplayPlan(database, base, { mode: "independent-replay", iterationCount: 2 });
      expect(draft.status).toBe("draft");
      expect(() => updateScenarioReplayDraft(database, draft, { mode: "independent-replay", iterationCount: 6 })).toThrow();
      const changed = updateScenarioReplayDraft(database, draft, { mode: "cumulative-replay", iterationCount: 3 });
      const reviewed = decideScenarioReplayPlan(database, changed, "reviewed");
      expect(reviewed.contentSha256).toBe(replayPlanContentHash(reviewed));
      expect(() => updateScenarioReplayDraft(database, reviewed, { mode: "independent-replay", iterationCount: 2 })).toThrow();
      expect(() => database.sqlite.prepare("UPDATE impact_scenario_replay_plans SET status='draft' WHERE id=?")
        .run(reviewed.id)).toThrow("reviewed replay plan immutable");
      const revision = reviseScenarioReplayPlan(database, reviewed);
      expect(revision.revision).toBe(2); expect(revision.revisionOf).toBe(reviewed.id);
      expect(revision.mode).toBe("cumulative-replay");
      expect(readScenarioReplayPlan(database, reviewed.id)?.status).toBe("reviewed");
    } finally { closeDatabase(database); }
  });
  it("retains runs and finalized iterations, enforces one active run and cancellation request", () => {
    const { database, base, artifact, session } = fixture();
    try { const plan = decideScenarioReplayPlan(database,
      createScenarioReplayPlan(database, base, { mode: "independent-replay", iterationCount: 2 }), "reviewed");
      const run = createScenarioReplayRun(database, plan);
      expect(() => createScenarioReplayRun(database, plan)).toThrow();
      expect(() => createImpactPoCExecution(database, { id: randomUUID(), artifactId: artifact.id,
        sourceSha256: artifact.sourceSha256, sessionId: session.id,
        runtimeTokenSha256: `sha256:${"e".repeat(64)}`, chainId: 1, forkBlock: 1,
        forkBlockHash: HASH, targetCodeHashes: session.targetCodeHashes,
        forgeVersion: null, forgeSha256: null })).toThrow("impact_replay_controller_busy");
      updateScenarioReplayRun(database, run.id, "running");
      const iteration = createScenarioReplayIteration(database, run.id, 1);
      requestScenarioReplayCancel(database, run.id);
      finishScenarioReplayIteration(database, iteration.id, "completed", { executionId: null,
        preSnapshotId: "pre", postSnapshotId: "post", assetFlowContentSha256: null, stopReason: null });
      expect(readScenarioReplayIterations(database, run.id)[0]?.status).toBe("completed");
      expect(() => database.sqlite.prepare("UPDATE impact_scenario_replay_iterations SET status='failed' WHERE id=?")
        .run(iteration.id)).toThrow("replay iteration immutable");
      updateScenarioReplayRun(database, run.id, "cancelled", "cancel_requested");
      expect(createScenarioReplayRun(database, plan).status).toBe("queued");
    } finally { closeDatabase(database); }
  });
  it("fails interrupted runs and iterations on restart without resuming them", () => {
    const { database, dbPath, base } = fixture();
    const plan = decideScenarioReplayPlan(database,
      createScenarioReplayPlan(database, base, { mode: "independent-replay", iterationCount: 2 }), "reviewed");
    const run = createScenarioReplayRun(database, plan);
    updateScenarioReplayRun(database, run.id, "running");
    createScenarioReplayIteration(database, run.id, 1);
    closeDatabase(database);
    const reopened = createDatabase(dbPath);
    try {
      recoverInterruptedImpactJobs(reopened);
      const recovered = reopened.sqlite.prepare("SELECT status, stop_reason FROM impact_scenario_replay_runs WHERE id=?")
        .get(run.id) as { status: string; stop_reason: string };
      expect(recovered).toEqual({ status: "failed", stop_reason: "impact_server_restart" });
      expect(readScenarioReplayIterations(reopened, run.id)[0]).toMatchObject({
        status: "failed", stopReason: "impact_server_restart" });
    } finally { closeDatabase(reopened); }
  });
});
