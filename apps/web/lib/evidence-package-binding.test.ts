import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { scenarioParticipantId, type AssetFlow, type ImpactForkSession,
  type ScenarioReplayResult } from "@contracthunter/core";
import { closeDatabase, createDatabase, createImpactPoCArtifact, createImpactPoCExecution,
  createImpactScenarioDraft, createScan, createScenarioReplayPlan, createScenarioReplayRun,
  decideScenarioReplayPlan, insertFindings, recordImpactForkSession, reviewImpactPoCArtifact,
  reviewImpactScenarioDraft, updateImpactPoCExecution, updateScenarioReplayRun,
  type DatabaseClient } from "@contracthunter/db";

const mocks = vi.hoisted(() => ({ flow: vi.fn(), overlay: vi.fn(), replay: vi.fn() }));
vi.mock("./asset-flow-server", () => ({ loadAssetFlow: mocks.flow }));
vi.mock("./impact-overlay-server", () => ({ loadImpactOverlay: mocks.overlay }));
vi.mock("./impact-scenario-replay", () => ({ readReplayResult: mocks.replay }));
import { createEvidencePackage } from "./evidence-package-server";

const dirs: string[] = [], P = `0x${"1".repeat(40)}`, S = `0x${"2".repeat(40)}`;
afterEach(() => { vi.resetAllMocks(); for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });
function fixture() {
  const dir = mkdtempSync(path.join(os.tmpdir(), "impact-g1-binding-")); dirs.push(dir);
  const db: DatabaseClient = createDatabase(path.join(dir, "db.sqlite"));
  const scan = createScan(db, { repositoryUrl: "https://example.invalid/g1", repositoryName: "g1", depth: "quick" });
  const finding = insertFindings(db, scan.id, [{ title: "Finding", severity: "informational",
    confidence: 90, source: "slither", detectorId: "g1", fingerprint: "a".repeat(64),
    contract: "Vault", functionName: "move", filePath: "contracts/Vault.sol", startLine: 1,
    endLine: 1, rootCause: "Fixture", attackScenario: "Fixture", impact: "Fixture",
    evidence: "Fixture", status: "candidate" }])[0]!;
  const fork: ImpactForkSession = { id: crypto.randomUUID(), findingId: finding.id,
    hypothesisId: null, chainId: 1, network: "fixture", upstreamRpcRef: "IMPACT_RPC_TEST",
    rpcConfigId: "test", targetContracts: [P], targetCodeHashes: { [P]: `sha256:${"b".repeat(64)}` },
    resolvedForkBlock: 10, historicalTransactionHash: null, forkBlockHash: `0x${"c".repeat(64)}`,
    status: "ready", localPort: 49001, localRpcEndpoint: "http://127.0.0.1:49001",
    anvilVersion: "1.7.1", anvilSha256: "d".repeat(64), processPid: 1234,
    baselineSnapshotId: "0x1", disposableAccounts: [S], createdAt: 1, startedAt: 2,
    stoppedAt: null, failureCode: null };
  recordImpactForkSession(db, fork);
  const poc = createImpactPoCArtifact(db, { findingId: finding.id, filename: "ImpactPoC.s.sol",
    source: "pragma solidity 0.8.36; contract ImpactPoC { function run() external {} }",
    entryContract: "ImpactPoC" });
  reviewImpactPoCArtifact(db, poc.id, "reviewed");
  const execution = createImpactPoCExecution(db, { id: crypto.randomUUID(), artifactId: poc.id,
    sourceSha256: poc.sourceSha256, sessionId: fork.id,
    runtimeTokenSha256: `sha256:${"e".repeat(64)}`, chainId: 1, forkBlock: 10,
    forkBlockHash: fork.forkBlockHash!, targetCodeHashes: fork.targetCodeHashes,
    forgeVersion: "1.7.1", forgeSha256: "f".repeat(64) });
  updateImpactPoCExecution(db, execution.id, "completed", { exitCode: 0, compiled: true,
    executed: true, stdout: "", stderr: "", transactionHashes: [], errorCode: null,
    forgeVersion: "1.7.1", forgeSha256: "f".repeat(64) });
  const flow = { schema: "contracthunter-asset-flow-v1", rulesetVersion: "contracthunter-asset-accounting-v1",
    scanId: scan.id, executionId: execution.id, sessionId: fork.id, chainId: 1,
    contentSha256: `sha256:${"1".repeat(64)}`, status: "partial",
    capabilities: { assetAccountingAvailable: true },
    participants: [{ address: P, label: "Mapped protocol contract", contractNodeId: null },
      { address: S, label: "Disposable PoC sender", contractNodeId: null }],
    ledgerEntries: [], attemptedFlows: [], transactions: [], reconciliation: [], warnings: [],
    assets: [], netPositions: [], provenance: {}, summary: {} } as unknown as AssetFlow;
  mocks.flow.mockReturnValue(flow);
  mocks.overlay.mockReturnValue({ contentSha256: `sha256:${"2".repeat(64)}`,
    observedCalls: [], observedLogs: [], transactions: [], pathComparisons: [], warnings: [],
    derivationVersion: "contracthunter-impact-overlay-deriver-v1", coverage: {} });
  const draft = createImpactScenarioDraft(db, flow, { type: "finding", id: finding.id }, {
    assignments: [{ participantId: scenarioParticipantId(flow, S), role: "scenario-subject" }], note: "" });
  const scenario = reviewImpactScenarioDraft(db, flow, draft.id);
  const planBase = { scanId: scan.id, scenarioId: scenario.scenarioId,
    scenarioRevisionId: scenario.id, executionId: execution.id, sessionId: fork.id,
    artifactId: poc.id, sourceSha256: poc.sourceSha256,
    assetFlowContentSha256: flow.contentSha256, scenarioContentSha256: scenario.contentSha256,
    observationPlanSha256: `sha256:${"3".repeat(64)}`, forgeVersion: "1.7.1",
    forgeSha256: "f".repeat(64), chainId: 1, forkBlock: 10,
    forkBlockHash: fork.forkBlockHash!, targetCodeHashes: fork.targetCodeHashes,
    runtimeTokenSha256: execution.runtimeTokenSha256 };
  const plan = decideScenarioReplayPlan(db,
    createScenarioReplayPlan(db, planBase, { mode: "independent-replay", iterationCount: 2 }), "reviewed");
  const run = createScenarioReplayRun(db, plan);
  updateScenarioReplayRun(db, run.id, "running"); updateScenarioReplayRun(db, run.id, "completed");
  const replayResult: ScenarioReplayResult = { schema: "contracthunter-scenario-replay-result-v1",
    rulesetVersion: "contracthunter-scenario-replay-ruleset-v1", planRevisionId: plan.id,
    runId: run.id, mode: "independent-replay", requestedIterations: 2, completedIterations: 0,
    matchingIterations: 0, repeatability: "unavailable", stopReason: null, iterations: [],
    cumulativePositions: [], cumulativeDirect: [], warnings: [],
    contentSha256: `sha256:${"4".repeat(64)}` };
  mocks.replay.mockReturnValue({ run, result: replayResult });
  return { db, scan, finding, flow, scenario, run, planBase };
}
describe("G1 reviewed scenario and replay binding", () => {
  it("includes only the exact F1/F2 chain and rejects stale or mismatched evidence", () => {
    const { db, scan, finding, flow, scenario, run, planBase } = fixture();
    const selection = { subjectType: "finding" as const, subjectId: finding.id,
      executionId: flow.executionId, scenarioRevisionId: scenario.id, replayRunId: run.id };
    try {
      const value = createEvidencePackage(db, scan.id, selection);
      expect(value.artifacts.some((item) => item.type === "reviewed-scenario")).toBe(true);
      expect(value.artifacts.some((item) => item.type === "replay")).toBe(true);
      expect(value.selection.replayRunId).toBe(run.id);
      mocks.flow.mockReturnValueOnce({ ...flow, contentSha256: `sha256:${"9".repeat(64)}` });
      expect(() => createEvidencePackage(db, scan.id, selection)).toThrow("evidence_scenario_stale_or_mismatched");
      const wrong = decideScenarioReplayPlan(db,
        createScenarioReplayPlan(db, { ...planBase, sourceSha256: `sha256:${"8".repeat(64)}` },
          { mode: "independent-replay", iterationCount: 2 }), "reviewed");
      const wrongRun = createScenarioReplayRun(db, wrong);
      updateScenarioReplayRun(db, wrongRun.id, "running"); updateScenarioReplayRun(db, wrongRun.id, "completed");
      expect(() => createEvidencePackage(db, scan.id, { ...selection,
        replayRunId: wrongRun.id })).toThrow("evidence_replay_binding_invalid");
    } finally { closeDatabase(db); }
  });
});
