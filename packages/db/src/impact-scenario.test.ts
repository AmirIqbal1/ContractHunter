import { randomUUID } from "node:crypto";
import Database from "better-sqlite3";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { scenarioParticipantId, type AssetFlow, type ImpactForkSession } from "@contracthunter/core";
import { closeDatabase, createDatabase, createScan, insertFindings,
  recordImpactForkSession, createImpactPoCArtifact, reviewImpactPoCArtifact, createImpactPoCExecution,
  getFinding } from "./index";
import { createImpactScenarioDraft, listImpactScenarioRevisions, readCurrentImpactScenario, readImpactScenarioRevision,
  rejectImpactScenario, reviseImpactScenario, reviewImpactScenarioDraft, updateImpactScenarioDraft } from "./impact-scenario";

const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });
const P = `0x${"1".repeat(40)}`, S = `0x${"2".repeat(40)}`, HASH = `0x${"a".repeat(64)}`;
function fixture() {
  const dir = mkdtempSync(path.join(os.tmpdir(), "impact-f1-db-")); dirs.push(dir);
  const database = createDatabase(path.join(dir, "test.db"));
  const scan = createScan(database, { repositoryUrl: "https://example.invalid/f1", repositoryName: "fixture/f1", depth: "quick" });
  const finding = insertFindings(database, scan.id, [{ title: "F1 fixture", severity: "informational", confidence: 90,
    source: "slither", detectorId: "f1", fingerprint: "b".repeat(64), contract: "Vault", functionName: "move",
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
    forgeVersion: null, forgeSha256: null });
  const flow = { schema: "contracthunter-asset-flow-v1", scanId: scan.id, executionId,
    contentSha256: `sha256:${"f".repeat(64)}`, rulesetVersion: "contracthunter-asset-accounting-v1",
    status: "partial", capabilities: { assetAccountingAvailable: true },
    participants: [{ address: P, label: "Mapped protocol contract", contractNodeId: null },
      { address: S, label: "Disposable PoC sender", contractNodeId: null }],
    ledgerEntries: [], attemptedFlows: [], transactions: [], reconciliation: [], warnings: [] } as unknown as AssetFlow;
  return { database, flow, findingId: finding.id };
}
describe("reviewed scenario revision persistence", () => {
  it("adds one migration and rolls back a conflicting scenario table without partial triggers", () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "impact-f1-migration-")); dirs.push(dir);
    const file = path.join(dir, "test.db");
    const created = createDatabase(file);
    expect(created.sqlite.prepare("SELECT COUNT(*) AS count FROM schema_migrations").get()).toEqual({ count: 19 });
    closeDatabase(created);
    const old = new Database(file);
    old.exec("DROP TABLE bounty_reports; DELETE FROM schema_migrations WHERE id='0019_v0_3_bounty_reports'; DROP TABLE evidence_packages; DELETE FROM schema_migrations WHERE id='0018_v0_3_evidence_packages'; DROP TABLE impact_scenario_replay_iterations; DROP TABLE impact_scenario_replay_runs; DROP TABLE impact_scenario_replay_plans; DELETE FROM schema_migrations WHERE id='0017_v0_3_scenario_replay'; DROP TABLE impact_scenario_revisions; DELETE FROM schema_migrations WHERE id='0016_v0_3_impact_scenarios'; CREATE TABLE impact_scenario_revisions(id TEXT PRIMARY KEY)");
    old.close();
    expect(() => createDatabase(file)).toThrow("0016_v0_3_impact_scenarios");
    const check = new Database(file, { readonly: true });
    expect(check.prepare("SELECT 1 FROM schema_migrations WHERE id='0016_v0_3_impact_scenarios'").get()).toBeUndefined();
    expect(check.prepare("SELECT name FROM sqlite_master WHERE name='impact_scenario_final_immutable'").get()).toBeUndefined();
    check.close();
  });
  it("persists exact draft roles, immutable review, new revision, rejection and stale E1 reset", () => {
    const { database, flow, findingId } = fixture();
    try {
      const draft = createImpactScenarioDraft(database, flow, { type: "finding", id: findingId },
        { assignments: [], note: "<script>plain text</script>" });
      expect(draft.status).toBe("draft"); expect(draft.assignments).toEqual([]);
      expect(() => reviewImpactScenarioDraft(database, flow, draft.id)).toThrow("scenario_subject_required");
      const roles = [{ participantId: scenarioParticipantId(flow, P), role: "protocol" as const },
        { participantId: scenarioParticipantId(flow, S), role: "scenario-subject" as const }];
      expect(updateImpactScenarioDraft(database, flow, draft.id, { assignments: roles, note: draft.note }).assignments).toHaveLength(2);
      const reviewed = reviewImpactScenarioDraft(database, flow, draft.id);
      expect(reviewed.status).toBe("reviewed"); expect(reviewed.reviewedAt).toBeTypeOf("number");
      expect(() => updateImpactScenarioDraft(database, flow, reviewed.id, { assignments: [], note: "changed" })).toThrow();
      expect(() => database.sqlite.prepare("UPDATE impact_scenario_revisions SET note='tampered' WHERE id=?").run(reviewed.id)).toThrow("reviewed scenario immutable");
      const revision = reviseImpactScenario(database, flow, reviewed);
      expect(revision.revision).toBe(2); expect(revision.revisionOf).toBe(reviewed.id);
      expect(revision.assignments).toEqual(reviewed.assignments);
      expect(readImpactScenarioRevision(database, reviewed.id)?.status).toBe("reviewed");
      const rejectedDraft = rejectImpactScenario(database, revision);
      expect(rejectedDraft.status).toBe("rejected");
      const staleFlow = { ...flow, contentSha256: `sha256:${"9".repeat(64)}` };
      const newDraft = reviseImpactScenario(database, staleFlow, rejectedDraft);
      expect(newDraft.revision).toBe(3); expect(newDraft.assignments).toEqual([]);
      expect(newDraft.assetFlowContentSha256).toBe(staleFlow.contentSha256);
      expect(readCurrentImpactScenario(database, draft.scenarioId)?.id).toBe(newDraft.id);
      expect(listImpactScenarioRevisions(database, flow.scanId, flow.executionId, draft.scenarioId)
        .map((item) => item.status)).toEqual(["draft", "rejected", "reviewed"]);
      expect(getFinding(database, findingId)?.status).toBe("candidate");
      expect(database.sqlite.pragma("foreign_key_check")).toEqual([]);
    } finally { closeDatabase(database); }
  });
  it("rejects unknown or duplicate participant selectors before persistence", () => {
    const { database, flow, findingId } = fixture();
    try {
      expect(() => createImpactScenarioDraft(database, flow, { type: "finding", id: findingId },
        { assignments: [{ participantId: scenarioParticipantId(flow, `0x${"9".repeat(40)}`), role: "protocol" }], note: "" })).toThrow();
      const id = scenarioParticipantId(flow, P);
      expect(() => createImpactScenarioDraft(database, flow, { type: "finding", id: findingId },
        { assignments: [{ participantId: id, role: "protocol" }, { participantId: id, role: "scenario-subject" }], note: "" })).toThrow();
      expect(database.sqlite.prepare("SELECT COUNT(*) AS count FROM impact_scenario_revisions").get()).toEqual({ count: 0 });
    } finally { closeDatabase(database); }
  });
});
