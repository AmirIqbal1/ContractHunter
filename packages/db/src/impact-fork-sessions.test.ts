import Database from "better-sqlite3";
import { randomUUID } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { ImpactForkSession } from "@contracthunter/core";
import { closeDatabase, createDatabase, createScan, insertFindings, recordImpactForkSession, recoverStaleImpactForkSessions } from "./index";

const directories: string[] = [];
afterEach(() => { for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true }); });
function databaseFile() { const dir = mkdtempSync(path.join(tmpdir(), "contracthunter-impact-migration-")); directories.push(dir); return path.join(dir, "test.db"); }

describe("Impact Lab Phase A1 persistence", () => {
  it("migrates additively, records only bounded references, and fails stale runtime rows on restart", () => {
    const database = createDatabase(databaseFile());
    const scan = createScan(database, { repositoryUrl: "https://example.invalid/fixture", repositoryName: "fixture", depth: "quick" });
    const finding = insertFindings(database, scan.id, [{ title: "Finding", severity: "high", confidence: 80, source: "slither", detectorId: "rule", fingerprint: "f".repeat(64),
      contract: "Target", functionName: "run", filePath: "contracts/Target.sol", startLine: 1, endLine: 2, rootCause: "Cause", attackScenario: "Scenario", impact: "Impact", evidence: "Evidence", status: "candidate" }])[0];
    const session: ImpactForkSession = { id: randomUUID(), findingId: finding.id, hypothesisId: null, chainId: 8453, network: "base", upstreamRpcRef: "IMPACT_RPC_BASE",
      targetContracts: [`0x${"1".repeat(40)}`], resolvedForkBlock: 100, historicalTransactionHash: null, forkBlockHash: `0x${"a".repeat(64)}`, status: "ready",
      localPort: 49001, localRpcEndpoint: "http://127.0.0.1:49001", anvilVersion: "anvil 1.7.1", anvilSha256: "b".repeat(64), processPid: 4242,
      baselineSnapshotId: "0x1", disposableAccounts: [`0x${"2".repeat(40)}`], createdAt: Date.now(), startedAt: Date.now(), stoppedAt: null, failureCode: null };
    recordImpactForkSession(database, session);
    const row = database.sqlite.prepare("SELECT * FROM impact_fork_sessions WHERE id=?").get(session.id) as Record<string, unknown>;
    expect(row.status).toBe("ready"); expect(row.local_port).toBe(49001);
    expect(JSON.stringify(row)).not.toContain("provider.example");
    expect(JSON.stringify(row)).not.toContain("privateKey");
    expect(() => database.sqlite.prepare("UPDATE impact_fork_sessions SET chain_id=1 WHERE id=?").run(session.id)).toThrow("impact fork identity is immutable");
    expect(recoverStaleImpactForkSessions(database)).toBe(1);
    expect(database.sqlite.prepare("SELECT status, failure_code FROM impact_fork_sessions WHERE id=?").get(session.id)).toEqual({ status: "failed", failure_code: "impact_server_restart" });
    expect(database.sqlite.prepare("SELECT local_port FROM impact_fork_sessions WHERE id=?").get(session.id)).toEqual({ local_port: 49001 });
    expect(database.sqlite.pragma("foreign_key_check")).toEqual([]);
    expect(database.sqlite.pragma("integrity_check", { simple: true })).toBe("ok");
    expect((database.sqlite.prepare("SELECT id FROM schema_migrations ORDER BY id").all() as Array<{ id: string }>).at(-1)?.id).toBe("0009_v0_3_impact_fork_sessions");
    closeDatabase(database);
  });

  it("rolls back a conflicting migration without a partial index or trigger", () => {
    const file = databaseFile(); closeDatabase(createDatabase(file));
    const old = new Database(file);
    old.exec("DROP TABLE impact_fork_sessions; DELETE FROM schema_migrations WHERE id='0009_v0_3_impact_fork_sessions'; CREATE TABLE impact_fork_sessions (id TEXT PRIMARY KEY)"); old.close();
    expect(() => createDatabase(file)).toThrow("0009_v0_3_impact_fork_sessions");
    const check = new Database(file, { readonly: true });
    expect(check.prepare("SELECT 1 FROM schema_migrations WHERE id='0009_v0_3_impact_fork_sessions'").get()).toBeUndefined();
    expect(check.prepare("SELECT name FROM sqlite_master WHERE name='impact_fork_sessions_status_created_idx'").get()).toBeUndefined();
    expect(check.prepare("SELECT name FROM sqlite_master WHERE name='impact_fork_sessions_identity_immutable'").get()).toBeUndefined();
    check.close();
  });
});
