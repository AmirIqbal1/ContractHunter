import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { NewFinding } from "@contracthunter/core";
import {
  closeDatabase,
  createDatabase,
  createScan,
  getScan,
  insertFindings,
  listFindings,
  listScanScanners,
  markActiveScansInterrupted,
  markDetachedJobsInterrupted,
  upsertScanScanner,
} from "./index";

const directories: string[] = [];
afterEach(() => { for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true }); });

const finding: NewFinding = {
  title: "Collected before interruption",
  severity: "medium",
  confidence: 80,
  source: "aderyn",
  detectorId: "fixture",
  fingerprint: "c".repeat(64),
  contract: "Vault",
  functionName: "deposit",
  filePath: "src/Vault.sol",
  startLine: 12,
  endLine: 12,
  rootCause: "Fixture root cause.",
  attackScenario: "",
  impact: "Fixture impact.",
  evidence: "Fixture evidence.",
  status: "candidate",
};

describe("interrupted scan recovery", () => {
  it("fails only stale scans and preserves terminal scanner results and findings", () => {
    const directory = mkdtempSync(path.join(tmpdir(), "contracthunter-interrupted-")); directories.push(directory);
    const database = createDatabase(path.join(directory, "test.db"));
    try {
      const stale = createScan(database, { repositoryUrl: "https://github.com/example/stale", repositoryName: "example/stale", depth: "quick" });
      const running = createScan(database, { repositoryUrl: "https://github.com/example/running", repositoryName: "example/running", depth: "quick" });
      database.sqlite.prepare("UPDATE scans SET status = 'scanning', started_at = ?, dependency_status = 'ready', compiler_status = 'ready' WHERE id IN (?, ?)").run(Date.now() - 60_000, stale.id, running.id);
      upsertScanScanner(database, stale.id, { scannerId: "aderyn", scannerName: "Aderyn", status: "completed", findingCount: 1, durationMs: 1000 });
      upsertScanScanner(database, stale.id, { scannerId: "slither", scannerName: "Slither", status: "failed", findingCount: 0, error: "Slither failed." });
      insertFindings(database, stale.id, [finding]);

      expect(markActiveScansInterrupted(database, [running.id])).toBe(1);
      expect(getScan(database, stale.id)).toMatchObject({
        status: "failed",
        error: "Scan interrupted by application restart.",
        dependencyStatus: "ready",
        compilerStatus: "ready",
      });
      expect(getScan(database, stale.id)?.completedAt).toBeInstanceOf(Date);
      expect(getScan(database, running.id)?.status).toBe("scanning");
      expect(listScanScanners(database, stale.id).map(({ scannerId, status, error }) => ({ scannerId, status, error }))).toEqual([
        { scannerId: "aderyn", status: "completed", error: null },
        { scannerId: "slither", status: "failed", error: "Slither failed." },
      ]);
      expect(listFindings(database, { scanId: stale.id })).toHaveLength(1);
      expect(listFindings(database, { scanId: stale.id })[0]).toMatchObject({ title: finding.title, fingerprint: finding.fingerprint });
    } finally { closeDatabase(database); }
  });

  it("marks orphaned manual AI stages failed during application startup", () => {
    const directory = mkdtempSync(path.join(tmpdir(), "contracthunter-interrupted-ai-")); directories.push(directory);
    const database = createDatabase(path.join(directory, "test.db"));
    try {
      const scan = createScan(database, { repositoryUrl: "https://github.com/example/manual-ai", repositoryName: "example/manual-ai", depth: "quick" });
      const protectedScan = createScan(database, { repositoryUrl: "https://github.com/example/active-ai", repositoryName: "example/active-ai", depth: "quick" });
      database.sqlite.prepare("UPDATE scans SET status = 'completed', ai_status = 'running', review_status = 'pending' WHERE id = ?").run(scan.id);
      database.sqlite.prepare("UPDATE scans SET status = 'completed', ai_status = 'running', review_status = 'running' WHERE id = ?").run(protectedScan.id);
      markDetachedJobsInterrupted(database, [protectedScan.id], [protectedScan.id]);
      expect(getScan(database, scan.id)).toMatchObject({ status: "completed", aiStatus: "failed", reviewStatus: "failed" });
      expect(getScan(database, protectedScan.id)).toMatchObject({ status: "completed", aiStatus: "running", reviewStatus: "running" });
    } finally { closeDatabase(database); }
  });
});
