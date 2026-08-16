import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { NewFinding } from "@contracthunter/core";
import { closeDatabase, createDatabase, createScan, getScan, insertFindings, listInvestigations } from "@contracthunter/db";
import type { ScannerExecution } from "@contracthunter/scanners";
import { completeStaticScan } from "./runner";

const directories: string[] = [];
afterEach(() => { for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true }); });

function setup() {
  const root = mkdtempSync(path.join(tmpdir(), "contracthunter-static-runner-")); directories.push(root);
  const database = createDatabase(path.join(root, "test.db"));
  const scan = createScan(database, { repositoryUrl: "https://github.com/example/static", repositoryName: "example/static", depth: "quick" });
  database.sqlite.prepare("UPDATE scans SET status = 'scanning', started_at = ? WHERE id = ?").run(Date.now(), scan.id);
  return { database, scan };
}

const execution = (scannerId: string, status: ScannerExecution["status"], error: string | null = null): ScannerExecution => ({ scannerId, scannerName: scannerId, status, findingCount: 0, durationMs: 10, error });
const finding: NewFinding = { title: "Static warning", severity: "medium", confidence: 70, source: "aderyn", detectorId: "fixture", fingerprint: "e".repeat(64), contract: "Vault", functionName: "deposit", filePath: "src/Vault.sol", startLine: 1, endLine: 1, rootCause: "Fixture cause.", attackScenario: "", impact: "Fixture impact.", evidence: "line 1", status: "candidate" };

describe("static hunt completion", () => {
  it("completes after investigation reconciliation without starting either AI stage", () => {
    const { database, scan } = setup();
    try {
      insertFindings(database, scan.id, [finding]);
      expect(completeStaticScan(database, scan.id, [execution("aderyn", "completed"), execution("slither", "completed")])).toBe(true);
      expect(getScan(database, scan.id)).toMatchObject({ status: "completed", aiStatus: "disabled", reviewStatus: "disabled" });
      expect(listInvestigations(database, { scanId: scan.id })).toHaveLength(1);
    } finally { closeDatabase(database); }
  });

  it("completes when one scanner succeeds and one fails", () => {
    const { database, scan } = setup();
    try {
      expect(completeStaticScan(database, scan.id, [execution("aderyn", "completed"), execution("slither", "failed", "Slither failed.")])).toBe(true);
      expect(getScan(database, scan.id)).toMatchObject({ status: "completed", scannerStatus: "completed", aiStatus: "disabled", reviewStatus: "disabled" });
    } finally { closeDatabase(database); }
  });

  it("fails when all scanners fail", () => {
    const { database, scan } = setup();
    try {
      expect(completeStaticScan(database, scan.id, [execution("aderyn", "failed", "Aderyn failed."), execution("slither", "failed", "Slither failed.")])).toBe(false);
      expect(getScan(database, scan.id)).toMatchObject({ status: "failed", scannerStatus: "failed", aiStatus: "disabled", reviewStatus: "disabled" });
    } finally { closeDatabase(database); }
  });
});
