import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { NewFinding } from "@contracthunter/core";
import { closeDatabase, createDatabase, createScan, insertFindings, listInvestigationFindings, reconcileInvestigations, updateInvestigationStatus } from "./index";

const directories: string[] = [];
afterEach(() => { for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true }); });

function finding(source: string, fingerprint: string): NewFinding {
  return {
    title: source === "slither" ? "Missing zero-address validation" : "State variable has no address check",
    severity: "medium", confidence: source === "aderyn" ? 40 : 80, source,
    detectorId: source === "slither" ? "missing-zero-check" : "state-no-address-check",
    fingerprint, contract: "Owner", functionName: source === "slither" ? "setOwner" : null,
    filePath: "src/Owner.sol", startLine: source === "slither" ? 7 : 8, endLine: source === "slither" ? 7 : 8,
    rootCause: "An address assignment lacks validation.", attackScenario: "", impact: "", evidence: "fixture evidence", status: "candidate",
  };
}

describe("investigation persistence", () => {
  it("reconciles idempotently, preserves raw evidence, and retains manual status", () => {
    const directory = mkdtempSync(path.join(tmpdir(), "contracthunter-investigations-")); directories.push(directory);
    const database = createDatabase(path.join(directory, "test.db"));
    try {
      const scan = createScan(database, { repositoryUrl: "https://github.com/example/fixture", repositoryName: "example/fixture", depth: "quick" });
      const inserted = insertFindings(database, scan.id, [finding("slither", "a".repeat(64)), finding("aderyn", "b".repeat(64))]);
      const first = reconcileInvestigations(database, scan.id);
      const second = reconcileInvestigations(database, scan.id);
      expect(first).toHaveLength(1);
      expect(second).toHaveLength(1);
      expect(second[0]).toMatchObject({ id: first[0].id, fingerprint: first[0].fingerprint, sourceCount: 2, status: "candidate" });
      expect(listInvestigationFindings(database, first[0].id).map((item) => item.id).sort()).toEqual(inserted.map((item) => item.id).sort());
      updateInvestigationStatus(database, first[0].id, "investigating");
      expect(reconcileInvestigations(database, scan.id)[0].status).toBe("investigating");
      expect(database.sqlite.prepare("SELECT count(*) AS count FROM findings").get()).toEqual({ count: 2 });
      expect(database.sqlite.prepare("SELECT count(*) AS count FROM investigations").get()).toEqual({ count: 1 });
    } finally { closeDatabase(database); }
  });
});
