import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { closeDatabase, createDatabase, createScan, insertFindings } from "./index";
import { createImpactPoCArtifact, readImpactPoCArtifact, reviewImpactPoCArtifact } from "./impact-poc";

const directories: string[] = [];
afterEach(() => { for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true }); });
function fixture() {
  const directory = mkdtempSync(path.join(os.tmpdir(), "impact-b1-db-")); directories.push(directory);
  const database = createDatabase(path.join(directory, "test.db"));
  const scan = createScan(database, { repositoryUrl: "https://example.invalid/b1", repositoryName: "fixture/b1", depth: "quick" });
  const finding = insertFindings(database, scan.id, [{ title: "Benign B1 fixture", severity: "informational", confidence: 100,
    source: "slither", detectorId: "b1-fixture", fingerprint: "a".repeat(64), contract: "Fixture", functionName: "run",
    filePath: "Fixture.sol", startLine: 1, endLine: 1, rootCause: "Test.", attackScenario: "Test.",
    impact: "None.", evidence: "Local fixture.", status: "candidate" }])[0]!;
  return { database, findingId: finding.id };
}
describe("manual PoC persistence", () => {
  it("keeps reviewed source immutable and requires a new review for a revision", () => {
    const { database, findingId } = fixture();
    try {
      const source = "pragma solidity 0.8.36; contract ImpactPoC { function run() external {} }";
      const first = createImpactPoCArtifact(database, { findingId, filename: "ImpactPoC.s.sol", source, entryContract: "ImpactPoC" });
      expect(first.reviewState).toBe("draft");
      expect(reviewImpactPoCArtifact(database, first.id, "reviewed").reviewState).toBe("reviewed");
      expect(() => reviewImpactPoCArtifact(database, first.id, "rejected")).toThrow("impact_poc_not_draft");
      expect(() => database.sqlite.prepare("UPDATE impact_poc_artifacts SET source=? WHERE id=?").run("changed", first.id)).toThrow();
      expect(readImpactPoCArtifact(database, first.id)?.source).toBe(source);
      const second = createImpactPoCArtifact(database, { findingId, revisionOf: first.id,
        filename: "ImpactPoC.s.sol", source: `${source}\n`, entryContract: "ImpactPoC" });
      expect(second.reviewState).toBe("draft");
      expect(second.sourceSha256).not.toBe(first.sourceSha256);
      expect(second.origin).toBe("manual");
    } finally { closeDatabase(database); }
  });
});
