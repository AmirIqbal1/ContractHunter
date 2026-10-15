import { randomUUID } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { buildEvidencePackage, evidenceArtifact } from "@contracthunter/core";
import { closeDatabase, createDatabase, createScan } from "./index";
import { finalizeEvidencePackage, insertEvidencePackage, readEvidencePackage } from "./evidence-package";

const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });
describe("evidence package persistence", () => {
  it("adds migration 18, freezes finalized JSON, and rejects cross-hunt reads", () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "impact-g1-db-")); dirs.push(dir);
    const database = createDatabase(path.join(dir, "test.db"));
    try {
      const scan = createScan(database, { repositoryUrl: "https://example.invalid/g1",
        repositoryName: "fixture/g1", depth: "quick" });
      const other = createScan(database, { repositoryUrl: "https://example.invalid/other",
        repositoryName: "fixture/other", depth: "quick" });
      const subjectId = randomUUID(), id = randomUUID();
      const artifact = evidenceArtifact({ type: "static-context", id: subjectId,
        schemaVersion: "contracthunter-subject-context-v1", status: "available",
        sourceContentHash: null, provenance: [], recordCount: 0, data: { status: "candidate" } });
      const base = { packageId: id, huntId: scan.id, scanId: scan.id,
        subject: { type: "finding" as const, id: subjectId, title: "Fixture", status: "candidate",
          existingSeverity: null, existingConfidence: null },
        selection: { executionId: null, scenarioRevisionId: null, replayRunId: null },
        artifacts: [artifact], warnings: [], createdAt: 10 };
      const draft = buildEvidencePackage({ ...base, status: "draft", finalizedAt: null });
      insertEvidencePackage(database, draft);
      expect(readEvidencePackage(database, scan.id, id)?.status).toBe("draft");
      expect(readEvidencePackage(database, other.id, id)).toBeNull();
      const changedArtifact = evidenceArtifact({ type: "static-context", id: subjectId,
        schemaVersion: "contracthunter-subject-context-v1", status: "available",
        sourceContentHash: null, provenance: [], recordCount: 0,
        data: { status: "investigating" } });
      const changedFinal = buildEvidencePackage({ ...base, artifacts: [changedArtifact],
        status: "finalized", finalizedAt: 20 });
      expect(() => finalizeEvidencePackage(database, draft, changedFinal))
        .toThrow("evidence_package_finalization_invalid");
      expect(readEvidencePackage(database, scan.id, id)?.status).toBe("draft");
      const final = buildEvidencePackage({ ...base, status: "finalized", finalizedAt: 20 });
      finalizeEvidencePackage(database, draft, final);
      expect(readEvidencePackage(database, scan.id, id)).toEqual(final);
      expect(() => database.sqlite.prepare("UPDATE evidence_packages SET package_json='{}' WHERE id=?")
        .run(id)).toThrow("finalized evidence package immutable");
      expect(() => database.sqlite.prepare("DELETE FROM evidence_packages WHERE id=?").run(id))
        .toThrow("finalized evidence package immutable");
      expect(database.sqlite.prepare("SELECT count(*) AS count FROM schema_migrations").get())
        .toEqual({ count: 18 });
    } finally { closeDatabase(database); }
  });
});
