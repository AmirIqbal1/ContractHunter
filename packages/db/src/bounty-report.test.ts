import { randomUUID } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { buildBountyReport, buildEvidencePackage, canonicalEvidenceJson, defaultBountyReportFields, evidenceArtifact } from "@contracthunter/core";
import { closeDatabase, createDatabase, createScan } from "./index";
import { finalizeEvidencePackage, insertEvidencePackage } from "./evidence-package";
import { finalizeBountyReport, insertBountyReport, readBountyReport, updateDraftBountyReport } from "./bounty-report";

const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });
describe("bounty report persistence", () => {
  it("binds a finalized G1 package, keeps final revisions immutable and rejects cross-scan reads", () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "impact-g2-db-")); dirs.push(dir);
    const database = createDatabase(path.join(dir, "test.db"));
    try {
      const scan = createScan(database, { repositoryUrl: "https://example.invalid/g2",
        repositoryName: "fixture/g2", depth: "quick" });
      const other = createScan(database, { repositoryUrl: "https://example.invalid/other",
        repositoryName: "fixture/other", depth: "quick" });
      const subjectId = randomUUID(), packageId = randomUUID(), reportId = randomUUID();
      const artifact = evidenceArtifact({ type: "static-context", id: subjectId, schemaVersion: "context-v1",
        status: "available", sourceContentHash: null, provenance: [], recordCount: 1,
        data: { status: "candidate" } });
      const base = { packageId, huntId: scan.id, scanId: scan.id,
        subject: { type: "finding" as const, id: subjectId, title: "Fixture", status: "candidate",
          existingSeverity: null, existingConfidence: null },
        selection: { executionId: null, scenarioRevisionId: null, replayRunId: null },
        artifacts: [artifact], warnings: [], createdAt: 1 };
      const draftPackage = buildEvidencePackage({ ...base, status: "draft", finalizedAt: null });
      insertEvidencePackage(database, draftPackage);
      const pkg = buildEvidencePackage({ ...base, status: "finalized", finalizedAt: 2 });
      finalizeEvidencePackage(database, draftPackage, pkg);
      const identity = { reportId, revisionOf: null, status: "draft" as const, createdAt: 3, finalizedAt: null };
      const draft = buildBountyReport(pkg, defaultBountyReportFields(pkg), identity);
      insertBountyReport(database, scan.id, draft);
      const stored = database.sqlite.prepare("SELECT report_json FROM bounty_reports WHERE id=?").get(reportId) as { report_json: string };
      expect(stored.report_json).not.toContain('"sections"');
      expect(stored.report_json).not.toContain('"artifacts"');
      // Reports written before compact metadata remains readable during this unreleased migration.
      database.sqlite.prepare("UPDATE bounty_reports SET report_json=? WHERE id=?")
        .run(canonicalEvidenceJson(draft), reportId);
      expect(readBountyReport(database, scan.id, reportId)).toEqual(draft);
      expect(readBountyReport(database, other.id, reportId)).toBeNull();
      const edited = buildBountyReport(pkg, { ...draft.fields, summary: "Researcher note" }, identity);
      updateDraftBountyReport(database, scan.id, edited);
      const final = buildBountyReport(pkg, edited.fields, { ...identity, status: "finalized", finalizedAt: 4 });
      finalizeBountyReport(database, scan.id, final);
      expect(readBountyReport(database, scan.id, reportId)).toEqual(final);
      expect(() => database.sqlite.prepare("UPDATE bounty_reports SET report_json='{}' WHERE id=?")
        .run(reportId)).toThrow("finalized bounty report immutable");
      expect(() => database.sqlite.prepare("DELETE FROM bounty_reports WHERE id=?").run(reportId))
        .toThrow("finalized bounty report immutable");
      expect(() => updateDraftBountyReport(database, scan.id, edited)).toThrow();
      const revision = buildBountyReport(pkg, final.fields, { reportId: randomUUID(), revisionOf: final.reportId,
        status: "draft", createdAt: 5, finalizedAt: null });
      insertBountyReport(database, scan.id, revision);
      expect(readBountyReport(database, scan.id, revision.reportId)?.revisionOf).toBe(final.reportId);
      expect(database.sqlite.prepare("SELECT count(*) AS count FROM schema_migrations").get()).toEqual({ count: 19 });
    } finally { closeDatabase(database); }
  });
});
