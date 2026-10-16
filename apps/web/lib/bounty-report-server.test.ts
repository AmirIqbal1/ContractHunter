import { randomUUID } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { buildEvidencePackage, evidenceArtifact, renderBountyReportMarkdown } from "@contracthunter/core";
import { closeDatabase, createDatabase, createScan, finalizeEvidencePackage, insertEvidencePackage,
  readBountyReport, readEvidencePackage } from "@contracthunter/db";
import { createReportDraft, finalizeReportDraft, saveReportDraft } from "./bounty-report-server";

describe("G2 report service lifecycle", () => {
  it("uses only same-scan finalized G1, preserves evidence, and creates immutable revisions", () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "impact-g2-service-"));
    const database = createDatabase(path.join(dir, "test.db"));
    try {
      const scan = createScan(database, { repositoryUrl: "https://example.invalid/g2",
        repositoryName: "fixture/g2", depth: "quick" });
      const other = createScan(database, { repositoryUrl: "https://example.invalid/other",
        repositoryName: "fixture/other", depth: "quick" });
      const packageId = randomUUID(), subjectId = randomUUID();
      const base = { packageId, huntId: scan.id, scanId: scan.id,
        subject: { type: "finding" as const, id: subjectId, title: "Static fixture", status: "candidate",
          existingSeverity: null, existingConfidence: null },
        selection: { executionId: null, scenarioRevisionId: null, replayRunId: null },
        artifacts: [evidenceArtifact({ type: "static-context", id: subjectId, schemaVersion: "v1",
          status: "available", sourceContentHash: null, provenance: [], recordCount: 0,
          data: { findings: [] } })], warnings: [], createdAt: 1 };
      const draftPackage = buildEvidencePackage({ ...base, status: "draft", finalizedAt: null });
      insertEvidencePackage(database, draftPackage);
      expect(() => createReportDraft(database, scan.id, packageId)).toThrow("bounty_report_package_not_finalized");
      const pkg = buildEvidencePackage({ ...base, status: "finalized", finalizedAt: 2 });
      finalizeEvidencePackage(database, draftPackage, pkg);
      const packageBefore = readEvidencePackage(database, scan.id, packageId);
      const findingsBefore = database.sqlite.prepare("SELECT * FROM findings").all();
      expect(() => createReportDraft(database, other.id, packageId)).toThrow("bounty_report_package_not_finalized");
      const draft = createReportDraft(database, scan.id, packageId);
      const updated = saveReportDraft(database, scan.id, draft.reportId,
        { ...draft.fields, summary: "Researcher-authored summary" });
      expect(updated.contentHash).not.toBe(draft.contentHash);
      expect(() => saveReportDraft(database, scan.id, draft.reportId,
        { ...updated.fields, summary: "x".repeat(4097) })).toThrow();
      const final = finalizeReportDraft(database, scan.id, draft.reportId);
      expect(final.status).toBe("finalized");
      expect(renderBountyReportMarkdown(final)).toContain("Researcher-authored summary");
      expect(() => saveReportDraft(database, scan.id, final.reportId, final.fields)).toThrow("bounty_report_not_draft");
      expect(() => finalizeReportDraft(database, scan.id, final.reportId)).toThrow("bounty_report_not_draft");
      expect(() => createReportDraft(database, other.id, packageId, final.reportId)).toThrow();
      const revision = createReportDraft(database, scan.id, packageId, final.reportId);
      expect(revision.fields).toEqual(final.fields);
      expect(revision.revisionOf).toBe(final.reportId);
      expect(readBountyReport(database, scan.id, final.reportId)).toEqual(final);
      expect(readEvidencePackage(database, scan.id, packageId)).toEqual(packageBefore);
      expect(database.sqlite.prepare("SELECT * FROM findings").all()).toEqual(findingsBefore);
      // Simulate historical package corruption by bypassing the immutable guard in the test database.
      database.sqlite.prepare("DROP TRIGGER evidence_packages_final_immutable").run();
      database.sqlite.prepare("UPDATE evidence_packages SET package_json='{}' WHERE id=?").run(packageId);
      expect(() => finalizeReportDraft(database, scan.id, revision.reportId)).toThrow();
      expect(() => readBountyReport(database, scan.id, final.reportId)).toThrow();
    } finally { closeDatabase(database); rmSync(dir, { recursive: true, force: true }); }
  });
});
