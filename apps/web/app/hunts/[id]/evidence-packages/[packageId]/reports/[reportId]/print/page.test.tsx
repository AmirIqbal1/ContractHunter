import { describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { buildBountyReport, buildEvidencePackage, defaultBountyReportFields, evidenceArtifact } from "@contracthunter/core";

const calls = vi.hoisted(() => ({ read: vi.fn() }));
vi.mock("@contracthunter/db", () => ({ getDatabase: () => ({}), readBountyReport: calls.read }));
import ReportPrintPage from "./page";

const id = "11111111-1111-4111-8111-111111111111";
const packageId = "22222222-2222-4222-8222-222222222222";
const reportId = "33333333-3333-4333-8333-333333333333";
const params = { params: Promise.resolve({ id, packageId, reportId }) };
describe("G2 print route", () => {
  it("shows the exact finalized report without editor actions", async () => {
    const subjectId = "44444444-4444-4444-8444-444444444444";
    const pkg = buildEvidencePackage({ packageId, scanId: id, huntId: id,
      subject: { type: "finding", id: subjectId, title: "Print fixture", status: "candidate",
        existingSeverity: null, existingConfidence: null },
      selection: { executionId: null, scenarioRevisionId: null, replayRunId: null }, status: "finalized",
      artifacts: [evidenceArtifact({ type: "static-context", id: subjectId, schemaVersion: "v1",
        status: "available", sourceContentHash: null, provenance: [], recordCount: 0, data: {} })],
      warnings: [], createdAt: 1, finalizedAt: 2 });
    calls.read.mockReturnValue(buildBountyReport(pkg, defaultBountyReportFields(pkg),
      { reportId, revisionOf: null, status: "finalized", createdAt: 3, finalizedAt: 4 }));
    const html = renderToStaticMarkup(await ReportPrintPage(params));
    expect(html).toContain("FINALIZED BUG-BOUNTY REPORT");
    expect(html).toContain("<h2>Appendix</h2>");
    expect(html).toContain("Report content hash:");
    expect(html).not.toContain("<button");
    expect(html).not.toContain("<textarea");
  });
  it("shows current integrity failure instead of an unverifiable report", async () => {
    calls.read.mockImplementation(() => { throw Error("evidence_package_integrity_invalid"); });
    const html = renderToStaticMarkup(await ReportPrintPage(params));
    expect(html).toContain("Report integrity failure");
    expect(html).not.toContain("FINALIZED BUG-BOUNTY REPORT");
  });
});
