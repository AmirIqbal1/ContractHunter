import { describe, expect, it, vi } from "vitest";
import { buildBountyReport, buildEvidencePackage, defaultBountyReportFields, evidenceArtifact,
  renderBountyReportMarkdown } from "@contracthunter/core";

const calls = vi.hoisted(() => ({ read: vi.fn() }));
vi.mock("@contracthunter/db", () => ({ getDatabase: () => ({}), readBountyReport: calls.read }));
import { GET } from "./route";

const id = "11111111-1111-4111-8111-111111111111";
const packageId = "22222222-2222-4222-8222-222222222222";
const reportId = "33333333-3333-4333-8333-333333333333";
const subjectId = "44444444-4444-4444-8444-444444444444";
const params = { params: Promise.resolve({ id, packageId, reportId }) };
describe("bounty Markdown download", () => {
  it("serves final Markdown with an ID filename and no content sniffing", async () => {
    const pkg = buildEvidencePackage({ packageId, huntId: id, scanId: id,
      subject: { type: "finding", id: subjectId, title: "Test", status: "candidate",
        existingSeverity: null, existingConfidence: null },
      selection: { executionId: null, scenarioRevisionId: null, replayRunId: null }, status: "finalized",
      artifacts: [evidenceArtifact({ type: "static-context", id: subjectId, schemaVersion: "v1",
        status: "available", sourceContentHash: null, provenance: [], recordCount: 1, data: {} })],
      warnings: [], createdAt: 1, finalizedAt: 2 });
    const report = buildBountyReport(pkg, defaultBountyReportFields(pkg),
      { reportId, revisionOf: null, status: "finalized", createdAt: 3, finalizedAt: 4 });
    calls.read.mockReturnValue(report);
    const response = await GET(new Request("http://localhost"), params);
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("text/markdown; charset=utf-8");
    expect(response.headers.get("content-disposition")).toContain(`contracthunter-report-${reportId}.md`);
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(await response.text()).toBe(renderBountyReportMarkdown(report));
  });
  it("rejects drafts and mismatched package binding", async () => {
    calls.read.mockReturnValueOnce({ status: "draft", evidencePackageId: packageId })
      .mockReturnValueOnce({ status: "finalized", evidencePackageId: id });
    expect((await GET(new Request("http://localhost"), params)).status).toBe(404);
    expect((await GET(new Request("http://localhost"), params)).status).toBe(404);
  });
});
