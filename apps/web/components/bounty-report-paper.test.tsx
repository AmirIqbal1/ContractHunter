import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { buildBountyReport, buildEvidencePackage, defaultBountyReportFields, evidenceArtifact } from "@contracthunter/core";
import { BountyReportPaper } from "./bounty-report-paper";

const scanId = "11111111-1111-4111-8111-111111111111";
const subjectId = "22222222-2222-4222-8222-222222222222";
describe("bounty report paper", () => {
  it("renders semantic, read-only sections and escapes hostile labels", () => {
    const pkg = buildEvidencePackage({ packageId: "33333333-3333-4333-8333-333333333333",
      huntId: scanId, scanId, subject: { type: "finding", id: subjectId,
        title: "Issue <script>alert(1)</script>", status: "candidate", existingSeverity: null, existingConfidence: null },
      selection: { executionId: null, scenarioRevisionId: null, replayRunId: null }, status: "finalized",
      artifacts: [evidenceArtifact({ type: "static-context", id: subjectId, schemaVersion: "v1",
        status: "available", sourceContentHash: null, provenance: [], recordCount: 1,
        data: { findings: [{ id: subjectId, contract: "<img onerror=alert(1)>", sourceUnit: "src/X.sol" }] } })],
      warnings: [], createdAt: 1, finalizedAt: 2 });
    const report = buildBountyReport(pkg, defaultBountyReportFields(pkg),
      { reportId: "44444444-4444-4444-8444-444444444444", revisionOf: null,
        status: "finalized", createdAt: 3, finalizedAt: 4 });
    const html = renderToStaticMarkup(<BountyReportPaper value={report} />);
    expect(html).toContain("<article");
    expect(html).toContain("<h1>");
    expect(html).toContain("<h2>Summary</h2>");
    expect(html).toContain("<th scope=\"col\"");
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(html).toContain("&lt;img onerror=alert(1)&gt;");
    expect(html).not.toContain("<script>");
    expect(html).not.toContain("<input");
    expect(html).not.toContain("<button");
  });
});
