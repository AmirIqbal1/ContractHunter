import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { buildEvidencePackage, evidenceArtifact } from "@contracthunter/core";

vi.mock("next/navigation", () => ({ useRouter: () => ({ push: vi.fn(), refresh: vi.fn() }) }));
import { EvidencePackageView } from "./evidence-package-view";

describe("Evidence Package semantic view", () => {
  it("renders an accessible evidence index and escapes hostile repository text", () => {
    const scanId = "11111111-1111-4111-8111-111111111111";
    const id = "22222222-2222-4222-8222-222222222222";
    const value = buildEvidencePackage({ packageId: "33333333-3333-4333-8333-333333333333",
      huntId: scanId, scanId, subject: { type: "finding", id,
        title: "<script>alert(1)</script>", status: "candidate", existingSeverity: null,
        existingConfidence: null }, selection: { executionId: null, scenarioRevisionId: null,
        replayRunId: null }, status: "finalized", artifacts: [evidenceArtifact({ type: "static-context",
        id, schemaVersion: "v1", status: "available", sourceContentHash: null,
        provenance: [], recordCount: 1, data: { title: "<img src=x onerror=alert(1)>" } })],
      warnings: [], createdAt: 1, finalizedAt: 2 });
    const html = renderToStaticMarkup(<EvidencePackageView value={value} persisted />);
    expect(html).toContain("<table>");
    expect(html).toContain("Evidence index / manifest");
    expect(html).toContain("Download JSON");
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(html).not.toContain("<script>alert(1)</script>");
    expect(html).not.toContain("dangerouslySetInnerHTML");
  });
});
