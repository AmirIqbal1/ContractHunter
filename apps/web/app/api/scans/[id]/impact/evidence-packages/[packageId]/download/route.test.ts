import { describe, expect, it, vi } from "vitest";
import { buildEvidencePackage, evidenceArtifact } from "@contracthunter/core";

const calls = vi.hoisted(() => ({ read: vi.fn() }));
vi.mock("@contracthunter/db", () => ({ getDatabase: () => ({}), readEvidencePackage: calls.read }));
import { GET } from "./route";

const scanId = "11111111-1111-4111-8111-111111111111";
const packageId = "22222222-2222-4222-8222-222222222222";
describe("evidence JSON download", () => {
  it("returns the finalized canonical representation with safe headers", async () => {
    const subjectId = "33333333-3333-4333-8333-333333333333";
    const value = buildEvidencePackage({ packageId, huntId: scanId, scanId,
      subject: { type: "finding", id: subjectId, title: "Fixture", status: "candidate",
        existingSeverity: null, existingConfidence: null },
      selection: { executionId: null, scenarioRevisionId: null, replayRunId: null },
      status: "finalized", artifacts: [evidenceArtifact({ type: "static-context", id: subjectId,
        schemaVersion: "v1", status: "available", sourceContentHash: null,
        provenance: [], recordCount: 1, data: { rawAmount: "900719925474099312345" } })],
      warnings: [], createdAt: 1, finalizedAt: 2 });
    calls.read.mockReturnValue(value);
    const response = await GET(new Request("http://localhost"), { params: Promise.resolve({ id: scanId, packageId }) });
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/json; charset=utf-8");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("content-disposition")).toContain(packageId);
    expect(JSON.parse(await response.text())).toEqual(value);
    expect(calls.read).toHaveBeenCalledWith({}, scanId, packageId);
  });
  it("does not download drafts or cross-scan packages", async () => {
    calls.read.mockReturnValueOnce(null);
    const response = await GET(new Request("http://localhost"), { params: Promise.resolve({ id: scanId, packageId }) });
    expect(response.status).toBe(404);
  });
});
