import { describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ database: {}, scan: vi.fn(), graph: vi.fn(), finding: vi.fn(), derive: vi.fn() }));
vi.mock("@contracthunter/db", () => ({ getDatabase: () => mocks.database, getScan: mocks.scan,
  readStaticProtocolGraph: mocks.graph, getFinding: mocks.finding }));
vi.mock("@contracthunter/core", () => ({ securityViewTypes: ["money-flow", "permissions", "oracle-flow",
  "external-calls", "upgradeability", "attack-surface", "findings"], SECURITY_VIEW_LIMITS: { findingMetadata: 500 },
  deriveSecurityView: mocks.derive }));
import { GET } from "./route";

const scanId = "00000000-0000-4000-8000-000000000001", linked = "11111111-1111-4111-8111-111111111111";
const request = (id: string, view: string) => GET(new Request("http://localhost/test"), {
  params: Promise.resolve({ id, view }) });

describe("read-only Security View API", () => {
  it("rejects malformed scans and closed-type violations before data access", async () => {
    mocks.scan.mockReset(); mocks.derive.mockReset();
    expect((await request("bad", "money-flow")).status).toBe(400);
    expect((await request(scanId, "arbitrary-view")).status).toBe(400);
    expect(mocks.scan).not.toHaveBeenCalled(); expect(mocks.derive).not.toHaveBeenCalled();
  });
  it("returns bounded missing-scan and missing-graph responses", async () => {
    mocks.scan.mockReturnValueOnce(null).mockReturnValueOnce({ id: scanId });
    mocks.graph.mockReturnValueOnce(null);
    expect((await request(scanId, "money-flow")).status).toBe(404);
    expect((await request(scanId, "money-flow")).status).toBe(404);
  });
  it("loads only exact same-scan finding metadata for the findings projection", async () => {
    const artifact = { findingLinks: [{ findingId: linked, nodeId: "pn:x" },
      { findingId: linked, nodeId: "pn:y" }, { findingId: "22222222-2222-4222-8222-222222222222", nodeId: "pn:z" }] };
    mocks.scan.mockReturnValue({ id: scanId }); mocks.graph.mockReturnValue(artifact);
    mocks.finding.mockImplementation((_db, id: string) => ({ id, scanId: id === linked ? scanId : "other-scan",
      detectorId: "reentrancy", title: "Exact", status: "open", source: "slither" }));
    mocks.derive.mockReturnValue({ schema: "contracthunter-security-view-v1", viewType: "findings" });
    const response = await request(scanId, "findings");
    expect(response.status).toBe(200);
    expect(mocks.finding).toHaveBeenCalledTimes(2);
    expect(mocks.derive).toHaveBeenCalledWith(artifact, "findings", [{ id: linked,
      detectorId: "reentrancy", title: "Exact", status: "open", source: "slither" }]);
  });
  it("sanitizes graph integrity or derivation failures", async () => {
    mocks.scan.mockReturnValue({ id: scanId }); mocks.graph.mockImplementation(() => { throw Error("/secret/path"); });
    const response = await request(scanId, "external-calls");
    expect(response.status).toBe(500);
    expect(JSON.stringify(await response.json())).not.toContain("/secret/path");
  });
});
