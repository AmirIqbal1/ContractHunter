import { describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ scan: vi.fn(), graph: vi.fn(), map: vi.fn(), derive: vi.fn() }));
vi.mock("@contracthunter/db", () => ({ getDatabase: () => ({}), getScan: mocks.scan,
  readStaticProtocolGraph: mocks.graph, readRepositoryMap: mocks.map }));
vi.mock("@contracthunter/core", () => ({ deriveAuditPriorityFromArtifact: mocks.derive }));
import { GET } from "./route";

const scanId = "00000000-0000-4000-8000-000000000001";
const request = (id: string) => GET(new Request("http://localhost/test"), { params: Promise.resolve({ id }) });

describe("read-only audit-priority API", () => {
  it("validates scan identity and returns bounded absence errors", async () => {
    mocks.scan.mockReset(); mocks.graph.mockReset(); mocks.map.mockReset(); mocks.derive.mockReset();
    expect((await request("bad")).status).toBe(400);
    expect(mocks.graph).not.toHaveBeenCalled();
    mocks.scan.mockReturnValueOnce(null).mockReturnValueOnce({ id: scanId });
    mocks.graph.mockReturnValueOnce(null);
    expect((await request(scanId)).status).toBe(404);
    expect((await request(scanId)).status).toBe(404);
  });
  it("derives from exact saved graph and map without browser weights", async () => {
    const artifact = { id: "graph" }, map = { id: "map" }, result = { schema: "contracthunter-audit-priority-v1" };
    mocks.scan.mockReturnValue({ id: scanId }); mocks.graph.mockReturnValue(artifact); mocks.map.mockReturnValue(map);
    mocks.derive.mockReturnValue(result);
    const response = await request(scanId);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual(result);
    expect(mocks.derive).toHaveBeenCalledWith(artifact, map);
  });
  it("sanitizes integrity and derivation failures", async () => {
    mocks.scan.mockReturnValue({ id: scanId }); mocks.graph.mockImplementation(() => { throw Error("/private/path secret"); });
    const response = await request(scanId);
    expect(response.status).toBe(500);
    expect(JSON.stringify(await response.json())).not.toContain("/private/path");
  });
});
