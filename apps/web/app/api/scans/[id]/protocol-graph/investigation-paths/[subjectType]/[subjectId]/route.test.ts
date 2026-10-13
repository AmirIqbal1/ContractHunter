import { describe, expect, it, vi } from "vitest";
const calls = vi.hoisted(() => ({ scan: vi.fn(), graph: vi.fn(), load: vi.fn() }));
vi.mock("@contracthunter/db", () => ({ getDatabase: () => ({}), getScan: (...args: unknown[]) => calls.scan(...args),
  readStaticProtocolGraph: (...args: unknown[]) => calls.graph(...args) }));
vi.mock("@/lib/investigation-path-server", () => ({ loadInvestigationPaths: (...args: unknown[]) => calls.load(...args) }));
import { GET } from "./route";
const scanId = "11111111-1111-4111-8111-111111111111", subjectId = "22222222-2222-4222-8222-222222222222";
const request = (id = scanId, subjectType = "finding", target = subjectId) => GET(new Request("http://localhost"),
  { params: Promise.resolve({ id, subjectType, subjectId: target }) });
describe("read-only Investigation Path API", () => {
  it("rejects invalid subject taxonomy and identity", async () => {
    expect((await request(scanId, "exploit-path")).status).toBe(400);
    expect((await request(scanId, "finding", "bad")).status).toBe(400);
    expect(calls.load).not.toHaveBeenCalled();
  });
  it("rejects missing scan, graph, and wrong-scan subject", async () => {
    calls.scan.mockReturnValueOnce(null);
    expect((await request()).status).toBe(404);
    calls.scan.mockReturnValueOnce({ id: scanId }); calls.graph.mockReturnValueOnce(null);
    expect((await request()).status).toBe(404);
    calls.scan.mockReturnValueOnce({ id: scanId }); calls.graph.mockReturnValueOnce({ id: "graph" }); calls.load.mockReturnValueOnce(null);
    expect((await request()).status).toBe(404);
  });
  it("returns exact static model and sanitizes derivation failures", async () => {
    calls.scan.mockReturnValueOnce({ id: scanId }); calls.graph.mockReturnValueOnce({ id: "graph" });
    calls.load.mockReturnValueOnce({ schema: "contracthunter-investigation-path-v1", subject: { type: "finding", id: subjectId } });
    const response = await request(); expect(response.status).toBe(200);
    expect((await response.json()).schema).toBe("contracthunter-investigation-path-v1");
    expect(calls.load).toHaveBeenCalledWith({}, scanId, "finding", subjectId, { id: "graph" });
    calls.scan.mockReturnValueOnce({ id: scanId }); calls.graph.mockReturnValueOnce({ id: "graph" });
    calls.load.mockImplementationOnce(() => { throw new Error("/private/database.sql password"); });
    const failure = await request(); expect(failure.status).toBe(500);
    expect(await failure.text()).not.toContain("/private/database.sql");
  });
});
