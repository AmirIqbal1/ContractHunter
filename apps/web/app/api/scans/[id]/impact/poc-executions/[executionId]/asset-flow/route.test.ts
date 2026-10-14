import { describe, expect, it, vi } from "vitest";
const calls = vi.hoisted(() => ({ load: vi.fn() }));
vi.mock("@contracthunter/db", () => ({ getDatabase: () => ({}) }));
vi.mock("@/lib/asset-flow-server", () => ({ loadAssetFlow: calls.load }));
import { GET } from "./route";

const scanId = "11111111-1111-4111-8111-111111111111";
const executionId = "22222222-2222-4222-8222-222222222222";
const request = (id = scanId, execution = executionId) => GET(new Request("http://localhost"),
  { params: Promise.resolve({ id, executionId: execution }) });
describe("asset accounting read API", () => {
  it("validates IDs and returns 404 for a cross-scan execution", async () => {
    expect((await request("bad")).status).toBe(400);
    expect((await request(scanId, "bad")).status).toBe(400);
    expect(calls.load).not.toHaveBeenCalled();
    calls.load.mockReturnValueOnce(null);
    expect((await request()).status).toBe(404);
  });
  it("returns a bounded result and sanitizes internal failures", async () => {
    calls.load.mockReturnValueOnce({ schema: "contracthunter-asset-flow-v1", ledgerEntries: [] });
    expect((await (await request()).json()).schema).toBe("contracthunter-asset-flow-v1");
    calls.load.mockImplementationOnce(() => { throw Error("/private/rpc-secret"); });
    const response = await request();
    expect(response.status).toBe(409);
    expect(await response.text()).not.toContain("/private/rpc-secret");
  });
});
