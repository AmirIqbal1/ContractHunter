import { describe, expect, it, vi } from "vitest";
const calls = vi.hoisted(() => ({ load: vi.fn() }));
vi.mock("@contracthunter/db", () => ({ getDatabase: () => ({}) }));
vi.mock("@/lib/impact-overlay-server", () => ({ loadImpactOverlay: calls.load }));
import { GET } from "./route";

const scanId = "11111111-1111-4111-8111-111111111111";
const executionId = "22222222-2222-4222-8222-222222222222";
const request = (id = scanId, execution = executionId) => GET(new Request("http://localhost"),
  { params: Promise.resolve({ id, executionId: execution }) });
describe("read-only Impact Overlay API", () => {
  it("rejects malformed IDs before the resolver", async () => {
    expect((await request("bad")).status).toBe(400);
    expect((await request(scanId, "bad")).status).toBe(400);
    expect(calls.load).not.toHaveBeenCalled();
  });
  it("returns 404 for missing or cross-scan execution", async () => {
    calls.load.mockReturnValueOnce(null);
    expect((await request()).status).toBe(404);
  });
  it("returns bounded model and sanitizes internal errors", async () => {
    calls.load.mockReturnValueOnce({ schema: "contracthunter-impact-overlay-v1" });
    const response = await request();
    expect(response.status).toBe(200);
    expect((await response.json()).schema).toBe("contracthunter-impact-overlay-v1");
    calls.load.mockImplementationOnce(() => { throw Error("/private/fork-rpc-token"); });
    const failure = await request();
    expect(failure.status).toBe(409);
    expect(await failure.text()).not.toContain("/private/fork-rpc-token");
  });
});
