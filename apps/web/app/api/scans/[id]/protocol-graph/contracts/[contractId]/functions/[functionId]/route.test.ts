import { describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ read: vi.fn(), scan: vi.fn() }));
vi.mock("@contracthunter/db", () => ({ getDatabase: () => ({}), getScan: mocks.scan }));
vi.mock("@/lib/function-explorer-server", () => ({ readFunctionExplorer: mocks.read }));
import { GET } from "./route";

const scanId = "00000000-0000-4000-8000-000000000001";
const contractId = `pn:${"a".repeat(64)}`, functionId = `pn:${"b".repeat(64)}`;
const call = (id = scanId, contract = contractId, fn = functionId) => GET(new Request("http://localhost"),
  { params: Promise.resolve({ id, contractId: contract, functionId: fn }) });

describe("Function Explorer read-only API selectors", () => {
  it("rejects malformed and missing scan selectors before reading analysis", async () => {
    mocks.scan.mockReturnValue(null); mocks.read.mockReset();
    expect((await call("bad")).status).toBe(400);
    expect((await call(scanId, "Vault", functionId)).status).toBe(400);
    expect((await call()).status).toBe(404);
    expect(mocks.read).not.toHaveBeenCalled();
  });
  it("returns only exact service result and sanitizes integrity failures", async () => {
    mocks.scan.mockReturnValue({ id: scanId });
    mocks.read.mockReturnValue(null);
    expect((await call()).status).toBe(404);
    const result = { model: { schema: "contracthunter-function-explorer-v1" }, sourcePreview: null,
      sourcePreviewTruncated: false };
    mocks.read.mockReturnValue(result);
    expect(await (await call()).json()).toEqual(result);
    expect(mocks.read).toHaveBeenCalledWith({}, scanId, contractId, functionId);
    mocks.read.mockImplementation(() => { throw Error("/secret/internal/path"); });
    const failed = await call();
    expect(failed.status).toBe(500);
    expect(JSON.stringify(await failed.json())).not.toContain("/secret/internal/path");
  });
});
