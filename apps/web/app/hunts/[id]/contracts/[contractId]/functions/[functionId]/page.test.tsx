import { describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";

const mocks = vi.hoisted(() => ({ read: vi.fn(), scan: vi.fn(), findings: vi.fn() }));
vi.mock("next/navigation", () => ({ notFound: () => { throw Error("NOT_FOUND"); } }));
vi.mock("@contracthunter/db", () => ({ getDatabase: () => ({}), getScan: mocks.scan, getFinding: mocks.findings }));
vi.mock("@/lib/function-explorer-server", () => ({ readFunctionExplorer: mocks.read }));
vi.mock("@/lib/impact-overlay-selection", () => ({ listImpactExecutionIds: () => [], selectImpactOverlay: () => null }));
vi.mock("@/components/function-explorer", () => ({ FunctionExplorer: ({ data, findings }: {
  data: { model: { function: { signature: string } } }; findings: Array<{ title: string }> }) =>
  <div>{data.model.function.signature} · {findings.map((item) => item.title).join(", ")}</div> }));
import FunctionExplorerPage from "./page";

const scanId = "00000000-0000-4000-8000-000000000001", contractId = `pn:${"a".repeat(64)}`;
const functionId = `pn:${"b".repeat(64)}`;
const page = (contract = contractId, fn = functionId) => FunctionExplorerPage({
  params: Promise.resolve({ id: scanId, contractId: contract, functionId: fn }) });

describe("Function Explorer page authority", () => {
  it("rejects malformed selectors and exact IDs outside this scan/contract", async () => {
    mocks.scan.mockReturnValue({ repositoryName: "Fixture" }); mocks.read.mockReset();
    await expect(page("Vault.sol")).rejects.toThrow("NOT_FOUND");
    expect(mocks.read).not.toHaveBeenCalled();
    mocks.read.mockReturnValue(null);
    await expect(page()).rejects.toThrow("NOT_FOUND");
  });
  it("loads only exact linked findings and renders a bounded function result", async () => {
    mocks.scan.mockReturnValue({ repositoryName: "Fixture" });
    mocks.read.mockReturnValue({ model: { function: { signature: "foo(uint256)" }, findings: [
      "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"], operations: [], callees: [] } });
    mocks.findings.mockImplementation((_database, id: string) => id === "11111111-1111-4111-8111-111111111111" ?
      { id, scanId, title: "Exact finding", source: "slither", detectorId: "x", status: "open" } :
      { id, scanId: "22222222-2222-4222-8222-222222222222", title: "Wrong scan", source: "slither",
        detectorId: "x", status: "open" });
    const html = renderToStaticMarkup(await page());
    expect(html).toContain("foo(uint256)");
    expect(html).toContain("Exact finding");
    expect(html).not.toContain("Wrong scan");
    expect(mocks.read).toHaveBeenCalledWith({}, scanId, contractId, functionId);
    expect(mocks.findings).toHaveBeenCalledTimes(2);
  });
});
