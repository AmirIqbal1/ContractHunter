import { describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";

const { read } = vi.hoisted(() => ({ read: vi.fn() }));
vi.mock("next/navigation", () => ({ notFound: () => { throw Error("NOT_FOUND"); } }));
vi.mock("@contracthunter/db", () => ({ getDatabase: () => ({}), getScan: () => ({ repositoryName: "Fixture" }),
  listFindings: () => [], getScanSource: () => ({ available: false }) }));
vi.mock("@/lib/protocol-map-server", () => ({ loadProtocolMapForPage: (...args: unknown[]) => read(...args) }));
import ContractExplorerPage from "./page";

const scanId = "11111111-1111-4111-8111-111111111111";
const contractId = `pn:${"a".repeat(64)}`;
describe("Contract Explorer route authority", () => {
  it("rejects malformed and function selectors before graph lookup", async () => {
    read.mockClear();
    await expect(ContractExplorerPage({ params: Promise.resolve({ id: scanId, contractId: "Vault.sol" }) }))
      .rejects.toThrow("NOT_FOUND");
    expect(read).not.toHaveBeenCalled();
  });
  it("rejects an exact ID absent from this scan's graph without name fallback", async () => {
    read.mockReturnValue({ artifact: { graph: { scanId, nodes: [{ id: `pn:${"b".repeat(64)}`, kind: "contract",
      name: "Vault" }], edges: [] }, functionFacts: [], findingLinks: [], unresolved: [] }, invalid: false });
    await expect(ContractExplorerPage({ params: Promise.resolve({ id: scanId, contractId }) }))
      .rejects.toThrow("NOT_FOUND");
  });
  it("renders exact source navigation and no unauthorized Impact Lab launch", async () => {
    const source = { sourceUnitName: "src/core/Vault.sol", startLine: 8, endLine: 9,
      startColumn: 0, endColumn: 10, startByte: 4, endByte: 14 };
    const contract = { id: contractId, key: "fixture", kind: "contract", name: '<script>alert("x")</script>',
      qualifiedName: "src/core/Vault.sol:Vault", contractKind: "contract", source,
      repositoryClassification: { effective: "core", automatic: "core", automaticOrigin: "path-pattern",
        reasons: [], override: null }, evidence: [{ origin: "compiler", producerVersion: "0.8.36",
        source, referenceId: null }], characteristics: [] };
    read.mockReturnValue({ artifact: { graph: { scanId, nodes: [contract], edges: [], sourceUnits: [source] },
      functionFacts: [], findingLinks: [], unresolved: [] }, invalid: false });
    const html = renderToStaticMarkup(await ContractExplorerPage({ params: Promise.resolve({ id: scanId, contractId }) }));
    expect(html).toContain("src%2Fcore%2FVault.sol");
    expect(html).toContain("&lt;script&gt;");
    expect(html).not.toContain('<script>alert("x")</script>');
    expect(html).toContain("No contract-level launch action is available");
    expect(html).not.toContain("/api/impact/sessions");
  });
});
