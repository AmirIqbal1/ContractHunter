import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
const calls = vi.hoisted(() => ({ graph: vi.fn() }));
vi.mock("@contracthunter/db", () => ({ getDatabase: () => ({}), getScan: () => ({ repositoryName: "Fixture" }),
  getFinding: () => ({ id: "11111111-1111-4111-8111-111111111111", scanId: "22222222-2222-4222-8222-222222222222",
    title: "Finding", severity: "medium", confidence: 50, source: "slither", detectorId: "detector",
    contract: "Vault", functionName: "withdraw", status: "candidate", filePath: "src/Vault.sol", startLine: 12,
    endLine: 12, rootCause: "", attackScenario: "", impact: "", evidence: "", createdAt: new Date() }),
  readStaticProtocolGraph: (...args: unknown[]) => calls.graph(...args) }));
import FindingPage from "./page";
const findingId = "11111111-1111-4111-8111-111111111111";
const contractId = `pn:${"a".repeat(64)}`, functionId = `pn:${"b".repeat(64)}`;
describe("finding detail exact graph links", () => {
  it("opens canonical map and function only for persisted finding links", async () => {
    calls.graph.mockReturnValueOnce({ graph: { nodes: [{ id: functionId, kind: "function", contractId,
      name: "withdraw" }] }, findingLinks: [{ findingId, nodeId: functionId }] });
    const html = renderToStaticMarkup(await FindingPage({ params: Promise.resolve({ id: findingId }) }));
    expect(html).toContain(`protocol-map?node=${encodeURIComponent(contractId)}`);
    expect(html).toContain(`/functions/${encodeURIComponent(functionId)}`);
    expect(html).toContain("does not establish runtime reachability");
  });
  it("omits graph navigation when exact attachment is absent", async () => {
    calls.graph.mockReturnValueOnce({ graph: { nodes: [] }, findingLinks: [] });
    const html = renderToStaticMarkup(await FindingPage({ params: Promise.resolve({ id: findingId }) }));
    expect(html).not.toContain("Show in Protocol Map");
  });
});
