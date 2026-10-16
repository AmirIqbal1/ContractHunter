import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ graph: vi.fn(), derive: vi.fn() }));
vi.mock("@contracthunter/db", () => ({ getDatabase: () => ({}), getScan: () => ({ repositoryName: "Example" }),
  readRepositoryMap: () => null, readStaticProtocolGraph: (...args: unknown[]) => mocks.graph(...args) }));
vi.mock("@contracthunter/core", async (importOriginal) => ({ ...(await importOriginal<Record<string, unknown>>()),
  deriveAuditPriorityFromArtifact: (...args: unknown[]) => mocks.derive(...args) }));
vi.mock("@/components/start-here", () => ({ StartHere: ({ initialMode }: { initialMode: string }) => <div>loaded {initialMode}</div> }));
import StartHerePage from "./page";

const params = Promise.resolve({ id: "11111111-1111-4111-8111-111111111111" });
describe("Start Here server loading", () => {
  it("uses exact scan graph and bounded derivation without a browser analysis input", async () => {
    mocks.graph.mockReturnValueOnce({ id: "graph" }); mocks.derive.mockReturnValueOnce({ schema: "audit" });
    const html = renderToStaticMarkup(await StartHerePage({ params,
      searchParams: Promise.resolve({ mode: "researcher" }) }));
    expect(html).toContain("loaded researcher"); expect(mocks.derive).toHaveBeenCalledWith({ id: "graph" }, null);
  });
  it("bounds missing and failed graph states", async () => {
    mocks.graph.mockReturnValueOnce(null);
    expect(renderToStaticMarkup(await StartHerePage({ params }))).toContain("not backfilled");
    mocks.graph.mockImplementationOnce(() => { throw new Error("/private/secret.sql"); });
    const html = renderToStaticMarkup(await StartHerePage({ params }));
    expect(html).toContain("could not be loaded"); expect(html).not.toContain("/private/secret.sql");
  });
});
