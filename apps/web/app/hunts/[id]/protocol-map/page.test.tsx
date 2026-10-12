import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { loadProtocolMapForPage } from "@/lib/protocol-map-server";

const { readStaticProtocolGraph } = vi.hoisted(() => ({ readStaticProtocolGraph: vi.fn() }));
vi.mock("@contracthunter/db", () => ({
  getDatabase: () => ({}), getScan: () => ({ id: "11111111-1111-4111-8111-111111111111", repositoryName: "Fixture" }),
  readStaticProtocolGraph: (...args: unknown[]) => readStaticProtocolGraph(...args),
}));
import ProtocolMapPage from "./page";

describe("Protocol Map unavailable states", () => {
  beforeEach(() => readStaticProtocolGraph.mockReset());
  const params = Promise.resolve({ id: "11111111-1111-4111-8111-111111111111" });
  it("shows a useful historical-scan empty state", async () => {
    readStaticProtocolGraph.mockReturnValue(null);
    const html = renderToStaticMarkup(await ProtocolMapPage({ params }));
    expect(html).toContain("Protocol Map unavailable");
    expect(html).toContain("not backfilled");
  });
  it("sanitizes graph integrity failures", async () => {
    const loaded = loadProtocolMapForPage({} as never, "scan", () => {
      throw new Error("/private/database: secret socket details");
    });
    expect(loaded).toEqual({ artifact: null, invalid: true });
    expect(JSON.stringify(loaded)).not.toContain("/private/database");
  });
});
