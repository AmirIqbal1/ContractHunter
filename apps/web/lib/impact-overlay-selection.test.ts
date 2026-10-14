import { describe, expect, it, vi } from "vitest";
const mocked = vi.hoisted(() => ({ load: vi.fn() }));
vi.mock("./impact-overlay-server", () => ({ loadImpactOverlay: mocked.load }));
import { listImpactExecutionIds, selectImpactOverlay } from "./impact-overlay-selection";

describe("Impact execution selection", () => {
  it("scopes the bounded query to a scan and subject and refuses a foreign execution ID", () => {
    const all = vi.fn(() => [{ id: "local" }]);
    const prepare = vi.fn((sql: string) => { expect(sql).toContain("SELECT e.id"); return { all }; });
    const database = { sqlite: { prepare } } as never;
    const ids = listImpactExecutionIds(database, "scan-a", { type: "finding", id: "finding-a" });
    expect(ids).toEqual(["local"]);
    expect(prepare.mock.calls[0]?.[0]).toContain("a.review_state = 'reviewed'");
    expect(prepare.mock.calls[0]?.[0]).toContain("f.scan_id = ? OR h.scan_id = ?");
    expect(all).toHaveBeenCalledWith("scan-a", "scan-a", "finding-a");
    expect(selectImpactOverlay(database, "scan-a", ids, "foreign")).toBeNull();
    expect(mocked.load).not.toHaveBeenCalled();
    selectImpactOverlay(database, "scan-a", ids, "local");
    expect(mocked.load).toHaveBeenCalledWith(database, "scan-a", "local");
  });
});
