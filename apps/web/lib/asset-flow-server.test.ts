import { beforeEach, describe, expect, it, vi } from "vitest";

const calls = vi.hoisted(() => ({ overlay: vi.fn(), session: vi.fn(), derive: vi.fn() }));
vi.mock("./impact-overlay-server", () => ({ loadImpactOverlay: calls.overlay }));
vi.mock("@contracthunter/db", () => ({ readImpactForkSession: calls.session }));
vi.mock("@contracthunter/core", () => ({ deriveAssetFlow: calls.derive }));
import { loadAssetFlow } from "./asset-flow-server";

beforeEach(() => {
  vi.resetAllMocks();
  calls.overlay.mockReturnValue({ sessionId: "session" });
  calls.session.mockReturnValue({ id: "session", disposableAccounts: ["0x" + "a".repeat(40)] });
  calls.derive.mockReturnValue({ schema: "contracthunter-asset-flow-v1" });
});
describe("exact read-only asset accounting service", () => {
  it("rejects a cross-hunt execution through the Phase 10 ownership gate", () => {
    calls.overlay.mockReturnValueOnce(null);
    expect(loadAssetFlow({} as never, "other-scan", "execution")).toBeNull();
    expect(calls.session).not.toHaveBeenCalled();
    expect(calls.derive).not.toHaveBeenCalled();
  });
  it("uses only bound overlay and the bound session's disposable account identities", () => {
    expect(loadAssetFlow({} as never, "scan", "execution")?.schema).toBe("contracthunter-asset-flow-v1");
    expect(calls.derive).toHaveBeenCalledWith({ sessionId: "session" }, {
      disposableAccounts: ["0x" + "a".repeat(40)], trustedAssetStandards: [] });
  });
  it("fails closed when the bound session disappears", () => {
    calls.session.mockReturnValueOnce(null);
    expect(() => loadAssetFlow({} as never, "scan", "execution")).toThrow("asset_flow_session_unavailable");
  });
});
