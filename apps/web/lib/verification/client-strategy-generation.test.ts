import { describe, expect, it, vi } from "vitest";
import { requestSelectedStrategy } from "./client-strategy-generation";

describe("browser strategy action", () => {
  it.each(["structured-verification", "foundry-fuzz-property", "foundry-stateful-invariant", "echidna-stateful-invariant"] as const)("sends only the %s route identity", async (strategy) => {
    const send = vi.fn(async () => new Response(JSON.stringify({ code: "strategy_not_compatible" }), { status: 409 }));
    const result = await requestSelectedStrategy("hypothesis-id", strategy, send as typeof fetch);
    expect(result).toEqual({ ok: false, body: { code: "strategy_not_compatible" } });
    expect(send).toHaveBeenCalledExactlyOnceWith(`/api/hypotheses/hypothesis-id/verification-options/${strategy}/generate`, { method: "POST" });
  });
});
