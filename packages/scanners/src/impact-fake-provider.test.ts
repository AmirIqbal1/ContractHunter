import { describe, expect, it, vi } from "vitest";
import { forwardApprovedUpstreamRequest } from "./impact-upstream-proxy";

const address = `0x${"1".repeat(40)}`;
const block = { number: "0x64", hash: `0x${"a".repeat(64)}` };
class FakeUpstreamProvider {
  received: string[] = [];
  fetch = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
    const input = JSON.parse(Buffer.from(init?.body as Uint8Array).toString("utf8")) as { id: number; method: string; params: unknown[] } | Array<{ id: number; method: string; params: unknown[] }>;
    const reply = (call: { id: number; method: string; params: unknown[] }) => {
      this.received.push(call.method);
      const result = call.method === "eth_chainId" ? "0x2105"
        : call.method === "eth_getBlockByNumber" ? block
        : call.method === "eth_getCode" && call.params[0] === address ? "0x6001600055"
        : call.method === "eth_getBalance" ? "0x10"
        : call.method === "eth_getStorageAt" ? `0x${"0".repeat(64)}` : null;
      return { jsonrpc: "2.0", id: call.id, result };
    };
    return new Response(JSON.stringify(Array.isArray(input) ? input.map(reply) : reply(input)), { status: 200 });
  });
}

describe("deterministic upstream read provider", () => {
  it("serves pinned read state and never receives forbidden methods or mixed batches", async () => {
    const provider = new FakeUpstreamProvider();
    const url = new URL("https://provider.example/key?apiKey=secret");
    const call = (method: string, params: unknown[] = []) => Buffer.from(JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }));
    for (const [method, params] of [["eth_chainId", []], ["eth_getBlockByNumber", ["0x64", false]],
      ["eth_getCode", [address, "0x64"]], ["eth_getBalance", [address, "0x64"]],
      ["eth_getStorageAt", [address, "0x0", "0x64"]]] as Array<[string, unknown[]]>) {
      const result = await forwardApprovedUpstreamRequest(url, call(method, params), provider.fetch as typeof fetch);
      expect(result.status).toBe(200);
    }
    for (const forbidden of ["eth_sendTransaction", "eth_sendRawTransaction", "personal_sign", "evm_mine",
      "anvil_impersonateAccount", "hardhat_setBalance", "wallet_addEthereumChain", "admin_addPeer", "debug_setHead"])
      await expect(forwardApprovedUpstreamRequest(url, call(forbidden), provider.fetch as typeof fetch)).rejects.toThrow("impact_upstream_method_forbidden");
    const readBatch = Buffer.from(JSON.stringify([
      { jsonrpc: "2.0", id: 7, method: "eth_chainId", params: [] },
      { jsonrpc: "2.0", id: 8, method: "eth_getBlockByNumber", params: ["0x64", false] },
    ]));
    const batchResult = await forwardApprovedUpstreamRequest(url, readBatch, provider.fetch as typeof fetch);
    expect(JSON.parse(batchResult.body.toString("utf8"))).toHaveLength(2);
    const mixed = Buffer.from(JSON.stringify([
      { jsonrpc: "2.0", id: 1, method: "eth_chainId", params: [] },
      { jsonrpc: "2.0", id: 2, method: "eth_sendRawTransaction", params: ["0x1234"] },
    ]));
    await expect(forwardApprovedUpstreamRequest(url, mixed, provider.fetch as typeof fetch)).rejects.toThrow("impact_upstream_method_forbidden");
    expect(provider.received).toEqual(["eth_chainId", "eth_getBlockByNumber", "eth_getCode", "eth_getBalance", "eth_getStorageAt", "eth_chainId", "eth_getBlockByNumber"]);
  });
});
