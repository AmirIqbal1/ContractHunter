import { EventEmitter } from "node:events";
import { randomUUID } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { impactForkConfigSchema } from "@contracthunter/core";
import { anvilArguments, ImpactForkService } from "./impact-fork-service";
import { forwardApprovedUpstreamRequest, startReadOnlyUpstreamProxy, validateUpstreamPayload } from "./impact-upstream-proxy";

const blockHash = `0x${"a".repeat(64)}`;
const address = `0x${"1".repeat(40)}`;
const code = "0x6001600055";
const proxyUrl = `http://127.0.0.1:49000/${"a".repeat(48)}`;
const config = () => ({ chainId: 8453, network: "base", upstreamRpcRef: "IMPACT_RPC_BASE", targetContracts: [address], forkBlock: 100,
  findingId: randomUUID(), localBindAddress: "127.0.0.1" });

class FakeChild extends EventEmitter {
  pid = 4242; exitCode: number | null = null; killed = false;
  stdout = new EventEmitter(); stderr = new EventEmitter();
  crash() { this.exitCode = 1; this.emit("exit", 1); }
}

function fixture(options: { sourceChain?: string; sourceHash?: string; localHash?: string; sourceCode?: string; localCode?: string;
  sourceBlockMissing?: boolean; proxyListening?: boolean; proxyDiesDuringStartup?: boolean; proxyStartFails?: boolean;
  snapshotResult?: unknown; rpcFailure?: string; crashOnLaunch?: boolean } = {}) {
  const child = new FakeChild();
  const calls: Array<{ endpoint: string; method: string; params: unknown[] }> = [];
  const close = vi.fn(async () => undefined);
  const terminate = vi.fn(async () => { child.exitCode = 0; child.killed = true; child.emit("exit", 0); });
  const launch = vi.fn((binary: unknown, args: string[]) => { void binary; void args; if (options.crashOnLaunch) queueMicrotask(() => child.crash()); return child as never; });
  let ownsPort = true, token = "process-start-1", nextSnapshot = 1;
  let nextPort = 49001;
  let rpcFailure = options.rpcFailure;
  const service = new ImpactForkService({
    resolveBinary: async () => ({ path: "/usr/local/bin/anvil", version: "anvil 1.7.1", sha256: "b".repeat(64) }),
    resolveUpstream: (ref) => ref === "IMPACT_RPC_BASE" ? "https://provider.example/secret" : undefined,
    startProxy: async () => {
      if (options.proxyStartFails) throw Error("proxy startup failed");
      return { url: proxyUrl, isListening: () => options.proxyListening !== false && !(options.proxyDiesDuringStartup && launch.mock.calls.length > 0), close };
    },
    reservePort: async () => nextPort++,
    launch, processToken: () => token, ownsPort: () => ownsPort, terminate,
    rpc: async (endpoint, method, params) => {
      calls.push({ endpoint, method, params });
      if (rpcFailure === method) throw Error("fixture RPC failure");
      if (method === "eth_chainId") return endpoint.includes("49000") ? options.sourceChain ?? "0x2105" : "0x2105";
      if (method === "eth_getBlockByNumber") return endpoint.includes("49000") && options.sourceBlockMissing ? null :
        { number: "0x64", hash: endpoint.includes("49000") ? options.sourceHash ?? blockHash : options.localHash ?? blockHash };
      if (method === "eth_getCode") return endpoint.includes("49000") ? options.sourceCode ?? code : options.localCode ?? code;
      if (method === "web3_clientVersion") return "anvil/1.7.1";
      if (method === "eth_accounts") return [address];
      if (method === "evm_snapshot") return options.snapshotResult ?? `0x${nextSnapshot++}`;
      if (method === "evm_revert" || method === "anvil_impersonateAccount" || method === "anvil_stopImpersonatingAccount") return true;
      throw Error("unexpected RPC method");
    },
  });
  return { service, child, calls, close, terminate, launch, setOwnsPort: (value: boolean) => { ownsPort = value; }, setToken: (value: string) => { token = value; }, setRpcFailure: (value: string) => { rpcFailure = value; } };
}

describe("Impact Lab Phase A1 safety boundary", () => {
  it("requires one linked finding/hypothesis, an exact block, a secret reference, and loopback only", () => {
    expect(impactForkConfigSchema.safeParse(config()).success).toBe(true);
    expect(impactForkConfigSchema.safeParse({ ...config(), forkBlock: undefined }).success).toBe(false);
    expect(impactForkConfigSchema.safeParse({ ...config(), localBindAddress: "0.0.0.0" }).success).toBe(false);
    expect(impactForkConfigSchema.safeParse({ ...config(), upstreamRpcRef: "https://provider.example/key" }).success).toBe(false);
    expect(impactForkConfigSchema.safeParse({ ...config(), walletPrivateKey: "secret" }).success).toBe(false);
    expect(impactForkConfigSchema.safeParse({ ...config(), hypothesisId: randomUUID() }).success).toBe(false);
    expect(anvilArguments(impactForkConfigSchema.parse(config()), 49001, proxyUrl)).toEqual([
      "--host", "127.0.0.1", "--port", "49001", "--fork-url", proxyUrl, "--fork-block-number", "100", "--chain-id", "8453", "--accounts", "1", "--silent",
    ]);
  });

  it("forbids upstream transactions and mixed batches before forwarding", async () => {
    const forwarded = vi.fn(async (input: string | URL | Request, init?: RequestInit) => { void input; void init; return new Response('{"jsonrpc":"2.0","id":1,"result":"0x1"}', { status: 200 }); });
    const upstream = new URL("https://provider.example/secret");
    const call = (method: string, id = 1) => ({ jsonrpc: "2.0", id, method, params: [] });
    for (const payload of [call("eth_sendTransaction"), call("eth_sendRawTransaction"), call("personal_unlockAccount"),
      [call("eth_chainId"), call("eth_sendRawTransaction", 2)]]) {
      await expect(forwardApprovedUpstreamRequest(upstream, Buffer.from(JSON.stringify(payload)), forwarded as typeof fetch)).rejects.toThrow("impact_upstream_method_forbidden");
    }
    expect(forwarded).toHaveBeenCalledTimes(0);
    const allowed = await forwardApprovedUpstreamRequest(upstream, Buffer.from(JSON.stringify(call("eth_chainId"))), forwarded as typeof fetch);
    expect(allowed.status).toBe(200);
    expect(forwarded).toHaveBeenCalledTimes(1);
    expect(forwarded.mock.calls[0]?.[1]).toMatchObject({ redirect: "manual" });
  });

  it.skipIf(process.env.CONTRACTHUNTER_LOOPBACK_TEST !== "1")("binds the real read filter only to loopback and rejects mutation before the mock provider", async () => {
    const forwarded = vi.fn(async () => new Response('{"jsonrpc":"2.0","id":1,"result":"0x2105"}', { status: 200 }));
    const proxy = await startReadOnlyUpstreamProxy("https://provider.example/private", forwarded as typeof fetch);
    try {
      expect(proxy.url).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/[a-f0-9]{48}$/);
      const request = (method: string) => ({ method: "POST", body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params: [] }) });
      expect((await fetch(proxy.url, request("eth_sendTransaction"))).status).toBe(403);
      expect((await fetch(proxy.url, request("eth_sendRawTransaction"))).status).toBe(403);
      expect(forwarded).toHaveBeenCalledTimes(0);
      expect((await fetch(proxy.url, request("eth_chainId"))).status).toBe(200);
      expect(forwarded).toHaveBeenCalledTimes(1);
      expect((await fetch(proxy.url.replace(/\/[a-f0-9]+$/, "/wrong"), request("eth_chainId"))).status).toBe(403);
    } finally { await proxy.close(); }
  });

  it("starts a pinned session, proves Anvil ownership, snapshots, reverts, resets, impersonates, then stops", async () => {
    const f = fixture(); const handle = f.service.createForkSession(config());
    const ready = await f.service.startForkSession(handle);
    expect(ready).toMatchObject({ status: "ready", resolvedForkBlock: 100, forkBlockHash: blockHash, localRpcEndpoint: "http://127.0.0.1:49001", baselineSnapshotId: "0x1", disposableAccounts: [address] });
    expect(f.calls.filter((call) => call.method === "eth_getCode").map((call) => call.params)).toEqual([[address, "0x64"], [address, "0x64"], [address, "0x64"]]);
    expect(f.launch.mock.calls[0]?.[1]).toContain("--silent");
    expect(f.launch.mock.calls[0]?.[1]).not.toContain("--mnemonic");
    expect(await f.service.assertSafeImpactExecutionEndpoint(handle)).toMatchObject({ id: handle.id });
    const extra = await f.service.takeSnapshot(handle); expect(extra).toBe("0x2");
    await f.service.revertToSnapshot(handle, extra);
    expect(await f.service.resetForkSession(handle)).toBe("0x3");
    await f.service.impersonate(handle, address); await f.service.stopImpersonating(handle, address);
    expect(f.calls.filter((call) => call.method === "anvil_impersonateAccount")).toHaveLength(1);
    expect(await f.service.stopForkSession(handle)).toMatchObject({ status: "stopped", localPort: 49001, localRpcEndpoint: null });
    expect((await f.service.stopForkSession(handle)).status).toBe("stopped");
    expect(f.terminate).toHaveBeenCalledTimes(1); expect(f.close).toHaveBeenCalledTimes(1);
    await expect(f.service.assertSafeImpactExecutionEndpoint(handle)).rejects.toMatchObject({ code: "impact_execution_endpoint_unsafe" });
  });

  it("rejects arbitrary localhost, upstream HTTPS, wrong handle, and changed process or port identity", async () => {
    const f = fixture(); const handle = f.service.createForkSession(config()); await f.service.startForkSession(handle);
    for (const endpoint of ["http://127.0.0.1:49002", "https://provider.example/rpc", proxyUrl])
      await expect(f.service.assertSafeImpactExecutionEndpoint(handle, endpoint)).rejects.toMatchObject({ code: "impact_execution_endpoint_unsafe" });
    await expect(f.service.assertSafeImpactExecutionEndpoint({ id: handle.id, token: "wrong" })).rejects.toMatchObject({ code: "impact_session_identity_invalid" });
    f.setOwnsPort(false);
    await expect(f.service.assertSafeImpactExecutionEndpoint(handle)).rejects.toMatchObject({ code: "impact_execution_endpoint_unsafe" });
    expect(f.service.getSession(handle.id)?.status).toBe("failed");
    expect(f.terminate).toHaveBeenCalledTimes(1);
    const changedPid = fixture(); const second = changedPid.service.createForkSession(config()); await changedPid.service.startForkSession(second);
    changedPid.setToken("reused-pid-start");
    await expect(changedPid.service.assertSafeImpactExecutionEndpoint(second)).rejects.toMatchObject({ code: "impact_execution_endpoint_unsafe" });
  });

  it("rejects a mismatched upstream chain or fork block and closes the proxy before readiness", async () => {
    for (const options of [{ sourceChain: "0x1" }, { localHash: `0x${"c".repeat(64)}` }]) {
      const f = fixture(options); const handle = f.service.createForkSession(config());
      await expect(f.service.startForkSession(handle)).rejects.toBeInstanceOf(Error);
      expect(f.service.getSession(handle.id)?.status).toBe("failed");
      expect(f.close).toHaveBeenCalledTimes(1);
    }
  }, 25_000);

  it("marks a crashed Anvil unsafe and enforces a two-session limit", async () => {
    const f = fixture(); const one = f.service.createForkSession(config()); await f.service.startForkSession(one);
    const two = f.service.createForkSession(config()); await f.service.startForkSession(two);
    expect(f.service.getSession(one.id)?.localRpcEndpoint).not.toBe(f.service.getSession(two.id)?.localRpcEndpoint);
    expect(() => f.service.createForkSession(config())).toThrow("impact_session_limit");
    f.child.crash();
    expect(f.service.getSession(one.id)?.status).toBe("failed");
    await expect(f.service.assertSafeImpactExecutionEndpoint(one)).rejects.toMatchObject({ code: "impact_execution_endpoint_unsafe" });
    await f.service.stopForkSession(one);
    await f.service.stopForkSession(two);
  });

  it("fails closed and cleans up after a snapshot failure", async () => {
    const f = fixture(); const handle = f.service.createForkSession(config()); await f.service.startForkSession(handle);
    f.setRpcFailure("evm_snapshot");
    await expect(f.service.takeSnapshot(handle)).rejects.toBeInstanceOf(Error);
    expect(f.service.getSession(handle.id)?.status).toBe("failed");
    expect(f.terminate).toHaveBeenCalledTimes(1);
  });

  it("fails closed and cleans up after a revert failure", async () => {
    const f = fixture(); const handle = f.service.createForkSession(config()); await f.service.startForkSession(handle);
    const snapshot = await f.service.takeSnapshot(handle);
    f.setRpcFailure("evm_revert");
    await expect(f.service.revertToSnapshot(handle, snapshot)).rejects.toBeInstanceOf(Error);
    expect(f.service.getSession(handle.id)?.status).toBe("failed");
    expect(f.terminate).toHaveBeenCalledTimes(1);
  });

  it("rejects invalid lifecycle transitions and unknown snapshots", async () => {
    const f = fixture(); const handle = f.service.createForkSession(config());
    await expect(f.service.stopForkSession(handle)).rejects.toMatchObject({ code: "impact_transition_invalid" });
    await f.service.startForkSession(handle);
    await expect(f.service.startForkSession(handle)).rejects.toMatchObject({ code: "impact_transition_invalid" });
    await expect(f.service.revertToSnapshot(handle, "0xdead")).rejects.toMatchObject({ code: "impact_snapshot_unknown" });
    await expect(f.service.impersonate(handle, "invalid")).rejects.toBeInstanceOf(Error);
    await f.service.stopForkSession(handle);
  });

  it("cleans up a cancelled or crashed startup", async () => {
    const cancelled = fixture(); const handle = cancelled.service.createForkSession(config()); const abort = new AbortController(); abort.abort();
    await expect(cancelled.service.startForkSession(handle, abort.signal)).rejects.toMatchObject({ code: "impact_startup_cancelled" });
    expect(cancelled.service.getSession(handle.id)?.status).toBe("failed");
    const crashed = fixture({ crashOnLaunch: true }); const other = crashed.service.createForkSession(config());
    await expect(crashed.service.startForkSession(other)).rejects.toBeInstanceOf(Error);
    expect(crashed.service.getSession(other.id)?.status).toBe("failed");
    expect(crashed.terminate).toHaveBeenCalled();
  });

  it("requires upstream deployment code and identical local deployed bytecode", async () => {
    for (const options of [{ sourceCode: "0x" }, { localCode: "0x6002" }]) {
      const f = fixture(options); const handle = f.service.createForkSession(config());
      await expect(f.service.startForkSession(handle)).rejects.toBeInstanceOf(Error);
      expect(f.service.getSession(handle.id)?.status).toBe("failed");
      expect(f.terminate).toHaveBeenCalledTimes(options.sourceCode ? 0 : 1);
      expect(f.close).toHaveBeenCalledTimes(1);
      expect(f.calls.some((call) => call.method === "evm_snapshot")).toBe(false);
    }
  });

  it("cleans up unavailable chain state, a dead proxy, and failed baseline snapshots", async () => {
    for (const options of [{ sourceBlockMissing: true }, { proxyListening: false }, { proxyDiesDuringStartup: true },
      { snapshotResult: false }, { rpcFailure: "eth_chainId" }, { proxyStartFails: true }]) {
      const f = fixture(options); const handle = f.service.createForkSession(config());
      await expect(f.service.startForkSession(handle)).rejects.toBeInstanceOf(Error);
      expect(f.service.getSession(handle.id)?.status).toBe("failed");
      if (!options.proxyStartFails) expect(f.close).toHaveBeenCalled();
      if (options.snapshotResult === false) expect(f.terminate).toHaveBeenCalled();
    }
  });

  it("retains exact block and code identity on recreation and rejects upstream changes", async () => {
    const first = fixture(); const initial = first.service.createForkSession(config());
    const ready = await first.service.startForkSession(initial);
    expect(ready.targetCodeHashes[address]).toMatch(/^sha256:[0-9a-f]{64}$/);
    const stopped = await first.service.stopForkSession(initial);
    const changedBlock = fixture({ sourceHash: `0x${"c".repeat(64)}` });
    const blockHandle = changedBlock.service.recreateForkSession(stopped);
    await expect(changedBlock.service.startForkSession(blockHandle)).rejects.toMatchObject({ code: "impact_upstream_block_changed" });
    expect(changedBlock.launch).not.toHaveBeenCalled();
    const changedCode = fixture({ sourceCode: "0x6002" });
    const codeHandle = changedCode.service.recreateForkSession(stopped);
    await expect(changedCode.service.startForkSession(codeHandle)).rejects.toMatchObject({ code: "impact_upstream_code_changed" });
    expect(changedCode.launch).not.toHaveBeenCalled();
    const repeat = fixture(); const handle = repeat.service.recreateForkSession(stopped);
    const recreated = await repeat.service.startForkSession(handle);
    expect(recreated.id).toBe(stopped.id);
    expect(recreated.baselineSnapshotId).toBe("0x1");
    expect(recreated.targetCodeHashes).toEqual(stopped.targetCodeHashes);
    await repeat.service.stopForkSession(handle);
  });

  it("bounds JSON-RPC and redacts provider URL errors", async () => {
    const call = (method: string, id: unknown = 1) => ({ jsonrpc: "2.0", id, method, params: [] });
    expect(() => validateUpstreamPayload(Buffer.from(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_chainId" })))).not.toThrow();
    expect(() => validateUpstreamPayload(Buffer.from(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_getCode" })))).toThrow();
    for (const payload of [[], [call("eth_chainId"), call("eth_sendRawTransaction")], call("eth_chainId", null),
      call("x".repeat(65)), { ...call("eth_chainId"), params: {} }, Array.from({ length: 21 }, (_, i) => call("eth_chainId", i))])
      expect(() => validateUpstreamPayload(Buffer.from(JSON.stringify(payload)))).toThrow();
    for (const method of ["debug_traceTransaction", "trace_transaction", "anvil_setCode", "hardhat_setStorageAt"])
      expect(() => validateUpstreamPayload(Buffer.from(JSON.stringify(call(method))))).toThrow("impact_upstream_method_forbidden");
    const secret = "sensitive-token-123";
    const url = new URL(`https://provider.example/${secret}?apiKey=${secret}`);
    const fetcher = vi.fn(async () => { throw new Error(`failed ${url}`); });
    await expect(forwardApprovedUpstreamRequest(url, Buffer.from(JSON.stringify(call("eth_chainId"))), fetcher as typeof fetch))
      .rejects.toThrow("impact_upstream_unavailable");
    try { await forwardApprovedUpstreamRequest(url, Buffer.from(JSON.stringify(call("eth_chainId"))), fetcher as typeof fetch); }
    catch (error) { expect(String(error)).not.toContain(secret); }
    expect(fetcher).toHaveBeenCalledTimes(2);
    const providerError = vi.fn(async () => new Response(JSON.stringify({ jsonrpc: "2.0", id: 1,
      error: { code: -32000, message: `URL ${url} failed`, data: secret } }), { status: 200 }));
    const sanitized = await forwardApprovedUpstreamRequest(url, Buffer.from(JSON.stringify(call("eth_chainId"))), providerError as typeof fetch);
    expect(sanitized.body.toString("utf8")).not.toContain(secret);
    await expect(startReadOnlyUpstreamProxy(`https://user:${secret}@provider.example/rpc`)).rejects.toThrow("impact_upstream_unavailable");
  });
});
