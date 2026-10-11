import { execFile, spawn, type ChildProcess } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { createServer } from "node:net";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import { ImpactForkService, deployedCodeHash } from "./impact-fork-service";
import { startReadOnlyUpstreamProxy } from "./impact-upstream-proxy";
import { ImpactPoCRuntimeService } from "./impact-poc-runtime";

// From the checksum-pinned Foundry v1.7.1 amd64 archive in Dockerfile.
const APPROVED_ANVIL_SHA256 = "10c1c727d6c1de973aeb160e59875b9a9a23464d6e74149ee8abb30b3500311b";
const binaryPath = process.env.IMPACT_TEST_ANVIL;
const probeImageId = process.env.IMPACT_PROBE_IMAGE_ID;
const execFileAsync = promisify(execFile);
const enabled = Boolean(binaryPath && process.arch === "x64" && process.platform === "linux" && process.env.CONTRACTHUNTER_LOOPBACK_TEST === "1");
const host = "127.0.0.1";
const target = `0x${"1".repeat(40)}`;
const code = "0x60005460005260206000f3"; // Return storage slot zero as a uint256.
const slot = `0x${"0".repeat(64)}`;
const value = `0x${"0".repeat(62)}2a`;
const children: ChildProcess[] = [];
afterEach(async () => {
  for (const child of children.splice(0)) {
    if (child.exitCode === null) child.kill("SIGKILL");
    await new Promise<void>((resolve) => { if (child.exitCode !== null) resolve(); else child.once("exit", () => resolve()); });
  }
});

async function port(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, host, resolve); });
  const address = server.address();
  await new Promise<void>((resolve) => server.close(() => resolve()));
  if (!address || typeof address === "string") throw Error("local port unavailable");
  return address.port;
}
async function rpc(endpoint: string, method: string, params: unknown[] = []): Promise<unknown> {
  const response = await fetch(endpoint, { method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }), signal: AbortSignal.timeout(5000) });
  const body = await response.json() as { result?: unknown; error?: unknown };
  if (!response.ok || body.error || !("result" in body)) throw Error(`local fixture RPC failed: ${method}`);
  return body.result;
}
async function waitReady(endpoint: string, child: ChildProcess): Promise<void> {
  for (let i = 0; i < 80; i++) {
    if (child.exitCode !== null) throw Error("fixture Anvil exited");
    try { if (await rpc(endpoint, "eth_chainId") === "0x7a69") return; } catch { /* Wait for owned fixture. */ }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw Error("fixture Anvil startup timed out");
}

describe.skipIf(!enabled)("real Anvil through the read-only proxy", () => {
  it("pins exact state, mutates only the local fork, and reverts without upstream submission", async () => {
    const binary = binaryPath!;
    const stat = statSync(binary);
    expect(stat.isFile()).toBe(true);
    expect(stat.mode & 0o022).toBe(0);
    expect(createHash("sha256").update(readFileSync(binary)).digest("hex")).toBe(APPROVED_ANVIL_SHA256);
    const upstreamPort = await port();
    const upstreamEndpoint = `http://${host}:${upstreamPort}`;
    const upstream = spawn(binary, ["--host", host, "--port", String(upstreamPort), "--chain-id", "31337", "--accounts", "2", "--silent"],
      { shell: false, stdio: "ignore", env: { NODE_ENV: "test", PATH: "/usr/bin:/bin", HOME: "/nonexistent", LANG: "C" } });
    children.push(upstream);
    await waitReady(upstreamEndpoint, upstream);
    await rpc(upstreamEndpoint, "anvil_setCode", [target, code]);
    await rpc(upstreamEndpoint, "anvil_setStorageAt", [target, slot, value]);
    await rpc(upstreamEndpoint, "anvil_mine", ["0x1"]);
    const latest = Number(BigInt(await rpc(upstreamEndpoint, "eth_blockNumber") as string));
    const sourceBlock = await rpc(upstreamEndpoint, "eth_getBlockByNumber", [`0x${latest.toString(16)}`, false]) as { number: string; hash: string };
    const sourceCode = await rpc(upstreamEndpoint, "eth_getCode", [target, sourceBlock.number]);
    const sourceStorage = await rpc(upstreamEndpoint, "eth_getStorageAt", [target, slot, sourceBlock.number]);
    expect(sourceCode).toBe(code);
    expect(sourceStorage).toBe(value);
    const beforeAccounts = await rpc(upstreamEndpoint, "eth_accounts") as string[];
    const sourceBalance = await rpc(upstreamEndpoint, "eth_getBalance", [beforeAccounts[0], sourceBlock.number]);
    const observed: string[] = [];
    const forwarded: string[] = [];
    let proxyUrl = "";
    let diagnostic = "";
    const bridge: typeof fetch = async (_url, init) => {
      const payload = JSON.parse(Buffer.from(init?.body as Uint8Array).toString("utf8")) as { method: string } | Array<{ method: string }>;
      for (const item of Array.isArray(payload) ? payload : [payload]) forwarded.push(item.method);
      return fetch(upstreamEndpoint, init);
    };
    const service = new ImpactForkService({
      resolveBinary: async () => ({ path: binary, version: "anvil 1.7.1", sha256: APPROVED_ANVIL_SHA256 }),
      resolveUpstream: () => "https://fixture.invalid/read-only",
      startProxy: async () => {
        const proxy = await startReadOnlyUpstreamProxy("https://fixture.invalid/read-only", bridge, (method) => observed.push(method));
        proxyUrl = proxy.url;
        return proxy;
      },
      launch: (trusted, args) => {
        const child = spawn("/usr/bin/setpriv", ["--pdeathsig", "SIGKILL", "--", trusted.path, ...args], {
          shell: false, detached: true, stdio: ["ignore", "pipe", "pipe"],
          env: { NODE_ENV: "test", PATH: "/usr/bin:/bin", HOME: "/nonexistent", LANG: "C", NO_COLOR: "1" },
        });
        child.stderr?.on("data", (chunk: Buffer) => { diagnostic = (diagnostic + chunk.toString("utf8")).slice(-2048); });
        return child;
      },
    });
    const handle = service.createForkSession({ findingId: randomUUID(), chainId: 31337, network: "anvil-test",
      upstreamRpcRef: "IMPACT_RPC_LOCAL_TEST", targetContracts: [target], forkBlock: latest });
    try {
      const ready = await service.startForkSession(handle).catch((error) => {
        throw Error(`${error instanceof Error ? error.message : String(error)}: ${diagnostic}; methods=${observed.join(",")}`);
      });
      expect(ready.status).toBe("ready");
      expect(ready.forkBlockHash).toBe(sourceBlock.hash.toLowerCase());
      expect(ready.targetCodeHashes[target]).toBe(deployedCodeHash(code));
      const local = ready.localRpcEndpoint!;
      expect(await rpc(local, "eth_getStorageAt", [target, slot, sourceBlock.number])).toBe(value);
      expect(await rpc(local, "eth_call", [{ to: target, data: "0x" }, sourceBlock.number])).toBe(value);
      const accounts = await rpc(local, "eth_accounts") as string[];
      const snapshot = await service.takeSnapshot(handle);
      const originalLocalBalance = await rpc(local, "eth_getBalance", [accounts[0], "latest"]);
      const tx = await rpc(local, "eth_sendTransaction", [{ from: accounts[0], to: target, value: "0x1" }]);
      expect(typeof tx).toBe("string");
      expect(await rpc(local, "eth_getBalance", [accounts[0], "latest"])).not.toBe(originalLocalBalance);
      expect(await rpc(upstreamEndpoint, "eth_getBalance", [beforeAccounts[0], sourceBlock.number])).toBe(sourceBalance);
      expect(await rpc(upstreamEndpoint, "eth_getStorageAt", [target, slot, sourceBlock.number])).toBe(value);
      await service.revertToSnapshot(handle, snapshot);
      expect(await rpc(local, "eth_getBalance", [accounts[0], "latest"])).toBe(originalLocalBalance);
      expect(await rpc(local, "eth_getStorageAt", [target, slot, sourceBlock.number])).toBe(value);
      expect(forwarded).not.toContain("eth_sendTransaction");
      expect(forwarded).not.toContain("eth_sendRawTransaction");
      expect(forwarded.every((method) => !/^(personal_|anvil_|hardhat_|wallet_|evm_)/.test(method))).toBe(true);
      const rejected = [...observed];
      for (const method of forwarded) rejected.splice(rejected.indexOf(method), 1);
      expect(rejected).toEqual(["eth_getAccountInfo"]);
      expect([...new Set(forwarded)].sort()).toEqual([
        "eth_chainId", "eth_gasPrice", "eth_getBalance", "eth_getBlockByNumber", "eth_getCode",
        "eth_getStorageAt", "eth_getTransactionCount",
      ]);
      if (probeImageId) {
        const currentHandles = new Map([[handle.id, handle]]);
        const poc = new ImpactPoCRuntimeService(service, (id) => currentHandles.get(id), probeImageId);
        try {
          const runtime = await poc.create({ sessionId: handle.id });
          expect(runtime.status).toBe("ready");
          expect((await poc.inspect(runtime.id)).id).toBe(runtime.id);
          const secondHandle = service.createForkSession({ findingId: randomUUID(), chainId: 31337, network: "anvil-test",
            upstreamRpcRef: "IMPACT_RPC_LOCAL_TEST", targetContracts: [target], forkBlock: latest });
          currentHandles.set(secondHandle.id, secondHandle);
          const secondReady = await service.startForkSession(secondHandle);
          const secondRuntime = await poc.create({ sessionId: secondHandle.id });
          expect(secondRuntime.status).toBe("ready");
          const { stdout: containerIdRaw } = await execFileAsync("/usr/bin/docker", ["ps", "-q", "--filter", `label=org.contracthunter.impact-runtime-id=${runtime.id}`]);
          const containerId = containerIdRaw.trim();
          expect(containerId).toMatch(/^[0-9a-f]{12,64}$/);
          const { stdout: secondContainerIdRaw } = await execFileAsync("/usr/bin/docker", ["ps", "-q", "--filter", `label=org.contracthunter.impact-runtime-id=${secondRuntime.id}`]);
          const secondContainerId = secondContainerIdRaw.trim();
          const { stdout: detailsRaw } = await execFileAsync("/usr/bin/docker", ["inspect", containerId]);
          const { stdout: secondDetailsRaw } = await execFileAsync("/usr/bin/docker", ["inspect", secondContainerId]);
          const details = JSON.parse(detailsRaw)[0] as { HostConfig: { NetworkMode: string; Privileged: boolean }; Mounts: Array<{ Source: string }>; NetworkSettings: { Networks: Record<string, unknown> } };
          const secondDetails = JSON.parse(secondDetailsRaw)[0] as { Mounts: Array<{ Source: string }> };
          expect(details.HostConfig.NetworkMode).toBe("none");
          expect(details.HostConfig.Privileged).toBe(false);
          expect(details.Mounts).toHaveLength(1);
          expect(details.Mounts[0]?.Source).not.toBe(secondDetails.Mounts[0]?.Source);
          expect(Object.keys(details.NetworkSettings.Networks)).toEqual(["none"]);
          const tcp = async (hostName: string, portNumber: number) => {
            const { stdout } = await execFileAsync("/usr/bin/docker", ["exec", containerId, "node", "/probe/probe.mjs", "tcp", hostName, String(portNumber)]);
            return (JSON.parse(stdout.trim()) as { reachable: boolean }).reachable;
          };
          const { stdout: gatewayRaw } = await execFileAsync("/usr/bin/docker", ["network", "inspect", "bridge", "--format", "{{(index .IPAM.Config 0).Gateway}}"]);
          const gateway = gatewayRaw.trim();
          const hostListener = createServer();
          await new Promise<void>((resolve, reject) => { hostListener.once("error", reject); hostListener.listen(0, gateway, resolve); });
          try {
            const hostPort = (hostListener.address() as { port: number }).port;
            expect(await tcp(gateway, hostPort)).toBe(false);
            expect(await tcp("1.1.1.1", 80)).toBe(false);
            expect(await tcp(host, Number(new URL(proxyUrl).port))).toBe(false);
            expect(await tcp(gateway, Number(new URL(proxyUrl).port))).toBe(false);
            expect(await tcp(gateway, Number(new URL(local).port))).toBe(false);
            expect(await tcp(gateway, Number(new URL(secondReady.localRpcEndpoint!).port))).toBe(false);
            const { stdout: crossSocketRaw } = await execFileAsync("/usr/bin/docker", ["exec", containerId,
              "node", "/probe/probe.mjs", "socket", secondDetails.Mounts[0]!.Source]);
            expect((JSON.parse(crossSocketRaw.trim()) as { reachable: boolean }).reachable).toBe(false);
          } finally { await new Promise<void>((resolve) => hostListener.close(() => resolve())); }
          currentHandles.set(handle.id, { id: handle.id, token: "stale" });
          await expect(poc.inspect(runtime.id)).rejects.toThrow("impact_runtime_stale");
          currentHandles.set(handle.id, handle);
          expect((await poc.destroy(runtime.id)).status).toBe("stopped");
          expect((await poc.destroy(runtime.id)).status).toBe("stopped");
          expect((await poc.destroy(secondRuntime.id)).status).toBe("stopped");
        } finally { await poc.shutdown(); }
      }
    } finally { await service.shutdown(); }
  }, 30000);
});
