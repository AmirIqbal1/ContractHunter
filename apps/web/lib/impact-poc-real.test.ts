import { execFile, spawn, type ChildProcess } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { chmodSync, mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { createServer } from "node:net";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";
import { createDatabase, closeDatabase, createScan, insertFindings, createImpactPoCArtifact,
  reviewImpactPoCArtifact, recordImpactForkSession } from "@contracthunter/db";
import { ImpactForkService, startReadOnlyUpstreamProxy } from "@contracthunter/scanners";

const binary = process.env.IMPACT_TEST_ANVIL;
const imageId = process.env.IMPACT_B1_WORKER_IMAGE;
const compilerVolume = process.env.IMPACT_B1_TEST_COMPILER_VOLUME;
const enabled = process.env.CONTRACTHUNTER_LOOPBACK_TEST === "1" && Boolean(binary &&
  /^sha256:[0-9a-f]{64}$/.test(imageId ?? "") && /^[a-zA-Z0-9_-]+$/.test(compilerVolume ?? ""));
const exec = promisify(execFile);
const host = "127.0.0.1", target = `0x${"1".repeat(40)}`;
const sourceCode = `pragma solidity 0.8.36;
interface Vm { function startBroadcast() external; function stopBroadcast() external; }
contract ImpactPoC {
  Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
  function run() external {
    vm.startBroadcast();
    (bool ok,) = payable(${target}).call{value: 1 wei}("");
    require(ok, "local transfer failed");
    vm.stopBroadcast();
  }
}`;
const ffiCode = `pragma solidity 0.8.36;
interface Vm { function ffi(string[] calldata) external returns (bytes memory); }
contract ImpactPoC {
  Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
  function run() external { string[] memory args = new string[](2); args[0] = "touch"; args[1] = "/tmp/impact-ffi-sentinel"; vm.ffi(args); }
}`;
async function port() {
  const server = createServer();
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, host, resolve); });
  const address = server.address();
  await new Promise<void>((resolve) => server.close(() => resolve()));
  if (!address || typeof address === "string") throw Error("port unavailable");
  return address.port;
}
async function rpc(endpoint: string, method: string, params: unknown[] = []): Promise<unknown> {
  const response = await fetch(endpoint, { method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }), signal: AbortSignal.timeout(5000) });
  const payload = await response.json() as { result?: unknown; error?: unknown };
  if (!response.ok || payload.error || !("result" in payload)) throw Error(`fixture RPC failed: ${method}`);
  return payload.result;
}
async function ready(endpoint: string, child: ChildProcess) {
  for (let i = 0; i < 80; i++) {
    if (child.exitCode !== null) throw Error("fixture exited");
    try { if (await rpc(endpoint, "eth_chainId") === "0x7a69") return; } catch { /* startup */ }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw Error("fixture startup timed out");
}

describe.skipIf(!enabled)("Phase B1 real local Forge worker", () => {
  it("executes only reviewed manual source against the fork, rejects FFI, and resets", async () => {
    const anvil = binary!;
    expect(createHash("sha256").update(readFileSync(anvil)).digest("hex"))
      .toBe("10c1c727d6c1de973aeb160e59875b9a9a23464d6e74149ee8abb30b3500311b");
    expect(statSync(anvil).mode & 0o022).toBe(0);
    const { stdout: imageRaw } = await exec("/usr/bin/docker", ["image", "inspect", imageId!]);
    const image = JSON.parse(imageRaw)[0] as { Id: string; Config: { Labels: Record<string, string> } };
    expect(image.Id).toBe(imageId);
    expect(image.Config.Labels["org.contracthunter.impact-poc-worker-schema"]).toBe("v1");
    const directory = mkdtempSync(path.join(os.tmpdir(), "ch-b1-ipc-")); chmodSync(directory, 0o777);
    const oldIpc = process.env.IMPACT_POC_IPC_DIR, oldMode = process.env.IMPACT_POC_TEST_SOCKET_MODE;
    const hostileHostEnv = ["PRIVATE_KEY", "FOUNDRY_ETH_RPC_URL", "OPENAI_API_KEY"] as const;
    const oldHostEnv = hostileHostEnv.map((name) => process.env[name]);
    for (const name of hostileHostEnv) process.env[name] = "fake-b1-host-secret";
    process.env.IMPACT_POC_IPC_DIR = directory; process.env.IMPACT_POC_TEST_SOCKET_MODE = "0666";
    const workerName = `ch-b1-${randomUUID()}`;
    const upstreamPort = await port(), upstreamEndpoint = `http://${host}:${upstreamPort}`;
    const upstream = spawn(anvil, ["--host", host, "--port", String(upstreamPort), "--chain-id", "31337", "--accounts", "2", "--silent"],
      { shell: false, stdio: "ignore", env: { PATH: "/usr/bin:/bin", HOME: "/nonexistent", NODE_ENV: "test" } });
    let service: ImpactForkService | null = null;
    let proxyEndpoint: string | null = null;
    let unrelatedHostListener: ReturnType<typeof createServer> | null = null;
    const dbDir = mkdtempSync(path.join(os.tmpdir(), "ch-b1-db-"));
    const database = createDatabase(path.join(dbDir, "test.db"));
    try {
      await ready(upstreamEndpoint, upstream);
      await rpc(upstreamEndpoint, "anvil_setCode", [target, "0x60005460005260206000f3"]);
      await rpc(upstreamEndpoint, "anvil_setStorageAt", [target, `0x${"0".repeat(64)}`, `0x${"0".repeat(62)}2a`]);
      await rpc(upstreamEndpoint, "anvil_mine", ["0x1"]);
      const blockNumber = Number(BigInt(await rpc(upstreamEndpoint, "eth_blockNumber") as string));
      const block = await rpc(upstreamEndpoint, "eth_getBlockByNumber", [`0x${blockNumber.toString(16)}`, false]) as { hash: string };
      const before = await rpc(upstreamEndpoint, "eth_getBalance", [target, "latest"]);
      const forwarded: string[] = [];
      const provider: typeof fetch = async (_url, init) => {
        const call = JSON.parse(Buffer.from(init?.body as Uint8Array).toString("utf8")) as { method: string };
        forwarded.push(call.method);
        return fetch(upstreamEndpoint, init);
      };
      service = new ImpactForkService({ resolveBinary: async () => ({ path: anvil, version: "anvil 1.7.1",
        sha256: "10c1c727d6c1de973aeb160e59875b9a9a23464d6e74149ee8abb30b3500311b" }),
        resolveUpstream: () => "https://fixture.invalid/read-only",
        startProxy: async () => { const proxy = await startReadOnlyUpstreamProxy("https://fixture.invalid/read-only", provider);
          proxyEndpoint = proxy.url; return proxy; },
        onStatus: (session) => recordImpactForkSession(database, session),
        launch: (tool, args) => spawn("/usr/bin/setpriv", ["--pdeathsig", "SIGKILL", "--", tool.path, ...args], {
          shell: false, detached: true, stdio: ["ignore", "pipe", "pipe"],
          env: { PATH: "/usr/bin:/bin", HOME: "/nonexistent", NODE_ENV: "test", LANG: "C" },
        }),
      });
      const scan = createScan(database, { repositoryUrl: "https://example.invalid/b1", repositoryName: "fixture/b1", depth: "quick" });
      const finding = insertFindings(database, scan.id, [{ title: "B1 benign fixture", severity: "informational", confidence: 100,
        source: "slither", detectorId: "b1-fixture", fingerprint: "f".repeat(64), contract: "Fixture",
        functionName: "run", filePath: "contracts/Fixture.sol", startLine: 1, endLine: 1,
        rootCause: "Test only.", attackScenario: "Test only.", impact: "None.", evidence: "Local fixture.", status: "candidate" }])[0]!;
      const handle = service.createForkSession({ findingId: finding.id, chainId: 31337, network: "anvil-test",
        upstreamRpcRef: "IMPACT_RPC_LOCAL_TEST", targetContracts: [target], forkBlock: blockNumber });
      const session = await service.startForkSession(handle);
      expect(session.forkBlockHash).toBe(block.hash.toLowerCase());
      const unrelatedHandle = service.createForkSession({ findingId: finding.id, chainId: 31337, network: "anvil-test",
        upstreamRpcRef: "IMPACT_RPC_LOCAL_TEST", targetContracts: [target], forkBlock: blockNumber });
      const unrelatedSession = await service.startForkSession(unrelatedHandle);
      const { stdout: containerId } = await exec("/usr/bin/docker", ["run", "-d", "--name", workerName,
        "--network", "none", "--user", "10003:10001", "--read-only", "--pids-limit", "48", "--cpus", "1", "--memory", "1g",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
        "--tmpfs", "/work:size=67108864,mode=0700,uid=10003,gid=10001",
        "--tmpfs", "/tmp:size=16777216,mode=1770,uid=10003,gid=10001",
        "--tmpfs", "/home/impact:size=16777216,mode=0700,uid=10003,gid=10001",
        "--mount", `type=bind,source=${directory},target=/run/impact-poc`,
        "--mount", `type=volume,source=${compilerVolume},target=/data/tool-home,volume-subpath=tool-home,readonly`, imageId!]);
      expect(containerId.trim()).toMatch(/^[0-9a-f]{64}$/);
      const { stdout: inspectRaw } = await exec("/usr/bin/docker", ["inspect", workerName]);
      const inspected = JSON.parse(inspectRaw)[0] as { Config: { User: string; Env: string[] };
        HostConfig: { NetworkMode: string; Privileged: boolean; ReadonlyRootfs: boolean; CapDrop: string[];
          SecurityOpt: string[]; PidsLimit: number; Memory: number; NanoCpus: number; Binds: string[] | null };
        Mounts: Array<{ Destination: string; RW: boolean }>; NetworkSettings: { Networks: Record<string, unknown> } };
      expect(inspected.Config.User).toBe("10003:10001");
      expect(inspected.HostConfig.NetworkMode).toBe("none");
      expect(inspected.HostConfig.Privileged).toBe(false);
      expect(inspected.HostConfig.ReadonlyRootfs).toBe(true);
      expect(inspected.HostConfig.CapDrop).toContain("ALL");
      expect(inspected.HostConfig.SecurityOpt).toContain("no-new-privileges:true");
      expect(inspected.HostConfig.PidsLimit).toBe(48);
      expect(inspected.HostConfig.Memory).toBe(1073741824);
      expect(inspected.HostConfig.NanoCpus).toBe(1_000_000_000);
      expect(Object.keys(inspected.NetworkSettings.Networks)).toEqual(["none"]);
      expect(inspected.Mounts.map((mount) => mount.Destination).sort()).toEqual(["/data/tool-home", "/run/impact-poc"]);
      expect(inspected.Mounts.find((mount) => mount.Destination === "/data/tool-home")?.RW).toBe(false);
      expect(inspected.Config.Env.join("\n")).not.toMatch(/PRIVATE_KEY|OPENAI_API_KEY|IMPACT_RPC_|FOUNDRY_ETH_RPC_URL|DATABASE_URL/);
      unrelatedHostListener = createServer();
      await new Promise<void>((resolve, reject) => { unrelatedHostListener!.once("error", reject);
        unrelatedHostListener!.listen(0, host, resolve); });
      const hostAddress = unrelatedHostListener.address();
      if (!hostAddress || typeof hostAddress === "string") throw Error("host listener unavailable");
      const blockedEndpoints = [[host, upstreamPort], [host, Number(new URL(proxyEndpoint!).port)],
        [host, hostAddress.port], [host, new URL(unrelatedSession.localRpcEndpoint!).port], ["1.1.1.1", 443]] as const;
      const probe = `const net=require('node:net');const s=net.createConnection({host:process.argv[1],port:Number(process.argv[2])});
        s.setTimeout(500);s.on('connect',()=>process.exit(1));s.on('error',()=>process.exit(0));s.on('timeout',()=>process.exit(0));`;
      for (const [address, destinationPort] of blockedEndpoints) {
        const result = await exec("/usr/bin/docker", ["exec", workerName, "node", "-e", probe, address, String(destinationPort)]);
        expect(result.stdout).toBe("");
      }
      for (let i = 0; i < 30; i++) { if (statSync(path.join(directory, "control.sock"), { throwIfNoEntry: false })) break;
        await new Promise((resolve) => setTimeout(resolve, 100)); }
      await exec("/usr/bin/docker", ["exec", "-u", "10003:10001", workerName, "chmod", "0666", "/run/impact-poc/control.sock"]);
      const poc = createImpactPoCArtifact(database, { findingId: finding.id, filename: "ImpactPoC.s.sol", source: sourceCode, entryContract: "ImpactPoC" });
      const { executeManualPoC } = await import("./impact-poc");
      await expect(executeManualPoC(session.id, { pocArtifactId: poc.id }, { database, service,
        resolveHandle: (id) => id === handle.id ? handle : undefined })).rejects.toThrow("impact_poc_not_reviewed_or_session_missing");
      reviewImpactPoCArtifact(database, poc.id, "reviewed");
      const resetFork = service.resetForkSession.bind(service);
      let resets = 0, balanceBeforeFinalReset: unknown = null;
      service.resetForkSession = async (currentHandle) => {
        resets++;
        if (resets === 2) balanceBeforeFinalReset = await rpc(session.localRpcEndpoint!, "eth_getBalance", [target, "latest"]);
        return resetFork(currentHandle);
      };
      const executing = executeManualPoC(session.id, { pocArtifactId: poc.id }, { database, service,
        resolveHandle: (id) => id === handle.id ? handle : undefined });
      for (let i = 0; i < 30 && !statSync(path.join(directory, "fork.sock"), { throwIfNoEntry: false }); i++)
        await new Promise((resolve) => setTimeout(resolve, 20));
      expect(statSync(path.join(directory, "fork.sock"), { throwIfNoEntry: false })).toBeTruthy();
      await Promise.all(blockedEndpoints.map(async ([address, destinationPort]) => {
        await exec("/usr/bin/docker", ["exec", workerName, "node", "-e", probe, address, String(destinationPort)]);
      }));
      const outcome = await executing;
      service.resetForkSession = resetFork;
      expect(outcome.status, `${outcome.errorCode}: ${outcome.stderr}`).toBe("completed");
      expect(outcome.compiled).toBe(true);
      expect(outcome.executed).toBe(true);
      expect(outcome.transactionScope).toBe("local-impact-lab");
      expect(outcome.transactionHashes.length).toBeGreaterThan(0);
      expect(BigInt(balanceBeforeFinalReset as string)).toBe(BigInt(before as string) + 1n);
      expect(await rpc(upstreamEndpoint, "eth_getBalance", [target, "latest"])).toBe(before);
      expect(await rpc(session.localRpcEndpoint!, "eth_getBalance", [target, "latest"])).toBe(before);
      expect((database.sqlite.prepare("SELECT status FROM findings WHERE id=?").get(finding.id) as { status: string }).status)
        .toBe("candidate");
      expect((database.sqlite.prepare("SELECT count(*) AS n FROM authoritative_invariant_evidence").get() as { n: number }).n)
        .toBe(0);
      expect(forwarded).not.toContain("eth_sendTransaction");
      expect(forwarded).not.toContain("eth_sendRawTransaction");
      const ffi = createImpactPoCArtifact(database, { findingId: finding.id, filename: "ImpactPoC.s.sol", source: ffiCode, entryContract: "ImpactPoC" });
      reviewImpactPoCArtifact(database, ffi.id, "reviewed");
      const ffiResult = await executeManualPoC(session.id, { pocArtifactId: ffi.id }, { database, service,
        resolveHandle: (id) => id === handle.id ? handle : undefined });
      expect(ffiResult.status).toBe("failed");
      expect(`${ffiResult.stdout}\n${ffiResult.stderr}`).toMatch(/ffi|permission|disabled/i);
      const { stdout: ffiSentinel } = await exec("/usr/bin/docker", ["exec", workerName, "test", "!", "-e", "/tmp/impact-ffi-sentinel"]);
      expect(ffiSentinel).toBe("");
      await service.stopForkSession(handle);
      await expect(executeManualPoC(session.id, { pocArtifactId: poc.id }, { database, service,
        resolveHandle: (id) => id === handle.id ? handle : undefined })).rejects.toThrow();
      const recreatedHandle = service.recreateForkSession(service.getSession(handle.id)!);
      await service.startForkSession(recreatedHandle);
      await expect(executeManualPoC(session.id, { pocArtifactId: poc.id }, { database, service,
        resolveHandle: (id) => id === handle.id ? handle : undefined })).rejects.toThrow("impact_session_identity_invalid");
      await service.stopForkSession(recreatedHandle);
    } finally {
      await service?.shutdown().catch(() => undefined);
      if (unrelatedHostListener) await new Promise<void>((resolve) => unrelatedHostListener!.close(() => resolve()));
      await exec("/usr/bin/docker", ["rm", "-f", workerName]).catch(() => undefined);
      upstream.kill("SIGKILL");
      closeDatabase(database);
      rmSync(directory, { recursive: true, force: true }); rmSync(dbDir, { recursive: true, force: true });
      if (oldIpc === undefined) delete process.env.IMPACT_POC_IPC_DIR; else process.env.IMPACT_POC_IPC_DIR = oldIpc;
      if (oldMode === undefined) delete process.env.IMPACT_POC_TEST_SOCKET_MODE; else process.env.IMPACT_POC_TEST_SOCKET_MODE = oldMode;
      hostileHostEnv.forEach((name, index) => { if (oldHostEnv[index] === undefined) delete process.env[name];
        else process.env[name] = oldHostEnv[index]; });
    }
  }, 60_000);
});
