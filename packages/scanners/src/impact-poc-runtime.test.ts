import { randomUUID } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import type { ImpactForkSession } from "@contracthunter/core";
import { type ImpactForkHandle, type ImpactForkService } from "./impact-fork-service";
import { ImpactPoCRuntimeService, type ImpactContainerDriver, type ImpactContainerInspect } from "./impact-poc-runtime";

const imageId = `sha256:${"a".repeat(64)}`;
const sessionId = randomUUID();
const handle: ImpactForkHandle = { id: sessionId, token: "current-token" };
const session: ImpactForkSession = { id: sessionId, status: "ready", findingId: randomUUID(), hypothesisId: null,
  chainId: 31337, network: "anvil-test", upstreamRpcRef: "IMPACT_RPC_TEST", rpcConfigId: "test",
  targetContracts: [`0x${"1".repeat(40)}`], targetCodeHashes: { [`0x${"1".repeat(40)}`]: `sha256:${"b".repeat(64)}` },
  resolvedForkBlock: 1, historicalTransactionHash: null, forkBlockHash: `0x${"c".repeat(64)}`,
  localPort: 49001, localRpcEndpoint: "http://127.0.0.1:49001", anvilVersion: "anvil 1.7.1", anvilSha256: "d".repeat(64),
  processPid: 1234, baselineSnapshotId: "0x1", disposableAccounts: [], createdAt: 1, startedAt: 2, stoppedAt: null, failureCode: null };

function fixture() {
  let currentHandle: ImpactForkHandle | undefined = handle;
  let currentSession = session;
  let unsafe = false;
  let removed = false;
  let creation: Parameters<ImpactContainerDriver["create"]>[0] | null = null;
  const driver: ImpactContainerDriver = {
    verifyImage: vi.fn(async (id) => { expect(id).toBe(imageId); }),
    removeStale: vi.fn(async () => undefined),
    create: vi.fn(async (input) => { creation = input; removed = false; return "container-1"; }),
    start: vi.fn(async () => undefined),
    inspect: vi.fn(async () => {
      const input = creation!;
      return { Id: "container-1", State: { Running: !removed }, Config: { Image: imageId, User: `10003:${input.groupId}`, Env: ["NODE_VERSION=22"] },
        HostConfig: { NetworkMode: unsafe ? "host" : "none", ReadonlyRootfs: true, Privileged: false, CapDrop: ["ALL"],
          SecurityOpt: ["no-new-privileges:true"], PidsLimit: 32, NanoCpus: 500_000_000, Memory: 128 * 1024 * 1024, Binds: null },
        Mounts: [{ Type: "bind", Source: input.socketPath, Destination: "/run/impact/fork.sock", RW: false }] } satisfies ImpactContainerInspect;
    }),
    logs: vi.fn(async () => JSON.stringify({ schema: "impact-probe-v1", chainId: "0x7a69", interfaces: ["lo"], routes: [],
      uid: 10003, capEff: "0000000000000000", capBnd: "0000000000000000", noNewPrivs: "1", seccomp: "2", appArmor: "docker-default (enforce)",
      dockerSocket: false, dataDir: false, verificationDir: false, otherForkSocket: false, sensitiveEnvironmentKeys: [] })),
    remove: vi.fn(async () => { removed = true; }),
  };
  const forks = { assertSafeImpactExecutionEndpoint: vi.fn(async (candidate: ImpactForkHandle) => {
    if (!currentHandle || candidate.token !== currentHandle.token || currentSession.status !== "ready") throw Error("impact_execution_endpoint_unsafe");
    return currentSession;
  }) } as unknown as ImpactForkService;
  const service = new ImpactPoCRuntimeService(forks, () => currentHandle, imageId, driver);
  return { service, driver, setHandle: (next: ImpactForkHandle | undefined) => { currentHandle = next; },
    setStatus: (status: ImpactForkSession["status"]) => { currentSession = { ...currentSession, status }; },
    setUnsafe: (value: boolean) => { unsafe = value; } };
}

describe.skipIf(process.env.CONTRACTHUNTER_LOOPBACK_TEST !== "1")("Impact PoC runtime foundation", () => {
  it("accepts only a guarded ready session ID and fixed trusted image, then cleans up idempotently", async () => {
    const f = fixture();
    for (const extra of [{ rpcUrl: "https://provider.example" }, { image: "attacker:latest" },
      { command: ["/bin/sh"] }, { argv: ["--network", "host"] }, { environment: { PRIVATE_KEY: "secret" } }])
      await expect(f.service.create({ sessionId, ...extra })).rejects.toBeInstanceOf(Error);
    const view = await f.service.create({ sessionId });
    expect(view).toMatchObject({ sessionId, status: "ready", imageId, runtimeSchema: "v1" });
    expect((await f.service.inspect(view.id)).status).toBe("ready");
    expect(f.driver.verifyImage).toHaveBeenCalledTimes(1);
    expect(f.driver.removeStale).toHaveBeenCalledTimes(1);
    await f.service.stopForSession(sessionId);
    expect(f.service.get(view.id)?.status).toBe("stopped");
    expect((await f.service.destroy(view.id)).status).toBe("stopped");
    expect(f.driver.remove).toHaveBeenCalledTimes(1);
  });

  it("rejects stopped and stale-token sessions and unsafe container attachments", async () => {
    const stopped = fixture(); stopped.setStatus("stopped");
    await expect(stopped.service.create({ sessionId })).rejects.toThrow("impact_execution_endpoint_unsafe");
    const f = fixture(); const view = await f.service.create({ sessionId });
    f.setHandle({ id: sessionId, token: "replacement" });
    await expect(f.service.inspect(view.id)).rejects.toThrow("impact_runtime_stale");
    f.setHandle(handle);
    f.setUnsafe(true);
    await expect(f.service.inspect(view.id)).rejects.toThrow("impact_container_unsafe");
    await f.service.destroy(view.id);
  });

  it("fails closed and removes a container whose live security settings are wrong", async () => {
    const f = fixture(); f.setUnsafe(true);
    await expect(f.service.create({ sessionId })).rejects.toThrow("impact_container_unsafe");
    expect(f.driver.remove).toHaveBeenCalledTimes(1);
  });
});
