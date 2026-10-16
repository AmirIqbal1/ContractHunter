import { randomUUID } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { configuredImpactRpcs, createImpactSession, publicImpactSession } from "./impact-lab";

afterEach(() => vi.unstubAllEnvs());
const request = () => ({ findingId: randomUUID(), rpcConfigId: "base-test", forkBlock: 100, targetContracts: [`0x${"1".repeat(40)}`] });

describe("Impact Lab configured RPC boundary", () => {
  it("rejects raw upstream URLs, execution URLs, and unknown IDs before creating a session", async () => {
    vi.stubEnv("IMPACT_RPC_CONFIGS", JSON.stringify([{ id: "base-test", chainId: 8453, network: "base", upstreamUrlSecretRef: "IMPACT_RPC_BASE_TEST", enabled: true }]));
    vi.stubEnv("IMPACT_RPC_BASE_TEST", "https://provider.example/private-token");
    for (const extra of [{ upstreamUrl: "https://evil.example" }, { localRpcUrl: "http://127.0.0.1:1234" },
      { anvilExecutable: "/bin/sh" }, { argv: ["--foo"] }, { privateKey: "secret" }])
      await expect(createImpactSession({ ...request(), ...extra })).rejects.toBeInstanceOf(Error);
    await expect(createImpactSession({ ...request(), rpcConfigId: "unknown" })).rejects.toThrow("impact_rpc_configuration_unavailable");
    expect(configuredImpactRpcs()).toHaveLength(1);
  });

  it("requires unique bounded server configurations and omits secret references from public sessions", () => {
    const config = { id: "base-test", chainId: 8453, network: "base", upstreamUrlSecretRef: "IMPACT_RPC_BASE_TEST", enabled: true };
    vi.stubEnv("IMPACT_RPC_CONFIGS", JSON.stringify([config, config]));
    expect(() => configuredImpactRpcs()).toThrow("impact_rpc_configuration_invalid");
    const publicView = publicImpactSession({ id: randomUUID(), status: "ready", findingId: randomUUID(), hypothesisId: null,
      chainId: 8453, network: "base", rpcConfigId: "base-test", upstreamRpcRef: "IMPACT_RPC_BASE_TEST",
      targetContracts: [`0x${"1".repeat(40)}`], targetCodeHashes: { [`0x${"1".repeat(40)}`]: `sha256:${"a".repeat(64)}` },
      resolvedForkBlock: 100, historicalTransactionHash: null, forkBlockHash: `0x${"b".repeat(64)}`,
      localPort: 49001, localRpcEndpoint: "http://127.0.0.1:49001", anvilVersion: "anvil 1.7.1", anvilSha256: "c".repeat(64),
      processPid: 123, baselineSnapshotId: "0x1", disposableAccounts: [], createdAt: 1, startedAt: 2, stoppedAt: null, failureCode: null });
    expect(JSON.stringify(publicView)).not.toContain("IMPACT_RPC_BASE_TEST");
    expect(JSON.stringify(publicView)).not.toContain("localRpcEndpoint");
    expect(publicView.targetContracts[0]?.codeHash).toMatch(/^sha256:/);
  });
});
