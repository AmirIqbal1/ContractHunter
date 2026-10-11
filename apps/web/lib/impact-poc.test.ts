import { describe, expect, it } from "vitest";
import { impactPoCCreateSchema, impactPoCExecutionSchema, impactPoCSourceHash } from "@contracthunter/core";
import { validateImpactLocalCalls } from "./impact-poc";

const findingId = "00000000-0000-4000-8000-000000000001";
const sender = `0x${"1".repeat(40)}`;
const source = "pragma solidity 0.8.36; contract ImpactPoC { function run() external {} }";
const create = (overrides: Record<string, unknown> = {}) => ({ findingId,
  filename: "ImpactPoC.s.sol", source, entryContract: "ImpactPoC", ...overrides });
const call = (method: string, params?: unknown[], id: string | number = 1) =>
  ({ jsonrpc: "2.0", id, method, ...(params === undefined ? {} : { params }) });
const validate = (value: unknown, remaining = 4) =>
  validateImpactLocalCalls(Buffer.from(JSON.stringify(value)), sender, remaining);

describe("manual Impact PoC admission", () => {
  it("requires an exact reviewed source identity and excludes browser-controlled execution fields", () => {
    expect(impactPoCSourceHash(source)).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(impactPoCCreateSchema.parse(create()).source).toBe(source);
    for (const extra of [{ rpcUrl: "http://127.0.0.1" }, { command: "sh" }, { image: "other" },
      { privateKey: "fake" }, { filename: "../escape.sol" }, { filename: "/tmp/x.sol" },
      { filename: "ImpactPoC.s.sol/../escape.sol" }, { source: "pragma solidity 0.8.36; import 'x.sol';" },
      { source: "pragma solidity 0.8.36;\u0000" }]) expect(impactPoCCreateSchema.safeParse(create(extra)).success).toBe(false);
    expect(impactPoCExecutionSchema.safeParse({ pocArtifactId: findingId, rpcUrl: "http://127.0.0.1" }).success).toBe(false);
    expect(impactPoCExecutionSchema.safeParse({ pocArtifactId: findingId, forgeFlags: ["--ffi"] }).success).toBe(false);
  });

  it("accepts only bounded, disposable-sender local RPC and rejects admin, raw transaction and mixed batches", () => {
    expect(validate(call("eth_chainId")).count).toBe(0); // JSON-RPC params are optional.
    expect(validate(call("eth_sendTransaction", [{ from: sender, to: sender, value: "0x1" }])).count).toBe(1);
    for (const method of ["eth_sendRawTransaction", "anvil_setBalance", "evm_snapshot", "hardhat_impersonateAccount",
      "eth_sign", "personal_sign", "wallet_sendCalls", "debug_traceTransaction"])
      expect(() => validate(call(method, []))).toThrow("impact_local_rpc_rejected");
    expect(() => validate([call("eth_chainId"), call("eth_sendRawTransaction", ["0x00"])]))
      .toThrow("impact_local_rpc_rejected");
    expect(() => validate(call("eth_sendTransaction", [{ from: `0x${"2".repeat(40)}` }])))
      .toThrow("impact_local_sender_rejected");
    expect(() => validate(call("eth_sendTransaction", [{ from: sender }]), 0)).toThrow("impact_local_transaction_limit");
    expect(() => validate({ jsonrpc: "1.0", id: 1, method: "eth_chainId" })).toThrow("impact_local_rpc_rejected");
  });
});
