import { createHash, randomUUID } from "node:crypto";
import { cp, mkdtemp, mkdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { canonicalInvariantPlan, executableInvariantExecutionManifestSchema, executableInvariantPlanSchema, invariantPlanHash, INVARIANT_HARNESS_MANIFEST, type ExecutableInvariantPlan } from "@contracthunter/core";
import { ExecutableInvariantGenerator } from "./executable-invariant-generator";
import { VerificationWorkspaceBuilder } from "./verification-workspace-builder";
import { createContractHunterInvariantFoundryConfig } from "./verification-foundry-config";

const scanId = "11111111-1111-4111-8111-111111111111";
const hypothesisId = "22222222-2222-4222-8222-222222222222";
const commit = "a".repeat(40);
const fixtureRoot = path.resolve("packages/scanners/fixtures/invariants");
const source = (name: string) => `contracts/${name}.sol`;
const accountingProperty = {
  name: "accounting", observations: [
    { kind: "read-uint", instanceName: "target", functionName: "totalRecordedBalance", resultName: "recorded" },
    { kind: "read-balance", target: { kind: "instance", name: "target" }, resultName: "nativeBalance" },
  ], assertions: [{ id: "conservation", kind: "uint-eq", actual: "recorded", expected: { kind: "result", name: "nativeBalance" } }],
};
function fuzz(contractName = "VulnerableAccounting"): Extract<ExecutableInvariantPlan, { mode: "fuzz-property" }> {
  return executableInvariantPlanSchema.parse({ schemaVersion: "contracthunter-invariant-plan-v1", mode: "fuzz-property", scanId, hypothesisId, resolvedCommit: commit, compilerVersion: "0.8.24",
    primaryContract: contractName, primarySourcePath: source(contractName), sourceFiles: [source(contractName)], actors: ["deployer", "attacker"],
    setup: [{ kind: "deploy", contractName, instanceName: "target" }], property: accountingProperty,
    fuzzAction: { instanceName: "target", functionName: "record", caller: "attacker", parameters: [{ name: "amount", type: "uint256" }], args: [{ kind: "parameter", name: "amount" }] },
  }) as Extract<ExecutableInvariantPlan, { mode: "fuzz-property" }>;
}
function stateful(): Extract<ExecutableInvariantPlan, { mode: "stateful-invariant" }> {
  return executableInvariantPlanSchema.parse({ schemaVersion: "contracthunter-invariant-plan-v1", mode: "stateful-invariant", scanId, hypothesisId, resolvedCommit: commit, compilerVersion: "0.8.24",
    primaryContract: "StatefulAccessControl", primarySourcePath: source("StatefulAccessControl"), sourceFiles: [source("StatefulAccessControl")], actors: ["deployer", "attacker"],
    setup: [{ kind: "deploy", contractName: "StatefulAccessControl", instanceName: "target" }],
    handlerActions: [
      { name: "takeOwnership", instanceName: "target", functionName: "transferOwnership", caller: "attacker", parameters: [], args: [{ kind: "address", source: "actor", name: "attacker" }] },
      { name: "touch", instanceName: "target", functionName: "touch", caller: "attacker", parameters: [{ name: "flag", type: "bool" }], args: [{ kind: "parameter", name: "flag" }] },
    ], properties: [{ name: "ownerStable", observations: [{ kind: "read-address", instanceName: "target", functionName: "owner", resultName: "observedOwner" }],
      assertions: [{ id: "owner", kind: "address-eq", actual: "observedOwner", expected: { kind: "address", source: "actor", name: "deployer" } }] }],
  }) as Extract<ExecutableInvariantPlan, { mode: "stateful-invariant" }>;
}
const clone = (value: unknown): Record<string, unknown> => JSON.parse(JSON.stringify(value)) as Record<string, unknown>;
const parse = (value: unknown) => executableInvariantPlanSchema.safeParse(value).success;
async function sourceMap(plan: ExecutableInvariantPlan) { return new Map([[plan.primarySourcePath, await readFile(path.join(fixtureRoot, plan.primarySourcePath), "utf8")]]); }

describe("executable invariant plan boundaries", () => {
  it("accepts both explicit modes and preserves authoritative identity", () => {
    for (const plan of [fuzz(), stateful()]) { expect(parse(plan)).toBe(true); expect(plan.scanId).toBe(scanId); expect(plan.hypothesisId).toBe(hypothesisId); expect(plan.compilerVersion).toBe("0.8.24"); }
  });
  it("rejects invalid mode, unknown fields, and arbitrary source/config/cheatcodes", () => {
    for (const field of [{ mode: "script" }, { solidity: "vm.ffi()" }, { foundry: { ffi: true } }, { importPath: "forge-std/Test.sol" }, { seed: "random" }]) expect(parse({ ...fuzz(), ...field })).toBe(false);
    for (const functionName of ["ffi", "createFork", "selectFork", "broadcast", "startBroadcast", "envString", "readFile", "writeFile", "rpc"]) expect(parse({ ...fuzz(), fuzzAction: { ...fuzz().fuzzAction, functionName } })).toBe(false);
  });
  it("rejects unsupported fuzz types and raw address parameters", () => {
    for (const type of ["address", "bytes", "bytes32", "string", "uint8", "uint256[]", "(uint256,bool)", "function"]) {
      const plan = clone(fuzz()); const action = plan.fuzzAction as Record<string, unknown>; action.parameters = [{ name: "amount", type }]; expect(parse(plan)).toBe(false);
    }
  });
  it("bounds all major collections", () => {
    const plan = fuzz();
    expect(parse({ ...plan, actors: Array.from({ length: 9 }, (_, i) => `person${i}`) })).toBe(false);
    expect(parse({ ...plan, setup: Array.from({ length: 33 }, () => plan.setup[0]) })).toBe(false);
    const selected = stateful(); if (selected.mode !== "stateful-invariant") throw new Error("unexpected mode");
    expect(parse({ ...selected, handlerActions: Array.from({ length: 17 }, (_, i) => ({ ...selected.handlerActions[0], name: `handler${i}` })) })).toBe(false);
    expect(parse({ ...selected, handlerActions: [{ ...selected.handlerActions[1], parameters: Array.from({ length: 9 }, (_, i) => ({ name: `p${i}`, type: "bool" })), args: Array.from({ length: 9 }, (_, i) => ({ kind: "parameter", name: `p${i}` })) }] })).toBe(false);
    expect(parse({ ...selected, properties: Array.from({ length: 17 }, (_, i) => ({ ...selected.properties[0], name: `property${i}` })) })).toBe(false);
    expect(parse({ ...selected, properties: [{ ...selected.properties[0], observations: Array.from({ length: 17 }, (_, i) => ({ kind: "read-address", instanceName: "target", functionName: "owner", resultName: `result${i}` })) }] })).toBe(false);
    expect(parse({ ...selected, properties: [{ ...selected.properties[0], assertions: Array.from({ length: 17 }, (_, i) => ({ ...selected.properties[0].assertions[0], id: `assert${i}` })) }] })).toBe(false);
  });
  it("rejects duplicates, unsafe identifiers, and invalid symbolic references", () => {
    const plan = fuzz();
    expect(parse({ ...plan, actors: ["attacker", "attacker"] })).toBe(false);
    expect(parse({ ...plan, actors: ["address"] })).toBe(false);
    expect(parse({ ...plan, property: { ...plan.property, name: "x; vm.ffi()" } })).toBe(false);
    expect(parse({ ...plan, fuzzAction: { ...plan.fuzzAction, caller: "unknown" } })).toBe(false);
    expect(parse({ ...plan, fuzzAction: { ...plan.fuzzAction, args: [{ kind: "parameter", name: "amount" }, { kind: "parameter", name: "amount" }] } })).toBe(false);
    expect(parse({ ...plan, setup: [...plan.setup, plan.setup[0]] })).toBe(false);
    expect(parse({ ...plan, fuzzAction: { ...plan.fuzzAction, parameters: [{ name: "target", type: "uint256" }], args: [{ kind: "parameter", name: "target" }] } })).toBe(false);
    expect(parse({ ...plan, fuzzAction: { ...plan.fuzzAction, parameters: [{ name: "recorded", type: "uint256" }], args: [{ kind: "parameter", name: "recorded" }] } })).toBe(false);
    expect(parse({ ...plan, fuzzAction: { ...plan.fuzzAction, parameters: [], args: [] } })).toBe(false);
    expect(parse({ ...plan, setup: [...plan.setup, { kind: "fund", target: { kind: "instance", name: "target" }, amountWei: "100000000000000000000" }, { kind: "fund", target: { kind: "instance", name: "target" }, amountWei: "1" }] })).toBe(false);
  });
  it("canonicalizes object key order and hashes plan identity without runtime values", () => {
    const plan = fuzz(); const reordered = { mode: plan.mode, ...clone(plan) } as ExecutableInvariantPlan;
    expect(canonicalInvariantPlan(plan)).toBe(canonicalInvariantPlan(reordered)); expect(invariantPlanHash(plan)).toBe(invariantPlanHash(reordered));
    expect(invariantPlanHash({ ...plan, resolvedCommit: "b".repeat(40) })).not.toBe(invariantPlanHash(plan));
    expect(invariantPlanHash(plan)).toMatch(/^[a-f0-9]{64}$/);
    expect(parse({ ...plan, setup: [...plan.setup, { kind: "fund", target: { kind: "instance", name: "target" }, amountWei: "01" }] })).toBe(false);
  });
});

describe("deterministic invariant harnesses", () => {
  it("renders a typed fuzz call with symbolic caller, reads, and equality assertion", async () => {
    const plan = fuzz(), files = await sourceMap(plan); const first = new ExecutableInvariantGenerator().generate(plan, files); const second = new ExecutableInvariantGenerator().generate(plan, files);
    expect(first).toEqual(second); expect(first.source).toContain("function testFuzz_accounting(uint256 amount) public");
    expect(first.source).toContain("vm.prank(actor_attacker);"); expect(first.source).toContain("target.record(amount);");
    expect(first.source).toContain("uint256 recorded = target.totalRecordedBalance();"); expect(first.source).toContain("uint256 nativeBalance = address(target).balance;");
    expect(first.source).toContain('require(recorded == nativeBalance, "CH_ASSERT_0");');
    expect(first.foundryConfig).toBe(createContractHunterInvariantFoundryConfig("0.8.24", first.planHash));
    expect(first.foundryConfig).toContain(`seed = "0x${first.planHash}"`);
  });
  it("renders a named stateful handler, target registration, and current-state invariant", async () => {
    const plan = stateful(), result = new ExecutableInvariantGenerator().generate(plan, await sourceMap(plan));
    expect(result.source).toContain("contract ContractHunterHandler is ContractHunterCheats");
    expect(result.source).toContain("function action_takeOwnership() external");
    expect(result.source).toContain("target.transferOwnership(actor_attacker);");
    expect(result.source).toContain("function action_touch(bool flag) external");
    expect(result.source).toContain("targetContract(address(handler));");
    expect(result.source).toContain("function targetContracts() public view returns (address[] memory)");
    expect(result.source).toContain("function invariant_ownerStable() public view");
    expect(result.source).toContain("target.owner();");
  });
  it("supports boolean fuzz values and uint256 stateful handler values", async () => {
    const statefulBase = clone(stateful());
    delete statefulBase.handlerActions; delete statefulBase.properties;
    const boolPlan = executableInvariantPlanSchema.parse({ ...statefulBase, mode: "fuzz-property",
      property: stateful().properties[0], fuzzAction: { instanceName: "target", functionName: "touch", caller: "attacker", parameters: [{ name: "flag", type: "bool" }], args: [{ kind: "parameter", name: "flag" }] } });
    const boolOutput = new ExecutableInvariantGenerator().generate(boolPlan, await sourceMap(boolPlan));
    expect(boolOutput.source).toContain("function testFuzz_ownerStable(bool flag) public");
    const base = stateful();
    const accounting = executableInvariantPlanSchema.parse({ ...base, primaryContract: "SafeAccounting", primarySourcePath: source("SafeAccounting"), sourceFiles: [source("SafeAccounting")],
      setup: [{ kind: "deploy", contractName: "SafeAccounting", instanceName: "target" }], handlerActions: [{ name: "record", instanceName: "target", functionName: "record", caller: "attacker", parameters: [{ name: "amount", type: "uint256" }], args: [{ kind: "parameter", name: "amount" }] }], properties: [accountingProperty] });
    const output = new ExecutableInvariantGenerator().generate(accounting, await sourceMap(accounting));
    expect(output.source).toContain("function action_record(uint256 amount) external");
    expect(output.source).toContain("target.record(amount);");
  });
  it("uses safe accounting control with the same property", async () => {
    const plan = fuzz("SafeAccounting"), output = new ExecutableInvariantGenerator().generate(plan, await sourceMap(plan));
    expect(output.source).toContain("SafeAccounting target = new SafeAccounting();");
    expect(output.source).toContain("require(recorded == nativeBalance");
  });
  it("keeps forbidden primitives out of generated Solidity", async () => {
    for (const plan of [fuzz(), stateful()]) {
      const source = new ExecutableInvariantGenerator().generate(plan, await sourceMap(plan)).source;
      expect(source).not.toMatch(/\b(?:ffi|createFork|selectFork|broadcast|startBroadcast|envString|readFile|writeFile|http|https|rpc)\b/i);
      expect(source).not.toContain("forge-std");
    }
  });
  it("rejects missing or mismatched functions, getters, signatures, and unrelated contracts", async () => {
    const plan = fuzz(), files = await sourceMap(plan); const generator = new ExecutableInvariantGenerator();
    expect(() => generator.generate({ ...plan, fuzzAction: { ...plan.fuzzAction, functionName: "missing" } }, files)).toThrow("function_not_found");
    expect(() => generator.generate({ ...plan, fuzzAction: { ...plan.fuzzAction, args: [{ kind: "parameter", name: "flag" }], parameters: [{ name: "flag", type: "bool" }] } }, files)).toThrow("argument_shape_mismatch");
    const wrongGetter = clone(plan); const property = wrongGetter.property as Record<string, unknown>; property.observations = [{ kind: "read-address", instanceName: "target", functionName: "totalRecordedBalance", resultName: "recorded" }, { kind: "read-balance", target: { kind: "instance", name: "target" }, resultName: "nativeBalance" }]; property.assertions = [{ id: "addressCheck", kind: "address-eq", actual: "recorded", expected: { kind: "address", source: "actor", name: "attacker" } }];
    expect(() => generator.generate(wrongGetter as ExecutableInvariantPlan, files)).toThrow("unsupported_return_type");
    const other = new Map([[plan.primarySourcePath, "pragma solidity 0.8.24; contract VulnerableAccounting {} contract Other { function record(uint256) external {} uint256 public totalRecordedBalance; }"]]);
    expect(() => generator.generate(plan, other)).toThrow("function_not_found");
    const overload = new Map([[plan.primarySourcePath, "pragma solidity 0.8.24; contract VulnerableAccounting { uint256 public totalRecordedBalance; function record(uint256) external {} function record(uint256,bool) external {} function record(uint256) public {} }"]]);
    expect(() => generator.generate(plan, overload)).toThrow("ambiguous_function_signature");
    const privateCall = new Map([[plan.primarySourcePath, "pragma solidity 0.8.24; contract VulnerableAccounting { uint256 public totalRecordedBalance; function record(uint256) internal {} }"]]);
    expect(() => generator.generate(plan, privateCall)).toThrow("function_not_public");
    const mutatingGetter = new Map([[plan.primarySourcePath, "pragma solidity 0.8.24; contract VulnerableAccounting { function record(uint256) external {} function totalRecordedBalance() external returns(uint256) { return 0; } }"]]);
    expect(() => generator.generate(plan, mutatingGetter)).toThrow("getter_not_read_only");
  });
});

let base: string, repositoryRoot: string, repository: string;
beforeEach(async () => { base = await mkdtemp(path.join(tmpdir(), "ch-invariant-")); repositoryRoot = path.join(base, "repos"); repository = path.join(repositoryRoot, "scan"); await mkdir(repositoryRoot); await cp(fixtureRoot, repository, { recursive: true }); });
afterEach(async () => { await rm(base, { recursive: true, force: true }); });
const sha = (text: string) => createHash("sha256").update(text).digest("hex");
function builder(root: string) { return new VerificationWorkspaceBuilder({ verificationRoot: root, repositoryRoot, acceptedCompilerVersions: ["0.8.24"], approvedSourceRoots: ["contracts"], generatorVersion: "0.2.0" }); }

describe("invariant workspace manifest", () => {
  it("writes byte-identical controlled workspaces for repeated input", async () => {
    const id = randomUUID(), plan = stateful();
    const first = await builder(path.join(base, "workspaces-a")).buildInvariant({ workspaceId: id, repositoryPath: repository, plan });
    const second = await builder(path.join(base, "workspaces-b")).buildInvariant({ workspaceId: id, repositoryPath: repository, plan });
    expect(first.manifest).toEqual(second.manifest); expect(first.harnessSource).toBe(second.harnessSource);
    for (const file of [INVARIANT_HARNESS_MANIFEST, "foundry.toml", first.manifest.generatedHarnessPath]) expect(await readFile(path.join(first.workspacePath, file))).toEqual(await readFile(path.join(second.workspacePath, file)));
    expect(executableInvariantExecutionManifestSchema.parse(first.manifest)).toEqual(first.manifest);
    expect(first.manifest.planKind).toBe("executable-invariant"); expect(first.manifest.mode).toBe("stateful-invariant"); expect(first.manifest.planHash).toBe(invariantPlanHash(plan));
    expect(first.manifest.generatedHarnessSha256).toBe(sha(first.harnessSource));
    expect(first.manifest.foundryConfigSha256).toBe(sha(await readFile(path.join(first.workspacePath, "foundry.toml"), "utf8")));
    expect(first.manifest.foundry.seed).toBe(`0x${first.manifest.planHash}`);
    expect(first.manifest.sourceManifest).toHaveLength(1);
    expect(first.manifest.contentFingerprint).toMatch(/^[a-f0-9]{64}$/);
    expect(executableInvariantExecutionManifestSchema.safeParse({ ...first.manifest, planHash: "b".repeat(64) }).success).toBe(false);
    expect(executableInvariantExecutionManifestSchema.safeParse({ ...first.manifest, foundry: { ...first.manifest.foundry, seed: `0x${"b".repeat(64)}` } }).success).toBe(false);
  });
  it("rejects manifest extensions and repository-controlled config", async () => {
    const result = await builder(path.join(base, "workspaces")).buildInvariant({ workspaceId: randomUUID(), repositoryPath: repository, plan: fuzz() });
    expect(executableInvariantExecutionManifestSchema.safeParse({ ...result.manifest, command: "forge test" }).success).toBe(false);
    const config = await readFile(path.join(result.workspacePath, "foundry.toml"), "utf8");
    expect(config).toContain("offline = true"); expect(config).toContain("auto_detect_solc = false"); expect(config).toContain("ffi = false");
    expect(config).toContain("runs = 128"); expect(config).toContain("depth = 32"); expect(config).not.toMatch(/rpc_endpoints|fork|http/i);
  });
});
