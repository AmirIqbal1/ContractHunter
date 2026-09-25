import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { executableInvariantPlanSchema, INVARIANT_HARNESS_MANIFEST, type ExecutableInvariantPlan } from "@contracthunter/core";
import { executeInvariant, isolationPreflight } from "../../../docker/verification-worker";
import { parseInvariantForgeJson, parseTrustedInvariantForgeResult, interpretInvariantFacts } from "./executable-invariant-result";
import { validateExecutableInvariantWorkspaceIntegrity } from "./executable-invariant-workspace-integrity";
import { ExecutableInvariantWorkerClient } from "./verification-worker-client";
import { executableInvariantWorkerRequestSchema, INVARIANT_MAX_OUTPUT_BYTES, INVARIANT_TIMEOUT_MS, workerRequestSchema } from "./verification-worker-protocol";
import { VerificationWorkspaceBuilder } from "./verification-workspace-builder";

const scanId = "11111111-1111-4111-8111-111111111111";
const hypothesisId = "22222222-2222-4222-8222-222222222222";
const runId = "33333333-3333-4333-8333-333333333333";
const resolvedCommit = "a".repeat(40);
const fixtureRoot = path.resolve("packages/scanners/fixtures/invariants");
const property = { name: "accounting", observations: [{ kind: "read-uint", instanceName: "target", functionName: "totalRecordedBalance", resultName: "recorded" }, { kind: "read-balance", target: { kind: "instance", name: "target" }, resultName: "nativeBalance" }], assertions: [{ id: "conservation", kind: "uint-eq", actual: "recorded", expected: { kind: "result", name: "nativeBalance" } }] };
const common = { schemaVersion: "contracthunter-invariant-plan-v1", scanId, hypothesisId, resolvedCommit, compilerVersion: "0.8.36", actors: ["deployer", "attacker"] };
function fuzz(): ExecutableInvariantPlan { return executableInvariantPlanSchema.parse({ ...common, mode: "fuzz-property", primaryContract: "VulnerableAccounting", primarySourcePath: "contracts/VulnerableAccounting.sol", sourceFiles: ["contracts/VulnerableAccounting.sol"], setup: [{ kind: "deploy", contractName: "VulnerableAccounting", instanceName: "target" }], property, fuzzAction: { instanceName: "target", functionName: "record", caller: "attacker", parameters: [{ name: "amount", type: "uint256" }], args: [{ kind: "parameter", name: "amount" }] } }); }
function stateful(): ExecutableInvariantPlan { return executableInvariantPlanSchema.parse({ ...common, mode: "stateful-invariant", primaryContract: "StatefulAccessControl", primarySourcePath: "contracts/StatefulAccessControl.sol", sourceFiles: ["contracts/StatefulAccessControl.sol"], setup: [{ kind: "deploy", contractName: "StatefulAccessControl", instanceName: "target" }], handlerActions: [{ name: "touch", instanceName: "target", functionName: "touch", caller: "attacker", parameters: [{ name: "flag", type: "bool" }], args: [{ kind: "parameter", name: "flag" }] }, { name: "takeOwnership", instanceName: "target", functionName: "transferOwnership", caller: "attacker", parameters: [], args: [{ kind: "address", source: "actor", name: "attacker" }] }], properties: [{ name: "ownerStable", observations: [{ kind: "read-address", instanceName: "target", functionName: "owner", resultName: "observedOwner" }], assertions: [{ id: "owner", kind: "address-eq", actual: "observedOwner", expected: { kind: "address", source: "actor", name: "deployer" } }] }] }); }
const request = { command: "execute-invariant", runId, workspaceId: runId, scanId, hypothesisId, resolvedCommit, compilerVersion: "0.8.36", planHash: "b".repeat(64), mode: "fuzz-property", timeoutMs: INVARIANT_TIMEOUT_MS, maxOutputBytes: INVARIANT_MAX_OUTPUT_BYTES };
const forgeJson = (contract: string, test: string, status: "Success" | "Failure", kind: "Fuzz" | "Invariant", runs: number, counterexample: unknown = null) => JSON.stringify({ [`test/ContractHunterInvariant.t.sol:${contract}`]: { test_results: { [test]: { status, reason: status === "Failure" ? "CH_ASSERT_0" : null, kind: { [kind]: { runs } }, counterexample } } } });

describe("bounded invariant worker protocol", () => {
  it("accepts only explicit invariant jobs and rejects commands, paths, flags, and loose resource limits", () => {
    expect(executableInvariantWorkerRequestSchema.safeParse(request).success).toBe(true);
    expect(workerRequestSchema.safeParse(request).success).toBe(true);
    for (const change of [{ command: "forge" }, { runId: scanId }, { workspaceId: "../outside" }, { workspaceId: "/verification/other" }, { mode: "script" }, { planHash: "bad" }, { compilerVersion: "../solc" }, { resolvedCommit: "main" }, { timeoutMs: 0 }, { timeoutMs: 1_000_000 }, { maxOutputBytes: 100_000_000 }, { executable: "/bin/sh" }, { forgeArgs: ["--ffi"] }, { matchTest: "anything" }, { env: { RPC_URL: "secret" } }]) expect(executableInvariantWorkerRequestSchema.safeParse({ ...request, ...change }).success).toBe(false);
  });
  it("has no web Forge fallback when socket, workspace, or worker isolation is unavailable", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "ch-invariant-socket-"));
    try {
      await mkdir(path.join(root, runId));
      const client = new ExecutableInvariantWorkerClient(root, path.join(root, "missing.sock"));
      const input = { workspacePath: path.join(root, runId), scanId, hypothesisId, resolvedCommit, compilerVersion: "0.8.36", planHash: request.planHash, mode: "fuzz-property" as const };
      expect(await client.run(input)).toMatchObject({ status: "refused", errorCode: "invariant_worker_unavailable", isolation: null });
      expect(await client.run({ ...input, workspacePath: path.dirname(root) })).toMatchObject({ status: "refused", errorCode: "invariant_workspace_invalid" });
      await expect(isolationPreflight()).rejects.toThrow("worker identity is unavailable");
      await expect(executeInvariant(executableInvariantWorkerRequestSchema.parse(request))).rejects.toThrow("worker identity is unavailable");
    } finally { await rm(root, { recursive: true, force: true }); }
  });
});

describe("pinned Forge 1.7.1 JSON interpretation", () => {
  it("classifies a complete fuzz pass as bounded support", () => {
    const plan = fuzz(), parsed = parseInvariantForgeJson(forgeJson("ContractHunterFuzzTest", "testFuzz_accounting(uint256)", "Success", "Fuzz", 128), plan);
    expect(parsed).toMatchObject({ testCount: 1, passedCount: 1, failedCount: 0, runsExecuted: 128 });
    expect(interpretInvariantFacts(plan, parsed!, "docker-verification-worker-v1")).toMatchObject([{ propertyOutcome: "held-within-bounds", hypothesisRelation: "neutral", configuredRuns: 128, configuredDepth: null }]);
  });
  it("extracts bounded fuzz counterexamples without treating the Forge failure as an infrastructure failure", () => {
    const plan = fuzz(), parsed = parseInvariantForgeJson(forgeJson("ContractHunterFuzzTest", "testFuzz_accounting(uint256)", "Failure", "Fuzz", 0, { Single: { args: "436", calldata: "0x1234" } }), plan);
    expect(parsed?.tests[0]).toMatchObject({ status: "failed", reason: "CH_ASSERT_0", counterexample: { kind: "single", parameterValues: [{ name: "amount", value: "436" }] } });
    expect(interpretInvariantFacts(plan, parsed!, "docker-verification-worker-v1")).toMatchObject([{ propertyOutcome: "counterexample-found", hypothesisRelation: "unreviewed" }]);
  });
  it("parses stateful pass and a bounded failing handler sequence", () => {
    const plan = stateful();
    const passed = parseInvariantForgeJson(forgeJson("ContractHunterInvariantTest", "invariant_ownerStable()", "Success", "Invariant", 64), plan);
    expect(interpretInvariantFacts(plan, passed!, "docker-verification-worker-v1")).toMatchObject([{ configuredRuns: 64, configuredDepth: 32, hypothesisRelation: "neutral" }]);
    const failed = parseInvariantForgeJson(forgeJson("ContractHunterInvariantTest", "invariant_ownerStable()", "Failure", "Invariant", 0, { Sequence: [1, [{ contract_name: "test/ContractHunterInvariant.t.sol:ContractHunterHandler", signature: "action_takeOwnership()", args: "" }]] }), plan);
    expect(failed?.tests[0].counterexample).toMatchObject({ kind: "sequence", actions: [{ actionName: "takeOwnership" }] });
    expect(interpretInvariantFacts(plan, failed!, "docker-verification-worker-v1")).toMatchObject([{ hypothesisRelation: "unreviewed" }]);
  });
  it("fails closed on unrelated, incomplete, malformed, or oversized Forge output", () => {
    const plan = fuzz();
    expect(parseInvariantForgeJson("not-json", plan)).toBeNull();
    expect(parseInvariantForgeJson("x".repeat(INVARIANT_MAX_OUTPUT_BYTES + 1), plan)).toBeNull();
    expect(parseInvariantForgeJson(forgeJson("OtherTest", "testFuzz_accounting(uint256)", "Success", "Fuzz", 128), plan)).toBeNull();
    expect(parseInvariantForgeJson(forgeJson("ContractHunterFuzzTest", "testFuzz_accounting(uint256)", "Failure", "Fuzz", 0), plan)).toBeNull();
    expect(parseInvariantForgeJson(forgeJson("ContractHunterInvariantTest", "invariant_ownerStable()", "Failure", "Invariant", 0, { Sequence: [1, [{ contract_name: "test/ContractHunterInvariant.t.sol:ContractHunterHandler", signature: "action_arbitrary()" }]] }), stateful())).toBeNull();
    expect(() => interpretInvariantFacts(plan, { testCount: 1, passedCount: 1, failedCount: 0, runsExecuted: 129, tests: [{ propertyName: "accounting", testName: "testFuzz_accounting(uint256)", status: "passed", runsExecuted: 129, reason: null, counterexample: null }] }, "worker")).toThrow("invariant_result_unparseable");
  });
  it("fails closed for every malformed pinned Forge result shape and process inconsistency", () => {
    const plan = fuzz(), suite = "test/ContractHunterInvariant.t.sol:ContractHunterFuzzTest", validPass = forgeJson("ContractHunterFuzzTest", "testFuzz_accounting(uint256)", "Success", "Fuzz", 128);
    const result = (changes: Record<string, unknown>) => JSON.stringify({ [suite]: { test_results: changes } });
    const pass = { status: "Success", reason: null, kind: { Fuzz: { runs: 128 } }, counterexample: null };
    const failure = (counterexample: unknown, reason = "CH_ASSERT_0") => ({ status: "Failure", reason, kind: { Fuzz: { runs: 1 } }, counterexample });
    const single = { Single: { args: "436", calldata: "0x1234" } };
    for (const malformed of [
      result({}),
      result({ "testFuzz_accounting(uint256)": pass, "testFuzz_accounting(bool)": pass }),
      "{\"truncated\":",
      result({ "testFuzz_accounting(uint256)": failure({ Single: {} }) }),
      result({ "testFuzz_accounting(uint256)": failure({ Single: { args: "-1" } }) }),
      result({ "testFuzz_accounting(uint256)": failure({ Single: { args: (1n << 256n).toString() } }) }),
      result({ "testFuzz_accounting(uint256)": failure(single, "unexpected revert") }),
      result({ "testFuzz_accounting(uint256)": { ...pass, counterexample: single } }),
      result({ "testFuzz_accounting(uint256)": pass, "testUnexpected()": pass }),
    ]) expect(parseInvariantForgeJson(malformed, plan)).toBeNull();
    expect(parseTrustedInvariantForgeResult(validPass, plan, 1, false)).toBeNull();
    expect(parseTrustedInvariantForgeResult(forgeJson("ContractHunterFuzzTest", "testFuzz_accounting(uint256)", "Failure", "Fuzz", 1, single), plan, 0, false)).toBeNull();
    expect(parseTrustedInvariantForgeResult(validPass, plan, 0, true)).toBeNull();

    const statefulPlan = stateful(), handler = "test/ContractHunterInvariant.t.sol:ContractHunterHandler";
    const statefulJson = (steps: unknown[]) => forgeJson("ContractHunterInvariantTest", "invariant_ownerStable()", "Failure", "Invariant", 1, { Sequence: [1, steps] });
    expect(parseInvariantForgeJson(statefulJson([{ contract_name: handler, signature: "action_touch(bool)", args: ["maybe"] }]), statefulPlan)).toBeNull();
    expect(parseInvariantForgeJson(statefulJson([{ contract_name: handler, signature: "action_unknown()", args: "" }]), statefulPlan)).toBeNull();
    expect(parseInvariantForgeJson(statefulJson(Array.from({ length: 33 }, () => ({ contract_name: handler, signature: "action_takeOwnership()", args: "" }))), statefulPlan)).toBeNull();
  });
});

describe("worker-side invariant workspace revalidation", () => {
  let base: string, repositoryRoot: string, workspaceRoot: string, repository: string;
  beforeEach(async () => {
    base = await mkdtemp(path.join(tmpdir(), "ch-invariant-integrity-")); repositoryRoot = path.join(base, "repos"); workspaceRoot = path.join(base, "workspaces"); repository = path.join(repositoryRoot, scanId);
    await mkdir(path.join(repository, "contracts"), { recursive: true });
    await writeFile(path.join(repository, "contracts/VulnerableAccounting.sol"), await readFile(path.join(fixtureRoot, "contracts/VulnerableAccounting.sol")));
  });
  afterEach(async () => { await rm(base, { recursive: true, force: true }); });
  async function build() { return new VerificationWorkspaceBuilder({ verificationRoot: workspaceRoot, repositoryRoot, acceptedCompilerVersions: ["0.8.36"], approvedSourceRoots: ["contracts"], generatorVersion: "0.2.0" }).buildInvariant({ workspaceId: runId, repositoryPath: repository, plan: fuzz() }); }
  it("accepts generated manifest, plan, hashes, and exact file set", async () => { const built = await build(); expect(await validateExecutableInvariantWorkspaceIntegrity(built.workspacePath)).toEqual(built.manifest); });
  it("rejects a changed canonical plan hash, compiler identity, or manifest mode", async () => {
    const built = await build(), manifestPath = path.join(built.workspacePath, INVARIANT_HARNESS_MANIFEST);
    const original = await readFile(manifestPath, "utf8");
    for (const change of [{ planHash: "0".repeat(64) }, { compilerVersion: "0.8.24" }, { mode: "stateful-invariant" }]) {
      await writeFile(manifestPath, JSON.stringify({ ...built.manifest, ...change }));
      await expect(validateExecutableInvariantWorkspaceIntegrity(built.workspacePath)).rejects.toThrow();
    }
    await writeFile(manifestPath, original);
    expect(await validateExecutableInvariantWorkspaceIntegrity(built.workspacePath)).toEqual(built.manifest);
  });
  it("rejects changed harness or Foundry configuration and unexpected files or symlinks", async () => {
    const built = await build(), harness = path.join(built.workspacePath, built.manifest.generatedHarnessPath), config = path.join(built.workspacePath, "foundry.toml");
    const source = await readFile(harness), foundry = await readFile(config);
    await writeFile(harness, "contract Evil {}"); await expect(validateExecutableInvariantWorkspaceIntegrity(built.workspacePath)).rejects.toThrow(); await writeFile(harness, source);
    await writeFile(config, `${foundry.toString()}\nffi = true\n`); await expect(validateExecutableInvariantWorkspaceIntegrity(built.workspacePath)).rejects.toThrow(); await writeFile(config, foundry);
    await writeFile(path.join(built.workspacePath, "evil.sh"), "echo bad"); await expect(validateExecutableInvariantWorkspaceIntegrity(built.workspacePath)).rejects.toThrow(); await rm(path.join(built.workspacePath, "evil.sh"));
    await symlink(config, path.join(built.workspacePath, "cache", "link")); await expect(validateExecutableInvariantWorkspaceIntegrity(built.workspacePath)).rejects.toThrow();
  });
});
