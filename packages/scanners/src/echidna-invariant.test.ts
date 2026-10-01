import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { ECHIDNA_BINARY_SHA256, ECHIDNA_MANIFEST_FILE, counterexampleHash, echidnaSeed, executableInvariantPlanSchema, invariantPlanHash, invariantReplayPlanSchema, validateReplayAgainstInvariant, type ExecutableInvariantPlan } from "@contracthunter/core";
import { EchidnaInvariantGenerator, validateEchidnaPlanCompatibility } from "./echidna-invariant-generator";
import { validateEchidnaInvariantWorkspaceIntegrity } from "./echidna-invariant-workspace-integrity";
import { interpretEchidnaFacts, parseTrustedEchidnaResult } from "./echidna-invariant-result";
import { echidnaInvariantWorkerRequestSchema, workerRequestSchema } from "./verification-worker-protocol";
import { EchidnaInvariantWorkerClient } from "./verification-worker-client";
import { VerificationWorkspaceBuilder } from "./verification-workspace-builder";
import { InvariantReplayGenerator } from "./invariant-replay-generator";

const scanId = "11111111-1111-4111-8111-111111111111", hypothesisId = "22222222-2222-4222-8222-222222222222", runId = "33333333-3333-4333-8333-333333333333";
const fixture = path.resolve("packages/scanners/fixtures/echidna/contracts/VulnerableAccounting.sol");
const address = "0x00a329c0648769A73afAc7F9381E08FB43dBEA72", sender = "0x0000000000000000000000000000000000010000";
const observation = (functionName: string, resultName: string) => ({ kind: "read-uint", instanceName: "target", functionName, resultName });
const property = (name: string, right: string) => ({ name, observations: [observation("recorded", "recordedValue"), observation(right, "otherValue")], assertions: [{ id: "balanced", kind: "uint-eq", actual: "recordedValue", expected: { kind: "result", name: "otherValue" } }] });
function plan(properties = [property("safe", "guard"), property("vulnerable", "mirror")]): ExecutableInvariantPlan {
  return executableInvariantPlanSchema.parse({ schemaVersion: "contracthunter-invariant-plan-v1", scanId, hypothesisId, resolvedCommit: "a".repeat(40), compilerVersion: "0.8.36", primaryContract: "VulnerableAccounting", primarySourcePath: "contracts/VulnerableAccounting.sol", sourceFiles: ["contracts/VulnerableAccounting.sol"], actors: [], mode: "stateful-invariant", setup: [{ kind: "deploy", contractName: "VulnerableAccounting", instanceName: "target" }], handlerActions: [
    { name: "credit", instanceName: "target", functionName: "credit", parameters: [{ name: "amount", type: "uint256" }], args: [{ kind: "parameter", name: "amount" }] },
    { name: "debit", instanceName: "target", functionName: "debit", parameters: [{ name: "amount", type: "uint256" }], args: [{ kind: "parameter", name: "amount" }] },
  ], properties });
}
const transaction = { function: "action_debit", arguments: ["1"], sender, destination: address, timeDelay: "0x0", blockDelay: "0x0", value: "0x0" };
function output(input: ExecutableInvariantPlan, tests: unknown[], reason = "test-limit-reached") { return JSON.stringify({ schema: "contracthunter-echidna-result-v1", echidnaVersion: "2.3.3+contracthunter.1", seed: echidnaSeed(invariantPlanHash(input)), configuredTestLimit: 128, executedCalls: 135, workerStopReasons: [reason], tests, error: null }); }
const held = (name: string) => ({ name: `echidna_ch_${name}`, type: "property", outcome: "held-within-bounds", transactions: null });
const failed = (name: string, steps = [transaction]) => ({ name: `echidna_ch_${name}`, type: "property", outcome: "counterexample-found", transactions: steps });

describe("Echidna compatibility and deterministic generation", () => {
  it("accepts a narrow stateful plan, preserves both properties, and repeats byte-identically", async () => {
    const input = plan(), sources = new Map([[input.primarySourcePath, await readFile(fixture, "utf8")]]);
    expect(validateEchidnaPlanCompatibility(input, sources)).toEqual({ compatible: true, reasons: [] });
    const one = new EchidnaInvariantGenerator().generate(input, sources), two = new EchidnaInvariantGenerator().generate(input, sources);
    expect(one).toEqual(two);
    expect(one.source).toContain("function echidna_ch_safe()");
    expect(one.source).toContain("function echidna_ch_vulnerable()");
    expect(one.config).toContain(`seed: ${echidnaSeed(invariantPlanHash(input))}`);
    expect(one.config).toContain("workers: 1");
  });
  it("rejects unsupported mode, actors, setup, source caller semantics, and unsafe protocol fields", async () => {
    const input = plan(), sources = new Map([[input.primarySourcePath, await readFile(fixture, "utf8")]]);
    const actors = executableInvariantPlanSchema.parse({ ...input, actors: ["attacker"], handlerActions: input.mode === "stateful-invariant" ? input.handlerActions.map((action) => ({ ...action, caller: "attacker" })) : [] });
    expect(validateEchidnaPlanCompatibility(actors, sources)).toMatchObject({ compatible: false, reasons: expect.arrayContaining(["symbolic-actors-unsupported", "explicit-caller-unsupported"]) });
    expect(validateEchidnaPlanCompatibility(input, new Map([[input.primarySourcePath, `${sources.get(input.primarySourcePath)}\n// comment\ncontract Other { address x = msg.sender; }`]]))).toMatchObject({ compatible: false, reasons: ["caller-or-environment-sensitive-source"] });
    expect(validateEchidnaPlanCompatibility(executableInvariantPlanSchema.parse({ ...input, setup: [...input.setup, { kind: "call", instanceName: "target", functionName: "credit", args: [{ kind: "uint", value: "1" }] }] }), sources)).toMatchObject({ compatible: false, reasons: ["setup-semantics-unsupported"] });
    const request = { command: "execute-echidna-invariant", runId, workspaceId: runId, scanId, hypothesisId, resolvedCommit: "a".repeat(40), compilerVersion: "0.8.36", planHash: invariantPlanHash(input) };
    expect(workerRequestSchema.safeParse(request).success).toBe(true);
    for (const extra of [{ executable: "/bin/sh" }, { argv: ["--rpc-url"] }, { config: "rpcUrl: evil" }, { source: "contract Evil {}" }, { compilerPath: "/tmp/solc" }, { timeoutMs: 0 }, { env: { RPC_URL: "x" } }]) expect(echidnaInvariantWorkerRequestSchema.safeParse({ ...request, ...extra }).success).toBe(false);
  });
});

describe("strict patched Echidna result", () => {
  it("binds safe and failing properties independently and maps an exact action sequence", () => {
    const input = plan(), raw = output(input, [held("safe"), failed("vulnerable")]);
    const parsed = parseTrustedEchidnaResult(raw, input, 1, false);
    expect(parsed?.tests).toMatchObject([{ propertyName: "safe", outcome: "held-within-bounds", replayAvailable: false }, { propertyName: "vulnerable", outcome: "counterexample-found", replayAvailable: true }]);
    expect(parsed?.tests[1].counterexample).toMatchObject({ kind: "sequence", actions: [{ actionName: "debit", parameterValues: [{ name: "amount", type: "uint256", value: "1" }] }] });
    expect(interpretEchidnaFacts(input, parsed!, "docker-verification-worker-v1")).toMatchObject([{ engine: "echidna", hypothesisRelation: "neutral" }, { engine: "echidna", hypothesisRelation: "unreviewed" }]);
  });
  it("fails closed on ambiguous identity, output, version, stop reason, and exit code", () => {
    const input = plan(), good = output(input, [held("safe"), failed("vulnerable")]);
    for (const text of [`progress\n${good}`, `${good}\nfinished`, "{broken", output(input, [held("safe"), held("safe")]), output(input, [held("safe"), failed("unknown")]), output(input, [held("safe"), failed("vulnerable")], "killed"), good.replace("2.3.3+contracthunter.1", "2.3.3")]) expect(parseTrustedEchidnaResult(text, input, 1, false)).toBeNull();
    expect(parseTrustedEchidnaResult(good, input, 0, false)).toBeNull();
    expect(parseTrustedEchidnaResult(good, input, 1, true)).toBeNull();
    expect(parseTrustedEchidnaResult("x".repeat(2_097_153), input, 1, false)).toBeNull();
    expect(parseTrustedEchidnaResult(output(input, [{ ...held("safe"), outcome: "shrinking" }, failed("vulnerable")]), input, 1, false)).toBeNull();
  });
  it("retains terminal failure while denying replay for unknown actions, typed values, and delays", () => {
    const input = plan();
    for (const step of [{ ...transaction, timeDelay: "0x1" }, { ...transaction, destination: sender }]) {
      const parsed = parseTrustedEchidnaResult(output(input, [held("safe"), failed("vulnerable", [step])]), input, 1, false);
      expect(parsed?.tests[1]).toMatchObject({ outcome: "counterexample-found", replayAvailable: false, counterexample: null });
    }
    for (const step of [{ ...transaction, function: "action_unknown" }, { ...transaction, function: "credit" }, { ...transaction, arguments: ["-1"] }, { ...transaction, arguments: ["maybe"] }, { ...transaction, arguments: ["true"] }, { ...transaction, arguments: ["1", "2"] }])
      expect(parseTrustedEchidnaResult(output(input, [held("safe"), failed("vulnerable", [step])]), input, 1, false)).toBeNull();
    expect(parseTrustedEchidnaResult(output(input, [held("safe"), failed("vulnerable", Array.from({ length: 33 }, () => transaction))]), input, 1, false)).toBeNull();
    expect(parseTrustedEchidnaResult(output(input, [{ ...held("safe"), outcome: "inconclusive" }, { ...held("vulnerable"), outcome: "inconclusive" }], "time-limit-reached"), input, 2, false)?.tests.every((item) => item.outcome === "inconclusive")).toBe(true);
  });
  it("rejects malformed bool values but maps an exact bool action", () => {
    const original = plan(); if (original.mode !== "stateful-invariant") throw new Error("Stateful fixture required.");
    const input = executableInvariantPlanSchema.parse({ ...original, handlerActions: [{ name: "flag", instanceName: "target", functionName: "flag", parameters: [{ name: "enabled", type: "bool" }], args: [{ kind: "parameter", name: "enabled" }] }] });
    const step = { ...transaction, function: "action_flag", arguments: ["true"] };
    expect(parseTrustedEchidnaResult(output(input, [held("safe"), failed("vulnerable", [step])]), input, 1, false)?.tests[1].counterexample).toMatchObject({ actions: [{ actionName: "flag", parameterValues: [{ name: "enabled", type: "bool", value: true }] }] });
    expect(parseTrustedEchidnaResult(output(input, [held("safe"), failed("vulnerable", [{ ...step, arguments: ["maybe"] }])]), input, 1, false)).toBeNull();
  });
  it("rejects every ambiguous envelope and terminal combination", () => {
    const input = plan(), good = JSON.parse(output(input, [held("safe"), failed("vulnerable")])) as Record<string, unknown>;
    const bad: Record<string, unknown>[] = [
      { ...good, schema: "other" }, { ...good, buildId: "wrong" }, { ...good, seed: Number(good.seed) + 1 },
      { ...good, tests: [held("safe")] }, { ...good, tests: [held("safe"), failed("unknown")] },
      { ...good, tests: [held("safe"), held("safe")] },
      { ...good, tests: [{ ...held("safe"), outcome: "shrinking" }, failed("vulnerable")] },
      { ...good, workerStopReasons: ["killed"] },
      { ...good, tests: [held("safe"), failed("vulnerable", [{ ...transaction, arguments: ["not-a-uint"] }])] },
      { ...good, tests: [held("safe"), failed("vulnerable", [{ ...transaction, function: "action_missing" }])] },
      { ...good, tests: [held("safe"), failed("vulnerable", Array.from({ length: 33 }, () => transaction))] },
    ];
    for (const value of bad) expect(parseTrustedEchidnaResult(JSON.stringify(value), input, 1, false)).toBeNull();
    expect(parseTrustedEchidnaResult(JSON.stringify({ ...good, tests: [held("safe"), held("vulnerable")] }), input, 1, false)).toBeNull();
    expect(parseTrustedEchidnaResult(JSON.stringify({ ...good, tests: [held("safe"), failed("vulnerable")] }), input, 0, false)).toBeNull();
    expect(parseTrustedEchidnaResult(JSON.stringify({ ...good, tests: [held("safe"), failed("vulnerable")] }), input, 2, false)).toBeNull();
    expect(parseTrustedEchidnaResult(JSON.stringify(good), input, 1, true)).toBeNull();
  });
  it("feeds an exact Echidna sequence into the existing deterministic Foundry replay generator", async () => {
    const input = plan(), parsed = parseTrustedEchidnaResult(output(input, [held("safe"), failed("vulnerable", [{ ...transaction, function: "action_credit" }, transaction])]), input, 1, false);
    const counterexample = parsed?.tests[1].counterexample;
    expect(counterexample).toBeTruthy();
    const replay = invariantReplayPlanSchema.parse({ schemaVersion: "contracthunter-invariant-replay-v1", hypothesisId, scanId, resolvedCommit: "a".repeat(40), compilerVersion: "0.8.36", proposalId: "44444444-4444-4444-8444-444444444444", invariantRunId: runId, invariantPlanHash: invariantPlanHash(input), propertyName: "vulnerable", hypothesisExpectation: "hypothesis-predicts-property-violation", counterexample, counterexampleHash: counterexampleHash(counterexample) });
    validateReplayAgainstInvariant(replay, input);
    const sources = new Map([[input.primarySourcePath, await readFile(fixture, "utf8")]]);
    const generated = new InvariantReplayGenerator().generate(replay, input, sources);
    expect(generated.source).toContain("target.credit(1);");
    expect(generated.source).toContain("target.debit(1);");
    expect(generated.source).toContain("CH_REPLAY_NOT_REPRODUCED");
  });
});

describe("Echidna workspace and worker boundary", () => {
  let root: string;
  afterEach(async () => { if (root) await rm(root, { recursive: true, force: true }); });
  it("rejects manifest, config, harness, and symlink tampering", async () => {
    root = await mkdtemp(path.join(tmpdir(), "ch-echidna-workspace-"));
    const repositoryRoot = path.join(root, "repos"), repositoryPath = path.join(repositoryRoot, scanId), verificationRoot = path.join(root, "verification");
    await mkdir(path.join(repositoryPath, "contracts"), { recursive: true });
    await writeFile(path.join(repositoryPath, "contracts/VulnerableAccounting.sol"), await readFile(fixture));
    const built = await new VerificationWorkspaceBuilder({ verificationRoot, repositoryRoot, acceptedCompilerVersions: ["0.8.36"], approvedSourceRoots: ["contracts"], generatorVersion: "0.2.1" }).buildEchidnaInvariant({ workspaceId: runId, repositoryPath, plan: plan() });
    expect(await validateEchidnaInvariantWorkspaceIntegrity(built.workspacePath)).toEqual(built.manifest);
    expect(built.manifest.binaryHash).toBe(ECHIDNA_BINARY_SHA256);
    const manifestPath = path.join(built.workspacePath, ECHIDNA_MANIFEST_FILE), originalManifest = await readFile(manifestPath);
    for (const edit of [{ planHash: "0".repeat(64) }, { binaryHash: "0".repeat(64) }, { buildId: "other" }, { echidnaVersion: "2.3.1" }, { configHash: "0".repeat(64) }]) {
      await writeFile(manifestPath, JSON.stringify({ ...built.manifest, ...edit }));
      await expect(validateEchidnaInvariantWorkspaceIntegrity(built.workspacePath)).rejects.toThrow();
    }
    await writeFile(manifestPath, originalManifest);
    for (const relative of ["echidna.yaml", "ContractHunterEchidna.sol"]) {
      const target = path.join(built.workspacePath, relative), original = await readFile(target);
      await writeFile(target, "evil"); await expect(validateEchidnaInvariantWorkspaceIntegrity(built.workspacePath)).rejects.toThrow(); await writeFile(target, original);
    }
    await symlink(path.join(built.workspacePath, "echidna.yaml"), path.join(built.workspacePath, "src", "escape"));
    await expect(validateEchidnaInvariantWorkspaceIntegrity(built.workspacePath)).rejects.toThrow();
    const client = new EchidnaInvariantWorkerClient(verificationRoot, path.join(root, "missing.sock"));
    expect(await client.run({ workspacePath: built.workspacePath, scanId, hypothesisId, resolvedCommit: "a".repeat(40), compilerVersion: "0.8.36", planHash: built.manifest.planHash })).toEqual({ status: "refused", errorCode: "echidna_worker_unavailable" });
  });
});
