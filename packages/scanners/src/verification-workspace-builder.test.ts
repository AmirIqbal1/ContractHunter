import { cp, mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { verificationHarnessManifestSchema, verificationHarnessPlanSchema, type VerificationHarnessPlan } from "@contracthunter/core";
import {
  VerificationHarnessGenerationError, VerificationHarnessGenerator, VerificationWorkspaceBuildError, VerificationWorkspaceBuilder,
  createContractHunterFoundryConfig, sha256Bytes, validateVerificationWorkspaceIntegrity,
} from "./index";

const fixture = path.resolve("packages/scanners/fixtures/verification");
const scanId = "11111111-1111-4111-8111-111111111111";
const hypothesisId = "22222222-2222-4222-8222-222222222222";
const resolvedCommit = "a".repeat(40);
let base: string; let repositoryRoot: string; let repository: string; let verificationRoot: string;

beforeEach(async () => {
  base = await mkdtemp(path.join(tmpdir(), "contracthunter-workspace-builder-")); repositoryRoot = path.join(base, "repositories"); repository = path.join(repositoryRoot, "scan"); verificationRoot = path.join(base, "verifications");
  await mkdir(repositoryRoot); await cp(fixture, repository, { recursive: true });
});
afterEach(async () => { await rm(base, { recursive: true, force: true }); });

function plan(overrides: Partial<VerificationHarnessPlan> = {}): VerificationHarnessPlan {
  return verificationHarnessPlanSchema.parse({
    scanId, hypothesisId, resolvedCommit, compilerVersion: "0.8.24", primaryContract: "Counter", primarySourcePath: "contracts/Counter.sol",
    relevantFunctions: ["increment", "count"], sourceFiles: ["contracts/Counter.sol"], verificationGoal: "Confirm a benign deterministic counter transition.",
    expectedProperty: "Calling increment changes count from zero to one.", verificationSteps: ["Deploy Counter.", "Call increment.", "Read count."],
    operations: [{ kind: "deploy", contractName: "Counter", instanceName: "target" }, { kind: "call", instanceName: "target", functionName: "increment" }, { kind: "read-uint", instanceName: "target", functionName: "count", resultName: "observed" }],
    assertions: [{ kind: "uint-eq", actual: "observed", expected: "1", description: "The count changed to one." }], ...overrides,
  });
}

function builder(overrides: Partial<ConstructorParameters<typeof VerificationWorkspaceBuilder>[0]> = {}) {
  return new VerificationWorkspaceBuilder({ verificationRoot, repositoryRoot, acceptedCompilerVersions: ["0.8.24"], approvedSourceRoots: ["contracts", "lib"], generatorVersion: "0.1.0", ...overrides });
}

async function build(runId = crypto.randomUUID(), selectedPlan = plan()) { return builder().build({ verificationRunId: runId, repositoryPath: repository, plan: selectedPlan, createdAt: new Date("2026-08-15T12:00:00.000Z") }); }

describe("verification source closure", () => {
  it("copies normal and nested relative imports deterministically with hashes", async () => {
    const result = await build();
    expect(result.manifest.sourceManifest.map((entry) => entry.originalPath)).toEqual(["contracts/Counter.sol", "contracts/lib/CounterMath.sol", "contracts/lib/Unit.sol"]);
    for (const entry of result.manifest.sourceManifest) {
      const copied = await readFile(path.join(result.workspacePath, ...entry.workspacePath.split("/")));
      expect(copied.length).toBe(entry.byteLength); expect(sha256Bytes(copied)).toBe(entry.sha256);
      expect(copied).toEqual(await readFile(path.join(repository, ...entry.originalPath.split("/"))));
    }
  });

  it("rejects traversal, URL imports, and unsupported external dependencies", async () => {
    const cases = [
      ["Traversal.sol", 'import "../../outside.sol"; contract Traversal {}'],
      ["Url.sol", 'import "https://example.com/Remote.sol"; contract Url {}'],
      ["External.sol", 'import "forge-std/Test.sol"; contract External {}'],
    ] as const;
    for (const [name, source] of cases) {
      const sourcePath = `contracts/${name}`; await writeFile(path.join(repository, sourcePath), `pragma solidity 0.8.24; ${source}`);
      await expect(builder().build({ verificationRunId: crypto.randomUUID(), repositoryPath: repository, plan: plan({ primaryContract: name.replace(".sol", ""), primarySourcePath: sourcePath, sourceFiles: [sourcePath], relevantFunctions: ["noop"], operations: [{ kind: "deploy", contractName: name.replace(".sol", ""), instanceName: "target" }], assertions: [{ kind: "uint-eq", actual: "missing", expected: "0", description: "fixture" }] }) })).rejects.toBeInstanceOf(VerificationWorkspaceBuildError);
    }
  });

  it("rejects symlink escapes", async () => {
    const outside = path.join(base, "Outside.sol"); await writeFile(outside, "pragma solidity 0.8.24; contract Outside {}");
    await symlink(outside, path.join(repository, "contracts/Outside.sol"));
    await expect(builder().build({ verificationRunId: crypto.randomUUID(), repositoryPath: repository, plan: plan({ primaryContract: "Outside", primarySourcePath: "contracts/Outside.sol", sourceFiles: ["contracts/Outside.sol"], relevantFunctions: ["noop"], operations: [{ kind: "deploy", contractName: "Outside", instanceName: "target" }] }) })).rejects.toThrow("not a regular repository file");
  });

  it("enforces file-count and byte bounds", async () => {
    await expect(builder({ maxSourceFiles: 2 }).build({ verificationRunId: crypto.randomUUID(), repositoryPath: repository, plan: plan() })).rejects.toThrow("file-count limit");
    await writeFile(path.join(repository, "contracts/Large.sol"), `pragma solidity 0.8.24; contract Large { /* ${"x".repeat(2_000)} */ }`);
    await expect(builder({ maxSourceBytes: 1_024 }).build({ verificationRunId: crypto.randomUUID(), repositoryPath: repository, plan: plan({ primaryContract: "Large", primarySourcePath: "contracts/Large.sol", sourceFiles: ["contracts/Large.sol"], relevantFunctions: ["noop"], operations: [{ kind: "deploy", contractName: "Large", instanceName: "target" }] }) })).rejects.toThrow("byte limit");
  });
});

describe("structured harness generation", () => {
  it("generates deterministic source from controlled operations", () => {
    const generator = new VerificationHarnessGenerator(); const first = generator.generate(plan()); const second = generator.generate(plan());
    expect(first).toBe(second); expect(first).toContain("Counter target = new Counter();"); expect(first).toContain("target.increment();"); expect(first).toContain("uint256 observed = target.count();"); expect(first).toContain('require(observed == 1, "CH_ASSERT_0");');
    expect(first).not.toMatch(/\bvm\.|ffi|createFork|selectFork|readFile|writeFile|env[A-Z]|broadcast|deriveKey|private key|rpc/i);
  });

  it("cannot emit prohibited capability calls", () => {
    for (const functionName of ["ffi", "createFork", "selectFork", "readFile", "writeFile", "envUint", "broadcast", "startBroadcast", "deriveKey"]) {
      const unsafe = plan({ relevantFunctions: [functionName, "count"], operations: [{ kind: "deploy", contractName: "Counter", instanceName: "target" }, { kind: "call", instanceName: "target", functionName }, { kind: "read-uint", instanceName: "target", functionName: "count", resultName: "observed" }] });
      expect(() => new VerificationHarnessGenerator().generate(unsafe)).toThrow(VerificationHarnessGenerationError);
    }
  });
});

describe("verification workspace and manifest", () => {
  it("creates unique contained workspaces with deterministic content fingerprints", async () => {
    const first = await build(); const second = await build();
    expect(first.workspacePath).not.toBe(second.workspacePath); expect(first.workspacePath.startsWith(`${verificationRoot}${path.sep}`)).toBe(true);
    expect(first.harnessSource).toBe(second.harnessSource); expect(first.manifest.contentFingerprint).toBe(second.manifest.contentFingerprint);
    expect(first.manifest.generatedHarnessSha256).toBe(second.manifest.generatedHarnessSha256); expect(first.manifest.foundryConfigSha256).toBe(second.manifest.foundryConfigSha256);
  });

  it("writes controlled pinned Foundry configuration", async () => {
    await writeFile(path.join(repository, "foundry.toml"), "[rpc_endpoints]\nmainnet='secret'\n[profile.evil]\nffi=true\n");
    const result = await build(); const config = await readFile(path.join(result.workspacePath, "foundry.toml"), "utf8");
    expect(config).toBe(createContractHunterFoundryConfig("0.8.24")); expect(config).toContain('solc_version = "0.8.24"'); expect(config).toContain("auto_detect_solc = false"); expect(config).toContain("offline = true"); expect(config).toContain("ffi = false");
    expect(config).not.toMatch(/rpc_endpoints|etherscan|profile\.evil|mainnet|secret/);
  });

  it("produces a strict command-free manifest with complete hashes", async () => {
    const result = await build(); const manifestJson = JSON.stringify(result.manifest);
    expect(verificationHarnessManifestSchema.parse(result.manifest)).toEqual(result.manifest);
    expect(verificationHarnessManifestSchema.safeParse({ ...result.manifest, command: "forge test" }).success).toBe(false);
    expect(result.manifest.sourceManifest).toHaveLength(3); expect(result.manifest.generatedHarnessSha256).toHaveLength(64); expect(result.manifest.foundryConfigSha256).toHaveLength(64); expect(result.manifest.contentFingerprint).toHaveLength(64);
    expect(manifestJson).not.toMatch(/command|OPENAI_API_KEY|PRIVATE_KEY|RPC_URL|https?:\/\//i);
  });

  it("is compatible with shared runner integrity validation and detects tampering", async () => {
    const sourceResult = await build(); await expect(validateVerificationWorkspaceIntegrity(sourceResult.workspacePath)).resolves.toEqual(sourceResult.manifest);
    await writeFile(path.join(sourceResult.workspacePath, sourceResult.manifest.sourceManifest[0].workspacePath), "pragma solidity 0.8.24;");
    await expect(validateVerificationWorkspaceIntegrity(sourceResult.workspacePath)).rejects.toThrow("source integrity");
    const harnessResult = await build(); await writeFile(path.join(harnessResult.workspacePath, harnessResult.manifest.generatedHarnessPath), "contract Modified {}");
    await expect(validateVerificationWorkspaceIntegrity(harnessResult.workspacePath)).rejects.toThrow("harness integrity");
  });

  it("rejects unaccepted compilers and never overwrites an existing run", async () => {
    await expect(builder().build({ verificationRunId: crypto.randomUUID(), repositoryPath: repository, plan: plan({ compilerVersion: "0.8.25" }) })).rejects.toThrow("not accepted");
    const runId = crypto.randomUUID(); await build(runId); await expect(build(runId)).rejects.toThrow("already exists");
  });

  it("cleans partial temporary workspaces after failure", async () => {
    await writeFile(path.join(repository, "contracts/Bad.sol"), 'pragma solidity 0.8.24; import "https://example.com/Bad.sol"; contract Bad {}');
    const instance = builder();
    await expect(instance.build({ verificationRunId: crypto.randomUUID(), repositoryPath: repository, plan: plan({ primaryContract: "Bad", primarySourcePath: "contracts/Bad.sol", sourceFiles: ["contracts/Bad.sol"], relevantFunctions: ["noop"], operations: [{ kind: "deploy", contractName: "Bad", instanceName: "target" }] }) })).rejects.toBeInstanceOf(VerificationWorkspaceBuildError);
    expect(await instance.listTemporaryWorkspaces()).toEqual([]); expect((await readdir(verificationRoot)).some((entry) => entry.startsWith(".tmp-"))).toBe(false);
  });
});
