import { randomUUID } from "node:crypto";
import { copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { executableInvariantPlanSchema, type ExecutableInvariantPlan } from "../packages/core/src/executable-invariant";
import { verificationHarnessPlanSchema } from "../packages/core/src/hypothesis-verification";
import { VerificationWorkspaceBuilder } from "../packages/scanners/src/verification-workspace-builder";
import { ExecutableInvariantWorkerClient, VerificationWorkerClient } from "../packages/scanners/src/verification-worker-client";
import { interpretVerificationResult } from "../packages/scanners/src/verification-result-interpreter";

const scanId = randomUUID();
const hypothesisId = randomUUID();
const resolvedCommit = "a".repeat(40);
const compilerVersion = "0.8.36";
const repository = path.join("/data/repositories", scanId);
const root = "/verification";
const source = (name: string) => `contracts/${name}.sol`;
const property = {
  name: "accounting",
  observations: [
    { kind: "read-uint", instanceName: "target", functionName: "totalRecordedBalance", resultName: "recorded" },
    { kind: "read-balance", target: { kind: "instance", name: "target" }, resultName: "nativeBalance" },
  ],
  assertions: [{ id: "conservation", kind: "uint-eq", actual: "recorded", expected: { kind: "result", name: "nativeBalance" } }],
};
function fuzz(contractName: string): ExecutableInvariantPlan {
  return executableInvariantPlanSchema.parse({ schemaVersion: "contracthunter-invariant-plan-v1", mode: "fuzz-property", scanId, hypothesisId, resolvedCommit, compilerVersion,
    primaryContract: contractName, primarySourcePath: source(contractName), sourceFiles: [source(contractName)], actors: ["deployer", "attacker"],
    setup: [{ kind: "deploy", contractName, instanceName: "target" }], property,
    fuzzAction: { instanceName: "target", functionName: "record", caller: "attacker", parameters: [{ name: "amount", type: "uint256" }], args: [{ kind: "parameter", name: "amount" }] },
  });
}
function stateful(): ExecutableInvariantPlan {
  return executableInvariantPlanSchema.parse({ schemaVersion: "contracthunter-invariant-plan-v1", mode: "stateful-invariant", scanId, hypothesisId, resolvedCommit, compilerVersion,
    primaryContract: "StatefulAccessControl", primarySourcePath: source("StatefulAccessControl"), sourceFiles: [source("StatefulAccessControl")], actors: ["deployer", "attacker"],
    setup: [{ kind: "deploy", contractName: "StatefulAccessControl", instanceName: "target" }],
    handlerActions: [
      { name: "takeOwnership", instanceName: "target", functionName: "transferOwnership", caller: "attacker", parameters: [], args: [{ kind: "address", source: "actor", name: "attacker" }] },
      { name: "touch", instanceName: "target", functionName: "touch", caller: "attacker", parameters: [{ name: "flag", type: "bool" }], args: [{ kind: "parameter", name: "flag" }] },
    ], properties: [{ name: "ownerStable", observations: [{ kind: "read-address", instanceName: "target", functionName: "owner", resultName: "observedOwner" }],
      assertions: [{ id: "owner", kind: "address-eq", actual: "observedOwner", expected: { kind: "address", source: "actor", name: "deployer" } }] }],
  });
}
async function main() {
  if (process.env.CONTRACTHUNTER_PROBE_ISOLATED !== "1") throw new Error("This probe requires an explicitly isolated Compose workspace volume.");
  await mkdir(path.join(repository, "contracts"), { recursive: true });
  for (const name of ["VulnerableAccounting", "SafeAccounting", "StatefulAccessControl"]) await copyFile(path.join("/tmp/fixtures/contracts", `${name}.sol`), path.join(repository, source(name)));
  const builder = new VerificationWorkspaceBuilder({ verificationRoot: root, repositoryRoot: "/data/repositories", acceptedCompilerVersions: [compilerVersion], approvedSourceRoots: ["contracts"], generatorVersion: "0.2.0" });
  const client = new ExecutableInvariantWorkerClient(root);
  for (const [name, plan] of [["vulnerable", fuzz("VulnerableAccounting")], ["safe", fuzz("SafeAccounting")], ["stateful", stateful()]] as const) {
    const workspaceId = randomUUID();
    const built = await builder.buildInvariant({ workspaceId, repositoryPath: repository, plan });
    const result = await client.run({ workspacePath: built.workspacePath, scanId, hypothesisId, resolvedCommit, compilerVersion, planHash: built.manifest.planHash, mode: plan.mode });
    process.stdout.write(`${JSON.stringify({ name, workspaceId, manifest: { planHash: built.manifest.planHash, mode: built.manifest.mode }, result })}\n`);
  }
  const brokenSource = (await readFile("/tmp/verification-fixtures/contracts/BrokenAccessControl.sol", "utf8")).replace("pragma solidity 0.8.24;", "pragma solidity ^0.8.24;");
  await writeFile(path.join(repository, source("BrokenAccessControl")), brokenSource);
  const legacyPlan = verificationHarnessPlanSchema.parse({ scanId, hypothesisId, resolvedCommit, compilerVersion, primaryContract: "BrokenAccessControl", primarySourcePath: source("BrokenAccessControl"), sourceFiles: [source("BrokenAccessControl")],
    relevantFunctions: ["setOwner", "owner", "withdraw"], actors: ["deployer", "attacker"], verificationGoal: "Observe unauthorized ownership replacement and withdrawal.", expectedProperty: "Only owner can replace owner.", verificationSteps: ["Deploy and fund.", "Call as attacker.", "Read owner and balance."],
    operations: [{ kind: "deploy", contractName: "BrokenAccessControl", instanceName: "target" }, { kind: "fund", target: { kind: "instance", name: "target" }, amountWei: "1000000000000000000" }, { kind: "call", instanceName: "target", functionName: "setOwner", caller: "attacker", args: [{ kind: "address", source: "actor", name: "attacker" }] }, { kind: "read-address", instanceName: "target", functionName: "owner", resultName: "ownerAfter" }, { kind: "call", instanceName: "target", functionName: "withdraw", caller: "attacker", args: [] }, { kind: "read-balance", target: { kind: "instance", name: "target" }, resultName: "targetBalance" }],
    assertions: [{ id: "attacker-is-owner", kind: "address-eq", actual: "ownerAfter", expected: { kind: "address", source: "actor", name: "attacker" }, expectedOutcome: "hypothesis-supported", description: "The unauthorized attacker becomes the observed owner." }, { id: "target-drained", kind: "uint-eq", actual: "targetBalance", expected: "0", expectedOutcome: "hypothesis-supported", description: "The target native balance is zero after attacker withdrawal." }],
  });
  const legacyRunId = randomUUID();
  const legacy = await builder.build({ verificationRunId: legacyRunId, repositoryPath: repository, plan: legacyPlan });
  const legacyResult = await new VerificationWorkerClient(root).run({ workspacePath: legacy.workspacePath, scanId, hypothesisId, resolvedCommit, compilerVersion, timeoutMs: 180_000, maxOutputBytes: 2_097_152 });
  process.stdout.write(`${JSON.stringify({ name: "BrokenAccessControl-v0.1.9-regression", legacyRunId, result: legacyResult, interpretation: interpretVerificationResult(legacyPlan, legacyResult) })}\n`);
}
main().catch((error) => { process.stderr.write(String(error)); process.exitCode = 1; });
