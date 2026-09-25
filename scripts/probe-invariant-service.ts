import { randomUUID } from "node:crypto";
import { copyFile, mkdir } from "node:fs/promises";
import path from "node:path";
import { executableInvariantPlanSchema, validAIOutput, type ProtocolAnalysisResult } from "../packages/core/src";
import { closeDatabase, createDatabase, createProtocolAnalysis, createScan, createSecurityReviewerRun, createSecurityReviewPlan, insertVulnerabilityHypotheses, listExecutableInvariantRuns, getVulnerabilityHypothesis } from "../packages/db/src";
import { ExecutableInvariantService } from "../apps/web/lib/verification/executable-invariant-service";
import { VerificationWorkspaceBuilder } from "../packages/scanners/src/verification-workspace-builder";
import { ExecutableInvariantWorkerClient } from "../packages/scanners/src/verification-worker-client";

const resolvedCommit = "b".repeat(40);
const compilerVersion = "0.8.36";
const repositoryRoot = "/data/repositories";
const verificationRoot = "/verification";
const property = { name: "accounting", observations: [{ kind: "read-uint", instanceName: "target", functionName: "totalRecordedBalance", resultName: "recorded" }, { kind: "read-balance", target: { kind: "instance", name: "target" }, resultName: "nativeBalance" }], assertions: [{ id: "conservation", kind: "uint-eq", actual: "recorded", expected: { kind: "result", name: "nativeBalance" } }] };
async function main() {
  if (process.env.CONTRACTHUNTER_PROBE_ISOLATED !== "1") throw new Error("This probe requires an explicitly isolated Compose data volume.");
  const database = createDatabase("/data/contracthunter.db");
  try {
    const scan = createScan(database, { repositoryUrl: "https://example.invalid/synthetic-m2", repositoryName: "synthetic-m2", depth: "quick" });
    const repository = path.join(repositoryRoot, scan.id);
    await mkdir(path.join(repository, "contracts"), { recursive: true });
    for (const contract of ["VulnerableAccounting", "SafeAccounting", "StatefulAccessControl"]) await copyFile(path.join("/tmp/fixtures/contracts", `${contract}.sol`), path.join(repository, "contracts", `${contract}.sol`));
    database.sqlite.prepare("UPDATE scans SET status = 'completed', resolved_commit = ?, compiler_status = 'ready', compiler_versions = ? WHERE id = ?").run(resolvedCommit, JSON.stringify([compilerVersion]), scan.id);
    const analysis = createProtocolAnalysis(database, { scanId: scan.id, provider: "fixture", requestedModel: "fixture", actualModel: "fixture", promptVersion: "protocol-analysis-v1", result: validAIOutput as unknown as ProtocolAnalysisResult, coverageStatus: "complete", contextManifest: {}, durationMs: 1, inputTokens: 0, outputTokens: 0, totalTokens: 0, requestId: randomUUID() });
    const reviewPlan = createSecurityReviewPlan(database, { scanId: scan.id, protocolAnalysisId: analysis.id, plan: { selected: [], skipped: [], estimatedRequestCount: 0 }, estimatedSourceBytes: 0 });
    const reviewer = createSecurityReviewerRun(database, { planId: reviewPlan.id, scanId: scan.id, protocolAnalysisId: analysis.id, reviewerId: "fixture", reviewerName: "Fixture", selectionReason: "Local synthetic test", promptVersion: "security-review-fixture-v1", provider: "fixture", requestedModel: "fixture", contextManifest: {} });
    const hypothesisId = insertVulnerabilityHypotheses(database, [{ scanId: scan.id, protocolAnalysisId: analysis.id, reviewerId: "fixture", reviewerRunId: reviewer.id, title: "Synthetic invariant fixture", category: "state-transition", severity: "low", severityJustification: "Fixture", confidence: 60, summary: "Local synthetic run", rootCause: "Fixture", preconditions: "[]", attackPath: "[]", impact: "Fixture", affectedAssets: "[]", affectedContracts: "[]", affectedFunctions: "[]", evidence: "[]", violatedInvariantIds: "[]", relatedInvestigationIds: "[]", falsePositiveRisks: "[]", verificationStrategy: "[]" }])[0].id;
    const service = new ExecutableInvariantService({ database, repositoryRoot, runner: new ExecutableInvariantWorkerClient(verificationRoot), workspaceBuilder: (acceptedCompilerVersions) => new VerificationWorkspaceBuilder({ verificationRoot, repositoryRoot, acceptedCompilerVersions, approvedSourceRoots: ["contracts"], generatorVersion: "0.2.0" }) });
    const common = { schemaVersion: "contracthunter-invariant-plan-v1", scanId: scan.id, hypothesisId, resolvedCommit, compilerVersion, actors: ["deployer", "attacker"] };
    for (const contract of ["VulnerableAccounting", "SafeAccounting"]) {
      const plan = executableInvariantPlanSchema.parse({ ...common, mode: "fuzz-property", primaryContract: contract, primarySourcePath: `contracts/${contract}.sol`, sourceFiles: [`contracts/${contract}.sol`], setup: [{ kind: "deploy", contractName: contract, instanceName: "target" }], property, fuzzAction: { instanceName: "target", functionName: "record", caller: "attacker", parameters: [{ name: "amount", type: "uint256" }], args: [{ kind: "parameter", name: "amount" }] } });
      const result = await service.run(hypothesisId, plan);
      process.stdout.write(`${JSON.stringify({ contract, run: { id: result.run.id, status: result.run.status, outcome: result.run.outcome, compilerVersion: result.run.compilerVersion, configuredRuns: result.run.configuredRuns, runsExecuted: result.run.runsExecuted, dynamicEvidence: JSON.parse(result.run.dynamicEvidence), errorCode: result.run.errorCode } })}\n`);
    }
    const stateful = executableInvariantPlanSchema.parse({ ...common, mode: "stateful-invariant", primaryContract: "StatefulAccessControl", primarySourcePath: "contracts/StatefulAccessControl.sol", sourceFiles: ["contracts/StatefulAccessControl.sol"], setup: [{ kind: "deploy", contractName: "StatefulAccessControl", instanceName: "target" }], handlerActions: [{ name: "takeOwnership", instanceName: "target", functionName: "transferOwnership", caller: "attacker", parameters: [], args: [{ kind: "address", source: "actor", name: "attacker" }] }, { name: "touch", instanceName: "target", functionName: "touch", caller: "attacker", parameters: [{ name: "flag", type: "bool" }], args: [{ kind: "parameter", name: "flag" }] }], properties: [{ name: "ownerStable", observations: [{ kind: "read-address", instanceName: "target", functionName: "owner", resultName: "observedOwner" }], assertions: [{ id: "owner", kind: "address-eq", actual: "observedOwner", expected: { kind: "address", source: "actor", name: "deployer" } }] }] });
    const result = await service.run(hypothesisId, stateful);
    process.stdout.write(`${JSON.stringify({ contract: "StatefulAccessControl", run: { id: result.run.id, status: result.run.status, outcome: result.run.outcome, compilerVersion: result.run.compilerVersion, configuredRuns: result.run.configuredRuns, configuredDepth: result.run.configuredDepth, runsExecuted: result.run.runsExecuted, dynamicEvidence: JSON.parse(result.run.dynamicEvidence), errorCode: result.run.errorCode } })}\n`);
    process.stdout.write(`${JSON.stringify({ historyCount: listExecutableInvariantRuns(database, hypothesisId).length, hypothesisStatus: getVulnerabilityHypothesis(database, hypothesisId)?.status })}\n`);
  } finally { closeDatabase(database); }
}
main().catch((error) => { process.stderr.write(String(error)); process.exitCode = 1; });
