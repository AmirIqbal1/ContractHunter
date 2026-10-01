/** Disposable isolated Compose project only. No AI provider calls. */
import { createHash, randomUUID } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { executableInvariantPlanSchema, invariantPlanHash, validAIOutput, type ProtocolAnalysisResult } from "../packages/core/src";
import { closeDatabase, createDatabase, createExecutableInvariantProposal, createProtocolAnalysis, createScan, createSecurityReviewerRun, createSecurityReviewPlan, getVulnerabilityHypothesis, insertVulnerabilityHypotheses, listExecutableInvariantRuns } from "../packages/db/src";
import { EchidnaInvariantWorkerClient, ExecutableInvariantWorkerClient, InvariantReplayWorkerClient, VerificationWorkspaceBuilder } from "../packages/scanners/src";
import { EchidnaInvariantService } from "../apps/web/lib/verification/echidna-invariant-service";
import { ExecutableInvariantService } from "../apps/web/lib/verification/executable-invariant-service";
import { InvariantProposalService } from "../apps/web/lib/verification/invariant-proposal-service";
import { InvariantReplayService } from "../apps/web/lib/verification/invariant-replay-service";

const repositoryRoot = "/data/repositories", verificationRoot = "/verification", commit = "b".repeat(40), compilerVersion = "0.8.36";
const sources: Record<string, string> = {
  SafeAccounting: "// SPDX-License-Identifier: UNLICENSED\npragma solidity 0.8.36;\ncontract SafeAccounting { uint256 public recorded; uint256 public mirror; function credit(uint256 amount) external { recorded += amount; mirror += amount; } function debit(uint256 amount) external { if (amount > recorded) return; recorded -= amount; mirror -= amount; } }\n",
  VulnerableAccounting: "// SPDX-License-Identifier: UNLICENSED\npragma solidity 0.8.36;\ncontract VulnerableAccounting { uint256 public recorded; uint256 public mirror; function credit(uint256 amount) external { recorded += amount; mirror += amount; } function debit(uint256 amount) external { if (amount > recorded) return; recorded -= amount; } }\n",
  StatefulAccessControl: "// SPDX-License-Identifier: UNLICENSED\npragma solidity 0.8.36;\ncontract StatefulAccessControl { address public owner; constructor() { owner = msg.sender; } function transferOwnership(address nextOwner) external { owner = nextOwner; } function touch(bool) external {} }\n",
};
function requireFact(value: unknown, message: string): asserts value { if (!value) throw new Error(message); }
function plan(scanId: string, hypothesisId: string, name: string) {
  const common = { schemaVersion: "contracthunter-invariant-plan-v1", mode: "stateful-invariant", scanId, hypothesisId, resolvedCommit: commit, compilerVersion, primaryContract: name, primarySourcePath: "contracts/" + name + ".sol", sourceFiles: ["contracts/" + name + ".sol"] };
  if (name === "StatefulAccessControl") return executableInvariantPlanSchema.parse({ ...common, actors: ["deployer", "attacker"], setup: [{ kind: "deploy", contractName: name, instanceName: "target" }], handlerActions: [{ name: "takeOwnership", instanceName: "target", functionName: "transferOwnership", caller: "attacker", parameters: [], args: [{ kind: "address", source: "actor", name: "attacker" }] }], properties: [{ name: "ownerStable", observations: [{ kind: "read-address", instanceName: "target", functionName: "owner", resultName: "observed" }], assertions: [{ id: "owner", kind: "address-eq", actual: "observed", expected: { kind: "address", source: "actor", name: "deployer" } }] }] });
  return executableInvariantPlanSchema.parse({ ...common, actors: [], setup: [{ kind: "deploy", contractName: name, instanceName: "target" }], handlerActions: ["credit", "debit"].map((action) => ({ name: action, instanceName: "target", functionName: action, parameters: [{ name: "amount", type: "uint256" }], args: [{ kind: "parameter", name: "amount" }] })), properties: [{ name: "balanced", observations: [{ kind: "read-uint", instanceName: "target", functionName: "recorded", resultName: "recordedValue" }, { kind: "read-uint", instanceName: "target", functionName: "mirror", resultName: "mirrorValue" }], assertions: [{ id: "same", kind: "uint-eq", actual: "recordedValue", expected: { kind: "result", name: "mirrorValue" } }] }] });
}
async function main() {
  if (process.env.CONTRACTHUNTER_PROBE_ISOLATED !== "1") throw new Error("Isolated Compose probe marker required.");
  const database = createDatabase("/data/contracthunter.db");
  try {
    if (process.env.CONTRACTHUNTER_PROBE_APPEND_FOUNDRY_REPLAY === "1") {
      const fixture = database.sqlite.prepare("SELECT h.id AS hypothesisId, p.id AS proposalId, r.id AS runId FROM vulnerability_hypotheses h JOIN executable_invariant_proposals p ON p.hypothesis_id=h.id JOIN executable_invariant_runs r ON r.hypothesis_id=h.id AND r.plan_hash=p.plan_hash WHERE h.title='VulnerableAccounting probe' AND r.engine='foundry' LIMIT 1").get() as { hypothesisId: string; proposalId: string; runId: string } | undefined;
      requireFact(fixture, "Foundry replay source is missing.");
      const builder = (compilers: string[]) => new VerificationWorkspaceBuilder({ verificationRoot, repositoryRoot, acceptedCompilerVersions: compilers, approvedSourceRoots: ["contracts"], generatorVersion: "0.2.1" });
      const replay = new InvariantReplayService({ database, repositoryRoot, verificationRoot, workspaceBuilder: builder, runner: new InvariantReplayWorkerClient(verificationRoot) });
      const artifact = await replay.generate(fixture.hypothesisId, fixture.proposalId, fixture.runId);
      const replayRun = await replay.execute(fixture.hypothesisId, artifact.id);
      requireFact(replayRun.outcome === "reproduced", "Historical Foundry replay did not reproduce.");
      const review = replay.review(fixture.hypothesisId, fixture.proposalId, fixture.runId, replayRun.id);
      process.stdout.write(JSON.stringify({ historicalFoundryReplay: replayRun.outcome, sourceEngine: artifact.sourceEngine, reviewId: review.id }) + "\n");
      return;
    }
    if (process.env.CONTRACTHUNTER_PROBE_APPEND_UPGRADE_ECHIDNA === "1") {
      const fixture = database.sqlite.prepare("SELECT h.id AS hypothesisId, h.scan_id AS scanId, p.id AS proposalId FROM vulnerability_hypotheses h JOIN executable_invariant_proposals p ON p.hypothesis_id=h.id WHERE h.title='SafeAccounting probe' LIMIT 1").get() as { hypothesisId: string; scanId: string; proposalId: string } | undefined;
      requireFact(fixture, "Historical safe proposal is missing.");
      const repository = path.join(repositoryRoot, fixture.scanId, "contracts"); await mkdir(repository, { recursive: true });
      await writeFile(path.join(repository, "SafeAccounting.sol"), sources.SafeAccounting);
      const proposals = new InvariantProposalService({ database, repositoryRoot, provider: { id: "mock", async generateInvariantProposal() { throw new Error("AI must not run in upgrade probe."); } }, requestedModel: "mock", timeoutMs: 1000, maxSourceBytes: 10000, maxFiles: 3, maxFileBytes: 10000 });
      const builder = (compilers: string[]) => new VerificationWorkspaceBuilder({ verificationRoot, repositoryRoot, acceptedCompilerVersions: compilers, approvedSourceRoots: ["contracts"], generatorVersion: "0.2.1" });
      const echidna = new EchidnaInvariantService({ database, repositoryRoot, proposals, workspaceBuilder: builder, runner: new EchidnaInvariantWorkerClient(verificationRoot) });
      const result = await echidna.run(fixture.hypothesisId, fixture.proposalId);
      process.stdout.write(JSON.stringify({ upgradeAppendedEchidna: { status: result.status, outcome: result.run.outcome, errorCode: result.run.errorCode }, engines: listExecutableInvariantRuns(database, fixture.hypothesisId).map((run) => run.engine), historicalReviewCount: (database.sqlite.prepare("SELECT count(*) AS count FROM invariant_evidence_reviews").get() as { count: number }).count }) + "\n");
      return;
    }
    if (process.env.CONTRACTHUNTER_PROBE_REPLAY_OLD_FOUNDRY === "1") {
      const fixture = database.sqlite.prepare("SELECT id AS artifactId, scan_id AS scanId, hypothesis_id AS hypothesisId FROM invariant_replay_artifacts WHERE source_engine='foundry' LIMIT 1").get() as { artifactId: string; scanId: string; hypothesisId: string } | undefined;
      requireFact(fixture, "Historical Foundry artifact is missing.");
      const repository = path.join(repositoryRoot, fixture.scanId, "contracts"); await mkdir(repository, { recursive: true });
      await writeFile(path.join(repository, "VulnerableAccounting.sol"), sources.VulnerableAccounting);
      const builder = (compilers: string[]) => new VerificationWorkspaceBuilder({ verificationRoot, repositoryRoot, acceptedCompilerVersions: compilers, approvedSourceRoots: ["contracts"], generatorVersion: "0.2.1" });
      const replay = new InvariantReplayService({ database, repositoryRoot, verificationRoot, workspaceBuilder: builder, runner: new InvariantReplayWorkerClient(verificationRoot) });
      const result = await replay.execute(fixture.hypothesisId, fixture.artifactId);
      process.stdout.write(JSON.stringify({ historicalFoundryReplayAfterUpgrade: result.outcome, errorCode: result.errorCode, historicalReviewCount: (database.sqlite.prepare("SELECT count(*) AS count FROM invariant_evidence_reviews").get() as { count: number }).count }) + "\n");
      return;
    }
    requireFact((database.sqlite.prepare("SELECT count(*) AS count FROM scans").get() as { count: number }).count === 0, "Probe requires empty isolated database.");
    const scan = createScan(database, { repositoryUrl: "https://example.invalid/m2", repositoryName: "isolated/m2", depth: "quick" });
    const repository = path.join(repositoryRoot, scan.id); await mkdir(path.join(repository, "contracts"), { recursive: true });
    for (const [name, source] of Object.entries(sources)) await writeFile(path.join(repository, "contracts", name + ".sol"), source);
    database.sqlite.prepare("UPDATE scans SET status='completed', resolved_commit=?, compiler_status='ready', compiler_versions=? WHERE id=?").run(commit, JSON.stringify([compilerVersion]), scan.id);
    const analysis = createProtocolAnalysis(database, { scanId: scan.id, provider: "mock", requestedModel: "mock", actualModel: "mock", promptVersion: "protocol-analysis-v1", result: validAIOutput as unknown as ProtocolAnalysisResult, coverageStatus: "complete", contextManifest: {}, durationMs: 1, inputTokens: 0, outputTokens: 0, totalTokens: 0, requestId: randomUUID() });
    const review = createSecurityReviewPlan(database, { scanId: scan.id, protocolAnalysisId: analysis.id, plan: { selected: [], skipped: [], estimatedRequestCount: 0 }, estimatedSourceBytes: 0 });
    const reviewer = createSecurityReviewerRun(database, { planId: review.id, scanId: scan.id, protocolAnalysisId: analysis.id, reviewerId: "fixture", reviewerName: "Fixture", selectionReason: "Isolated probe", promptVersion: "security-review-fixture-v1", provider: "mock", requestedModel: "mock", contextManifest: {} });
    const proposals = new InvariantProposalService({ database, repositoryRoot, provider: { id: "mock", async generateInvariantProposal() { throw new Error("AI must not run in worker probe."); } }, requestedModel: "mock", timeoutMs: 1000, maxSourceBytes: 10000, maxFiles: 3, maxFileBytes: 10000 });
    const builder = (compilers: string[]) => new VerificationWorkspaceBuilder({ verificationRoot, repositoryRoot, acceptedCompilerVersions: compilers, approvedSourceRoots: ["contracts"], generatorVersion: "0.2.1" });
    const foundry = new ExecutableInvariantService({ database, repositoryRoot, workspaceBuilder: builder, runner: new ExecutableInvariantWorkerClient(verificationRoot) });
    const echidna = new EchidnaInvariantService({ database, repositoryRoot, proposals, workspaceBuilder: builder, runner: new EchidnaInvariantWorkerClient(verificationRoot) });
    const replay = new InvariantReplayService({ database, repositoryRoot, verificationRoot, workspaceBuilder: builder, runner: new InvariantReplayWorkerClient(verificationRoot) });
    for (const name of Object.keys(sources)) {
      const hypothesis = insertVulnerabilityHypotheses(database, [{ scanId: scan.id, protocolAnalysisId: analysis.id, reviewerId: reviewer.reviewerId, reviewerRunId: reviewer.id, title: name + " probe", category: "state-transition", severity: "low", severityJustification: "Fixture", confidence: 50, summary: "Fixture", rootCause: "Fixture", preconditions: "[]", attackPath: "[]", impact: "Fixture", affectedAssets: "[]", affectedContracts: JSON.stringify([name]), affectedFunctions: "[]", evidence: "[]", violatedInvariantIds: "[]", relatedInvestigationIds: "[]", falsePositiveRisks: "[]", verificationStrategy: "[]" }])[0];
      const invariant = plan(scan.id, hypothesis.id, name), sourcePath = "contracts/" + name + ".sol", source = sources[name];
      const proposal = createExecutableInvariantProposal(database, { hypothesisId: hypothesis.id, scanId: scan.id, result: { status: "generated", plan: invariant, planHash: invariantPlanHash(invariant), hypothesisExpectation: "hypothesis-predicts-property-violation", relationRationale: "Fixture property relation.", rationale: "Isolated worker probe.", limitations: [], notPlannableReasons: [], failureCode: null, provenance: { provider: "mock", requestedModel: "mock", actualModel: "mock", promptVersion: "invariant-plan-v1", generatedAt: new Date().toISOString(), inputTokens: 0, outputTokens: 0, totalTokens: 0, estimatedCostUsd: 0, durationMs: 1, sourceFileCount: 1, totalSourceBytes: Buffer.byteLength(source), sourceContextTruncated: false } }, contextManifest: { files: [{ path: sourcePath, truncated: false }], sourceHashes: { [sourcePath]: createHash("sha256").update(source).digest("hex") }, totalSourceBytes: Buffer.byteLength(source), truncated: false }, requestId: null });
      const validated = await proposals.validate(hypothesis.id, proposal.id);
      const foundryResult = await foundry.run(hypothesis.id, validated.plan, proposal.id);
      const output: Record<string, unknown> = { name, foundry: { status: foundryResult.status, outcome: foundryResult.run.outcome, errorCode: foundryResult.run.errorCode }, compatibility: validated.compatibility };
      if (name === "StatefulAccessControl") {
        requireFact(!validated.compatibility.echidna.compatible && validated.compatibility.echidna.reasons.includes("explicit-caller-unsupported"), "Explicit caller incompatibility missing.");
        try { await echidna.run(hypothesis.id, proposal.id); throw new Error("Incompatible Echidna run accepted."); } catch (error) { requireFact(error instanceof Error && error.message.includes("explicit-caller-unsupported"), "Wrong incompatible-plan rejection."); }
        output.echidnaRunCount = listExecutableInvariantRuns(database, hypothesis.id).filter((run) => run.engine === "echidna").length;
      } else {
        requireFact(validated.compatibility.echidna.compatible, name + " incompatible");
        const echidnaResult = await echidna.run(hypothesis.id, proposal.id);
        output.echidna = { status: echidnaResult.status, outcome: echidnaResult.run.outcome, errorCode: echidnaResult.run.errorCode, evidence: JSON.parse(echidnaResult.run.dynamicEvidence) };
        output.runCount = listExecutableInvariantRuns(database, hypothesis.id).length;
        output.statusBeforeReview = getVulnerabilityHypothesis(database, hypothesis.id)?.status;
        if (name === "VulnerableAccounting" && echidnaResult.run.outcome === "counterexample-found") {
          const artifact = await replay.generate(hypothesis.id, proposal.id, echidnaResult.run.id);
          const replayRun = await replay.execute(hypothesis.id, artifact.id);
          output.replay = { sourceEngine: artifact.sourceEngine, outcome: replayRun.outcome, errorCode: replayRun.errorCode };
          if (replayRun.outcome === "reproduced") { const reviewed = replay.review(hypothesis.id, proposal.id, echidnaResult.run.id, replayRun.id); output.review = { evidenceId: reviewed.evidenceId, hypothesisStatus: getVulnerabilityHypothesis(database, hypothesis.id)?.status }; }
        }
      }
      process.stdout.write(JSON.stringify(output) + "\n");
    }
  } finally { closeDatabase(database); }
}
main().catch((error) => { process.stderr.write((error instanceof Error ? error.stack : String(error)) + "\n"); process.exitCode = 1; });
