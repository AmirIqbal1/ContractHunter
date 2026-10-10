import path from "node:path";
import { ECHIDNA_BINARY_SHA256, ECHIDNA_BUILD_ID, ECHIDNA_COMPAT_VERSION, ECHIDNA_UPSTREAM_VERSION, echidnaSeed, invariantPlanHash, loadConfig, type EchidnaInvariantManifest, type ResolvedAuthoritativeSourceClosure } from "@contracthunter/core";
import { completeExecutableInvariantRun, createExecutableInvariantRun, failExecutableInvariantRun, getActiveExecutableInvariantRun, getDatabase, getVulnerabilityHypothesis, markExecutableInvariantRunRunning, setEchidnaInvariantRunMetadata, type DatabaseClient, type ExecutableInvariantRunRow } from "@contracthunter/db";
import { EchidnaInvariantWorkerClient, VerificationWorkspaceBuilder, interpretEchidnaFacts, validateEchidnaInvariantWorkspaceIntegrity, type EchidnaInvariantWorkerInput, type EchidnaInvariantWorkerResult } from "@contracthunter/scanners";
import { createInvariantProposalService, type InvariantProposalService } from "./invariant-proposal-service";
import { sourceAuthorityForHypothesis } from "./authoritative-source-authority";

export class EchidnaInvariantRequestError extends Error {
  constructor(readonly code: "echidna_plan_incompatible" | "echidna_execution_unavailable", message: string) { super(message); this.name = "EchidnaInvariantRequestError"; }
}
type Built = Awaited<ReturnType<VerificationWorkspaceBuilder["buildEchidnaInvariant"]>>;
type WorkerResult = EchidnaInvariantWorkerResult | { status: "refused"; errorCode: string };
export type EchidnaInvariantServiceOptions = {
  database: DatabaseClient; repositoryRoot: string;
  proposals: Pick<InvariantProposalService, "validate">;
  workspaceBuilder: (compilers: string[]) => { buildEchidnaInvariant(input: { workspaceId: string; repositoryPath: string; plan: Awaited<ReturnType<InvariantProposalService["validate"]>>["plan"]; authoritativeClosure?: ResolvedAuthoritativeSourceClosure }): Promise<Built> };
  runner: { run(input: EchidnaInvariantWorkerInput): Promise<WorkerResult> };
  validateIntegrity?: (workspacePath: string) => Promise<EchidnaInvariantManifest>;
};
export class EchidnaInvariantService {
  constructor(private readonly options: EchidnaInvariantServiceOptions) {}
  async run(hypothesisId: string, proposalId: string): Promise<{ status: "completed" | "failed" | "conflict"; run: ExecutableInvariantRunRow }> {
    const validated = await this.options.proposals.validate(hypothesisId, proposalId);
    if (!validated.compatibility.echidna.compatible) throw new EchidnaInvariantRequestError("echidna_plan_incompatible", `Echidna is incompatible: ${validated.compatibility.echidna.reasons.join(", ")}`);
    const plan = validated.plan;
    const hypothesis = getVulnerabilityHypothesis(this.options.database, hypothesisId);
    if (!hypothesis) throw new EchidnaInvariantRequestError("echidna_plan_incompatible", "Hypothesis is unavailable.");
    const authority = sourceAuthorityForHypothesis(this.options.database, hypothesis, { sourceUnitName: plan.primarySourcePath, contract: plan.primaryContract });
    if (plan.mode !== "stateful-invariant") throw new EchidnaInvariantRequestError("echidna_plan_incompatible", "Echidna requires a compatible stateful invariant plan.");
    const active = getActiveExecutableInvariantRun(this.options.database, hypothesisId);
    if (active) return { status: "conflict", run: active };
    let run: ExecutableInvariantRunRow;
    try { run = createExecutableInvariantRun(this.options.database, { plan, proposalId, engine: "echidna" }); }
    catch (error) { const concurrent = getActiveExecutableInvariantRun(this.options.database, hypothesisId); if (concurrent) return { status: "conflict", run: concurrent }; throw error; }
    markExecutableInvariantRunRunning(this.options.database, run.id);
    const started = Date.now(); let built: Built | undefined; let result: WorkerResult | undefined;
    try {
      built = await this.options.workspaceBuilder([plan.compilerVersion]).buildEchidnaInvariant({ workspaceId: run.id, repositoryPath: path.join(this.options.repositoryRoot, plan.scanId), plan, ...(authority.kind === "authoritative" ? { authoritativeClosure: authority.closure } : {}) });
      const manifest = await (this.options.validateIntegrity ?? validateEchidnaInvariantWorkspaceIntegrity)(built.workspacePath);
      if (JSON.stringify(manifest) !== JSON.stringify(built.manifest) || manifest.planHash !== invariantPlanHash(plan) || manifest.workspaceId !== run.id) throw new Error("echidna_manifest_mismatch");
      setEchidnaInvariantRunMetadata(this.options.database, run.id, { upstreamVersion: manifest.echidnaVersion, compatibilityBuildId: manifest.buildId, binarySha256: manifest.binaryHash, configHash: manifest.configHash, harnessHash: manifest.harnessHash, seed: manifest.settings.seed, manifestFingerprint: manifest.contentFingerprint });
      result = await this.options.runner.run({ workspacePath: built.workspacePath, scanId: plan.scanId, hypothesisId, resolvedCommit: plan.resolvedCommit, compilerVersion: plan.compilerVersion, planHash: manifest.planHash });
      if (result.status === "refused") throw new Error(result.errorCode);
      if (result.status !== "completed" || result.errorCode || result.timedOut || result.outputTruncated || !result.isolation || result.planHash !== manifest.planHash || result.seed !== echidnaSeed(manifest.planHash) || result.binaryHash !== ECHIDNA_BINARY_SHA256 || result.echidnaVersion !== ECHIDNA_UPSTREAM_VERSION || result.compatibilityVersion !== ECHIDNA_COMPAT_VERSION || result.buildId !== ECHIDNA_BUILD_ID || result.tests.length !== plan.properties.length || new Set(result.tests.map((test) => test.propertyName)).size !== plan.properties.length || result.campaignStopReason === null || result.executedCalls === null || result.tests.some((test) => !plan.properties.some((property) => property.name === test.propertyName))) throw new Error(result.errorCode ?? "echidna_result_unparseable");
      const expectedExit = result.tests.some((test) => test.outcome === "execution-failed" || test.outcome === "inconclusive") ? 2 : result.tests.some((test) => test.outcome === "counterexample-found") ? 1 : 0;
      if (result.exitCode !== expectedExit) throw new Error("echidna_result_unparseable");
      const evidence = interpretEchidnaFacts(plan, { seed: result.seed!, executedCalls: result.executedCalls!, campaignStopReason: result.campaignStopReason!, tests: result.tests }, result.isolation.providerId);
      const passedCount = evidence.filter((item) => item.propertyOutcome === "held-within-bounds").length, failedCount = evidence.filter((item) => item.propertyOutcome === "counterexample-found").length;
      const completed = completeExecutableInvariantRun(this.options.database, run.id, { evidence, testCount: evidence.length, passedCount, failedCount, runsExecuted: evidence.reduce((sum, item) => sum + item.runsExecuted, 0), stdoutSummary: result.stdoutSummary, stderrSummary: result.stderrSummary, contentFingerprint: manifest.contentFingerprint, isolationMetadata: JSON.stringify(result.isolation).slice(0, 4096), exitCode: result.exitCode, durationMs: result.durationMs });
      return { status: "completed", run: completed };
    } catch (error) {
      const code = error instanceof Error && /^[a-z_]{1,80}$/.test(error.message) ? error.message : "echidna_workspace_invalid";
      const actual = result && result.status !== "refused" ? result : undefined;
      const failed = failExecutableInvariantRun(this.options.database, run.id, { errorCode: code, durationMs: actual?.durationMs ?? Date.now() - started, stdoutSummary: actual?.stdoutSummary, stderrSummary: actual?.stderrSummary, contentFingerprint: built?.manifest.contentFingerprint, isolationMetadata: actual?.isolation ? JSON.stringify(actual.isolation).slice(0, 4096) : null, exitCode: actual?.exitCode, timedOut: actual?.timedOut });
      return { status: "failed", run: failed };
    }
  }
}
export function createEchidnaInvariantService(database: DatabaseClient = getDatabase()): EchidnaInvariantService {
  const config = loadConfig(), verificationRoot = process.env.VERIFICATION_ROOT ?? path.join(config.DATA_DIR, "verifications");
  return new EchidnaInvariantService({ database, repositoryRoot: config.REPOSITORY_DIR, proposals: createInvariantProposalService(database), runner: new EchidnaInvariantWorkerClient(verificationRoot), workspaceBuilder: (acceptedCompilerVersions) => new VerificationWorkspaceBuilder({ verificationRoot, repositoryRoot: config.REPOSITORY_DIR, acceptedCompilerVersions, approvedSourceRoots: ["src", "contracts", "lib", "node_modules"], generatorVersion: "0.2.1" }) });
}
