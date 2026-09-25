import { lstat, realpath } from "node:fs/promises";
import path from "node:path";
import { executableInvariantPlanSchema, invariantPlanHash, loadConfig, stableCompilerVersionSchema, type ExecutableInvariantPlan, type ExecutableInvariantExecutionManifest } from "@contracthunter/core";
import { completeExecutableInvariantRun, createExecutableInvariantRun, failExecutableInvariantRun, getActiveExecutableInvariantRun, getDatabase, getScan, getVulnerabilityHypothesis, markExecutableInvariantRunRunning, type DatabaseClient, type ExecutableInvariantRunRow } from "@contracthunter/db";
import { ExecutableInvariantWorkerClient, VerificationWorkspaceBuilder, interpretInvariantFacts, validateExecutableInvariantWorkspaceIntegrity, type ExecutableInvariantWorkerInput, type ExecutableInvariantWorkerResult } from "@contracthunter/scanners";

export class ExecutableInvariantRequestError extends Error {
  constructor(readonly code: "invalid_plan" | "unknown_hypothesis" | "invalid_state" | "state_mismatch", message: string) { super(message); this.name = "ExecutableInvariantRequestError"; }
}
type Built = Awaited<ReturnType<VerificationWorkspaceBuilder["buildInvariant"]>>;
export type ExecutableInvariantServiceOptions = {
  database: DatabaseClient; repositoryRoot: string;
  workspaceBuilder: (compilers: string[]) => { buildInvariant(input: { workspaceId: string; repositoryPath: string; plan: ExecutableInvariantPlan }): Promise<Built> };
  runner: { run(input: ExecutableInvariantWorkerInput): Promise<ExecutableInvariantWorkerResult> };
  validateIntegrity?: (path: string) => Promise<ExecutableInvariantExecutionManifest>;
};
export class ExecutableInvariantService {
  constructor(private readonly options: ExecutableInvariantServiceOptions) {}
  private async bind(hypothesisId: string, rawPlan: unknown): Promise<{ plan: ExecutableInvariantPlan; repositoryPath: string; compilers: string[] }> {
    const parsed = executableInvariantPlanSchema.safeParse(rawPlan);
    if (!parsed.success) throw new ExecutableInvariantRequestError("invalid_plan", "Executable invariant plan is invalid.");
    const plan = parsed.data, hypothesis = getVulnerabilityHypothesis(this.options.database, hypothesisId);
    if (!hypothesis) throw new ExecutableInvariantRequestError("unknown_hypothesis", "Hypothesis not found.");
    if (hypothesis.status === "rejected") throw new ExecutableInvariantRequestError("invalid_state", "Rejected hypotheses cannot receive invariant runs.");
    const scan = getScan(this.options.database, hypothesis.scanId);
    if (!scan || scan.status !== "completed" || !scan.resolvedCommit || !["ready", "cached"].includes(scan.compilerStatus)) throw new ExecutableInvariantRequestError("invalid_state", "A completed scan with trusted compiler is required.");
    if (plan.hypothesisId !== hypothesis.id || plan.scanId !== scan.id || plan.resolvedCommit !== scan.resolvedCommit) throw new ExecutableInvariantRequestError("state_mismatch", "Invariant plan identity differs from persisted scan state.");
    let rawCompilers: unknown;
    try { rawCompilers = JSON.parse(scan.compilerVersions ?? "null"); } catch { throw new ExecutableInvariantRequestError("invalid_state", "Trusted compiler selection is malformed."); }
    const parsedCompilers = stableCompilerVersionSchema.array().min(1).max(32).safeParse(rawCompilers);
    if (!parsedCompilers.success || !parsedCompilers.data.includes(plan.compilerVersion)) throw new ExecutableInvariantRequestError("state_mismatch", "Invariant compiler was not accepted for the scan.");
    const root = await realpath(this.options.repositoryRoot).catch(() => { throw new ExecutableInvariantRequestError("invalid_state", "Repository root is unavailable."); });
    const expected = path.join(root, scan.id), info = await lstat(expected).catch(() => { throw new ExecutableInvariantRequestError("invalid_state", "Prepared repository is unavailable."); });
    if (!info.isDirectory() || info.isSymbolicLink() || await realpath(expected) !== expected) throw new ExecutableInvariantRequestError("invalid_state", "Prepared repository path is unsafe.");
    return { plan, repositoryPath: expected, compilers: parsedCompilers.data };
  }
  async run(hypothesisId: string, rawPlan: unknown): Promise<{ status: "completed" | "failed" | "conflict"; run: ExecutableInvariantRunRow }> {
    const bound = await this.bind(hypothesisId, rawPlan);
    const active = getActiveExecutableInvariantRun(this.options.database, hypothesisId);
    if (active) return { status: "conflict", run: active };
    let run: ExecutableInvariantRunRow;
    try { run = createExecutableInvariantRun(this.options.database, { plan: bound.plan }); }
    catch (error) { const concurrent = getActiveExecutableInvariantRun(this.options.database, hypothesisId); if (concurrent) return { status: "conflict", run: concurrent }; throw error; }
    markExecutableInvariantRunRunning(this.options.database, run.id);
    const started = Date.now(); let built: Built | undefined; let result: ExecutableInvariantWorkerResult | undefined;
    try {
      built = await this.options.workspaceBuilder(bound.compilers).buildInvariant({ workspaceId: run.id, repositoryPath: bound.repositoryPath, plan: bound.plan });
      const manifest = await (this.options.validateIntegrity ?? validateExecutableInvariantWorkspaceIntegrity)(built.workspacePath);
      if (JSON.stringify(manifest) !== JSON.stringify(built.manifest) || manifest.planHash !== invariantPlanHash(bound.plan)) throw new Error("invariant_manifest_mismatch");
      result = await this.options.runner.run({ workspacePath: built.workspacePath, scanId: bound.plan.scanId, hypothesisId, resolvedCommit: bound.plan.resolvedCommit, compilerVersion: bound.plan.compilerVersion, planHash: built.manifest.planHash, mode: bound.plan.mode });
      if (result.status !== "completed" || !result.isolation || result.mode !== bound.plan.mode || result.planHash !== built.manifest.planHash || result.timedOut || result.outputTruncated || result.errorCode || result.runsExecuted === null || result.testCount === null || result.passedCount === null || result.failedCount === null || result.exitCode === null || (result.failedCount === 0 ? result.exitCode !== 0 : result.exitCode === 0)) {
        const failed = failExecutableInvariantRun(this.options.database, run.id, { errorCode: result.errorCode ?? "invariant_result_unparseable", durationMs: result.durationMs, stdoutSummary: result.stdoutSummary.slice(0, 4096), stderrSummary: result.stderrSummary.slice(0, 4096), contentFingerprint: built.manifest.contentFingerprint, isolationMetadata: result.isolation ? JSON.stringify(result.isolation).slice(0, 4096) : null, exitCode: result.exitCode, timedOut: result.timedOut });
        return { status: "failed", run: failed };
      }
      const evidence = interpretInvariantFacts(bound.plan, { testCount: result.testCount, passedCount: result.passedCount, failedCount: result.failedCount, runsExecuted: result.runsExecuted, tests: result.tests }, result.isolation.providerId);
      const completed = completeExecutableInvariantRun(this.options.database, run.id, { evidence, testCount: result.testCount, passedCount: result.passedCount, failedCount: result.failedCount, runsExecuted: result.runsExecuted,
        stdoutSummary: result.stdoutSummary.slice(0, 4096), stderrSummary: result.stderrSummary.slice(0, 4096), contentFingerprint: built.manifest.contentFingerprint, isolationMetadata: JSON.stringify(result.isolation).slice(0, 4096), exitCode: result.exitCode ?? -1, durationMs: result.durationMs });
      return { status: "completed", run: completed };
    } catch (error) {
      const reason = error instanceof Error && /^[a-z_]{1,80}$/.test(error.message) ? error.message : "invariant_workspace_invalid";
      const failed = failExecutableInvariantRun(this.options.database, run.id, { errorCode: reason, durationMs: result?.durationMs ?? Date.now() - started, stdoutSummary: result?.stdoutSummary.slice(0, 4096), stderrSummary: result?.stderrSummary.slice(0, 4096), contentFingerprint: built?.manifest.contentFingerprint ?? null, isolationMetadata: result?.isolation ? JSON.stringify(result.isolation).slice(0, 4096) : null, exitCode: result?.exitCode ?? null, timedOut: result?.timedOut ?? false });
      return { status: "failed", run: failed };
    }
  }
}
export function createLocalExecutableInvariantService(database: DatabaseClient = getDatabase()): ExecutableInvariantService {
  const config = loadConfig(), verificationRoot = process.env.VERIFICATION_ROOT ?? path.join(config.DATA_DIR, "verifications");
  return new ExecutableInvariantService({ database, repositoryRoot: config.REPOSITORY_DIR, runner: new ExecutableInvariantWorkerClient(verificationRoot),
    workspaceBuilder: (acceptedCompilerVersions) => new VerificationWorkspaceBuilder({ verificationRoot, repositoryRoot: config.REPOSITORY_DIR, acceptedCompilerVersions, approvedSourceRoots: ["src", "contracts", "lib", "node_modules"], generatorVersion: "0.2.0" }) });
}
