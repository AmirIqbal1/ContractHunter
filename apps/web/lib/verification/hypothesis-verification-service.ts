import { lstat, realpath } from "node:fs/promises";
import path from "node:path";
import { loadConfig, sourceEvidenceSchema, stableCompilerVersionSchema, validateEvidence, verificationHarnessPlanSchema, type VerificationHarnessManifest, type VerificationHarnessPlan } from "@contracthunter/core";
import {
  completeHypothesisVerificationRun, createHypothesisVerificationRun, failHypothesisVerificationRun, getActiveHypothesisVerificationRun,
  getDatabase, getScan, getVulnerabilityHypothesis, markHypothesisVerificationRunRunning,
  type DatabaseClient, type HypothesisVerificationRunRow,
} from "@contracthunter/db";
import {
  FoundryVerificationRunner, VerificationWorkspaceBuilder, interpretVerificationResult, validateVerificationWorkspaceIntegrity,
  type BuiltVerificationWorkspace, type FoundryVerificationInput, type FoundryVerificationResult,
} from "@contracthunter/scanners";

export type HypothesisVerificationRequestResult =
  | { status: "completed" | "failed"; run: HypothesisVerificationRunRow }
  | { status: "conflict"; run: HypothesisVerificationRunRow };

export class HypothesisVerificationRequestError extends Error {
  constructor(readonly code: "invalid_plan" | "unknown_hypothesis" | "invalid_state" | "state_mismatch", message: string) {
    super(message); this.name = "HypothesisVerificationRequestError";
  }
}

type WorkspaceBuilder = { build(input: { verificationRunId: string; repositoryPath: string; plan: VerificationHarnessPlan }): Promise<BuiltVerificationWorkspace> };
type VerificationRunner = { run(input: FoundryVerificationInput): Promise<FoundryVerificationResult> };

export type HypothesisVerificationServiceOptions = {
  database: DatabaseClient;
  repositoryRoot: string;
  workspaceBuilder: (acceptedCompilerVersions: string[]) => WorkspaceBuilder;
  runner: VerificationRunner;
  validateIntegrity?: (workspacePath: string, manifest?: VerificationHarnessManifest) => Promise<VerificationHarnessManifest>;
  timeoutMs: number;
  maxOutputBytes: number;
  verifierId?: string;
  generatorVersion?: string;
};

function acceptedCompilerVersions(raw: string | null): string[] {
  let value: unknown;
  try { value = raw === null ? null : JSON.parse(raw); }
  catch { throw new HypothesisVerificationRequestError("invalid_state", "The scan compiler state is malformed."); }
  const parsed = stableCompilerVersionSchema.array().min(1).max(32).safeParse(value);
  if (!parsed.success) throw new HypothesisVerificationRequestError("invalid_state", "The scan has no trusted compiler selection.");
  return [...new Set(parsed.data)];
}

function validatePersistedEvidence(repositoryPath: string, raw: string): void {
  let evidence: unknown;
  try { evidence = JSON.parse(raw); }
  catch { throw new HypothesisVerificationRequestError("invalid_state", "Persisted hypothesis evidence is malformed."); }
  if (!Array.isArray(evidence) || evidence.length === 0) throw new HypothesisVerificationRequestError("invalid_state", "Persisted hypothesis evidence is missing or malformed.");
  for (const item of evidence) {
    if (!item || typeof item !== "object") throw new HypothesisVerificationRequestError("invalid_state", "Persisted hypothesis evidence is malformed.");
    const record = item as Record<string, unknown>;
    const parsed = sourceEvidenceSchema.safeParse({ filePath: record.filePath, contract: record.contract, functionName: record.functionName, startLine: record.startLine, endLine: record.endLine });
    if (!parsed.success || !validateEvidence(repositoryPath, parsed.data).valid) throw new HypothesisVerificationRequestError("invalid_state", "Hypothesis evidence does not belong to the prepared scanned repository.");
  }
}

export class HypothesisVerificationService {
  private readonly validateIntegrity: NonNullable<HypothesisVerificationServiceOptions["validateIntegrity"]>;

  constructor(private readonly options: HypothesisVerificationServiceOptions) {
    this.validateIntegrity = options.validateIntegrity ?? validateVerificationWorkspaceIntegrity;
  }

  private async bind(hypothesisId: string, rawPlan: unknown): Promise<{ plan: VerificationHarnessPlan; repositoryPath: string; compilers: string[] }> {
    const parsed = verificationHarnessPlanSchema.safeParse(rawPlan);
    if (!parsed.success) throw new HypothesisVerificationRequestError("invalid_plan", "The verification plan is invalid.");
    const plan = parsed.data;
    const hypothesis = getVulnerabilityHypothesis(this.options.database, hypothesisId);
    if (!hypothesis) throw new HypothesisVerificationRequestError("unknown_hypothesis", "Vulnerability hypothesis not found.");
    if (hypothesis.status === "rejected") throw new HypothesisVerificationRequestError("invalid_state", "Rejected hypotheses cannot be verified.");
    const scan = getScan(this.options.database, hypothesis.scanId);
    if (!scan || scan.status !== "completed" || !scan.resolvedCommit) throw new HypothesisVerificationRequestError("invalid_state", "The hypothesis scan is not completed at a resolved commit.");
    if (plan.hypothesisId !== hypothesis.id || plan.scanId !== hypothesis.scanId || plan.resolvedCommit !== scan.resolvedCommit) throw new HypothesisVerificationRequestError("state_mismatch", "The verification plan does not match persisted hypothesis and scan state.");
    if (scan.compilerStatus !== "ready" && scan.compilerStatus !== "cached") throw new HypothesisVerificationRequestError("invalid_state", "The scan compiler state is not trusted and ready.");
    const compilers = acceptedCompilerVersions(scan.compilerVersions);
    if (!compilers.includes(plan.compilerVersion)) throw new HypothesisVerificationRequestError("state_mismatch", "The verification compiler was not accepted for this scan.");
    const root = await realpath(this.options.repositoryRoot).catch(() => { throw new HypothesisVerificationRequestError("invalid_state", "The repository root is unavailable."); });
    const expected = path.join(root, scan.id);
    const info = await lstat(expected).catch(() => { throw new HypothesisVerificationRequestError("invalid_state", "The prepared scanned repository is unavailable."); });
    if (!info.isDirectory() || info.isSymbolicLink()) throw new HypothesisVerificationRequestError("invalid_state", "The prepared scanned repository is unsafe.");
    const repositoryPath = await realpath(expected);
    if (repositoryPath !== expected || !repositoryPath.startsWith(`${root}${path.sep}`)) throw new HypothesisVerificationRequestError("invalid_state", "The prepared scanned repository is unsafe.");
    validatePersistedEvidence(repositoryPath, hypothesis.evidence);
    return { plan, repositoryPath, compilers };
  }

  async run(hypothesisId: string, rawPlan: unknown): Promise<HypothesisVerificationRequestResult> {
    const bound = await this.bind(hypothesisId, rawPlan);
    const active = getActiveHypothesisVerificationRun(this.options.database, hypothesisId);
    if (active) return { status: "conflict", run: active };
    let run: HypothesisVerificationRunRow;
    try {
      run = createHypothesisVerificationRun(this.options.database, {
        hypothesisId, scanId: bound.plan.scanId, resolvedCommit: bound.plan.resolvedCommit, compilerVersion: bound.plan.compilerVersion,
        verificationPlan: bound.plan, verifierId: this.options.verifierId ?? "contracthunter-local-verification",
        toolName: "forge", toolVersion: null, verificationStrategy: bound.plan.verificationSteps,
      });
    } catch (error) {
      const concurrent = getActiveHypothesisVerificationRun(this.options.database, hypothesisId);
      if (concurrent) return { status: "conflict", run: concurrent };
      throw error;
    }
    const startedAt = Date.now(); let built: BuiltVerificationWorkspace | undefined; let result: FoundryVerificationResult | undefined;
    markHypothesisVerificationRunRunning(this.options.database, run.id);
    try {
      built = await this.options.workspaceBuilder(bound.compilers).build({ verificationRunId: run.id, repositoryPath: bound.repositoryPath, plan: bound.plan });
      const validatedManifest = await this.validateIntegrity(built.workspacePath);
      if (JSON.stringify(validatedManifest) !== JSON.stringify(built.manifest)) throw new Error("workspace_manifest_mismatch");
      result = await this.options.runner.run({ workspacePath: built.workspacePath, scanId: bound.plan.scanId, hypothesisId, resolvedCommit: bound.plan.resolvedCommit, compilerVersion: bound.plan.compilerVersion, timeoutMs: this.options.timeoutMs, maxOutputBytes: this.options.maxOutputBytes });
      const interpretation = interpretVerificationResult(bound.plan, result);
      const semanticAssertionFailure = result.status === "failed" && result.errorCode === "forge_failed" && interpretation.dynamicEvidence.some((item) => item.direction !== "neutral");
      if (result.status === "refused" || result.timedOut || (result.status === "failed" && !semanticAssertionFailure)) {
        const failed = failHypothesisVerificationRun(this.options.database, run.id, {
          error: result.errorCode ?? "verification_execution_failed", durationMs: result.durationMs, stdoutSummary: result.stdoutSummary, stderrSummary: result.stderrSummary,
          contentFingerprint: built.manifest.contentFingerprint, isolationBackend: result.isolation?.providerId ?? null, executionExitCode: result.exitCode, timedOut: result.timedOut,
        });
        return { status: "failed", run: failed };
      }
      if (!result.isolation) throw new Error("missing_isolation_audit");
      const completed = completeHypothesisVerificationRun(this.options.database, run.id, {
        outcome: interpretation.outcome, resultSummary: interpretation.resultSummary, durationMs: result.durationMs,
        testCount: result.testCount ?? 0, passedTestCount: result.passedCount ?? 0, failedTestCount: result.failedCount ?? 0,
        stdoutSummary: result.stdoutSummary, stderrSummary: result.stderrSummary, dynamicEvidence: interpretation.dynamicEvidence,
        contentFingerprint: built.manifest.contentFingerprint, isolationBackend: result.isolation.providerId, executionExitCode: result.exitCode ?? 0, timedOut: false,
      });
      return { status: "completed", run: completed };
    } catch (error) {
      const reason = error instanceof Error && error.message === "missing_isolation_audit" ? "invalid_isolation_metadata"
        : built ? "workspace_integrity_or_execution_failed" : "workspace_generation_failed";
      const failed = failHypothesisVerificationRun(this.options.database, run.id, {
        error: reason, durationMs: result?.durationMs ?? Date.now() - startedAt, stdoutSummary: result?.stdoutSummary ?? "", stderrSummary: result?.stderrSummary ?? "",
        contentFingerprint: built?.manifest.contentFingerprint ?? null, isolationBackend: result?.isolation?.providerId ?? null, executionExitCode: result?.exitCode ?? null, timedOut: result?.timedOut ?? false,
      });
      return { status: "failed", run: failed };
    }
  }
}

export function createLocalHypothesisVerificationService(database: DatabaseClient = getDatabase()): HypothesisVerificationService {
  const config = loadConfig(); const verificationRoot = path.join(config.DATA_DIR, "verifications"); const temporaryDirectory = path.join(config.DATA_DIR, "verification-tmp");
  const runner = new FoundryVerificationRunner({ verificationRoot, repositoryRoot: config.REPOSITORY_DIR, toolHomeDir: config.TOOL_HOME_DIR, temporaryDirectory, executablePath: process.env.PATH ?? "/usr/local/bin:/usr/bin:/bin" });
  return new HypothesisVerificationService({
    database, repositoryRoot: config.REPOSITORY_DIR, timeoutMs: 300_000, maxOutputBytes: config.SCANNER_MAX_OUTPUT_BYTES, runner,
    workspaceBuilder: (acceptedCompilerVersions) => new VerificationWorkspaceBuilder({ verificationRoot, repositoryRoot: config.REPOSITORY_DIR, acceptedCompilerVersions, approvedSourceRoots: ["src", "contracts", "lib", "node_modules"], generatorVersion: "0.1.0" }),
  });
}
