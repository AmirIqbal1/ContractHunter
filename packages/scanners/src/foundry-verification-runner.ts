import { lstat, readFile, realpath, rename, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { VERIFICATION_HARNESS_MANIFEST, verificationHarnessManifestSchema } from "@contracthunter/core";
import { runObservedProcess, type ObservedProcessResult, type ObservedProcessRunner, type ProcessRequest } from "./process-runner";

const MAX_MANIFEST_BYTES = 16_384;
const MAX_TIMEOUT_MS = 1_800_000;
const MAX_OUTPUT_BYTES = 20_971_520;
const SAFE_TEST_FILTER = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const COMMIT = /^[a-f0-9]{40}$/;

export const CONTRACTHUNTER_FOUNDRY_CONFIG = `[profile.default]
src = "src"
test = "test"
script = ".contracthunter-disabled-scripts"
out = "out"
libs = ["lib"]
ffi = false
fs_permissions = []
offline = true
auto_detect_solc = false
`;

export type FoundryVerificationInput = {
  workspacePath: string;
  scanId: string;
  hypothesisId: string;
  resolvedCommit: string;
  timeoutMs: number;
  maxOutputBytes: number;
  matchTest?: string;
};

export type VerificationIsolationConfirmation = { providerId: string; networkAccess: "disabled" };
export interface VerificationIsolationProvider {
  confirmNetworkIsolation(): Promise<VerificationIsolationConfirmation | null>;
  execute(request: ProcessRequest, processRunner: ObservedProcessRunner): Promise<ObservedProcessResult>;
}

export class UnavailableVerificationIsolationProvider implements VerificationIsolationProvider {
  async confirmNetworkIsolation(): Promise<null> { return null; }
  async execute(): Promise<never> { throw new Error("Network isolation is unavailable."); }
}

export type FoundryVerificationErrorCode =
  | "invalid_input"
  | "invalid_workspace"
  | "invalid_manifest"
  | "manifest_mismatch"
  | "unsafe_configuration"
  | "network_isolation_unavailable"
  | "execution_timeout"
  | "forge_failed"
  | "execution_error";

export type FoundryVerificationResult = {
  status: "completed" | "failed" | "refused";
  exitCode: number | null;
  durationMs: number;
  timedOut: boolean;
  testCount: number | null;
  passedCount: number | null;
  failedCount: number | null;
  stdoutSummary: string;
  stderrSummary: string;
  stdoutTruncated: boolean;
  stderrTruncated: boolean;
  outputTruncated: boolean;
  errorCode: FoundryVerificationErrorCode | null;
  errorMessage: string | null;
};

export type FoundryVerificationRunnerOptions = {
  verificationRoot: string;
  repositoryRoot: string;
  toolHomeDir: string;
  temporaryDirectory: string;
  executablePath: string;
  isolationProvider?: VerificationIsolationProvider;
  processRunner?: ObservedProcessRunner;
};

class FoundryVerificationSafetyError extends Error {
  constructor(readonly code: FoundryVerificationErrorCode, message: string) { super(message); this.name = "FoundryVerificationSafetyError"; }
}

function isInside(candidate: string, root: string): boolean { return candidate !== root && candidate.startsWith(`${root}${path.sep}`); }

function validateInput(input: FoundryVerificationInput): void {
  if (!path.isAbsolute(input.workspacePath) || !UUID.test(input.scanId) || !UUID.test(input.hypothesisId) || !COMMIT.test(input.resolvedCommit)) throw new FoundryVerificationSafetyError("invalid_input", "Verification input is invalid.");
  if (!Number.isInteger(input.timeoutMs) || input.timeoutMs < 100 || input.timeoutMs > MAX_TIMEOUT_MS) throw new FoundryVerificationSafetyError("invalid_input", "Verification timeout is outside the allowed bounds.");
  if (!Number.isInteger(input.maxOutputBytes) || input.maxOutputBytes < 1_024 || input.maxOutputBytes > MAX_OUTPUT_BYTES) throw new FoundryVerificationSafetyError("invalid_input", "Verification output limit is outside the allowed bounds.");
  if (input.matchTest !== undefined && !SAFE_TEST_FILTER.test(input.matchTest)) throw new FoundryVerificationSafetyError("invalid_input", "Verification test filter is invalid.");
}

function parseTestCounts(output: string): { testCount: number; passedCount: number; failedCount: number } | null {
  const summaries = [...output.matchAll(/(\d+) tests? passed,\s*(\d+) failed(?:,\s*\d+ skipped)?/gi)];
  const summary = summaries.at(-1);
  if (summary) {
    const passedCount = Number(summary[1]); const failedCount = Number(summary[2]);
    return { testCount: passedCount + failedCount, passedCount, failedCount };
  }
  const suites = [...output.matchAll(/(\d+) passed;\s*(\d+) failed;/gi)];
  const suite = suites.at(-1);
  if (!suite) return null;
  const passedCount = Number(suite[1]); const failedCount = Number(suite[2]);
  return { testCount: passedCount + failedCount, passedCount, failedCount };
}

function emptyResult(startedAt: number, code: FoundryVerificationErrorCode, message: string): FoundryVerificationResult {
  return { status: "refused", exitCode: null, durationMs: Date.now() - startedAt, timedOut: false, testCount: null, passedCount: null, failedCount: null, stdoutSummary: "", stderrSummary: "", stdoutTruncated: false, stderrTruncated: false, outputTruncated: false, errorCode: code, errorMessage: message };
}

export class FoundryVerificationRunner {
  private readonly isolationProvider: VerificationIsolationProvider;
  private readonly processRunner: ObservedProcessRunner;

  constructor(private readonly options: FoundryVerificationRunnerOptions) {
    this.isolationProvider = options.isolationProvider ?? new UnavailableVerificationIsolationProvider();
    this.processRunner = options.processRunner ?? runObservedProcess;
  }

  private async checkedWorkspace(workspacePath: string): Promise<string> {
    let root: string; let repositoryRoot: string; let workspace: string;
    try { [root, repositoryRoot, workspace] = await Promise.all([realpath(this.options.verificationRoot), realpath(this.options.repositoryRoot), realpath(workspacePath)]); }
    catch { throw new FoundryVerificationSafetyError("invalid_workspace", "Verification workspace could not be resolved."); }
    if (!isInside(workspace, root)) throw new FoundryVerificationSafetyError("invalid_workspace", "Verification workspace is outside the configured verification root.");
    if (workspace === repositoryRoot || workspace.startsWith(`${repositoryRoot}${path.sep}`)) throw new FoundryVerificationSafetyError("invalid_workspace", "The scanned repository cannot be executed as a verification harness.");
    return workspace;
  }

  private async validateManifest(workspace: string, input: FoundryVerificationInput): Promise<void> {
    const filename = path.join(workspace, VERIFICATION_HARNESS_MANIFEST);
    let contents: string;
    try {
      const info = await lstat(filename);
      if (!info.isFile() || info.isSymbolicLink() || info.size > MAX_MANIFEST_BYTES) throw new Error("unsafe manifest");
      const canonical = await realpath(filename);
      if (!isInside(canonical, workspace)) throw new Error("manifest escaped workspace");
      contents = await readFile(canonical, "utf8");
    } catch { throw new FoundryVerificationSafetyError("invalid_manifest", "ContractHunter verification manifest is missing or unsafe."); }
    let raw: unknown;
    try { raw = JSON.parse(contents); }
    catch { throw new FoundryVerificationSafetyError("invalid_manifest", "ContractHunter verification manifest is malformed."); }
    const parsed = verificationHarnessManifestSchema.safeParse(raw);
    if (!parsed.success) throw new FoundryVerificationSafetyError("invalid_manifest", "ContractHunter verification manifest is invalid.");
    if (parsed.data.scanId !== input.scanId || parsed.data.hypothesisId !== input.hypothesisId || parsed.data.resolvedCommit !== input.resolvedCommit) throw new FoundryVerificationSafetyError("manifest_mismatch", "Verification manifest does not match the requested hypothesis, scan, and commit.");
  }

  private async installControlledConfig(workspace: string): Promise<void> {
    const target = path.join(workspace, "foundry.toml");
    const temporary = path.join(workspace, `.contracthunter-foundry-${randomUUID()}.tmp`);
    try {
      await writeFile(temporary, CONTRACTHUNTER_FOUNDRY_CONFIG, { encoding: "utf8", flag: "wx", mode: 0o600 });
      await rename(temporary, target);
    } catch {
      throw new FoundryVerificationSafetyError("unsafe_configuration", "ContractHunter-controlled Foundry configuration could not be installed.");
    } finally { await rm(temporary, { force: true }); }
  }

  private environment(): NodeJS.ProcessEnv {
    return { NODE_ENV: "production", PATH: this.options.executablePath, HOME: path.resolve(this.options.toolHomeDir), TMPDIR: path.resolve(this.options.temporaryDirectory), LANG: "C.UTF-8", LC_ALL: "C.UTF-8", NO_COLOR: "1", FOUNDRY_PROFILE: "default" };
  }

  async run(input: FoundryVerificationInput): Promise<FoundryVerificationResult> {
    const startedAt = Date.now();
    try {
      validateInput(input);
      const workspace = await this.checkedWorkspace(input.workspacePath);
      await this.validateManifest(workspace, input);
      const isolation = await this.isolationProvider.confirmNetworkIsolation();
      if (!isolation || isolation.networkAccess !== "disabled") throw new FoundryVerificationSafetyError("network_isolation_unavailable", "Reliable network isolation is unavailable; verification was not executed.");
      await this.installControlledConfig(workspace);
      const args = ["test", "--no-color", ...(input.matchTest ? ["--match-test", input.matchTest] : [])];
      let observed: ObservedProcessResult;
      try { observed = await this.isolationProvider.execute({ command: "forge", args, cwd: workspace, timeoutMs: input.timeoutMs, maxOutputBytes: input.maxOutputBytes, env: this.environment() }, this.processRunner); }
      catch { return { ...emptyResult(startedAt, "execution_error", "Foundry verification could not be executed."), status: "failed" }; }
      const counts = parseTestCounts(`${observed.stdout}\n${observed.stderr}`);
      const outputTruncated = observed.stdoutTruncated || observed.stderrTruncated;
      const failed = observed.timedOut || observed.exitCode !== 0;
      return {
        status: failed ? "failed" : "completed", exitCode: observed.exitCode, durationMs: observed.durationMs, timedOut: observed.timedOut,
        testCount: counts?.testCount ?? null, passedCount: counts?.passedCount ?? null, failedCount: counts?.failedCount ?? null,
        stdoutSummary: observed.stdout, stderrSummary: observed.stderr, stdoutTruncated: observed.stdoutTruncated, stderrTruncated: observed.stderrTruncated, outputTruncated,
        errorCode: observed.timedOut ? "execution_timeout" : observed.exitCode !== 0 ? "forge_failed" : null,
        errorMessage: observed.timedOut ? "Foundry verification timed out." : observed.exitCode !== 0 ? "Foundry verification exited unsuccessfully." : null,
      };
    } catch (error) {
      if (error instanceof FoundryVerificationSafetyError) return emptyResult(startedAt, error.code, error.message);
      return emptyResult(startedAt, "execution_error", "Foundry verification failed safely before execution.");
    }
  }
}
