import { access, lstat, readFile, readlink, realpath, rename, rm, stat, writeFile } from "node:fs/promises";
import { constants as fsConstants } from "node:fs";
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
const FORBIDDEN_ENVIRONMENT_KEYS = new Set(["OPENAI_API_KEY", "GITHUB_TOKEN", "GH_TOKEN", "PRIVATE_KEY", "MNEMONIC", "RPC_URL", "ETH_RPC_URL", "ETHERSCAN_API_KEY", "NPM_TOKEN", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"]);
const SAFE_ENVIRONMENT_KEYS = ["NODE_ENV", "LANG", "LC_ALL", "NO_COLOR", "FOUNDRY_PROFILE"] as const;
const DEFAULT_RESOURCE_LIMITS: VerificationResourceLimits = {
  maxCpuTimeSeconds: 300,
  maxVirtualMemoryBytes: 2_147_483_648,
  maxProcesses: 64,
  maxOpenFiles: 256,
  maxFileSizeBytes: 67_108_864,
};

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

export type VerificationResourceLimits = {
  maxCpuTimeSeconds: number;
  maxVirtualMemoryBytes: number;
  maxProcesses: number;
  maxOpenFiles: number;
  maxFileSizeBytes: number;
};

export type VerificationIsolationConfirmation = {
  providerId: "linux-bubblewrap" | string;
  isolationVersion: string;
  networkAccess: "disabled";
  networkIsolated: true;
  processIsolated: true;
  resourceLimitsApplied: VerificationResourceLimits;
};
export type VerificationIsolationMetadata = VerificationIsolationConfirmation & {
  wallClockTimeoutMs: number;
  maxOutputBytes: number;
  writableProjectPath: string;
};
export type IsolatedExecutionResult = ObservedProcessResult & { isolation: VerificationIsolationMetadata };
export interface VerificationIsolationProvider {
  confirmNetworkIsolation(): Promise<VerificationIsolationConfirmation | null>;
  execute(request: ProcessRequest, processRunner: ObservedProcessRunner): Promise<IsolatedExecutionResult>;
}

export class UnavailableVerificationIsolationProvider implements VerificationIsolationProvider {
  async confirmNetworkIsolation(): Promise<null> { return null; }
  async execute(): Promise<never> { throw new Error("Network isolation is unavailable."); }
}

export type LinuxBubblewrapIsolationProviderOptions = {
  verificationRoot: string;
  toolHomeDir: string;
  executableSearchPath: string;
  resourceLimits?: Partial<VerificationResourceLimits>;
  platform?: NodeJS.Platform;
  resolveExecutable?: (name: string) => Promise<string | null>;
  capabilityProcessRunner?: ObservedProcessRunner;
  readParentNetworkNamespace?: () => Promise<string>;
};

function validLimits(limits: VerificationResourceLimits): boolean {
  return Number.isInteger(limits.maxCpuTimeSeconds) && limits.maxCpuTimeSeconds >= 1 && limits.maxCpuTimeSeconds <= 600
    && Number.isInteger(limits.maxVirtualMemoryBytes) && limits.maxVirtualMemoryBytes >= 268_435_456 && limits.maxVirtualMemoryBytes <= 4_294_967_296
    && Number.isInteger(limits.maxProcesses) && limits.maxProcesses >= 8 && limits.maxProcesses <= 256
    && Number.isInteger(limits.maxOpenFiles) && limits.maxOpenFiles >= 32 && limits.maxOpenFiles <= 1_024
    && Number.isInteger(limits.maxFileSizeBytes) && limits.maxFileSizeBytes >= 1_048_576 && limits.maxFileSizeBytes <= 268_435_456;
}

async function defaultExecutableResolver(searchPath: string, name: string): Promise<string | null> {
  if (!/^[A-Za-z0-9._+-]+$/.test(name)) return null;
  for (const directory of searchPath.split(path.delimiter)) {
    if (!path.isAbsolute(directory)) continue;
    const candidate = path.join(directory, name);
    try { await access(candidate, fsConstants.X_OK); if ((await stat(candidate)).isFile()) return await realpath(candidate); }
    catch { /* Continue through the fixed search path. */ }
  }
  return null;
}

async function existingSystemMounts(): Promise<string[]> {
  const mounts: string[] = [];
  for (const candidate of ["/usr/lib", "/usr/lib64", "/lib", "/lib64"]) {
    try { if ((await stat(candidate)).isDirectory()) mounts.push(candidate); }
    catch { /* Optional compatibility path is absent. */ }
  }
  return mounts;
}

export class LinuxBubblewrapIsolationProvider implements VerificationIsolationProvider {
  private readonly limits: VerificationResourceLimits;
  private readonly platform: NodeJS.Platform;
  private readonly resolveExecutable: (name: string) => Promise<string | null>;
  private readonly capabilityProcessRunner: ObservedProcessRunner;
  private capability: Promise<VerificationIsolationConfirmation | null> | undefined;

  constructor(private readonly options: LinuxBubblewrapIsolationProviderOptions) {
    this.limits = { ...DEFAULT_RESOURCE_LIMITS, ...options.resourceLimits };
    this.platform = options.platform ?? process.platform;
    this.resolveExecutable = options.resolveExecutable ?? ((name) => defaultExecutableResolver(options.executableSearchPath, name));
    this.capabilityProcessRunner = options.capabilityProcessRunner ?? runObservedProcess;
  }

  private prlimitArguments(cpuSeconds: number): string[] {
    return [
      `--cpu=${cpuSeconds}:${cpuSeconds}`,
      `--as=${this.limits.maxVirtualMemoryBytes}:${this.limits.maxVirtualMemoryBytes}`,
      `--nproc=${this.limits.maxProcesses}:${this.limits.maxProcesses}`,
      `--nofile=${this.limits.maxOpenFiles}:${this.limits.maxOpenFiles}`,
      `--fsize=${this.limits.maxFileSizeBytes}:${this.limits.maxFileSizeBytes}`,
      "--",
    ];
  }

  private async baseBubblewrapArguments(): Promise<string[]> {
    const args = ["--die-with-parent", "--new-session", "--unshare-user", "--unshare-pid", "--unshare-net", "--unshare-ipc", "--unshare-uts", "--clearenv"];
    for (const mount of await existingSystemMounts()) args.push("--ro-bind", mount, mount);
    args.push("--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp");
    return args;
  }

  private async probe(): Promise<VerificationIsolationConfirmation | null> {
    if (this.platform !== "linux" || !validLimits(this.limits)) return null;
    const [bwrap, prlimit, readlinkExecutable] = await Promise.all([this.resolveExecutable("bwrap"), this.resolveExecutable("prlimit"), this.resolveExecutable("readlink")]);
    if (!bwrap || !prlimit || !readlinkExecutable) return null;
    const environment: NodeJS.ProcessEnv = { NODE_ENV: "production", PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C" };
    try {
      const version = await this.capabilityProcessRunner({ command: bwrap, args: ["--version"], timeoutMs: 2_000, maxOutputBytes: 1_024, env: environment, killProcessTree: true });
      if (version.exitCode !== 0 || version.timedOut) return null;
      const parentNetworkNamespace = (await (this.options.readParentNetworkNamespace ?? (() => readlink("/proc/self/ns/net")))()).trim();
      if (!parentNetworkNamespace) return null;
      const namespace = await this.capabilityProcessRunner({
        command: prlimit,
        args: [...this.prlimitArguments(2), bwrap, ...await this.baseBubblewrapArguments(), "--dir", "/opt", "--dir", "/opt/contracthunter-probe", "--ro-bind", readlinkExecutable, "/opt/contracthunter-probe/readlink", "--", "/opt/contracthunter-probe/readlink", "/proc/self/ns/net"],
        timeoutMs: 3_000,
        maxOutputBytes: 1_024,
        env: environment,
        killProcessTree: true,
      });
      const childNetworkNamespace = namespace.stdout.trim();
      if (namespace.exitCode !== 0 || namespace.timedOut || !childNetworkNamespace || childNetworkNamespace === parentNetworkNamespace) return null;
      return {
        providerId: "linux-bubblewrap",
        isolationVersion: version.stdout.trim().slice(0, 128) || "bubblewrap",
        networkAccess: "disabled",
        networkIsolated: true,
        processIsolated: true,
        resourceLimitsApplied: { ...this.limits },
      };
    } catch { return null; }
  }

  async confirmNetworkIsolation(): Promise<VerificationIsolationConfirmation | null> {
    this.capability ??= this.probe();
    return this.capability;
  }

  async execute(request: ProcessRequest, processRunner: ObservedProcessRunner): Promise<IsolatedExecutionResult> {
    const capability = await this.confirmNetworkIsolation();
    if (!capability || request.command !== "forge" || !request.cwd || !path.isAbsolute(request.cwd)) throw new Error("Required Linux verification isolation is unavailable.");
    const validArguments = request.args.length === 2
      ? request.args[0] === "test" && request.args[1] === "--no-color"
      : request.args.length === 4 && request.args[0] === "test" && request.args[1] === "--no-color" && request.args[2] === "--match-test" && SAFE_TEST_FILTER.test(request.args[3]);
    if (!validArguments || !Number.isInteger(request.timeoutMs) || request.timeoutMs < 100 || request.timeoutMs > MAX_TIMEOUT_MS || !Number.isInteger(request.maxOutputBytes) || request.maxOutputBytes < 1_024 || request.maxOutputBytes > MAX_OUTPUT_BYTES) throw new Error("The verification executable request is invalid.");
    const [verificationRoot, workspace, forge, toolHome] = await Promise.all([
      realpath(this.options.verificationRoot), realpath(request.cwd), this.resolveExecutable("forge"), realpath(this.options.toolHomeDir),
    ]);
    if (!isInside(workspace, verificationRoot) || !forge) throw new Error("The verification workspace or executable is unavailable.");
    const [bwrap, prlimit] = await Promise.all([this.resolveExecutable("bwrap"), this.resolveExecutable("prlimit")]);
    if (!bwrap || !prlimit) throw new Error("Required Linux verification isolation is unavailable.");

    const sandboxHome = "/home/contracthunter";
    const sandboxForge = "/opt/contracthunter/bin/forge";
    const bwrapArguments = [...await this.baseBubblewrapArguments(), "--dir", "/home", "--dir", sandboxHome, "--dir", "/opt", "--dir", "/opt/contracthunter", "--dir", "/opt/contracthunter/bin"];
    const compilerCache = path.join(toolHome, ".svm");
    try { if ((await stat(compilerCache)).isDirectory()) bwrapArguments.push("--ro-bind", compilerCache, `${sandboxHome}/.svm`); }
    catch { /* Missing trusted compiler cache makes Forge fail cleanly in offline mode. */ }
    bwrapArguments.push("--ro-bind", forge, sandboxForge, "--bind", workspace, workspace, "--chdir", workspace);

    const sandboxEnvironment: Record<string, string> = { NODE_ENV: "production", PATH: "/opt/contracthunter/bin", HOME: sandboxHome, TMPDIR: "/tmp" };
    for (const key of SAFE_ENVIRONMENT_KEYS) if (request.env?.[key] !== undefined) sandboxEnvironment[key] = request.env[key];
    for (const [key, value] of Object.entries(sandboxEnvironment)) {
      if (value !== undefined && !FORBIDDEN_ENVIRONMENT_KEYS.has(key)) bwrapArguments.push("--setenv", key, value);
    }
    bwrapArguments.push("--", sandboxForge, ...request.args);
    const cpuSeconds = Math.max(1, Math.min(this.limits.maxCpuTimeSeconds, Math.ceil(request.timeoutMs / 1_000) + 1));
    const observed = await processRunner({
      command: prlimit,
      args: [...this.prlimitArguments(cpuSeconds), bwrap, ...bwrapArguments],
      cwd: workspace,
      timeoutMs: request.timeoutMs,
      maxOutputBytes: request.maxOutputBytes,
      env: { NODE_ENV: "production", PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C" },
      killProcessTree: true,
    });
    return {
      ...observed,
      isolation: { ...capability, resourceLimitsApplied: { ...this.limits, maxCpuTimeSeconds: cpuSeconds }, wallClockTimeoutMs: request.timeoutMs, maxOutputBytes: request.maxOutputBytes, writableProjectPath: workspace },
    };
  }
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
  isolation: VerificationIsolationMetadata | null;
};

export type FoundryVerificationRunnerOptions = {
  verificationRoot: string;
  repositoryRoot: string;
  toolHomeDir: string;
  temporaryDirectory: string;
  executablePath: string;
  isolationProvider?: VerificationIsolationProvider;
  processRunner?: ObservedProcessRunner;
  isolationResourceLimits?: Partial<VerificationResourceLimits>;
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
  return { status: "refused", exitCode: null, durationMs: Date.now() - startedAt, timedOut: false, testCount: null, passedCount: null, failedCount: null, stdoutSummary: "", stderrSummary: "", stdoutTruncated: false, stderrTruncated: false, outputTruncated: false, errorCode: code, errorMessage: message, isolation: null };
}

export class FoundryVerificationRunner {
  private readonly isolationProvider: VerificationIsolationProvider;
  private readonly processRunner: ObservedProcessRunner;

  constructor(private readonly options: FoundryVerificationRunnerOptions) {
    this.isolationProvider = options.isolationProvider ?? new LinuxBubblewrapIsolationProvider({ verificationRoot: options.verificationRoot, toolHomeDir: options.toolHomeDir, executableSearchPath: options.executablePath, resourceLimits: options.isolationResourceLimits });
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
      if (!isolation || isolation.networkAccess !== "disabled" || !isolation.networkIsolated || !isolation.processIsolated || !validLimits(isolation.resourceLimitsApplied)) throw new FoundryVerificationSafetyError("network_isolation_unavailable", "Reliable network and process isolation is unavailable; verification was not executed.");
      await this.installControlledConfig(workspace);
      const args = ["test", "--no-color", ...(input.matchTest ? ["--match-test", input.matchTest] : [])];
      let observed: IsolatedExecutionResult;
      try { observed = await this.isolationProvider.execute({ command: "forge", args, cwd: workspace, timeoutMs: input.timeoutMs, maxOutputBytes: input.maxOutputBytes, env: this.environment() }, this.processRunner); }
      catch { return { ...emptyResult(startedAt, "execution_error", "Foundry verification could not be executed."), status: "failed" }; }
      if (!observed.isolation.networkIsolated || !observed.isolation.processIsolated || observed.isolation.networkAccess !== "disabled" || !validLimits(observed.isolation.resourceLimitsApplied)) return { ...emptyResult(startedAt, "execution_error", "Foundry verification isolation metadata was invalid."), status: "failed" };
      const counts = parseTestCounts(`${observed.stdout}\n${observed.stderr}`);
      const outputTruncated = observed.stdoutTruncated || observed.stderrTruncated;
      const failed = observed.timedOut || observed.exitCode !== 0;
      return {
        status: failed ? "failed" : "completed", exitCode: observed.exitCode, durationMs: observed.durationMs, timedOut: observed.timedOut,
        testCount: counts?.testCount ?? null, passedCount: counts?.passedCount ?? null, failedCount: counts?.failedCount ?? null,
        stdoutSummary: observed.stdout, stderrSummary: observed.stderr, stdoutTruncated: observed.stdoutTruncated, stderrTruncated: observed.stderrTruncated, outputTruncated,
        errorCode: observed.timedOut ? "execution_timeout" : observed.exitCode !== 0 ? "forge_failed" : null,
        errorMessage: observed.timedOut ? "Foundry verification timed out." : observed.exitCode !== 0 ? "Foundry verification exited unsuccessfully." : null,
        isolation: observed.isolation,
      };
    } catch (error) {
      if (error instanceof FoundryVerificationSafetyError) return emptyResult(startedAt, error.code, error.message);
      return emptyResult(startedAt, "execution_error", "Foundry verification failed safely before execution.");
    }
  }
}
