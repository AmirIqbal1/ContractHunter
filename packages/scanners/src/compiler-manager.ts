import { access, lstat, mkdir, realpath } from "node:fs/promises";
import { constants } from "node:fs";
import path from "node:path";
import { sanitiseError, type CompilerStatus } from "@contracthunter/core";
import { CompilerResolutionError, detectCompilerRequirements, resolveCompilerVersions, type CompilerDetection } from "./compiler-detection";
import { ProcessOutputLimitError, ProcessTimeoutError, runBoundedProcess, type ProcessRunner } from "./process-runner";

const VERSION = /^\d+\.\d+\.\d+$/;
const installLocks = new Map<string, Promise<void>>();

export type TrustedVerificationCompiler = { version: string; executablePath: string };
export class TrustedVerificationCompilerError extends Error {
  readonly code = "trusted_compiler_unavailable" as const;
  constructor(message: string) { super(message); this.name = "TrustedVerificationCompilerError"; }
}

export async function resolveTrustedVerificationCompiler(options: {
  toolHomeDir: string; version: string; processRunner?: ProcessRunner;
}): Promise<TrustedVerificationCompiler> {
  if (!VERSION.test(options.version)) throw new TrustedVerificationCompilerError("The requested compiler version is invalid.");
  const runner = options.processRunner ?? runBoundedProcess;
  try {
    const toolHomeInfo = await lstat(options.toolHomeDir);
    if (!toolHomeInfo.isDirectory() || toolHomeInfo.isSymbolicLink()) throw new Error("unsafe tool home");
    const toolHome = await realpath(options.toolHomeDir);
    const selectDirectory = path.join(toolHome, ".solc-select");
    const artifactsDirectory = path.join(selectDirectory, "artifacts");
    const versionDirectory = path.join(artifactsDirectory, `solc-${options.version}`);
    const executable = path.join(versionDirectory, `solc-${options.version}`);
    for (const directory of [selectDirectory, artifactsDirectory, versionDirectory]) {
      const info = await lstat(directory);
      if (!info.isDirectory() || info.isSymbolicLink() || await realpath(directory) !== directory) throw new Error("unsafe compiler directory");
    }
    const info = await lstat(executable);
    if (!info.isFile() || info.isSymbolicLink() || await realpath(executable) !== executable) throw new Error("unsafe compiler executable");
    await access(executable, constants.X_OK);
    const result = await runner({
      command: executable, args: ["--version"], timeoutMs: 10_000, maxOutputBytes: 65_536,
      env: { NODE_ENV: "production", PATH: "/usr/bin:/bin", HOME: toolHome, TMPDIR: "/tmp", LANG: "C.UTF-8", LC_ALL: "C.UTF-8" },
    });
    const reported = `${result.stdout}\n${result.stderr}`.match(/Version:\s*(\d+\.\d+\.\d+)/i)?.[1];
    if (result.exitCode !== 0 || reported !== options.version) throw new Error("compiler version mismatch");
    return { version: options.version, executablePath: executable };
  } catch (error) {
    if (error instanceof TrustedVerificationCompilerError) throw error;
    throw new TrustedVerificationCompilerError(`Trusted Solidity compiler ${options.version} is unavailable or invalid.`);
  }
}

export async function findExecutableOnPath(command: string, environmentPath: string | undefined): Promise<string | null> {
  for (const directory of (environmentPath ?? "").split(path.delimiter).filter(Boolean)) {
    const candidate = path.join(directory, command);
    try { await access(candidate, constants.X_OK); return candidate; }
    catch { /* Continue through the bounded configured PATH. */ }
  }
  return null;
}

export type CompilerPreparation = CompilerDetection & {
  versions: string[];
  cached: boolean;
  environment: NodeJS.ProcessEnv;
  slitherArgs: string[];
};

export type CompilerManagerOptions = {
  workspaceRoot: string;
  toolHomeDir: string;
  installTimeoutMs: number;
  maxOutputBytes: number;
  maxVersions: number;
  allowDownloads: boolean;
  environmentPath?: string;
  processRunner?: ProcessRunner;
  onStatus?: (status: CompilerStatus, metadata?: Partial<CompilerPreparation>, error?: string) => void;
};

export class CompilerManager {
  private readonly processRunner: ProcessRunner;
  constructor(private readonly options: CompilerManagerOptions) { this.processRunner = options.processRunner ?? runBoundedProcess; }

  private environment(extra: Record<string, string | undefined> = {}): NodeJS.ProcessEnv {
    return {
      ...extra,
      NODE_ENV: process.env.NODE_ENV ?? "production",
      PATH: this.options.environmentPath ?? process.env.PATH ?? "/usr/local/bin:/opt/slither/bin:/usr/bin:/bin",
      HOME: this.options.toolHomeDir,
      TMPDIR: "/tmp",
      LANG: "C.UTF-8",
      LC_ALL: "C.UTF-8",
      PYTHONUNBUFFERED: "1",
    };
  }

  async isAvailable(): Promise<boolean> {
    try {
      const result = await this.processRunner({ command: "solc-select", args: ["--version"], timeoutMs: 10_000, maxOutputBytes: 65_536, env: this.environment() });
      return result.exitCode === 0;
    } catch { return false; }
  }

  private async installedVersions(): Promise<string[]> {
    const result = await this.processRunner({ command: "solc-select", args: ["versions"], timeoutMs: 10_000, maxOutputBytes: 1_048_576, env: this.environment() });
    if (result.exitCode !== 0) throw new CompilerResolutionError(`Unable to list installed Solidity compilers. ${sanitiseError(result.stderr)}`);
    return [...result.stdout.matchAll(/\b\d+\.\d+\.\d+\b/g)].map((match) => match[0]);
  }

  private async availableVersions(): Promise<string[]> {
    const result = await this.processRunner({ command: "solc-select", args: ["install"], timeoutMs: 30_000, maxOutputBytes: 2_097_152, env: this.environment() });
    if (result.exitCode !== 0) throw new CompilerResolutionError(`Unable to obtain available Solidity compiler versions. ${sanitiseError(result.stderr)}`);
    return [...result.stdout.matchAll(/\b\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?\b/g)].map((match) => match[0]);
  }

  private async install(version: string): Promise<void> {
    if (!VERSION.test(version)) throw new CompilerResolutionError(`Unsupported Solidity compiler version: ${version}.`);
    const existing = installLocks.get(version);
    if (existing) return existing;
    const installation = (async () => {
      if ((await this.installedVersions()).includes(version)) return;
      if (!this.options.allowDownloads) throw new CompilerResolutionError(`Solidity compiler ${version} is required but automatic compiler downloads are disabled.`);
      this.options.onStatus?.("downloading", { versions: [version] });
      const result = await this.processRunner({ command: "solc-select", args: ["install", version], timeoutMs: this.options.installTimeoutMs, maxOutputBytes: this.options.maxOutputBytes, env: this.environment() });
      if (result.exitCode !== 0) throw new CompilerResolutionError(`Solidity compiler ${version} could not be prepared. ${sanitiseError(result.stderr)}`);
      if (!(await this.installedVersions()).includes(version)) throw new CompilerResolutionError(`Solidity compiler ${version} installation could not be verified.`);
    })().finally(() => installLocks.delete(version));
    installLocks.set(version, installation);
    return installation;
  }

  private async verify(version: string, environment: NodeJS.ProcessEnv): Promise<void> {
    const result = await this.processRunner({ command: "solc", args: ["--version"], timeoutMs: 10_000, maxOutputBytes: 65_536, env: environment });
    const reported = `${result.stdout}\n${result.stderr}`.match(/Version:\s*(\d+\.\d+\.\d+)/i)?.[1];
    if (result.exitCode !== 0 || reported !== version) throw new CompilerResolutionError(`Solidity compiler verification failed for ${version}.`);
  }

  async prepare(repositoryPath: string): Promise<CompilerPreparation> {
    const root = path.resolve(this.options.workspaceRoot);
    const repository = path.resolve(repositoryPath);
    if (repository === root || !repository.startsWith(`${root}${path.sep}`)) throw new CompilerResolutionError("Compiler workspace path is outside the configured repository directory.");
    await mkdir(this.options.toolHomeDir, { recursive: true });
    this.options.onStatus?.("detecting");
    try {
      if (!await this.isAvailable()) throw new CompilerResolutionError("solc-select is not available in the scanner environment.");
      const detection = await detectCompilerRequirements(repository);
      this.options.onStatus?.("detecting", detection);
      const installed = await this.installedVersions();
      if (!this.options.allowDownloads && detection.constraints.length === 1 && VERSION.test(detection.constraints[0]) && !installed.includes(detection.constraints[0])) {
        throw new CompilerResolutionError(`Solidity compiler ${detection.constraints[0]} is required but automatic compiler downloads are disabled.`);
      }
      const exactAlreadyInstalled = detection.constraints.length === 1 && VERSION.test(detection.constraints[0]) && installed.includes(detection.constraints[0]);
      const candidates = this.options.allowDownloads && !exactAlreadyInstalled ? [...installed, ...await this.availableVersions()] : installed;
      if (detection.source === "foundry-config" && !candidates.includes(detection.constraints[0])) {
        throw new CompilerResolutionError(`Unsupported Solidity compiler version: ${detection.constraints[0]}.`);
      }
      const versions = resolveCompilerVersions(detection.constraints, candidates, this.options.maxVersions);
      const initiallyCached = versions.every((version) => installed.includes(version));
      await Promise.all(versions.map((version) => this.install(version)));
      const environment = this.environment(versions.length === 1 ? { SOLC_VERSION: versions[0] } : {});
      if (versions.length === 1) {
        const solcExecutable = await findExecutableOnPath("solc", environment.PATH);
        if (solcExecutable) {
          environment.FOUNDRY_SOLC = solcExecutable;
          environment.FOUNDRY_OFFLINE = "true";
          environment.FOUNDRY_AUTO_DETECT_SOLC = "false";
        }
      }
      const slitherArgs = versions.length > 1 ? ["--solc-solcs-select", versions.join(",")] : [];
      if (versions.length === 1) await this.verify(versions[0], environment);
      const preparation = { ...detection, versions, cached: initiallyCached, environment, slitherArgs };
      this.options.onStatus?.(initiallyCached ? "cached" : "ready", preparation);
      return preparation;
    } catch (error) {
      const message = error instanceof ProcessTimeoutError ? `Compiler preparation timed out after ${this.options.installTimeoutMs} ms.`
        : error instanceof ProcessOutputLimitError ? "Compiler manager output exceeded the configured limit."
          : sanitiseError(error);
      this.options.onStatus?.("failed", undefined, message);
      throw new CompilerResolutionError(message);
    }
  }
}
