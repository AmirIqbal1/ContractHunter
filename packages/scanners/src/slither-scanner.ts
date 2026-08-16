import path from "node:path";
import type { CompilerStatus, Scanner, ScannerResult, ScanContext } from "@contracthunter/core";
import { sanitiseError } from "@contracthunter/core";
import { ProcessOutputLimitError, ProcessTimeoutError, runBoundedProcess, type ProcessRunner } from "./process-runner";
import { normaliseSlitherFindings, parseSlitherJson, SlitherParseError } from "./slither-parser";
import { CompilerManager, type CompilerPreparation } from "./compiler-manager";

export type SlitherScannerOptions = {
  workspaceRoot: string;
  timeoutMs: number;
  maxOutputBytes: number;
  toolHomeDir: string;
  installTimeoutMs: number;
  maxSolcVersions: number;
  allowCompilerDownloads: boolean;
  processRunner?: ProcessRunner;
  onCompilerStatus?: (scanId: string, status: CompilerStatus, metadata?: Partial<CompilerPreparation>, error?: string) => void;
};

export function slitherFailureDiagnostic(stderr: string, repositoryPath: string): string {
  const clean = stderr.split(path.resolve(repositoryPath)).join(".");
  if (/(?:Cannot execute[^\n]*\bforge\b|FileNotFoundError:[^\n]*['"]forge['"]|\bforge\b[^\n]*(?:not found|not installed|No such file))/i.test(clean)) return "Foundry compiler executable `forge` is unavailable.";
  if (/(?:Cannot execute|No such file)[^\n]*\bsolc\b|\bsolc\b[^\n]*(?:not found|unavailable|missing)/i.test(clean)) return "The resolved Solidity compiler is unavailable.";
  if (/forge build[^\n]*(?:failed|non-zero)|compilation (?:failed|error)|failed to compile/i.test(clean)) return "Foundry compilation failed.";
  if (/unsupported (?:framework|platform|project)|not supported by (?:Slither|crytic-compile)/i.test(clean)) return "The project framework is not supported by this Slither runtime.";
  if (/(?:Traceback|slither)[^\n]*(?:error|exception)|SlitherException/i.test(clean)) return "Slither execution failed.";
  return "Slither could not compile or analyse this repository.";
}

export class SlitherScanner implements Scanner {
  readonly id = "slither";
  readonly name = "Slither";
  private readonly processRunner: ProcessRunner;

  constructor(private readonly options: SlitherScannerOptions) {
    this.processRunner = options.processRunner ?? runBoundedProcess;
  }

  private environment(extra: Record<string, string | undefined> = {}): NodeJS.ProcessEnv {
    return {
      ...extra,
      NODE_ENV: process.env.NODE_ENV ?? "production",
      PATH: process.env.PATH ?? "/usr/local/bin:/usr/bin:/bin",
      HOME: process.env.HOME ?? "/tmp",
      TMPDIR: process.env.TMPDIR ?? "/tmp",
      LANG: "C.UTF-8",
      LC_ALL: "C.UTF-8",
      PYTHONUNBUFFERED: "1",
    };
  }

  private checkedRepositoryPath(repositoryPath: string): string {
    const root = path.resolve(this.options.workspaceRoot);
    const candidate = path.resolve(repositoryPath);
    if (candidate === root || !candidate.startsWith(`${root}${path.sep}`)) throw new Error("Scanner workspace path is outside the configured repository directory.");
    return candidate;
  }

  async isAvailable(): Promise<boolean> {
    try {
      const result = await this.processRunner({ command: "slither", args: ["--version"], timeoutMs: Math.min(this.options.timeoutMs, 10_000), maxOutputBytes: 65_536, env: this.environment() });
      return result.exitCode === 0;
    } catch { return false; }
  }

  async scan(context: ScanContext): Promise<ScannerResult> {
    const cwd = this.checkedRepositoryPath(context.repositoryPath);
    const started = Date.now();
    try {
      const compilerManager = new CompilerManager({
        workspaceRoot: this.options.workspaceRoot,
        toolHomeDir: this.options.toolHomeDir,
        installTimeoutMs: this.options.installTimeoutMs,
        maxOutputBytes: this.options.maxOutputBytes,
        maxVersions: this.options.maxSolcVersions,
        allowDownloads: this.options.allowCompilerDownloads,
        processRunner: this.processRunner,
        onStatus: (status, metadata, error) => this.options.onCompilerStatus?.(context.scan.id, status, metadata, error),
      });
      const compiler = await compilerManager.prepare(cwd);
      if (compiler.versions.length > 1) {
        const help = await this.processRunner({ command: "slither", args: ["--help"], timeoutMs: 10_000, maxOutputBytes: 2_097_152, env: compiler.environment });
        if (help.exitCode !== 0 || !`${help.stdout}\n${help.stderr}`.includes("--solc-solcs-select")) {
          throw new Error("This Slither version does not support the required multi-compiler selection mechanism.");
        }
      }
      const result = await this.processRunner({
        command: "slither", args: [".", "--json", "-", "--disable-color", ...compiler.slitherArgs], cwd,
        timeoutMs: this.options.timeoutMs, maxOutputBytes: this.options.maxOutputBytes, env: compiler.environment,
      });
      let output;
      try {
        output = parseSlitherJson(result.stdout);
      } catch (parseError) {
        if (result.exitCode !== 0) {
          throw new Error(`Slither analysis failed: ${slitherFailureDiagnostic(result.stderr, cwd)}`);
        }
        throw parseError;
      }
      return { scannerId: this.id, findings: normaliseSlitherFindings(output, context.scan.id, cwd), warnings: [], durationMs: Date.now() - started };
    } catch (error) {
      if (error instanceof ProcessTimeoutError) throw new Error(`Slither timed out after ${this.options.timeoutMs} ms.`);
      if (error instanceof ProcessOutputLimitError) throw new Error("Slither output exceeded the configured limit.");
      if (error instanceof SlitherParseError) throw new Error(`Slither parsing error: ${sanitiseError(error)}`);
      throw error;
    }
  }
}
