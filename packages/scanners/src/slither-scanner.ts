import path from "node:path";
import type { Scanner, ScannerResult, ScanContext } from "@contracthunter/core";
import { sanitiseError } from "@contracthunter/core";
import { ProcessOutputLimitError, ProcessTimeoutError, runBoundedProcess, type ProcessRunner } from "./process-runner";
import { normaliseSlitherFindings, parseSlitherJson, SlitherParseError } from "./slither-parser";

export type SlitherScannerOptions = {
  workspaceRoot: string;
  timeoutMs: number;
  maxOutputBytes: number;
  processRunner?: ProcessRunner;
};

export class SlitherScanner implements Scanner {
  readonly id = "slither";
  readonly name = "Slither";
  private readonly processRunner: ProcessRunner;

  constructor(private readonly options: SlitherScannerOptions) {
    this.processRunner = options.processRunner ?? runBoundedProcess;
  }

  private environment(): NodeJS.ProcessEnv {
    return {
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
      const result = await this.processRunner({
        command: "slither", args: [".", "--json", "-", "--disable-color"], cwd,
        timeoutMs: this.options.timeoutMs, maxOutputBytes: this.options.maxOutputBytes, env: this.environment(),
      });
      if (result.exitCode !== 0) {
        const diagnostic = sanitiseError((result.stderr || "Slither could not compile or analyse this repository.").split(cwd).join("."));
        throw new Error(`Slither analysis failed. ${diagnostic}`);
      }
      const output = parseSlitherJson(result.stdout);
      return { scannerId: this.id, findings: normaliseSlitherFindings(output, context.scan.id, cwd), warnings: [], durationMs: Date.now() - started };
    } catch (error) {
      if (error instanceof ProcessTimeoutError) throw new Error(`Slither timed out after ${this.options.timeoutMs} ms.`);
      if (error instanceof ProcessOutputLimitError) throw new Error("Slither output exceeded the configured limit.");
      if (error instanceof SlitherParseError) throw new Error(`Slither parsing error: ${sanitiseError(error)}`);
      throw error;
    }
  }
}
