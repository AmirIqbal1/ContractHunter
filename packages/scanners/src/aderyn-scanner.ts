import { mkdtemp, readFile, rm } from "node:fs/promises";
import path from "node:path";
import type { Scanner, ScannerResult, ScanContext } from "@contracthunter/core";
import { sanitiseError } from "@contracthunter/core";
import { AderynParseError, normaliseAderynFindings, parseAderynJson } from "./aderyn-parser";
import { ProcessOutputLimitError, ProcessTimeoutError, runBoundedProcess, type ProcessRunner } from "./process-runner";

export type AderynScannerOptions = {
  workspaceRoot: string;
  timeoutMs: number;
  maxOutputBytes: number;
  toolHomeDir: string;
  processRunner?: ProcessRunner;
};

export class AderynScanner implements Scanner {
  readonly id = "aderyn";
  readonly name = "Aderyn";
  private readonly processRunner: ProcessRunner;
  private scannerVersion: string | null = null;
  constructor(private readonly options: AderynScannerOptions) { this.processRunner = options.processRunner ?? runBoundedProcess; }

  private environment(): NodeJS.ProcessEnv {
    return {
      NODE_ENV: process.env.NODE_ENV ?? "production",
      PATH: process.env.PATH ?? "/usr/local/bin:/usr/bin:/bin",
      HOME: this.options.toolHomeDir,
      TMPDIR: "/tmp",
      LANG: "C.UTF-8",
      LC_ALL: "C.UTF-8",
      NO_COLOR: "1",
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
      const result = await this.processRunner({ command: "aderyn", args: ["--version"], timeoutMs: Math.min(this.options.timeoutMs, 10_000), maxOutputBytes: 65_536, env: this.environment() });
      this.scannerVersion = result.exitCode === 0 ? `${result.stdout}\n${result.stderr}`.match(/\b\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?\b/)?.[0] ?? null : null;
      return result.exitCode === 0;
    } catch { return false; }
  }

  async scan(context: ScanContext): Promise<ScannerResult> {
    const cwd = this.checkedRepositoryPath(context.repositoryPath);
    const started = Date.now();
    const temporary = await mkdtemp(path.join(cwd, ".contracthunter-aderyn-"));
    const reportPath = path.join(temporary, "report.json");
    try {
      const result = await this.processRunner({ command: "aderyn", args: [".", "--output", reportPath], cwd, timeoutMs: this.options.timeoutMs, maxOutputBytes: this.options.maxOutputBytes, env: this.environment() });
      if (result.exitCode !== 0) {
        const detail = sanitiseError(result.stderr || result.stdout || "Aderyn could not analyse this repository.").split(cwd).join(".").split(this.options.toolHomeDir).join("[tool-home]");
        throw new Error(`Aderyn analysis failed. ${detail}`);
      }
      let raw: string;
      try { raw = await readFile(reportPath, "utf8"); }
      catch { throw new AderynParseError("Aderyn did not produce its JSON report."); }
      const report = parseAderynJson(raw);
      const reportedSources = new Map<string, string | null>();
      const findings = normaliseAderynFindings(report, context.scan.id, cwd, reportedSources);
      return { scannerId: this.id, findings, scannerVersion: this.scannerVersion, reportedSourceIdentities: Object.fromEntries(reportedSources), warnings: [], durationMs: Date.now() - started };
    } catch (error) {
      if (error instanceof ProcessTimeoutError) throw new Error(`Aderyn timed out after ${this.options.timeoutMs} ms.`);
      if (error instanceof ProcessOutputLimitError) throw new Error("Aderyn output exceeded the configured limit.");
      if (error instanceof AderynParseError) throw new Error(`Aderyn parsing error: ${sanitiseError(error)}`);
      throw error;
    } finally {
      await rm(temporary, { recursive: true, force: true });
    }
  }
}
