import { cloneRepository, detectFramework, loadConfig, sanitiseError, type Scanner } from "@contracthunter/core";
import { getDatabase, getScan, insertFindings, markActiveScansInterrupted, reconcileInvestigations, transitionScan, updateCompilerState, updateDependencyState, updateScannerState, upsertScanScanner } from "@contracthunter/db";
import { AderynScanner, DependencyManager, executeScanners, SlitherScanner } from "@contracthunter/scanners";
import { runProtocolAnalysis } from "@/lib/ai/analysis-service";

export interface JobRunner {
  enqueue(scanId: string): void;
  isRunning(scanId: string): boolean;
}

class InProcessJobRunner implements JobRunner {
  private readonly active = new Set<string>();

  constructor(private readonly scanners: Scanner[]) {
    markActiveScansInterrupted(getDatabase());
  }

  enqueue(scanId: string): void {
    if (this.active.has(scanId)) return;
    this.active.add(scanId);
    setImmediate(() => void this.run(scanId));
  }

  isRunning(scanId: string): boolean {
    return this.active.has(scanId);
  }

  private async run(scanId: string): Promise<void> {
    const database = getDatabase();
    const config = loadConfig();
    try {
      for (const scanner of this.scanners) upsertScanScanner(database, scanId, { scannerId: scanner.id, scannerName: scanner.name, status: "pending", findingCount: 0, error: null });
      let scan = transitionScan(database, scanId, "cloning");
      const cloned = await cloneRepository({
        url: scan.repositoryUrl,
        requestedRef: scan.requestedRef ?? undefined,
        repositoryRoot: config.REPOSITORY_DIR,
        scanId,
        timeoutMs: config.GIT_CLONE_TIMEOUT_MS,
      });
      scan = transitionScan(database, scanId, "detecting", { resolvedCommit: cloned.commit });
      const framework = detectFramework(cloned.path);
      scan = transitionScan(database, scanId, "preparing_dependencies", { framework });
      const dependencyManager = new DependencyManager({
        workspaceRoot: config.REPOSITORY_DIR,
        toolHomeDir: config.TOOL_HOME_DIR,
        timeoutMs: config.DEPENDENCY_PREP_TIMEOUT_MS,
        maxOutputBytes: config.MAX_DEPENDENCY_OUTPUT_BYTES,
        maxSubmoduleDepth: config.MAX_SUBMODULE_DEPTH,
        maxSubmodules: config.MAX_SUBMODULES_PER_SCAN,
        allowNpm: config.ALLOW_NPM_DEPENDENCIES,
        allowGitSubmodules: config.ALLOW_GIT_SUBMODULES,
        allowedGitHosts: config.ALLOWED_GIT_DEPENDENCY_HOSTS,
        onStatus: (status, metadata, error) => updateDependencyState(database, scanId, status, metadata, error ?? null),
      });
      await dependencyManager.prepare(cloned.path);
      scan = transitionScan(database, scanId, "preparing_compiler");
      const executions = await executeScanners({
        scanners: this.scanners,
        context: { scan, repositoryPath: cloned.path },
        onResult: (_scanner, result) => { insertFindings(database, scanId, result.findings); },
        onState: (event) => {
          const current = getScan(database, scanId);
          if (event.status === "running" && current?.status === "preparing_compiler" && event.scannerId === "aderyn") transitionScan(database, scanId, "scanning");
          upsertScanScanner(database, scanId, event);
        },
      });
      const successful = executions.filter((execution) => execution.status === "completed");
      const totalDuration = executions.reduce((total, execution) => total + execution.durationMs, 0);
      updateScannerState(database, scanId, "Slither + Aderyn", successful.length ? "completed" : "failed", totalDuration);
      if (!successful.length) throw new Error(`All security scanners failed. ${executions.map((execution) => execution.error).filter(Boolean).join(" ")}`);
      const current = getScan(database, scanId);
      if (current?.status === "preparing_compiler") transitionScan(database, scanId, "scanning");
      reconcileInvestigations(database, scanId);
      await runProtocolAnalysis({ scanId, database, repositoryPath: cloned.path });
      transitionScan(database, scanId, "completed");
    } catch (error) {
      const scan = getScan(database, scanId);
      if (scan && scan.status !== "failed" && scan.status !== "completed") {
        transitionScan(database, scanId, "failed", { error: sanitiseError(error) });
      }
    } finally {
      this.active.delete(scanId);
    }
  }
}

const globalRunner = globalThis as typeof globalThis & { contractHunterRunner?: InProcessJobRunner };

export function getJobRunner(): JobRunner {
  if (!globalRunner.contractHunterRunner) {
    const config = loadConfig();
    globalRunner.contractHunterRunner = new InProcessJobRunner([new SlitherScanner({
      workspaceRoot: config.REPOSITORY_DIR,
      timeoutMs: config.SLITHER_TIMEOUT_MS,
      maxOutputBytes: config.SCANNER_MAX_OUTPUT_BYTES,
      toolHomeDir: config.TOOL_HOME_DIR,
      installTimeoutMs: config.SOLC_INSTALL_TIMEOUT_MS,
      maxSolcVersions: config.MAX_SOLC_VERSIONS_PER_SCAN,
      allowCompilerDownloads: config.ALLOW_COMPILER_DOWNLOADS,
      onCompilerStatus: (scanId, status, metadata, error) => {
        const database = getDatabase();
        updateCompilerState(database, scanId, {
          status,
          constraints: metadata?.constraints,
          versions: metadata?.versions,
          detectionSource: metadata?.source,
          error: error ?? null,
        });
        const scan = getScan(database, scanId);
        if (scan?.status === "preparing_compiler" && (status === "ready" || status === "cached")) transitionScan(database, scanId, "scanning");
      },
    }), new AderynScanner({
      workspaceRoot: config.REPOSITORY_DIR,
      timeoutMs: config.ADERYN_TIMEOUT_MS,
      maxOutputBytes: config.SCANNER_MAX_OUTPUT_BYTES,
      toolHomeDir: config.TOOL_HOME_DIR,
    })]);
  }
  return globalRunner.contractHunterRunner;
}
