import { cloneRepository, detectFramework, loadConfig, sanitiseError, type Scanner } from "@contracthunter/core";
import { getDatabase, getScan, insertFindings, markActiveScansInterrupted, transitionScan, updateCompilerState, updateScannerState } from "@contracthunter/db";
import { SlitherScanner } from "@contracthunter/scanners";

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
      scan = transitionScan(database, scanId, "scanning", { framework });
      for (const scanner of this.scanners) {
        if (!await scanner.isAvailable()) {
          updateScannerState(database, scanId, scanner.name, "failed");
          throw new Error(`${scanner.name} is not available in the scanner environment.`);
        }
        updateScannerState(database, scanId, scanner.name, "available");
        updateScannerState(database, scanId, scanner.name, "running");
        const scannerStarted = Date.now();
        try {
          const result = await scanner.scan({ scan, repositoryPath: cloned.path });
          insertFindings(database, scanId, result.findings);
          updateScannerState(database, scanId, scanner.name, "completed", result.durationMs ?? Date.now() - scannerStarted);
        } catch (error) {
          updateScannerState(database, scanId, scanner.name, "failed", Date.now() - scannerStarted);
          throw error;
        }
      }
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
      onCompilerStatus: (scanId, status, metadata, error) => updateCompilerState(getDatabase(), scanId, {
        status,
        constraints: metadata?.constraints,
        versions: metadata?.versions,
        detectionSource: metadata?.source,
        error: error ?? null,
      }),
    })]);
  }
  return globalRunner.contractHunterRunner;
}
