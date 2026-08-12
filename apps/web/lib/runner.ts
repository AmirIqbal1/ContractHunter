import { cloneRepository, detectFramework, loadConfig, sanitiseError, type Scanner } from "@contracthunter/core";
import { getDatabase, getScan, insertFindings, markActiveScansInterrupted, transitionScan } from "@contracthunter/db";
import { MockScanner } from "@contracthunter/scanners";

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
        if (!await scanner.isAvailable()) continue;
        const result = await scanner.scan({ scan, repositoryPath: cloned.path });
        insertFindings(database, scanId, result.findings);
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
  if (!globalRunner.contractHunterRunner) globalRunner.contractHunterRunner = new InProcessJobRunner([new MockScanner()]);
  return globalRunner.contractHunterRunner;
}
