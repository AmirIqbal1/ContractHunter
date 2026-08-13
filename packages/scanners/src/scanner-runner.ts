import { sanitiseError, type Scanner, type ScannerResult, type ScanContext, type ScannerStatus } from "@contracthunter/core";

export type ScannerExecution = {
  scannerId: string;
  scannerName: string;
  status: "completed" | "failed" | "unavailable";
  findingCount: number;
  durationMs: number;
  error: string | null;
};

export type ScannerStateEvent = {
  scannerId: string;
  scannerName: string;
  status: ScannerStatus;
  findingCount?: number;
  durationMs?: number;
  error?: string | null;
};

export async function executeScanners(options: {
  scanners: Scanner[];
  context: ScanContext;
  onState?: (event: ScannerStateEvent) => void;
  onResult?: (scanner: Scanner, result: ScannerResult) => void;
}): Promise<ScannerExecution[]> {
  const executions: ScannerExecution[] = [];
  for (const scanner of options.scanners) {
    const base = { scannerId: scanner.id, scannerName: scanner.name };
    options.onState?.({ ...base, status: "pending", findingCount: 0, error: null });
    let available = false;
    try { available = await scanner.isAvailable(); } catch { available = false; }
    if (!available) {
      const execution = { ...base, status: "unavailable" as const, findingCount: 0, durationMs: 0, error: `${scanner.name} is not available in the scanner environment.` };
      options.onState?.({ ...execution });
      executions.push(execution);
      continue;
    }
    options.onState?.({ ...base, status: "available" });
    options.onState?.({ ...base, status: "running", error: null });
    const started = Date.now();
    try {
      const result = await scanner.scan(options.context);
      const durationMs = result.durationMs ?? Date.now() - started;
      options.onResult?.(scanner, result);
      const execution = { ...base, status: "completed" as const, findingCount: result.findings.length, durationMs, error: null };
      options.onState?.({ ...execution });
      executions.push(execution);
    } catch (error) {
      const execution = { ...base, status: "failed" as const, findingCount: 0, durationMs: Date.now() - started, error: sanitiseError(error) };
      options.onState?.({ ...execution });
      executions.push(execution);
    }
  }
  return executions;
}
