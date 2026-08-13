import { runProtocolAnalysis } from "./analysis-service";

const active = new Set<string>();
export function enqueueProtocolAnalysis(scanId: string): boolean {
  if (active.has(scanId)) return false;
  active.add(scanId);
  setImmediate(() => void runProtocolAnalysis({ scanId }).finally(() => active.delete(scanId)));
  return true;
}
