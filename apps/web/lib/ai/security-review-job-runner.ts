import { runSecurityReview } from "./security-review-service";

const active = new Set<string>();
export function enqueueSecurityReview(scanId: string): boolean {
  if (active.has(scanId)) return false;
  active.add(scanId); setImmediate(() => void runSecurityReview({ scanId }).finally(() => active.delete(scanId))); return true;
}
