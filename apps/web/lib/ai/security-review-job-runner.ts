import { runSecurityReview } from "./security-review-service";

const active = new Set<string>();
export function isSecurityReviewActive(scanId: string): boolean { return active.has(scanId); }
export function activeSecurityReviewScanIds(): string[] { return [...active]; }
export function enqueueSecurityReview(scanId: string): boolean {
  if (active.has(scanId)) return false;
  active.add(scanId); setImmediate(() => void runSecurityReview({ scanId }).finally(() => active.delete(scanId))); return true;
}
