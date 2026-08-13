import type { ScanStatus } from "./domain";

const transitions: Record<ScanStatus, readonly ScanStatus[]> = {
  queued: ["cloning", "failed"],
  cloning: ["detecting", "failed"],
  detecting: ["scanning", "failed"],
  scanning: ["completed", "failed"],
  completed: [],
  failed: [],
};

export function canTransition(from: ScanStatus, to: ScanStatus): boolean {
  return transitions[from].includes(to);
}

export function assertTransition(from: ScanStatus, to: ScanStatus): void {
  if (!canTransition(from, to)) throw new Error(`Invalid scan state transition: ${from} -> ${to}`);
}

export function sanitiseError(error: unknown): string {
  const raw = error instanceof Error ? error.message : typeof error === "string" ? error : "An unexpected scan error occurred.";
  return raw.replace(/https?:\/\/[^\s@]+@/g, "https://").replace(/[\r\n\t]+/g, " ").slice(0, 500);
}
