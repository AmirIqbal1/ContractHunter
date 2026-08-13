import type { FindingStatus, ScanStatus, Severity } from "@contracthunter/core";

const severityTone: Record<Severity, string> = { critical: "red", high: "red", medium: "amber", low: "blue", informational: "gray" };
const scanTone: Record<ScanStatus, string> = { queued: "gray", cloning: "blue", detecting: "blue", preparing_dependencies: "purple", preparing_compiler: "purple", scanning: "purple", completed: "green", failed: "red" };

export function SeverityBadge({ value }: { value: Severity }) { return <span className={`badge ${severityTone[value]}`}>{value}</span>; }
export function ScanBadge({ value }: { value: ScanStatus }) { return <span className={`badge ${scanTone[value]}`}>{value}</span>; }
export function FindingStatusBadge({ value }: { value: FindingStatus }) { return <span className={`badge ${value === "verified" ? "green" : value === "rejected" ? "red" : value === "investigating" ? "blue" : "gray"}`}>{value}</span>; }
