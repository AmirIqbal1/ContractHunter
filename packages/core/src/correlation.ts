import { createHash } from "node:crypto";
import type { Finding, Severity, VulnerabilityCategory } from "./domain";

export const CORRELATION_THRESHOLD = 60;
export const STATIC_CONFIDENCE_CAP = 89;

const detectorCategories: Record<string, VulnerabilityCategory> = {
  "reentrancy-eth": "reentrancy", "reentrancy-no-eth": "reentrancy", "reentrancy-benign": "reentrancy", "reentrancy-events": "reentrancy", "reentrancy-state-change": "reentrancy",
  "arbitrary-send-eth": "access-control", "protected-vars": "access-control", "unprotected-upgrade": "upgradeability", "unprotected-initializer": "upgradeability", "centralization-risk": "access-control",
  "unchecked-lowlevel": "unchecked-call", "unchecked-send": "unchecked-call", "unchecked-transfer": "unchecked-call", "unchecked-return": "unchecked-call", "unchecked-low-level-call": "unchecked-call", "return-bomb": "unchecked-call",
  "divide-before-multiply": "arithmetic", "division-before-multiplication": "arithmetic", "incorrect-shift": "arithmetic", "unsafe-casting": "arithmetic",
  "weak-prng": "oracle", "weak-randomness": "oracle", "pyth-unchecked-confidence": "oracle",
  "timestamp": "timestamp", "block-timestamp-deadline": "timestamp",
  "calls-loop": "denial-of-service", "costly-loop": "denial-of-service", "msg-value-loop": "denial-of-service", "require-revert-in-loop": "denial-of-service",
  "missing-zero-check": "state-management", "state-change-without-event": "state-management", "state-no-address-check": "state-management", "uninitialized-state": "state-management", "uninitialized-local": "state-management",
  "incorrect-erc20-interface": "token", "incorrect-erc721-interface": "token", "unsafe-erc20-operation": "token", "arbitrary-transfer-from": "token",
  "solc-version": "informational", "pragma": "informational", "unspecific-solidity-pragma": "informational", "unused-import": "informational", "dead-code": "informational",
};

const detectorCorrelationKeys: Record<string, string> = {
  "missing-zero-check": "address-zero-check",
  "state-no-address-check": "address-zero-check",
  "unchecked-lowlevel": "unchecked-low-level-call",
  "unchecked-low-level-call": "unchecked-low-level-call",
  "divide-before-multiply": "division-order",
  "division-before-multiplication": "division-order",
  "weak-prng": "weak-randomness",
  "weak-randomness": "weak-randomness",
};

export type CorrelatableFinding = Pick<Finding, "id" | "scanId" | "title" | "severity" | "confidence" | "source" | "detectorId" | "fingerprint" | "contract" | "functionName" | "filePath" | "startLine" | "endLine">;

export type BuiltInvestigation = {
  fingerprint: string;
  findingIds: string[];
  title: string;
  severity: Severity;
  category: VulnerabilityCategory;
  priorityScore: number;
  confidenceScore: number;
  primaryFilePath: string | null;
  primaryContract: string | null;
  primaryFunction: string | null;
  startLine: number | null;
  endLine: number | null;
  sourceCount: number;
  reasons: string[];
};

export function categorizeFinding(finding: Pick<CorrelatableFinding, "detectorId">): VulnerabilityCategory {
  return detectorCategories[finding.detectorId?.toLowerCase() ?? ""] ?? "unknown";
}

function normalizedTokens(value: string): Set<string> {
  return new Set(value.toLowerCase().split(/[^a-z0-9]+/).filter((token) => token.length > 2 && !["potential", "warning", "condition", "issue"].includes(token)));
}

function titleSimilarity(first: CorrelatableFinding, second: CorrelatableFinding): boolean {
  const left = normalizedTokens(`${first.detectorId ?? ""} ${first.title}`);
  const right = normalizedTokens(`${second.detectorId ?? ""} ${second.title}`);
  if (!left.size || !right.size) return false;
  const intersection = [...left].filter((token) => right.has(token)).length;
  return intersection / Math.max(left.size, right.size) >= 0.6;
}

function range(finding: CorrelatableFinding): [number, number] | null {
  if (!finding.startLine) return null;
  return [finding.startLine, finding.endLine ?? finding.startLine];
}

/** Location dominates this score. Different named functions are a hard veto, and
 * overlap/nearby bonuses are mutually exclusive to avoid double counting. */
export function calculateCorrelationScore(first: CorrelatableFinding, second: CorrelatableFinding): number {
  if (first.scanId !== second.scanId) return 0;
  if (first.functionName && second.functionName && first.functionName !== second.functionName) return 0;
  let score = 0;
  if (first.filePath && first.filePath === second.filePath) score += 35;
  if (first.contract && first.contract === second.contract) score += 15;
  if (first.functionName && first.functionName === second.functionName) score += 20;
  const leftRange = range(first); const rightRange = range(second);
  if (leftRange && rightRange && first.filePath && first.filePath === second.filePath) {
    if (leftRange[0] <= rightRange[1] && rightRange[0] <= leftRange[1]) score += 20;
    else if (Math.min(Math.abs(leftRange[0] - rightRange[1]), Math.abs(rightRange[0] - leftRange[1])) <= 10) score += 10;
  }
  const firstCategory = categorizeFinding(first); const secondCategory = categorizeFinding(second);
  if (firstCategory !== "unknown" && firstCategory === secondCategory) score += 15;
  const firstKey = detectorCorrelationKeys[first.detectorId?.toLowerCase() ?? ""];
  const secondKey = detectorCorrelationKeys[second.detectorId?.toLowerCase() ?? ""];
  if ((firstKey && firstKey === secondKey) || titleSimilarity(first, second)) score += 5;
  return Math.min(100, score);
}

function sameScannerDuplicate(first: CorrelatableFinding, second: CorrelatableFinding): boolean {
  return first.source === second.source && first.detectorId === second.detectorId && first.filePath === second.filePath && first.startLine === second.startLine && first.endLine === second.endLine;
}

const severityRank: Record<Severity, number> = { critical: 5, high: 4, medium: 3, low: 2, informational: 1 };
const severityBase: Record<Severity, number> = { critical: 100, high: 80, medium: 60, low: 30, informational: 10 };

export function calculateInvestigationConfidence(findings: CorrelatableFinding[], representative: CorrelatableFinding): number {
  const signals = findings.map((finding) => finding.source === "aderyn" ? 45 : finding.source === "slither" ? 45 + finding.confidence * 0.25 : 50);
  let score = signals.reduce((sum, value) => sum + value, 0) / signals.length;
  const sources = new Set(findings.map((finding) => finding.source)).size;
  if (sources > 1) score += 15;
  const correlations = findings.filter((finding) => finding.id !== representative.id).map((finding) => calculateCorrelationScore(representative, finding));
  if (correlations.length) score += correlations.reduce((sum, value) => sum + value, 0) / correlations.length * 0.15;
  if (representative.filePath && representative.startLine && representative.functionName) score += 5;
  const categories = new Set(findings.map(categorizeFinding));
  if (categories.size === 1 && !categories.has("unknown")) score += 5;
  return Math.min(STATIC_CONFIDENCE_CAP, Math.max(0, Math.round(score)));
}

export function calculatePriorityScore(severity: Severity, confidence: number, sourceCount: number): number {
  return Math.min(100, Math.round(severityBase[severity] * 0.65 + confidence * 0.35 + (sourceCount > 1 ? 5 : 0)));
}

function canonicalTitle(category: VulnerabilityCategory, primary: CorrelatableFinding): string {
  if (category === "unknown" || category === "informational") return primary.title.slice(0, 200);
  const labels: Partial<Record<VulnerabilityCategory, string>> = { "access-control": "access-control issue", "unchecked-call": "unchecked call", "denial-of-service": "denial of service", "state-management": "state-management issue" };
  const location = primary.contract && primary.functionName ? `${primary.contract}.${primary.functionName}` : primary.functionName ?? primary.contract ?? primary.filePath;
  return `Potential ${labels[category] ?? category}${location ? ` in ${location}` : ""}`.slice(0, 200);
}

function investigationReasons(findings: CorrelatableFinding[], primary: CorrelatableFinding, category: VulnerabilityCategory): string[] {
  const sources = [...new Set(findings.map((finding) => finding.source))].sort();
  const reasons: string[] = [];
  if (sources.length > 1) reasons.push(`Reported by ${sources.length} independent scanners`);
  if (findings.length > 1 && primary.filePath && findings.every((finding) => finding.filePath === primary.filePath)) reasons.push(`Findings reference ${primary.filePath}`);
  if (findings.length > 1 && primary.functionName && findings.every((finding) => finding.functionName === primary.functionName)) reasons.push(`Findings reference ${primary.functionName}()`);
  const primaryRange = range(primary);
  if (primaryRange && findings.some((finding) => { const candidate = range(finding); return finding.id !== primary.id && candidate && finding.filePath === primary.filePath && (primaryRange[0] <= candidate[1] + 10 && candidate[0] <= primaryRange[1] + 10); })) reasons.push("Source locations overlap or are nearby");
  if (findings.length > 1 && category !== "unknown" && findings.every((finding) => categorizeFinding(finding) === category)) reasons.push(`Findings are classified as ${category}`);
  if (!reasons.length) reasons.push("Single static-analysis finding queued for review");
  return reasons;
}

function stableOrder(findings: CorrelatableFinding[]): CorrelatableFinding[] {
  return [...findings].sort((first, second) => Number(Boolean(second.functionName)) - Number(Boolean(first.functionName)) || Number(Boolean(second.contract)) - Number(Boolean(first.contract)) || [first.filePath ?? "~", first.functionName ?? "~", first.startLine ?? Number.MAX_SAFE_INTEGER, first.source, first.detectorId ?? "", first.fingerprint].join("|").localeCompare([second.filePath ?? "~", second.functionName ?? "~", second.startLine ?? Number.MAX_SAFE_INTEGER, second.source, second.detectorId ?? "", second.fingerprint].join("|")));
}

export function buildInvestigations(input: CorrelatableFinding[]): BuiltInvestigation[] {
  const groups: Array<{ primary: CorrelatableFinding; findings: CorrelatableFinding[] }> = [];
  const remaining = stableOrder(input);
  while (remaining.length) {
    const primary = remaining.shift()!;
    const selected = [primary];
    const matches = remaining.map((finding) => ({ finding, score: calculateCorrelationScore(primary, finding) })).filter(({ score }) => score >= CORRELATION_THRESHOLD).sort((left, right) => {
      const scoreDifference = right.score - left.score;
      return scoreDifference || (stableOrder([left.finding, right.finding])[0].id === left.finding.id ? -1 : 1);
    });
    for (const match of matches) {
      const sameSource = selected.filter((finding) => finding.source === match.finding.source);
      if (!sameSource.length || sameSource.some((finding) => sameScannerDuplicate(finding, match.finding))) selected.push(match.finding);
    }
    const selectedIds = new Set(selected.map((finding) => finding.id));
    for (let index = remaining.length - 1; index >= 0; index--) if (selectedIds.has(remaining[index].id)) remaining.splice(index, 1);
    groups.push({ primary, findings: selected });
  }
  return groups.map(({ primary, findings }) => {
    const ordered = stableOrder(findings);
    const categoryCounts = new Map<VulnerabilityCategory, number>();
    for (const finding of ordered) { const category = categorizeFinding(finding); categoryCounts.set(category, (categoryCounts.get(category) ?? 0) + 1); }
    const category = [...categoryCounts].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))[0]?.[0] ?? "unknown";
    const severity = [...ordered].sort((a, b) => severityRank[b.severity] - severityRank[a.severity] || a.fingerprint.localeCompare(b.fingerprint))[0].severity;
    const sourceCount = new Set(ordered.map((finding) => finding.source)).size;
    const confidenceScore = calculateInvestigationConfidence(ordered, primary);
    const fingerprint = createHash("sha256").update(ordered.map((finding) => finding.fingerprint).sort().join(":"), "utf8").digest("hex");
    return { fingerprint, findingIds: ordered.map((finding) => finding.id), title: canonicalTitle(category, primary), severity, category, priorityScore: calculatePriorityScore(severity, confidenceScore, sourceCount), confidenceScore, primaryFilePath: primary.filePath, primaryContract: primary.contract, primaryFunction: primary.functionName, startLine: primary.startLine, endLine: primary.endLine, sourceCount, reasons: investigationReasons(ordered, primary, category) };
  }).sort((a, b) => b.priorityScore - a.priorityScore || a.fingerprint.localeCompare(b.fingerprint));
}
