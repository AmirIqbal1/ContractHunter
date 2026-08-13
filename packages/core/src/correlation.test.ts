import { describe, expect, it } from "vitest";
import type { CorrelatableFinding } from "./correlation";
import { buildInvestigations, calculateCorrelationScore, calculateInvestigationConfidence, calculatePriorityScore, categorizeFinding, CORRELATION_THRESHOLD, STATIC_CONFIDENCE_CAP } from "./correlation";

const scanId = "123e4567-e89b-42d3-a456-426614174000";
let sequence = 0;
function finding(overrides: Partial<CorrelatableFinding> = {}): CorrelatableFinding {
  sequence++;
  const source = overrides.source ?? "slither";
  return { id: `123e4567-e89b-42d3-a456-${String(sequence).padStart(12, "0")}`, scanId, title: "Reentrancy ETH", severity: "high", confidence: 90, source, detectorId: source === "aderyn" ? "reentrancy-state-change" : "reentrancy-eth", fingerprint: String(sequence).padStart(64, "a"), contract: "Vault", functionName: "withdraw", filePath: "src/Vault.sol", startLine: 40, endLine: 45, ...overrides };
}

describe("finding categorization", () => {
  it.each([
    ["reentrancy-eth", "reentrancy"], ["reentrancy-state-change", "reentrancy"], ["protected-vars", "access-control"], ["centralization-risk", "access-control"], ["unchecked-lowlevel", "unchecked-call"], ["unchecked-low-level-call", "unchecked-call"], ["unsafe-erc20-operation", "token"], ["unknown-detector", "unknown"],
  ] as const)("maps %s to %s", (detectorId, category) => expect(categorizeFinding({ detectorId })).toBe(category));
});

describe("correlation score", () => {
  it("strongly matches the same file, function, category, and overlapping ranges", () => {
    expect(calculateCorrelationScore(finding(), finding({ source: "aderyn" }))).toBe(100);
  });

  it("uses nearby lines without double-counting overlap", () => {
    const score = calculateCorrelationScore(finding({ contract: null }), finding({ source: "aderyn", contract: null, startLine: 51, endLine: 52 }));
    expect(score).toBeGreaterThanOrEqual(CORRELATION_THRESHOLD);
    expect(score).toBeLessThan(100);
  });

  it("includes an exact threshold match", () => {
    const left = finding({ contract: null, functionName: null, title: "First signal" });
    const right = finding({ source: "aderyn", contract: null, functionName: null, title: "Different warning", detectorId: "reentrancy-state-change", startLine: 55, endLine: 55 });
    expect(calculateCorrelationScore(left, right)).toBe(CORRELATION_THRESHOLD);
    expect(buildInvestigations([left, right])).toHaveLength(1);
  });

  it("does not match distant locations, different files, category alone, or different functions", () => {
    const base = finding();
    expect(calculateCorrelationScore(base, finding({ source: "aderyn", startLine: 500, endLine: 501, contract: null, functionName: null }))).toBeLessThan(CORRELATION_THRESHOLD);
    expect(calculateCorrelationScore(base, finding({ source: "aderyn", filePath: "src/Other.sol", contract: null, functionName: null }))).toBeLessThan(CORRELATION_THRESHOLD);
    expect(calculateCorrelationScore(base, finding({ source: "aderyn", filePath: null, contract: null, functionName: null, startLine: null, endLine: null }))).toBeLessThan(CORRELATION_THRESHOLD);
    expect(calculateCorrelationScore(base, finding({ source: "aderyn", functionName: "deposit" }))).toBe(0);
  });

  it("requires findings to belong to the same scan", () => {
    expect(calculateCorrelationScore(finding(), finding({ scanId: "223e4567-e89b-42d3-a456-426614174000" }))).toBe(0);
  });
});

describe("deterministic grouping and ranking", () => {
  it("groups Slither and Aderyn evidence without raising severity", () => {
    const slither = finding({ severity: "medium" });
    const aderyn = finding({ source: "aderyn", severity: "medium" });
    const [investigation] = buildInvestigations([slither, aderyn]);
    expect(investigation).toMatchObject({ severity: "medium", category: "reentrancy", sourceCount: 2 });
    expect(investigation.findingIds).toHaveLength(2);
    expect(investigation.reasons[0]).toContain("2 independent scanners");
  });

  it("keeps unrelated and same-scanner warnings separate", () => {
    const first = finding();
    const unrelated = finding({ source: "aderyn", functionName: "deposit", startLine: 500, endLine: 501 });
    const sameScanner = finding({ detectorId: "reentrancy-no-eth", startLine: 41, endLine: 45 });
    expect(buildInvestigations([first, unrelated, sameScanner])).toHaveLength(3);
  });

  it("groups exact same-scanner duplicates without treating them as independent", () => {
    const first = finding();
    const duplicate = finding({ detectorId: first.detectorId, startLine: first.startLine, endLine: first.endLine });
    const [investigation] = buildInvestigations([first, duplicate]);
    expect(investigation.findingIds).toHaveLength(2);
    expect(investigation.sourceCount).toBe(1);
  });

  it("does not transitively merge a weak chain", () => {
    const a = finding({ contract: null, functionName: null, startLine: 1, endLine: 1 });
    const b = finding({ source: "aderyn", contract: null, functionName: null, startLine: 10, endLine: 10 });
    const c = finding({ source: "other", contract: null, functionName: null, startLine: 19, endLine: 19 });
    const groups = buildInvestigations([a, b, c]);
    expect(groups).toHaveLength(2);
    expect(groups.map((group) => group.findingIds.length).sort()).toEqual([1, 2]);
  });

  it("is stable across input ordering and reruns", () => {
    const items = [finding(), finding({ source: "aderyn" }), finding({ functionName: "deposit", startLine: 80, endLine: 80 })];
    const first = buildInvestigations(items);
    const second = buildInvestigations([...items].reverse());
    expect(second).toEqual(first);
    expect(buildInvestigations(items)).toEqual(first);
  });

  it("caps static confidence and ranks corroborated evidence above equivalent single-source evidence", () => {
    const single = buildInvestigations([finding({ severity: "medium" })])[0];
    const multi = buildInvestigations([finding({ severity: "medium" }), finding({ source: "aderyn", severity: "medium" })])[0];
    expect(multi.confidenceScore).toBeGreaterThan(single.confidenceScore);
    expect(multi.priorityScore).toBeGreaterThan(single.priorityScore);
    expect(multi.confidenceScore).toBeLessThanOrEqual(STATIC_CONFIDENCE_CAP);
  });

  it("uses documented severity, confidence, and priority calculations", () => {
    const base = finding();
    expect(calculateInvestigationConfidence([base], base)).toBeLessThanOrEqual(STATIC_CONFIDENCE_CAP);
    expect(calculatePriorityScore("high", 80, 1)).toBe(80);
    expect(calculatePriorityScore("high", 80, 2)).toBe(85);
  });
});
