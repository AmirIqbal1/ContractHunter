import { describe, expect, it } from "vitest";
import { detectorTitle, mapSlitherConfidence, mapSlitherSeverity, normaliseSlitherFindings, parseSlitherJson } from "./slither-parser";

const scanId = "123e4567-e89b-42d3-a456-426614174000";
const repositoryPath = "/data/repositories/123e4567-e89b-42d3-a456-426614174000";

function output(detectors: unknown[] = []) {
  return JSON.stringify({ success: true, error: null, results: { detectors, future_slither_field: true }, version: "future" });
}

describe("Slither JSON parsing and mappings", () => {
  it("accepts valid output, zero findings, and unknown additional fields", () => {
    expect(parseSlitherJson(output()).results?.detectors).toEqual([]);
  });

  it.each([["High", "high"], ["Medium", "medium"], ["Low", "low"], ["Informational", "informational"], ["Optimization", "informational"]] as const)("maps impact %s", (input, expected) => {
    expect(mapSlitherSeverity(input)).toBe(expected);
  });

  it.each([["High", 90], ["Medium", 70], ["Low", 50], ["Unknown", 40]] as const)("maps confidence %s", (input, expected) => {
    expect(mapSlitherConfidence(input)).toBe(expected);
  });

  it("rejects malformed and unsuccessful output", () => {
    expect(() => parseSlitherJson("not-json")).toThrow("malformed JSON");
    expect(() => parseSlitherJson(JSON.stringify({ success: false, error: "Compilation failed", results: {} }))).toThrow("Compilation failed");
  });

  it("normalises detector content and the best source mapping", () => {
    const parsed = parseSlitherJson(output([{
      check: "reentrancy-eth", impact: "High", confidence: "Medium", description: `${repositoryPath}/contracts/Vault.sol has an external call before state update.`, unexpected: 123,
      elements: [{
        type: "function", name: "withdraw(uint256)",
        source_mapping: { filename_relative: "contracts/Vault.sol", filename_short: "Vault.sol", lines: [18, 19, 20] },
        type_specific_fields: { parent: { name: "Vault" }, future: true },
      }],
    }]));
    const [finding] = normaliseSlitherFindings(parsed, scanId, repositoryPath);
    expect(finding).toMatchObject({
      title: "Reentrancy ETH", detectorId: "reentrancy-eth", source: "slither", severity: "high", confidence: 70,
      contract: "Vault", functionName: "withdraw(uint256)", filePath: "contracts/Vault.sol", startLine: 18, endLine: 20,
      attackScenario: "", impact: "",
    });
    expect(finding.evidence).not.toContain(repositoryPath);
  });

  it("supports informational findings and removes duplicate detector locations", () => {
    const detector = { check: "solc-version", impact: "Informational", confidence: "High", description: "Version range.", elements: [] };
    const findings = normaliseSlitherFindings(parseSlitherJson(output([detector, detector])), scanId, repositoryPath);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("informational");
  });

  it("never persists an absolute or escaping path", () => {
    const findings = normaliseSlitherFindings(parseSlitherJson(output([{
      check: "test", description: "Test", elements: [{ type: "contract", name: "Bad", source_mapping: { filename_relative: "/etc/passwd", lines: [1] } }],
    }])), scanId, repositoryPath);
    expect(findings[0].filePath).toBeNull();
  });

  it("creates readable titles without severity claims", () => {
    expect(detectorTitle("reentrancy-eth")).toBe("Reentrancy ETH");
  });
});
