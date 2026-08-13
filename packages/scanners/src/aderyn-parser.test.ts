import { mkdir, mkdtemp, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { mapAderynSeverity, normaliseAderynFindings, parseAderynJson } from "./aderyn-parser";

const scanId = "123e4567-e89b-42d3-a456-426614174000";

function report(high: unknown[] = [], low: unknown[] = []) {
  return JSON.stringify({ files_summary: { total_source_units: 1 }, issue_count: { high: high.length, low: low.length }, high_issues: { issues: high }, low_issues: { issues: low }, future_field: true });
}

describe("Aderyn JSON parsing and normalization", () => {
  it("accepts valid, zero-finding, and future-compatible reports", () => {
    expect(parseAderynJson(report()).high_issues?.issues).toEqual([]);
  });

  it("normalizes multiple issues and instances from the current Aderyn report structure", async () => {
    const repository = await mkdtemp(path.join(tmpdir(), "aderyn-parser-"));
    await mkdir(path.join(repository, "src"));
    await writeFile(path.join(repository, "src/Vault.sol"), "contract Vault {}");
    const parsed = parseAderynJson(report(
      [{ title: "Unchecked Call", description: "Return value is unchecked.", detector_name: "unchecked-call", references: ["https://example.com/reference"], instances: [{ contract_path: "src/Vault.sol", line_no: 12, end_line: 14, contract_name: "Vault", function_name: "withdraw", src: "100:20" }, { contract_path: "src/Vault.sol", line_no: 30 }] }],
      [{ title: "Low Signal", detector_name: "low-signal", instances: [{ contract_path: "src/Vault.sol", line_no: 5 }] }],
    ));
    const findings = normaliseAderynFindings(parsed, scanId, repository);
    expect(findings).toHaveLength(3);
    expect(findings[0]).toMatchObject({ title: "Unchecked Call", detectorId: "unchecked-call", source: "aderyn", severity: "high", confidence: 40, filePath: "src/Vault.sol", startLine: 12, endLine: 14, contract: "Vault", functionName: "withdraw", attackScenario: "", impact: "" });
    expect(findings[0].evidence).toContain("Source range: 100:20");
    expect(findings[0].evidence).toContain("https://example.com/reference");
    expect(findings[2].severity).toBe("low");
  });

  it("handles missing optional issue and location fields conservatively", async () => {
    const repository = await mkdtemp(path.join(tmpdir(), "aderyn-parser-"));
    const [finding] = normaliseAderynFindings(parseAderynJson(report([{ future: "value" }])), scanId, repository);
    expect(finding).toMatchObject({ title: "Aderyn Finding", detectorId: "aderyn-finding", filePath: null, startLine: null, endLine: null, contract: null, functionName: null });
  });

  it("rejects malformed JSON", () => {
    expect(() => parseAderynJson("not-json")).toThrow("malformed JSON");
  });

  it.each([["High", "high"], ["Medium", "medium"], ["Low", "low"], ["Informational", "informational"], ["Info", "informational"], ["Unknown", "informational"]] as const)("maps %s severity without promotion", (value, expected) => {
    expect(mapAderynSeverity(value)).toBe(expected);
  });

  it("does not persist absolute paths, traversal, or symlink escapes", async () => {
    const repository = await mkdtemp(path.join(tmpdir(), "aderyn-parser-"));
    await symlink("/etc/passwd", path.join(repository, "escaped.sol"));
    const issues = ["/etc/passwd", "../outside.sol", "escaped.sol"].map((contract_path, index) => ({ detector_name: `unsafe-${index}`, instances: [{ contract_path, line_no: 1 }] }));
    const findings = normaliseAderynFindings(parseAderynJson(report(issues)), scanId, repository);
    expect(findings.map((finding) => finding.filePath)).toEqual([null, null, null]);
  });
});
