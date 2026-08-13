import { describe, expect, it } from "vitest";
import type { NewFinding, Scanner, ScanContext } from "@contracthunter/core";
import { executeScanners } from "./scanner-runner";

const context = { repositoryPath: "/tmp/repository", scan: { id: "123e4567-e89b-42d3-a456-426614174000" } } as ScanContext;
const finding = (source: string): NewFinding => ({ title: `${source} finding`, severity: "low", confidence: 40, source, detectorId: `${source}-test`, fingerprint: source.padEnd(64, "a"), contract: null, functionName: null, filePath: null, startLine: null, endLine: null, rootCause: "Evidence", attackScenario: "", impact: "", evidence: "Evidence", status: "candidate" });
function scanner(id: string, outcome: "success" | "failure" | "unavailable", findings = 1): Scanner {
  return { id, name: id === "slither" ? "Slither" : "Aderyn", isAvailable: async () => outcome !== "unavailable", scan: async () => { if (outcome === "failure") throw new Error(`${id} failed`); return { scannerId: id, findings: Array.from({ length: findings }, () => finding(id)), warnings: [], durationMs: 10 }; } };
}

describe("independent scanner execution", () => {
  it("completes Slither and Aderyn and preserves both result sets", async () => {
    const sources: string[] = [];
    const result = await executeScanners({ scanners: [scanner("slither", "success"), scanner("aderyn", "success")], context, onResult: (_scanner, output) => sources.push(...output.findings.map((item) => item.source)) });
    expect(result.map((item) => item.status)).toEqual(["completed", "completed"]);
    expect(sources).toEqual(["slither", "aderyn"]);
  });

  it.each([["success", "failure"], ["failure", "success"]] as const)("keeps partial success when outcomes are %s / %s", async (slither, aderyn) => {
    const results: string[] = [];
    const execution = await executeScanners({ scanners: [scanner("slither", slither), scanner("aderyn", aderyn)], context, onResult: (item) => results.push(item.id) });
    expect(execution.filter((item) => item.status === "completed")).toHaveLength(1);
    expect(results).toHaveLength(1);
  });

  it("reports both failures without throwing away execution metadata", async () => {
    const execution = await executeScanners({ scanners: [scanner("slither", "failure"), scanner("aderyn", "unavailable")], context });
    expect(execution.map((item) => item.status)).toEqual(["failed", "unavailable"]);
  });

  it("treats zero findings as successful", async () => {
    const [execution] = await executeScanners({ scanners: [scanner("aderyn", "success", 0)], context });
    expect(execution).toMatchObject({ status: "completed", findingCount: 0 });
  });
});
