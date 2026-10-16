import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { AuditPriorityResult } from "@contracthunter/core";
import { conceptFor, StartHere } from "./start-here";

const scanId = "11111111-1111-4111-8111-111111111111";
const contractId = `pn:${"a".repeat(64)}`, functionId = `pn:${"b".repeat(64)}`;
const secondFunctionId = `pn:${"c".repeat(64)}`;
const location = { sourceUnitName: "src/Vault.sol", startLine: 12, endLine: 12,
  startColumn: 0, endColumn: 10, startByte: 100, endByte: 110 };
const factor = (id: string, key: string, points: number) => ({ id, count: 1, potentialPoints: points,
  points, explanationKey: key, evidence: [{ kind: "graph-node", id: functionId, source: location }] });
function fixture(): AuditPriorityResult {
  const result = { schema: "contracthunter-audit-priority-v1", scanId, scoreMeaning:
    "A higher Audit Priority Score means more known security-relevant characteristics worth manual review. It does not mean a vulnerability is more likely.",
    analysisStatus: "partial", warnings: [{ code: "call-target-unresolved", count: 2 }],
    rulesetVersion: "contracthunter-audit-priority-ruleset-v1", derivationVersion: "deriver-v1",
    explanationCatalogVersion: "catalog-v1", protocolGraphId: `pg:${"d".repeat(64)}`,
    repositoryMapId: `rm:${"e".repeat(64)}`, contentSha256: "f".repeat(64), totalRankableContracts: 2,
    projectOverview: { solidityFiles: 3, filesByClass: [{ classification: "core", count: 2 }], contracts: 2,
      coreContracts: 1, peripheryContracts: 1, interfaces: 0, libraries: 0, externalEntryPoints: 2,
      externalCalls: 1, unresolvedCalls: 2, tokenTransferLikeOperations: 1, nativeValueTransfers: 0,
      proxyRelationships: 0, controlRelationships: 0, contractsWithFindings: 1 },
    rankedContracts: [{ id: contractId, name: "Vault<script>alert(1)</script>", qualifiedName: "src/Vault.sol:Vault",
      source: location, classification: "core", score: 72, uncappedScore: 72, findingCount: 1,
      factors: [factor("token-transfer", "token-transfer", 12), factor("external-call", "external-call", 8)],
      securityViews: ["money-flow", "attack-surface"], checklist: [{ conceptKey: "external-call",
        prompt: "Inspect target selection and return handling.", factorIds: ["external-call"], findingIds: [] }],
      recommendedFunctions: [{ id: functionId, signature: "withdraw(uint256)", source: location, score: 35,
        uncappedScore: 35, findingCount: 1, factors: [factor("external-call", "external-call", 8)], checklist: [] },
        { id: secondFunctionId, signature: "withdraw(address)", source: location, score: 20,
          uncappedScore: 20, findingCount: 0, factors: [factor("token-transfer", "token-transfer", 12)], checklist: [] }] },
      { id: `pn:${"9".repeat(64)}`, name: "Helper", qualifiedName: "src/Helper.sol:Helper", source: { ...location, sourceUnitName: "src/Helper.sol" },
        classification: "periphery", score: 2, uncappedScore: 2, findingCount: 0, factors: [factor("core-protocol", "core-protocol", 2)],
        securityViews: [], checklist: [], recommendedFunctions: [] }] };
  return result as unknown as AuditPriorityResult;
}

describe("Start Here", () => {
  it("renders exact overview, server order, priority disclaimer and partial warning", () => {
    const html = renderToStaticMarkup(<StartHere result={fixture()} repositoryName="Example" />);
    expect(html).toContain("Solidity files"); expect(html).toContain(">3</dd>");
    expect(html.indexOf("Vault&lt;script&gt;")).toBeLessThan(html.indexOf("Helper"));
    expect(html).toContain("does not mean a vulnerability is more likely");
    expect(html).toContain("Partial analysis"); expect(html).toContain("External call targets unresolved: 2");
    expect(html).not.toContain("<script>alert(1)</script>");
    expect(html).not.toContain("safe</");
  });
  it("preserves canonical contract, overloaded function, map, view and source links", () => {
    const html = renderToStaticMarkup(<StartHere result={fixture()} repositoryName="Example" />);
    expect(html).toContain(`/contracts/${encodeURIComponent(contractId)}?mode=beginner`);
    expect(html).toContain(`/functions/${encodeURIComponent(functionId)}?mode=beginner`);
    expect(html).toContain(`/functions/${encodeURIComponent(secondFunctionId)}?mode=beginner`);
    expect(html).toContain(`view=money-flow&amp;node=${encodeURIComponent(contractId)}`);
    expect(html).not.toContain("view=permissions");
    expect(html).toContain("unit=src%2FVault.sol&amp;line=12");
  });
  it("shows researcher contributions without changing order or scores", () => {
    const beginner = renderToStaticMarkup(<StartHere result={fixture()} repositoryName="Example" initialMode="beginner" />);
    const researcher = renderToStaticMarkup(<StartHere result={fixture()} repositoryName="Example" initialMode="researcher" />);
    for (const html of [beginner, researcher]) { expect(html).toContain("72 / 100"); expect(html).toContain("Helper"); }
    expect(researcher).toContain("token-transfer +12 / 12");
    expect(researcher).toContain("contracthunter-audit-priority-ruleset-v1");
    expect(beginner).not.toContain("token-transfer +12 / 12");
    expect(researcher).toContain('aria-pressed="true"');
  });
  it("uses fixed help and bounded unknown-key fallback", () => {
    expect(conceptFor("external-call")?.term).toBe("External call");
    expect(conceptFor("<img src=x onerror=alert(1)>")).toBeNull();
    const poisoned = fixture();
    (poisoned.rankedContracts[0].factors[0] as { explanationKey: string }).explanationKey = "<img src=x onerror=alert(1)>";
    const html = renderToStaticMarkup(<StartHere result={poisoned} repositoryName="Example" />);
    expect(html).toContain("Explanation unavailable");
    expect(html).not.toContain("<img src=x onerror=alert(1)>");
  });
  it("keeps Impact Lab authority outside ranking actions and handles an empty result", () => {
    const html = renderToStaticMarkup(<StartHere result={fixture()} repositoryName="Example" />);
    expect(html).not.toContain("Open in Impact Lab");
    const empty = fixture(); empty.rankedContracts = []; empty.totalRankableContracts = 0;
    expect(renderToStaticMarkup(<StartHere result={empty} repositoryName="Example" />)).toContain("could not derive enough source-linked structure");
  });
});
