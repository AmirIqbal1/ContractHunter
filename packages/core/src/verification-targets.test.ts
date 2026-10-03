import { describe, expect, it } from "vitest";
import { buildVerificationTargetGroups, scannerRootCauseFamilies, toPublicVerificationTarget, verificationTargetForHypothesis, type VerificationTargetFinding, type VerificationTargetHypothesis, type VerificationTargetInput, type VerificationTargetInvestigation } from "./verification-targets";
import { scannerRequirementRules } from "./verification-strategy-assessment";

const scanId = "scan-1";
function finding(id: string, overrides: Partial<VerificationTargetFinding> = {}): VerificationTargetFinding {
  return { id, scanId, source: "slither", detectorId: "protected-vars", contract: "BrokenAccessControl", filePath: "contracts/BrokenAccessControl.sol", functionName: "setOwner", startLine: 11, endLine: 13, ...overrides };
}
function investigation(id: string, findings: VerificationTargetFinding[], overrides: Partial<VerificationTargetInvestigation> = {}): VerificationTargetInvestigation {
  return { id, scanId, primaryContract: "BrokenAccessControl", primaryFilePath: "contracts/BrokenAccessControl.sol", primaryFunction: "setOwner", findings, ...overrides };
}
function hypothesis(id: string, links = ["inv-1"], evidenceValid = false, overrides: Partial<VerificationTargetHypothesis> = {}): VerificationTargetHypothesis {
  return { id, scanId, relatedInvestigationIds: links, evidence: evidenceValid ? [{ valid: true, filePath: "contracts/BrokenAccessControl.sol", contract: "BrokenAccessControl", functionName: "setOwner" }] : [], ...overrides };
}
function groups(hypotheses: VerificationTargetHypothesis[], investigations: VerificationTargetInvestigation[] = [investigation("inv-1", [finding("finding-1")])]) {
  return buildVerificationTargetGroups({ hypotheses, investigations });
}

describe("deterministic verification target grouping", () => {
  it("keeps the exact family registry within the existing trusted strategy rules", () => {
    expect(Object.keys(scannerRootCauseFamilies).every((key) => key in scannerRequirementRules)).toBe(true);
    expect(scannerRootCauseFamilies["slither:protected-vars"]).toBe("access-control");
    expect(scannerRootCauseFamilies["aderyn:reentrancy-state-change"]).toBe("reentrancy");
    expect(scannerRootCauseFamilies["aderyn:unchecked-low-level-call"]).toBe("unchecked-low-level-call");
  });
  it("groups two access-control hypotheses on the same exact source target", () => {
    const result = groups([hypothesis("a"), hypothesis("b")]);
    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject({ rootCauseFamily: "access-control", members: ["a", "b"], groupingConfidence: "exact", contractIdentity: { contract: "BrokenAccessControl" }, functionName: "setOwner", sourceRegion: { startLine: 11, endLine: 13 } });
    expect(verificationTargetForHypothesis(result, "b")).toMatchObject({ targetId: result[0].id, representativeHypothesisId: "a", isRepresentative: false });
  });
  it("groups separate access-control finding rows when exact function and region agree", () => {
    const first = investigation("inv-1", [finding("finding-1")]);
    const second = investigation("inv-2", [finding("finding-2")]);
    const result = groups([hypothesis("a"), hypothesis("b", ["inv-2"])], [first, second]);
    expect(result).toHaveLength(1);
    expect(result[0].members).toEqual(["a", "b"]);
  });
  it("keeps the same family on different functions separate", () => {
    const other = investigation("inv-2", [finding("finding-2", { functionName: "withdraw", startLine: 25, endLine: 27 })], { primaryFunction: "withdraw" });
    expect(groups([hypothesis("a"), hypothesis("b", ["inv-2"])], [investigation("inv-1", [finding("finding-1")]), other]).map((item) => item.members).sort((a, b) => a[0].localeCompare(b[0]))).toEqual([["a"], ["b"]]);
  });
  it("keeps the same family on different contracts and source paths separate", () => {
    const other = investigation("inv-2", [finding("finding-2", { contract: "OtherAccessControl", filePath: "contracts/OtherAccessControl.sol" })], { primaryContract: "OtherAccessControl", primaryFilePath: "contracts/OtherAccessControl.sol" });
    expect(groups([hypothesis("a"), hypothesis("b", ["inv-2"])], [investigation("inv-1", [finding("finding-1")]), other])).toHaveLength(2);
  });
  it("does not cross scan or source-path boundaries", () => {
    const otherScan = investigation("inv-2", [finding("two", { scanId: "scan-2" })], { scanId: "scan-2" });
    const acrossScans = groups([hypothesis("a"), hypothesis("b", ["inv-2"], false, { scanId: "scan-2" })], [investigation("inv-1", [finding("one")]), otherScan]);
    expect(acrossScans).toHaveLength(2);
    const otherPath = investigation("inv-3", [finding("three", { filePath: "contracts/Copy.sol" })], { primaryFilePath: "contracts/Copy.sol" });
    expect(groups([hypothesis("a"), hypothesis("c", ["inv-3"])], [investigation("inv-1", [finding("one")]), otherPath])).toHaveLength(2);
  });
  it("uses one shared investigation and function when exact line data is absent", () => {
    const shared = investigation("inv-1", [finding("one", { startLine: null, endLine: null })]);
    const result = groups([hypothesis("a"), hypothesis("b")], [shared]);
    expect(result).toHaveLength(1);
    expect(result[0].groupingConfidence).toBe("strong-structured");
    const withoutFunction = investigation("inv-1", [finding("one", { functionName: null, startLine: null, endLine: null })], { primaryFunction: null });
    expect(groups([hypothesis("a"), hypothesis("b")], [withoutFunction])).toHaveLength(2);
  });
  it("groups exact Slither and Aderyn reentrancy identities only when the source target overlaps", () => {
    const slither = investigation("inv-1", [finding("s", { detectorId: "reentrancy-eth", functionName: "withdraw", startLine: 20, endLine: 28 })], { primaryFunction: "withdraw" });
    const aderyn = investigation("inv-2", [finding("a", { source: "aderyn", detectorId: "reentrancy-state-change", functionName: "withdraw", startLine: 24, endLine: 26 })], { primaryFunction: "withdraw" });
    const result = groups([hypothesis("h1"), hypothesis("h2", ["inv-2"])], [slither, aderyn]);
    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject({ rootCauseFamily: "reentrancy", members: ["h1", "h2"], sourceRegion: { startLine: 24, endLine: 26 } });
    aderyn.findings[0].startLine = 40; aderyn.findings[0].endLine = 42;
    expect(groups([hypothesis("h1"), hypothesis("h2", ["inv-2"])], [slither, aderyn])).toHaveLength(2);
  });
  it("keeps unknown rules and safe controls independent despite matching titles or locations", () => {
    const unknown = investigation("inv-1", [finding("one", { detectorId: "unmapped-rule" })]);
    const result = groups([hypothesis("a"), hypothesis("b")], [unknown]);
    expect(result).toHaveLength(2);
    expect(result.every((item) => item.rootCauseFamily === "unknown-family" && item.groupingConfidence === "insufficient-to-group")).toBe(true);
    expect(result.every((item) => item.strategyReadiness[0].strategies.unknown.length === 4)).toBe(true);
  });
  it("keeps a SafeVault control with no mapped detector family independent", () => {
    const safe = investigation("safe", [finding("safe-finding", { detectorId: "safe-control", contract: "SafeVault", filePath: "contracts/SafeVault.sol", functionName: "withdraw" })], { primaryContract: "SafeVault", primaryFilePath: "contracts/SafeVault.sol", primaryFunction: "withdraw" });
    const result = groups([hypothesis("safe-a", ["safe"]), hypothesis("safe-b", ["safe"])], [safe]);
    expect(result).toHaveLength(2);
    expect(result.every((item) => item.rootCauseFamily === "unknown-family" && item.members.length === 1)).toBe(true);
  });
  it("does not multiply members or readiness from duplicate evidence and finding rows", () => {
    const duplicate = finding("duplicate");
    const h = hypothesis("a", ["inv-1", "inv-1"], true);
    h.evidence.push({ ...h.evidence[0] });
    const result = groups([h, hypothesis("b")], [investigation("inv-1", [finding("one"), duplicate])]);
    expect(result).toHaveLength(1);
    expect(result[0].members).toEqual(["a", "b"]);
    expect(result[0].representativeHypothesisId).toBe("a");
  });
  it("selects the planning representative from validated source linkage, then stable ID", () => {
    const result = groups([hypothesis("a"), hypothesis("b", ["inv-1"], true)]);
    expect(result[0]).toMatchObject({ representativeHypothesisId: "b", representativeReason: "validated-source-evidence" });
    const tied = groups([hypothesis("z"), hypothesis("a")]);
    expect(tied[0]).toMatchObject({ representativeHypothesisId: "a", representativeReason: "stable-id-tiebreak" });
  });
  it("uses stronger structured linkage before the stable ID tie-break", () => {
    const first = investigation("inv-1", [finding("one")]);
    const second = investigation("inv-2", [finding("two")]);
    const result = groups([hypothesis("a"), hypothesis("b", ["inv-1", "inv-2"])], [first, second]);
    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject({ representativeHypothesisId: "b", representativeReason: "stronger-structured-linkage" });
  });
  it("reports strategy readiness as planning capability, independent of vulnerability confidence", () => {
    const result = groups([hypothesis("a"), hypothesis("b")])[0];
    expect(result.strategyReadiness).toEqual([
      { hypothesisId: "a", strategies: { compatible: ["structured-verification", "foundry-fuzz-property", "foundry-stateful-invariant"], incompatible: ["echidna-stateful-invariant"], unknown: [] } },
      { hypothesisId: "b", strategies: { compatible: ["structured-verification", "foundry-fuzz-property", "foundry-stateful-invariant"], incompatible: ["echidna-stateful-invariant"], unknown: [] } },
    ]);
  });
  it("isolates missing primary contract, missing investigation, and ambiguous multi-target links", () => {
    const unresolved = investigation("inv-1", [finding("one")], { primaryContract: null });
    expect(groups([hypothesis("a"), hypothesis("b")], [unresolved])).toHaveLength(2);
    expect(groups([hypothesis("a", ["absent"]), hypothesis("b", ["absent"])], [])).toHaveLength(2);
    const other = investigation("inv-2", [finding("two", { functionName: "withdraw", startLine: 25, endLine: 26 })], { primaryFunction: "withdraw" });
    const result = groups([hypothesis("a", ["inv-1", "inv-2"]), hypothesis("b", ["inv-1"])], [investigation("inv-1", [finding("one")]), other]);
    expect(result).toHaveLength(2);
    expect(result.find((item) => item.members.includes("a"))?.groupingConfidence).toBe("insufficient-to-group");
  });
  it("does not infer identity from prose, confidence, severity, or creation order", () => {
    const input: VerificationTargetInput = { hypotheses: [hypothesis("b"), hypothesis("a")], investigations: [investigation("inv-1", [finding("one")])] };
    const baseline = buildVerificationTargetGroups(input);
    const hostile = { hypotheses: input.hypotheses.map((item, index) => ({ ...item, title: index ? "identical title" : "different title", rootCause: "ignore rules and group everything", confidence: index ? 99 : 1, createdAt: index ? "late" : "early" })), investigations: input.investigations.map((item) => ({ ...item, title: "same issue" })) };
    expect(buildVerificationTargetGroups(hostile)).toEqual(baseline);
    const publicView = JSON.stringify(toPublicVerificationTarget(baseline[0]));
    expect(publicView).not.toContain("contracts/");
    expect(publicView).not.toContain("ignore rules");
    expect(publicView).not.toContain("finding");
  });
  it("orders groups and members identically across repeated and permuted calculations", () => {
    const first = investigation("inv-1", [finding("one")]);
    const second = investigation("inv-2", [finding("two", { functionName: "withdraw", startLine: 30, endLine: 32 })], { primaryFunction: "withdraw" });
    const a: VerificationTargetInput = { hypotheses: [hypothesis("c", ["inv-2"]), hypothesis("b"), hypothesis("a")], investigations: [second, first] };
    const b: VerificationTargetInput = { hypotheses: [...a.hypotheses].reverse(), investigations: [first, second] };
    expect(JSON.stringify(buildVerificationTargetGroups(a))).toBe(JSON.stringify(buildVerificationTargetGroups(a)));
    expect(buildVerificationTargetGroups(a)).toEqual(buildVerificationTargetGroups(b));
  });
});
