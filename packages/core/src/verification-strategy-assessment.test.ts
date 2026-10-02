import { describe, expect, it } from "vitest";
import {
  assessVerificationRequirements, assessVerificationStrategies, scannerRequirementRules,
  verificationCapabilityProfiles, verificationRequirements, verificationStrategies,
  type VerificationAssessmentInput,
} from "./verification-strategy-assessment";

const scanId = "scan-1";
const investigationId = "investigation-1";
function input(source = "slither", detectorId: string | null = "timestamp"): VerificationAssessmentInput {
  return {
    hypothesis: { scanId, relatedInvestigationIds: [investigationId] },
    investigations: [{
      id: investigationId, scanId, primaryContract: "Vault", primaryFilePath: "src/Vault.sol",
      findings: [{ scanId, source, detectorId, contract: "Vault", filePath: "src/Vault.sol" }],
    }],
  };
}
function compat(result: ReturnType<typeof assessVerificationStrategies>) {
  return Object.fromEntries(result.strategies.map((item) => [item.strategy, item.compatibility]));
}

describe("verification capability profiles", () => {
  it("represents every strategy once, separately from engine and plan mode", () => {
    expect(verificationCapabilityProfiles.map((profile) => profile.strategy)).toEqual(verificationStrategies);
    expect(verificationCapabilityProfiles.map(({ engine, planMode }) => [engine, planMode])).toEqual([
      [null, null], ["foundry", "fuzz-property"], ["foundry", "stateful-invariant"], ["echidna", "stateful-invariant"],
    ]);
    for (const profile of verificationCapabilityProfiles) {
      expect(new Set(profile.supportedRequirements).size).toBe(profile.supportedRequirements.length);
      expect(profile.supportedRequirements.every((requirement) => verificationRequirements.includes(requirement))).toBe(true);
    }
  });

  it("matches the currently implemented distinctions", () => {
    const byStrategy = Object.fromEntries(verificationCapabilityProfiles.map((profile) => [profile.strategy, new Set(profile.supportedRequirements)]));
    expect(byStrategy["structured-verification"].has("explicit-caller")).toBe(true);
    expect(byStrategy["structured-verification"].has("fuzzed-inputs")).toBe(false);
    expect(byStrategy["foundry-fuzz-property"].has("fuzzed-inputs")).toBe(true);
    expect(byStrategy["foundry-fuzz-property"].has("state-sequence")).toBe(false);
    expect(byStrategy["foundry-stateful-invariant"].has("state-sequence")).toBe(true);
    expect(byStrategy["echidna-stateful-invariant"].has("explicit-caller")).toBe(false);
    expect(byStrategy["echidna-stateful-invariant"].has("address-observation")).toBe(false);
    for (const profile of verificationCapabilityProfiles) {
      for (const requirement of ["block-timestamp", "tx-origin", "external-return-value", "reentrant-callback"] as const) {
        expect(profile.supportedRequirements).not.toContain(requirement);
      }
    }
  });
});

describe("advisory requirement assessment", () => {
  it("marks supported caller/actor requirements compatible and Echidna incompatible", () => {
    const result = assessVerificationRequirements(["multiple-actors", "explicit-caller"]);
    expect(compat(result)).toEqual({
      "structured-verification": "compatible", "foundry-fuzz-property": "compatible",
      "foundry-stateful-invariant": "compatible", "echidna-stateful-invariant": "incompatible",
    });
    expect(result.strategies[3].reasons).toEqual([
      { code: "unsupported-requirement", requirement: "explicit-caller" },
      { code: "unsupported-requirement", requirement: "multiple-actors" },
    ]);
  });

  it("keeps fuzz input and state sequence distinct", () => {
    const result = assessVerificationRequirements(["fuzzed-inputs", "state-sequence"]);
    expect(compat(result)).toEqual({
      "structured-verification": "incompatible", "foundry-fuzz-property": "incompatible",
      "foundry-stateful-invariant": "compatible", "echidna-stateful-invariant": "compatible",
    });
  });

  it("reports multiple unsupported requirements in stable order", () => {
    const result = assessVerificationRequirements(["tx-origin", "block-timestamp", "tx-origin"]);
    expect(result.requirements).toEqual(["block-timestamp", "tx-origin"]);
    expect(result.strategies[0].reasons).toEqual([
      { code: "unsupported-requirement", requirement: "block-timestamp" },
      { code: "unsupported-requirement", requirement: "tx-origin" },
    ]);
  });

  it("returns unknown when evidence is incomplete and no known blocker exists", () => {
    const result = assessVerificationRequirements(["uint-observation"], ["unmapped-scanner-rule"]);
    expect(result.strategies.every((item) => item.compatibility === "unknown")).toBe(true);
    expect(assessVerificationRequirements([]).strategies[0].reasons).toEqual([{ code: "insufficient-structured-evidence" }]);
  });

  it("retains a known incompatibility alongside unmapped evidence", () => {
    const result = assessVerificationRequirements(["block-timestamp"], ["unmapped-scanner-rule"]);
    expect(result.strategies.every((item) => item.compatibility === "incompatible")).toBe(true);
  });
});

describe("trusted scanner fact extraction", () => {
  it("maps only exact source and rule identities", () => {
    expect(scannerRequirementRules["slither:timestamp"]).toEqual(["block-timestamp"]);
    expect(scannerRequirementRules["slither:unchecked-lowlevel"]).toEqual(["external-return-value"]);
    expect(scannerRequirementRules["slither:reentrancy-eth"]).toContain("reentrant-callback");
    expect(scannerRequirementRules["slither:protected-vars"]).toEqual(["explicit-caller"]);
    expect(scannerRequirementRules["slither:tx-origin"]).toEqual(["tx-origin"]);
  });

  it("assesses ReentrancyVault-style exact reentrancy evidence conservatively", () => {
    const result = assessVerificationStrategies(input("slither", "reentrancy-eth"));
    expect(result.requirements).toEqual(["balance-observation", "state-sequence", "reentrant-callback"]);
    expect(Object.values(compat(result))).toEqual(Array(4).fill("incompatible"));
  });

  it("assesses UncheckedExternalCall-style exact unchecked return evidence conservatively", () => {
    const result = assessVerificationStrategies(input("slither", "unchecked-lowlevel"));
    expect(result.requirements).toEqual(["external-return-value"]);
    expect(Object.values(compat(result))).toEqual(Array(4).fill("incompatible"));
  });

  it("assesses TimestampLottery-style exact timestamp evidence conservatively", () => {
    const result = assessVerificationStrategies(input("slither", "timestamp"));
    expect(result.requirements).toEqual(["block-timestamp"]);
    expect(Object.values(compat(result))).toEqual(Array(4).fill("incompatible"));
  });

  it("assesses BrokenAccessControl-style protected-variable evidence with explicit caller", () => {
    const result = assessVerificationStrategies(input("slither", "protected-vars"));
    expect(result.requirements).toEqual(["explicit-caller"]);
    expect(compat(result)).toEqual({
      "structured-verification": "compatible", "foundry-fuzz-property": "compatible",
      "foundry-stateful-invariant": "compatible", "echidna-stateful-invariant": "incompatible",
    });
  });

  it("assesses TxOriginWallet-style exact tx.origin evidence conservatively", () => {
    const result = assessVerificationStrategies(input("slither", "tx-origin"));
    expect(result.requirements).toEqual(["tx-origin"]);
    expect(Object.values(compat(result))).toEqual(Array(4).fill("incompatible"));
  });

  it("returns unknown for an unrecognized scanner rule", () => {
    const result = assessVerificationStrategies(input("slither", "unknown-rule"));
    expect(result.requirements).toEqual([]);
    expect(Object.values(compat(result))).toEqual(Array(4).fill("unknown"));
    expect(result.strategies[0].reasons).toEqual([{ code: "unmapped-scanner-rule" }]);
  });

  it("does not infer from hypothesis or finding prose", () => {
    const withProse = {
      ...input("slither", "unknown-rule"),
      title: "tx.origin timestamp owner reentrancy",
    };
    expect(assessVerificationStrategies(withProse).strategies[0]).toEqual({
      strategy: "structured-verification", compatibility: "unknown", reasons: [{ code: "invalid-assessment-input" }],
    });
    expect(assessVerificationStrategies(input("slither", "unknown-rule")).requirements).toEqual([]);
  });

  it("returns unknown for SafeVault/control without correlated evidence", () => {
    const data = input(); data.investigations[0].findings = [];
    expect(assessVerificationStrategies(data).strategies[0].reasons).toEqual([{ code: "insufficient-structured-evidence" }]);
  });

  it("returns unknown for absent investigation and unresolved primary contract", () => {
    const missing = input(); missing.investigations = [];
    expect(assessVerificationStrategies(missing).strategies[0].reasons).toEqual([{ code: "missing-investigation" }]);
    const unresolved = input(); unresolved.investigations[0].primaryContract = null;
    expect(assessVerificationStrategies(unresolved).strategies[0].reasons).toEqual([{ code: "primary-contract-unresolved" }]);
  });

  it("rejects cross-scan and cross-contract evidence without using its facts", () => {
    const crossScan = input(); crossScan.investigations[0].scanId = "other";
    expect(assessVerificationStrategies(crossScan).requirements).toEqual([]);
    const crossContract = input(); crossContract.investigations[0].findings[0].contract = "Other";
    expect(assessVerificationStrategies(crossContract).strategies[0].reasons).toEqual([{ code: "ambiguous-primary-contract" }]);
  });

  it("is stable under duplicate and reordered evidence", () => {
    const data = input("slither", "timestamp");
    const second = { ...data.investigations[0].findings[0], detectorId: "unchecked-lowlevel" };
    data.investigations[0].findings.push(second);
    const once = assessVerificationStrategies(data);
    data.investigations[0].findings = [second, ...data.investigations[0].findings].reverse();
    data.hypothesis.relatedInvestigationIds.push(investigationId);
    expect(assessVerificationStrategies(data)).toEqual(once);
  });

  it("bounds malformed or oversized fact inputs", () => {
    const data = input(); data.hypothesis.relatedInvestigationIds = Array(33).fill(investigationId);
    expect(assessVerificationStrategies(data).strategies[0].reasons).toEqual([{ code: "invalid-assessment-input" }]);
    expect(assessVerificationStrategies({})).toEqual(assessVerificationRequirements([], ["invalid-assessment-input"]));
  });
});
