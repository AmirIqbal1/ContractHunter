import { describe, expect, it } from "vitest";
import { dynamicEvidenceSchema, verificationHarnessPlanSchema, verificationOutcomeSchema, verificationRunStatusSchema } from "./hypothesis-verification";

const evidence = {
  assertionName: "second depositor receives proportional shares",
  expectedBehavior: "The second depositor receives shares at the pre-deposit exchange rate.",
  observedBehavior: "The second depositor received fewer shares than the pre-deposit exchange rate requires.",
  direction: "supports",
  contract: "Vault",
  functionName: "deposit",
  details: "A bounded local assertion compared the expected and actual share amounts.",
} as const;

describe("hypothesis verification domain", () => {
  it("accepts only verification run statuses", () => {
    for (const status of ["queued", "running", "completed", "failed"]) expect(verificationRunStatusSchema.parse(status)).toBe(status);
    expect(verificationRunStatusSchema.safeParse("confirmed").success).toBe(false);
  });

  it("keeps verification outcomes distinct from execution status", () => {
    for (const outcome of ["confirmed", "refuted", "inconclusive"]) expect(verificationOutcomeSchema.parse(outcome)).toBe(outcome);
    expect(verificationOutcomeSchema.safeParse("completed").success).toBe(false);
  });

  it("validates bounded structured dynamic evidence", () => {
    expect(dynamicEvidenceSchema.parse(evidence)).toEqual(evidence);
    expect(dynamicEvidenceSchema.safeParse({ ...evidence, direction: "reviewer-agrees" }).success).toBe(false);
    expect(dynamicEvidenceSchema.safeParse({ ...evidence, observedBehavior: "" }).success).toBe(false);
    expect(dynamicEvidenceSchema.safeParse({ ...evidence, shellCommand: "forge test" }).success).toBe(false);
  });
});

const plan = {
  scanId: "11111111-1111-4111-8111-111111111111", hypothesisId: "22222222-2222-4222-8222-222222222222", resolvedCommit: "a".repeat(40), compilerVersion: "0.8.24",
  primaryContract: "Counter", primarySourcePath: "contracts/Counter.sol", relevantFunctions: ["increment", "count"], sourceFiles: ["contracts/Counter.sol"],
  verificationGoal: "Confirm deterministic counter state changes.", expectedProperty: "Increment changes count from zero to one.", verificationSteps: ["Deploy Counter.", "Call increment.", "Read count."],
  operations: [{ kind: "deploy", contractName: "Counter", instanceName: "target" }, { kind: "call", instanceName: "target", functionName: "increment" }, { kind: "read-uint", instanceName: "target", functionName: "count", resultName: "observed" }],
  assertions: [{ kind: "uint-eq", actual: "observed", expected: "1", description: "Count becomes one." }],
} as const;

describe("verification harness plan", () => {
  it("accepts a bounded structured plan", () => { expect(verificationHarnessPlanSchema.parse(plan)).toEqual(plan); });
  it("rejects arbitrary Solidity and unsafe source paths", () => {
    expect(verificationHarnessPlanSchema.safeParse({ ...plan, soliditySource: "contract Arbitrary {}" }).success).toBe(false);
    for (const primarySourcePath of ["../Counter.sol", "/tmp/Counter.sol", "https://example/Counter.sol", "contracts\\Counter.sol"]) expect(verificationHarnessPlanSchema.safeParse({ ...plan, primarySourcePath, sourceFiles: [primarySourcePath] }).success).toBe(false);
  });
  it("rejects oversized structured plans and unstable compilers", () => {
    expect(verificationHarnessPlanSchema.safeParse({ ...plan, verificationSteps: Array.from({ length: 31 }, () => "step") }).success).toBe(false);
    expect(verificationHarnessPlanSchema.safeParse({ ...plan, compilerVersion: "0.8.24-nightly" }).success).toBe(false);
  });
});
