import { describe, expect, it } from "vitest";
import { dynamicEvidenceSchema, verificationOutcomeSchema, verificationRunStatusSchema } from "./hypothesis-verification";

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
