import { describe, expect, it } from "vitest";
import { protocolAnalysisResultSchema } from "./ai-domain";
import { validAIOutput } from "./ai-test-fixture";

describe("protocol analysis structured schema", () => {
  it("accepts valid structured output", () => expect(protocolAnalysisResultSchema.safeParse(validAIOutput).success).toBe(true));
  it("rejects missing fields, unknown fields, invalid confidence, and AI-assigned invariant status", () => {
    expect(protocolAnalysisResultSchema.safeParse({ ...validAIOutput, assets: undefined }).success).toBe(false);
    expect(protocolAnalysisResultSchema.safeParse({ ...validAIOutput, unexpected: true }).success).toBe(false);
    expect(protocolAnalysisResultSchema.safeParse({ ...validAIOutput, protocol: { ...validAIOutput.protocol, confidence: 101 } }).success).toBe(false);
    expect(protocolAnalysisResultSchema.safeParse({ ...validAIOutput, invariants: [{ ...validAIOutput.invariants[0], status: "violated" }] }).success).toBe(false);
  });
});
