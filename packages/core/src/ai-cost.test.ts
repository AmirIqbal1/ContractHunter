import { describe, expect, it } from "vitest";
import {
  aggregateRecordedAICost,
  calculateAICost,
  estimateProtocolAICost,
  estimateSecurityReviewAICost,
  formatAICost,
} from "./ai-cost";

const pricing = { inputCostPerMillionUsd: 0.25, outputCostPerMillionUsd: 2 };

describe("AI cost calculations", () => {
  it("calculates exact input and output token cost", () => {
    expect(calculateAICost(1_000_000, 500_000, pricing)).toBe(1.25);
  });

  it("returns zero for zero tokens", () => {
    expect(calculateAICost(0, 0, pricing)).toBe(0);
  });

  it("returns null when either token count is unavailable", () => {
    expect(calculateAICost(null, 10, pricing)).toBeNull();
    expect(calculateAICost(10, null, pricing)).toBeNull();
  });

  it("estimates protocol cost from bytes and the bounded output allowance", () => {
    expect(estimateProtocolAICost(4_001, pricing)).toEqual({ inputTokens: 1_001, outputTokens: 4_000, costUsd: 0.00825025 });
  });

  it("estimates aggregate security-review cost and per-reviewer output", () => {
    expect(estimateSecurityReviewAICost(8_000, 3, pricing)).toEqual({ inputTokens: 2_000, outputTokens: 9_000, costUsd: 0.0185 });
  });

  it("aggregates only recorded stage costs", () => {
    expect(aggregateRecordedAICost([0.001, null, 0.0025])).toBeCloseTo(0.0035);
    expect(aggregateRecordedAICost([null, null])).toBeNull();
  });

  it("formats tiny and ordinary costs without floating-point noise", () => {
    expect(formatAICost(0.00044)).toBe("$0.0004");
    expect(formatAICost(0.01234)).toBe("$0.0123");
    expect(formatAICost(1.235)).toBe("$1.24");
  });
});
