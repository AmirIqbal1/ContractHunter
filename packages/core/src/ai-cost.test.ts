import { describe, expect, it } from "vitest";
import {
  aggregateRecordedAICost,
  calculateAICost,
  calculateGpt6LunaCost,
  DEFAULT_OPENAI_MODEL,
  estimateModelAICost,
  estimateProtocolAICost,
  estimateSecurityReviewAICost,
  formatAICost,
  GPT6_LUNA_STANDARD_PRICING,
} from "./ai-cost";

const pricing = { inputCostPerMillionUsd: 0.25, outputCostPerMillionUsd: 2 };

describe("AI cost calculations", () => {
  it("uses the canonical GPT-6 Luna Standard rate card for both context tiers", () => {
    expect(DEFAULT_OPENAI_MODEL).toBe("gpt-6-luna");
    expect(calculateAICost(1_000_000, 0, GPT6_LUNA_STANDARD_PRICING.short)).toBe(0.10);
    expect(calculateAICost(0, 1_000_000, GPT6_LUNA_STANDARD_PRICING.short)).toBe(0.50);
    expect(calculateAICost(1_000_000, 1_000_000, GPT6_LUNA_STANDARD_PRICING.short)).toBe(0.60);
    expect(GPT6_LUNA_STANDARD_PRICING.short.cachedInputCostPerMillionUsd).toBe(0.01);
    expect(GPT6_LUNA_STANDARD_PRICING.short.cacheWriteCostPerMillionUsd).toBe(0.125);
    expect(calculateAICost(1_000_000, 0, GPT6_LUNA_STANDARD_PRICING.long)).toBe(0.20);
    expect(calculateAICost(0, 1_000_000, GPT6_LUNA_STANDARD_PRICING.long)).toBe(0.75);
    expect(GPT6_LUNA_STANDARD_PRICING.long.cachedInputCostPerMillionUsd).toBe(0.02);
    expect(GPT6_LUNA_STANDARD_PRICING.long.cacheWriteCostPerMillionUsd).toBe(0.25);
  });

  it("uses recorded per-request input tokens to select Luna's exact context tier", () => {
    expect(calculateGpt6LunaCost(272_000, 1_000_000)).toBe(0.5272);
    expect(calculateGpt6LunaCost(272_001, 1_000_000)).toBe(0.8044002);
    expect(calculateGpt6LunaCost(null, 1)).toBeNull();
  });

  it("does not assign an unknown preflight context tier to the short rate", () => {
    const result = estimateModelAICost(1_000_000, 1_000_000, DEFAULT_OPENAI_MODEL, pricing);
    expect(result.costUsd).toBeNull();
    expect(result.display).toContain("short / ");
    expect(result.display).toContain("long");
    expect(estimateModelAICost(1_000_000, 1_000_000, "other-model", pricing)).toEqual({ costUsd: 2.25, display: "$2.25" });
  });
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
