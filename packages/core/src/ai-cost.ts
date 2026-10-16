export type AITokenPricing = {
  inputCostPerMillionUsd: number;
  outputCostPerMillionUsd: number;
};

export const DEFAULT_OPENAI_MODEL = "gpt-6-luna" as const;
export const GPT6_LUNA_LONG_CONTEXT_INPUT_THRESHOLD = 272_000;
/** Standard text-token API pricing snapshot. Rates are USD per million tokens. */
export const GPT6_LUNA_STANDARD_PRICING = {
  short: { inputCostPerMillionUsd: 0.10, cachedInputCostPerMillionUsd: 0.01,
    cacheWriteCostPerMillionUsd: 0.125, outputCostPerMillionUsd: 0.50 },
  long: { inputCostPerMillionUsd: 0.20, cachedInputCostPerMillionUsd: 0.02,
    cacheWriteCostPerMillionUsd: 0.25, outputCostPerMillionUsd: 0.75 },
} as const;

export function displayAIModel(model: string): string { return model === DEFAULT_OPENAI_MODEL ? "GPT-6 Luna" : model; }

/** Input/output-only estimate: current persistence does not record cache reads or writes. */
export function calculateGpt6LunaCost(inputTokens: number | null, outputTokens: number | null): number | null {
  if (inputTokens === null || outputTokens === null) return null;
  if (![inputTokens, outputTokens].every((value) => Number.isSafeInteger(value) && value >= 0)) return null;
  const tier = inputTokens > GPT6_LUNA_LONG_CONTEXT_INPUT_THRESHOLD ? GPT6_LUNA_STANDARD_PRICING.long : GPT6_LUNA_STANDARD_PRICING.short;
  const inputRateMicroUsd = BigInt(Math.round(tier.inputCostPerMillionUsd * 1_000_000));
  const outputRateMicroUsd = BigInt(Math.round(tier.outputCostPerMillionUsd * 1_000_000));
  return Number(BigInt(inputTokens) * inputRateMicroUsd + BigInt(outputTokens) * outputRateMicroUsd) / 1_000_000_000_000;
}

/** Preflight byte counts are approximate and cannot establish the billable context tier. */
export function estimateModelAICost(inputTokens: number, outputTokens: number, model: string,
  fallbackPricing: AITokenPricing): { costUsd: number | null; display: string } {
  if (model !== DEFAULT_OPENAI_MODEL) {
    const costUsd = calculateAICost(inputTokens, outputTokens, fallbackPricing);
    return { costUsd, display: costUsd === null ? "unavailable" : formatAICost(costUsd) };
  }
  const short = calculateAICost(inputTokens, outputTokens, GPT6_LUNA_STANDARD_PRICING.short)!;
  const long = calculateAICost(inputTokens, outputTokens, GPT6_LUNA_STANDARD_PRICING.long)!;
  return { costUsd: null, display: `${formatAICost(short)} short / ${formatAICost(long)} long (uncached estimate; tier unknown)` };
}

export const APPROXIMATE_BYTES_PER_TOKEN = 4;
export const PROTOCOL_ESTIMATED_OUTPUT_TOKENS = 4_000;
export const SECURITY_REVIEW_ESTIMATED_OUTPUT_TOKENS_PER_REVIEWER = 3_000;

export function calculateAICost(inputTokens: number | null, outputTokens: number | null, pricing: AITokenPricing): number | null {
  if (inputTokens === null || outputTokens === null) return null;
  return (inputTokens * pricing.inputCostPerMillionUsd + outputTokens * pricing.outputCostPerMillionUsd) / 1_000_000;
}

export function approximateTokensFromBytes(bytes: number): number {
  return Math.ceil(Math.max(0, bytes) / APPROXIMATE_BYTES_PER_TOKEN);
}

export function estimateProtocolAICost(approximateInputBytes: number, pricing: AITokenPricing): { inputTokens: number; outputTokens: number; costUsd: number } {
  const inputTokens = approximateTokensFromBytes(approximateInputBytes);
  return { inputTokens, outputTokens: PROTOCOL_ESTIMATED_OUTPUT_TOKENS, costUsd: calculateAICost(inputTokens, PROTOCOL_ESTIMATED_OUTPUT_TOKENS, pricing)! };
}

export function estimateSecurityReviewAICost(aggregateInputBytes: number, selectedReviewerCount: number, pricing: AITokenPricing): { inputTokens: number; outputTokens: number; costUsd: number } {
  const inputTokens = approximateTokensFromBytes(aggregateInputBytes);
  const outputTokens = Math.max(0, selectedReviewerCount) * SECURITY_REVIEW_ESTIMATED_OUTPUT_TOKENS_PER_REVIEWER;
  return { inputTokens, outputTokens, costUsd: calculateAICost(inputTokens, outputTokens, pricing)! };
}

export function aggregateRecordedAICost(costs: Array<number | null>): number | null {
  const recorded = costs.filter((cost): cost is number => cost !== null);
  return recorded.length ? recorded.reduce((total, cost) => total + cost, 0) : null;
}

export function formatAICost(costUsd: number): string {
  return costUsd < 1 ? `$${costUsd.toFixed(4)}` : `$${costUsd.toFixed(2)}`;
}
