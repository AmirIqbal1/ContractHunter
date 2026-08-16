export type AITokenPricing = {
  inputCostPerMillionUsd: number;
  outputCostPerMillionUsd: number;
};

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
