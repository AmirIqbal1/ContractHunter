import type { AIProvider, AIProviderResult, ProtocolAnalysisInput, ProtocolAnalysisResult } from "./ai-domain";
import type { SecurityReviewInput, SecurityReviewProviderResult, SecurityReviewResult } from "./security-review";

export class MockAIProvider implements AIProvider {
  readonly id = "mock";
  calls: ProtocolAnalysisInput[] = [];
  reviewCalls: SecurityReviewInput[] = [];
  constructor(private readonly result: ProtocolAnalysisResult | Error, private readonly metadata: Partial<Omit<AIProviderResult, "analysis">> = {}, private readonly reviews: Partial<Record<string, SecurityReviewResult | Error>> = {}) {}
  async analyzeProtocol(input: ProtocolAnalysisInput): Promise<AIProviderResult> {
    this.calls.push(input);
    if (this.result instanceof Error) throw this.result;
    return { analysis: this.result, actualModel: input.model, requestId: "mock-request", inputTokens: 100, outputTokens: 50, totalTokens: 150, durationMs: 5, ...this.metadata };
  }
  async reviewSecurity(input: SecurityReviewInput): Promise<SecurityReviewProviderResult> {
    this.reviewCalls.push(input); const configured = this.reviews[input.reviewerId];
    if (configured instanceof Error) throw configured;
    const review: SecurityReviewResult = configured ?? { reviewer: input.reviewerId, summary: "No material issues identified in the supplied bounded context.", hypotheses: [], areasReviewed: [input.reviewerId], limitations: ["Mock provider response."] };
    return { review, actualModel: input.model, requestId: `mock-review-${input.reviewerId}`, inputTokens: 120, outputTokens: 80, totalTokens: 200, durationMs: 5 };
  }
}
