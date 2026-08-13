import type { AIProvider, AIProviderResult, ProtocolAnalysisInput, ProtocolAnalysisResult } from "./ai-domain";

export class MockAIProvider implements AIProvider {
  readonly id = "mock";
  calls: ProtocolAnalysisInput[] = [];
  constructor(private readonly result: ProtocolAnalysisResult | Error, private readonly metadata: Partial<Omit<AIProviderResult, "analysis">> = {}) {}
  async analyzeProtocol(input: ProtocolAnalysisInput): Promise<AIProviderResult> {
    this.calls.push(input);
    if (this.result instanceof Error) throw this.result;
    return { analysis: this.result, actualModel: input.model, requestId: "mock-request", inputTokens: 100, outputTokens: 50, totalTokens: 150, durationMs: 5, ...this.metadata };
  }
}
