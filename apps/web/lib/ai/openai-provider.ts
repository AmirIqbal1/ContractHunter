import OpenAI from "openai";
import { zodTextFormat } from "openai/helpers/zod";
import { protocolAnalysisResultSchema, securityReviewResultSchema, type AIProvider, type AIProviderResult, type ProtocolAnalysisInput, type SecurityReviewInput, type SecurityReviewProviderResult } from "@contracthunter/core";

export class OpenAIProvider implements AIProvider {
  readonly id = "openai";
  private readonly client: OpenAI;
  constructor(apiKey: string, client?: OpenAI) { this.client = client ?? new OpenAI({ apiKey, maxRetries: 0 }); }

  async analyzeProtocol(input: ProtocolAnalysisInput): Promise<AIProviderResult> {
    const started = Date.now();
    try {
      const request = () => this.client.responses.parse({ model: input.model, store: false, tools: [], input: [{ role: "system", content: input.systemPrompt }, { role: "user", content: input.context.content }], text: { format: zodTextFormat(protocolAnalysisResultSchema, "protocol_analysis") } }, { timeout: input.timeoutMs });
      let response;
      try { response = await request(); }
      catch (error) {
        if (!(error instanceof OpenAI.APIConnectionError || error instanceof OpenAI.RateLimitError || error instanceof OpenAI.InternalServerError)) throw error;
        response = await request();
      }
      if (!response.output_parsed) throw new Error("OpenAI returned no structured protocol analysis.");
      const analysis = protocolAnalysisResultSchema.parse(response.output_parsed);
      return { analysis, actualModel: response.model ?? null, requestId: response._request_id ?? response.id ?? null, inputTokens: response.usage?.input_tokens ?? null, outputTokens: response.usage?.output_tokens ?? null, totalTokens: response.usage?.total_tokens ?? null, durationMs: Date.now() - started };
    } catch (error) {
      if (error instanceof OpenAI.AuthenticationError) throw new Error("OpenAI authentication failed.");
      if (error instanceof OpenAI.APIConnectionTimeoutError) throw new Error(`OpenAI analysis timed out after ${input.timeoutMs} ms.`);
      if (error instanceof OpenAI.BadRequestError) throw new Error("OpenAI rejected the structured analysis request.");
      throw error;
    }
  }

  async reviewSecurity(input: SecurityReviewInput): Promise<SecurityReviewProviderResult> {
    const started = Date.now();
    try {
      const response = await this.client.responses.parse({ model: input.model, store: false, tools: [], input: [{ role: "system", content: input.systemPrompt }, { role: "user", content: input.context.content }], text: { format: zodTextFormat(securityReviewResultSchema, "security_review") } }, { timeout: input.timeoutMs });
      if (!response.output_parsed) throw new Error("OpenAI returned no structured security review.");
      const review = securityReviewResultSchema.parse(response.output_parsed);
      return { review, actualModel: response.model ?? null, requestId: response._request_id ?? response.id ?? null, inputTokens: response.usage?.input_tokens ?? null, outputTokens: response.usage?.output_tokens ?? null, totalTokens: response.usage?.total_tokens ?? null, durationMs: Date.now() - started };
    } catch (error) {
      if (error instanceof OpenAI.AuthenticationError) throw new Error("OpenAI authentication failed.");
      if (error instanceof OpenAI.APIConnectionTimeoutError) throw new Error(`OpenAI security review timed out after ${input.timeoutMs} ms.`);
      if (error instanceof OpenAI.BadRequestError) throw new Error("OpenAI rejected the structured security review request.");
      throw error;
    }
  }
}
