import path from "node:path";
import { AnalysisContextBuilder, PROTOCOL_ANALYSIS_PROMPT_VERSION, PROTOCOL_ANALYSIS_SYSTEM_PROMPT, loadConfig, protocolAnalysisResultSchema, sanitiseError, validateEvidence, type AIProvider, type ProtocolAnalysisResult } from "@contracthunter/core";
import { createProtocolAnalysis, getDatabase, getScan, listInvestigations, listScanScanners, updateAIState, type DatabaseClient, type ProtocolAnalysisRow } from "@contracthunter/db";
import { OpenAIProvider } from "./openai-provider";

function validateResultEvidence(repositoryPath: string, result: ProtocolAnalysisResult): ProtocolAnalysisResult {
  const clone = structuredClone(result);
  const withEvidence = [clone.assets, clone.roles, clone.entryPoints, clone.criticalState, clone.externalDependencies, clone.flows, clone.trustAssumptions];
  for (const collection of withEvidence) for (const item of collection) item.evidence = item.evidence.map((evidence) => validateEvidence(repositoryPath, evidence));
  for (const invariant of clone.invariants) invariant.sourceEvidence = invariant.sourceEvidence.map((evidence) => validateEvidence(repositoryPath, evidence));
  return clone;
}

export async function runProtocolAnalysis(options: { scanId: string; provider?: AIProvider; database?: DatabaseClient; repositoryPath?: string }): Promise<ProtocolAnalysisRow | null> {
  const config = loadConfig(); const database = options.database ?? getDatabase(); const scan = getScan(database, options.scanId);
  if (!scan) throw new Error("Scan not found.");
  if (!config.AI_ENABLED && !options.provider) { updateAIState(database, scan.id, "disabled"); return null; }
  if (!options.provider && !config.OPENAI_API_KEY) { updateAIState(database, scan.id, "failed", "OpenAI is not configured."); return null; }
  updateAIState(database, scan.id, "running");
  const repositoryPath = options.repositoryPath ?? path.join(config.REPOSITORY_DIR, scan.id);
  try {
    const investigationRows = listInvestigations(database, { scanId: scan.id });
    const scannerSummary = Object.fromEntries(listScanScanners(database, scan.id).map((scanner) => [scanner.scannerId, scanner.findingCount]));
    const context = new AnalysisContextBuilder({ maxSourceBytes: config.AI_MAX_SOURCE_BYTES, maxFiles: config.AI_MAX_FILES, maxFileBytes: config.AI_MAX_FILE_BYTES }).build(repositoryPath, investigationRows, scannerSummary);
    const provider = options.provider ?? new OpenAIProvider(config.OPENAI_API_KEY);
    const response = await provider.analyzeProtocol({ model: config.OPENAI_MODEL || "mock-model", promptVersion: PROTOCOL_ANALYSIS_PROMPT_VERSION, systemPrompt: PROTOCOL_ANALYSIS_SYSTEM_PROMPT, context, timeoutMs: config.AI_TIMEOUT_MS });
    const result = validateResultEvidence(repositoryPath, protocolAnalysisResultSchema.parse(response.analysis));
    const saved = createProtocolAnalysis(database, { scanId: scan.id, provider: provider.id, requestedModel: config.OPENAI_MODEL || "mock-model", actualModel: response.actualModel, promptVersion: PROTOCOL_ANALYSIS_PROMPT_VERSION, result, coverageStatus: context.manifest.truncated || result.limitations.length > 0 ? "partial" : "complete", contextManifest: context.manifest, durationMs: response.durationMs, inputTokens: response.inputTokens, outputTokens: response.outputTokens, totalTokens: response.totalTokens, requestId: response.requestId });
    updateAIState(database, scan.id, "completed");
    return saved;
  } catch (error) {
    updateAIState(database, scan.id, "failed", sanitiseError(error));
    return null;
  }
}
