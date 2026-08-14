import path from "node:path";
import {
  ProviderSecurityReviewer, REVIEWER_NAMES, ReviewerContextBuilder, SecurityReviewPlanner, loadConfig, passesHypothesisQuality,
  sanitiseError, validateEvidence, type AIProvider, type ProtocolAnalysisResult, type QualityHypothesis,
  type ReviewerContextModel, type SecurityReviewPlan, type SecurityReviewerId,
} from "@contracthunter/core";
import {
  correlateAndPersistHypotheses, createSecurityReviewerRun, createSecurityReviewPlan, getCurrentProtocolAnalysis, getCurrentSecurityReviewPlan,
  getDatabase, getScan, insertVulnerabilityHypotheses, listInvariants, listInvestigations, listScanScanners,
  listSecurityReviewerRuns, updateSecurityReviewerRun, updateSecurityReviewPlan, updateSecurityReviewState,
  type DatabaseClient, type SecurityReviewPlanRow,
} from "@contracthunter/db";
import { OpenAIProvider } from "./openai-provider";

const parse = <T,>(value: string, fallback: T): T => { try { return JSON.parse(value) as T; } catch { return fallback; } };
const normalise = (value: string) => value.toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();

function protocolResult(row: NonNullable<ReturnType<typeof getCurrentProtocolAnalysis>>, invariantRows: ReturnType<typeof listInvariants>): ProtocolAnalysisResult {
  return {
    protocol: { name: row.protocolName, types: parse(row.protocolTypes, ["unknown"]), summary: row.summary, architectureSummary: row.architectureSummary, confidence: row.confidence },
    assets: parse(row.assets, []), roles: parse(row.roles, []), entryPoints: parse(row.entryPoints, []), criticalState: parse(row.criticalState, []), externalDependencies: parse(row.externalDependencies, []), flows: parse(row.flows, []), trustAssumptions: parse(row.trustAssumptions, []),
    invariants: invariantRows.map((item) => ({ title: item.title, description: item.description, category: item.category, severityIfViolated: item.severityIfViolated, confidence: item.confidence, rationale: item.rationale, relatedContracts: parse(item.relatedContracts, []), relatedFunctions: parse(item.relatedFunctions, []), relatedState: parse(item.relatedState, []), sourceEvidence: parse(item.sourceEvidence, []), testability: item.testability })), limitations: parse(row.limitations, []),
  };
}

function buildPlan(database: DatabaseClient, scanId: string): { analysis: NonNullable<ReturnType<typeof getCurrentProtocolAnalysis>>; protocol: ProtocolAnalysisResult; model: ReviewerContextModel; plan: SecurityReviewPlan } {
  const config = loadConfig(); const analysis = getCurrentProtocolAnalysis(database, scanId); if (!analysis) throw new Error("Protocol analysis is required before security review.");
  const invariantRows = listInvariants(database, { scanId }); const investigations = listInvestigations(database, { scanId }); const protocol = protocolResult(analysis, invariantRows);
  const plan = new SecurityReviewPlanner().plan({ protocol, invariantCount: invariantRows.length, investigationCategories: investigations.map((item) => item.category) }, Math.min(config.AI_MAX_REVIEWERS, config.AI_REVIEW_MAX_TOTAL_REQUESTS));
  const model: ReviewerContextModel = { protocol: protocol.protocol, assets: protocol.assets, roles: protocol.roles, entryPoints: protocol.entryPoints, criticalState: protocol.criticalState, externalDependencies: protocol.externalDependencies, flows: protocol.flows, trustAssumptions: protocol.trustAssumptions, invariants: invariantRows.map((item) => ({ id: item.id, title: item.title, description: item.description, category: item.category, relatedContracts: parse(item.relatedContracts, []), relatedFunctions: parse(item.relatedFunctions, []) })), investigations: investigations.map((item) => ({ id: item.id, title: item.title, category: item.category, severity: item.severity, filePath: item.primaryFilePath, contract: item.primaryContract, functionName: item.primaryFunction })) };
  return { analysis, protocol, model, plan };
}

export function previewSecurityReview(options: { scanId: string; database?: DatabaseClient; repositoryPath?: string }) {
  const config = loadConfig(); const database = options.database ?? getDatabase(); const scan = getScan(database, options.scanId); if (!scan) throw new Error("Scan not found.");
  const { analysis, model, plan } = buildPlan(database, scan.id); const repositoryPath = options.repositoryPath ?? path.join(config.REPOSITORY_DIR, scan.id); const scannerSummary = Object.fromEntries(listScanScanners(database, scan.id).map((scanner) => [scanner.scannerId, scanner.findingCount]));
  const builder = new ReviewerContextBuilder({ maxSourceBytes: config.AI_REVIEW_MAX_SOURCE_BYTES, maxFiles: config.AI_REVIEW_MAX_FILES, maxFileBytes: config.AI_MAX_FILE_BYTES });
  const contexts = new Map(plan.selected.map((item) => [item.reviewerId, builder.build(repositoryPath, item.reviewerId, model, scannerSummary)]));
  return { analysis, plan, contexts, approximateSourceBytes: [...contexts.values()].reduce((sum, item) => sum + item.manifest.totalSourceBytes, 0), approximateRequestCount: plan.selected.length };
}

async function boundedMap<T>(items: T[], concurrency: number, worker: (item: T) => Promise<void>): Promise<void> {
  let next = 0; await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, async () => { while (next < items.length) { const index = next++; await worker(items[index]); } }));
}

export async function runSecurityReview(options: { scanId: string; provider?: AIProvider; database?: DatabaseClient; repositoryPath?: string }): Promise<SecurityReviewPlanRow | null> {
  const config = loadConfig(); const database = options.database ?? getDatabase(); const scan = getScan(database, options.scanId); if (!scan) throw new Error("Scan not found.");
  if (!config.AI_ENABLED && !options.provider) { updateSecurityReviewState(database, scan.id, "disabled"); return null; }
  if (!options.provider && !config.OPENAI_API_KEY) { updateSecurityReviewState(database, scan.id, "failed", "OpenAI is not configured."); return null; }
  const started = Date.now(); let activePlan: SecurityReviewPlanRow | null = null;
  try {
    const preview = previewSecurityReview({ scanId: scan.id, database, repositoryPath: options.repositoryPath });
    if (preview.plan.estimatedRequestCount > config.AI_REVIEW_MAX_TOTAL_REQUESTS) throw new Error("Security review request limit exceeded.");
    const planRow = createSecurityReviewPlan(database, { scanId: scan.id, protocolAnalysisId: preview.analysis.id, plan: preview.plan, estimatedSourceBytes: preview.approximateSourceBytes }); activePlan = planRow;
    updateSecurityReviewPlan(database, planRow.id, { status: "running" }); updateSecurityReviewState(database, scan.id, "running");
    const provider = options.provider ?? new OpenAIProvider(config.OPENAI_API_KEY); const requestedModel = config.OPENAI_MODEL || "mock-model";
    const runItems = preview.plan.selected.map((planned) => {
      const context = preview.contexts.get(planned.reviewerId)!;
      const run = createSecurityReviewerRun(database, { planId: planRow.id, scanId: scan.id, protocolAnalysisId: preview.analysis.id, reviewerId: planned.reviewerId, reviewerName: REVIEWER_NAMES[planned.reviewerId], selectionReason: planned.reason, promptVersion: planned.promptVersion, provider: provider.id, requestedModel, contextManifest: context.manifest });
      return { planned, context, run };
    });
    const invariantRows = listInvariants(database, { scanId: scan.id }); const investigations = listInvestigations(database, { scanId: scan.id });
    const invariantByReference = new Map(invariantRows.flatMap((item) => [[item.id, item.id], [normalise(item.title), item.id]])); const investigationByReference = new Map(investigations.flatMap((item) => [[item.id, item.id], [normalise(item.title), item.id]]));
    await boundedMap(runItems, config.AI_REVIEW_CONCURRENCY, async ({ planned, context, run }) => {
      updateSecurityReviewerRun(database, run.id, "running");
      try {
        const reviewer = new ProviderSecurityReviewer(planned.reviewerId as SecurityReviewerId, provider, requestedModel, config.AI_REVIEW_TIMEOUT_MS); const result = await reviewer.review(context); const metadata = reviewer.lastResult!;
        const accepted: QualityHypothesis[] = result.hypotheses.map((hypothesis) => ({ ...hypothesis, confidence: Math.min(85, hypothesis.confidence), evidence: hypothesis.evidence.filter((evidence) => !path.isAbsolute(evidence.filePath) && !evidence.filePath.includes("\0") && !evidence.filePath.split(/[\\/]/).includes("..")).map((evidence) => ({ ...validateEvidence(options.repositoryPath ?? path.join(config.REPOSITORY_DIR, scan.id), evidence), explanation: evidence.explanation })), violatedInvariantIds: hypothesis.violatedInvariants.map((reference) => invariantByReference.get(reference) ?? invariantByReference.get(normalise(reference))).filter((id): id is string => Boolean(id)), relatedInvestigationIds: hypothesis.relatedInvestigations.map((reference) => investigationByReference.get(reference) ?? investigationByReference.get(normalise(reference))).filter((id): id is string => Boolean(id)) })).filter(passesHypothesisQuality);
        insertVulnerabilityHypotheses(database, accepted.map((item) => ({ scanId: scan.id, protocolAnalysisId: preview.analysis.id, reviewerId: planned.reviewerId, reviewerRunId: run.id, title: item.title, category: item.category, severity: item.severity, severityJustification: item.severityJustification, confidence: item.confidence, summary: item.summary, rootCause: item.rootCause, preconditions: JSON.stringify(item.preconditions), attackPath: JSON.stringify(item.attackPath), impact: item.impact, affectedAssets: JSON.stringify(item.affectedAssets), affectedContracts: JSON.stringify(item.affectedContracts), affectedFunctions: JSON.stringify(item.affectedFunctions), evidence: JSON.stringify(item.evidence), violatedInvariantIds: JSON.stringify(item.violatedInvariantIds), relatedInvestigationIds: JSON.stringify(item.relatedInvestigationIds), falsePositiveRisks: JSON.stringify(item.falsePositiveRisks), verificationStrategy: JSON.stringify(item.verificationStrategy) })));
        updateSecurityReviewerRun(database, run.id, "completed", { actualModel: metadata.actualModel, summary: result.summary, areasReviewed: JSON.stringify(result.areasReviewed), limitations: JSON.stringify([...result.limitations, ...(accepted.length < result.hypotheses.length ? [`${result.hypotheses.length - accepted.length} vague or unsupported hypothesis(es) rejected by deterministic quality controls.`] : [])]), hypothesisCount: accepted.length, inputTokens: metadata.inputTokens, outputTokens: metadata.outputTokens, totalTokens: metadata.totalTokens, durationMs: metadata.durationMs, requestId: metadata.requestId });
      } catch (error) { updateSecurityReviewerRun(database, run.id, "failed", { error: sanitiseError(error) }); }
    });
    correlateAndPersistHypotheses(database, planRow.id); const runs = listSecurityReviewerRuns(database, planRow.id); const completed = runs.filter((item) => item.status === "completed").length; const failed = runs.length - completed; const status = completed === 0 ? "failed" : failed > 0 ? "completed-with-warnings" : "completed"; const error = failed ? `${failed} of ${runs.length} reviewers failed.` : null;
    const sum = (field: "inputTokens" | "outputTokens" | "totalTokens") => { const values = runs.map((item) => item[field]).filter((value): value is number => value !== null); return values.length ? values.reduce((a, b) => a + b, 0) : null; };
    updateSecurityReviewPlan(database, planRow.id, { status, actualRequestCount: runs.length, totalInputTokens: sum("inputTokens"), totalOutputTokens: sum("outputTokens"), totalTokens: sum("totalTokens"), durationMs: Date.now() - started, error, completedAt: new Date() }); updateSecurityReviewState(database, scan.id, status, error);
    return getCurrentSecurityReviewPlan(database, scan.id) ?? null;
  } catch (error) { const message = sanitiseError(error); if (activePlan) updateSecurityReviewPlan(database, activePlan.id, { status: "failed", durationMs: Date.now() - started, error: message, completedAt: new Date() }); updateSecurityReviewState(database, scan.id, "failed", message); return null; }
}
