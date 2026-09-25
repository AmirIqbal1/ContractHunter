import { lstat, readFile, realpath } from "node:fs/promises";
import { createHash } from "node:crypto";
import path from "node:path";
import semver from "semver";
import {
  EXECUTABLE_INVARIANT_SCHEMA_VERSION, INVARIANT_PROPOSAL_PROMPT_VERSION, INVARIANT_PROPOSAL_SYSTEM_PROMPT,
  VerificationPlanContextBuilder, calculateAICost, executableInvariantPlanSchema, invariantCapabilityProfile, invariantPlanHash,
  invariantProposalSchema, loadConfig, repositorySolidityPathSchema, sourceEvidenceSchema, stableCompilerVersionSchema,
  validateEvidence, type ExecutableInvariantPlan, type InvariantProposalContext, type InvariantProposalFailureCode,
  type InvariantProposalGenerationResult, type InvariantProposalProvider, type InvariantProposalProviderResult,
} from "@contracthunter/core";
import {
  createExecutableInvariantProposal, getCurrentProtocolAnalysis, getDatabase, getExecutableInvariantProposal,
  getInvestigation, getInvariant, getScan, getVulnerabilityHypothesis, type DatabaseClient, type ExecutableInvariantProposalRow,
} from "@contracthunter/db";
import { ExecutableInvariantGenerator, extractSolidityPragmas, SolidityFunctionValidationError } from "@contracthunter/scanners";
import { OpenAIProvider } from "@/lib/ai/openai-provider";

export class InvariantProposalRequestError extends Error {
  constructor(readonly code: "unknown_hypothesis" | "unknown_proposal" | "invalid_state", message: string) { super(message); this.name = "InvariantProposalRequestError"; }
}
export type InvariantProposalServiceOptions = {
  database: DatabaseClient; repositoryRoot: string; provider: InvariantProposalProvider; requestedModel: string;
  timeoutMs: number; maxSourceBytes: number; maxFiles: number; maxFileBytes: number;
  pricing?: { inputCostPerMillionUsd: number; outputCostPerMillionUsd: number };
  logger?: (event: { hypothesisId: string; scanId: string; promptVersion: string; category: InvariantProposalFailureCode; reason: string }) => void;
};
const parse = <T,>(value: string | null, fallback: T): T => { try { return JSON.parse(value ?? "null") as T; } catch { return fallback; } };
const safeReason = (value: string) => value.slice(0, 96);
const emptyManifest = { files: [], totalSourceBytes: 0, omittedFileCount: 0, truncated: false, approximateInputBytes: 0 };
function selectedCompiler(raw: string | null, sources: ReadonlyMap<string, string>): string | null {
  const parsed = stableCompilerVersionSchema.array().min(1).max(32).safeParse(parse(raw, null));
  if (!parsed.success) return null;
  const constraints = [...sources.values()].flatMap(extractSolidityPragmas);
  if (!constraints.length || constraints.some((constraint) => !semver.validRange(constraint))) return null;
  const compatible = [...new Set(parsed.data)].filter((version) => constraints.every((constraint) => semver.satisfies(version, constraint, { includePrerelease: false })));
  return compatible.length === 1 ? compatible[0] : null;
}
async function safeRepository(rootPath: string, scanId: string): Promise<string> {
  const root = await realpath(rootPath).catch(() => { throw new InvariantProposalRequestError("invalid_state", "Repository root is unavailable."); });
  const expected = path.join(root, scanId), info = await lstat(expected).catch(() => { throw new InvariantProposalRequestError("invalid_state", "Prepared repository is unavailable."); });
  if (!info.isDirectory() || info.isSymbolicLink() || await realpath(expected) !== expected) throw new InvariantProposalRequestError("invalid_state", "Prepared repository is unsafe.");
  return expected;
}
async function sourcesFor(repository: string, context: InvariantProposalContext): Promise<Map<string, string>> {
  const sources = new Map<string, string>();
  for (const file of context.manifest.files) {
    if (!repositorySolidityPathSchema.safeParse(file.path).success || file.truncated) throw new Error("invalid_invariant_source");
    const expected = path.join(repository, file.path), info = await lstat(expected);
    if (!info.isFile() || info.isSymbolicLink() || await realpath(expected) !== expected) throw new Error("invalid_invariant_source");
    sources.set(file.path, await readFile(expected, "utf8"));
  }
  return sources;
}
function sourceEvidence(repository: string, hypothesis: { evidence: string; violatedInvariantIds: string; relatedInvestigationIds: string }, database: DatabaseClient, scanId: string) {
  const candidates: unknown[] = [...parse<unknown[]>(hypothesis.evidence, [])];
  for (const id of parse<string[]>(hypothesis.violatedInvariantIds, [])) {
    const linked = getInvariant(database, id);
    if (linked?.scanId === scanId) candidates.push(...parse<unknown[]>(linked.sourceEvidence, []));
  }
  for (const id of parse<string[]>(hypothesis.relatedInvestigationIds, [])) {
    const linked = getInvestigation(database, id);
    if (linked?.scanId === scanId && linked.primaryFilePath) candidates.push({ filePath: linked.primaryFilePath, contract: linked.primaryContract, functionName: linked.primaryFunction, startLine: linked.startLine, endLine: linked.endLine });
  }
  return candidates.flatMap((item) => {
    if (!item || typeof item !== "object") return [];
    const record = item as Record<string, unknown>;
    const parsed = sourceEvidenceSchema.safeParse({ filePath: record.filePath, contract: record.contract, functionName: record.functionName, startLine: record.startLine, endLine: record.endLine });
    return parsed.success && repositorySolidityPathSchema.safeParse(parsed.data.filePath).success && validateEvidence(repository, parsed.data).valid ? [parsed.data] : [];
  });
}
export class InvariantProposalService {
  constructor(private readonly options: InvariantProposalServiceOptions) {}
  private record(hypothesisId: string, scanId: string, result: InvariantProposalGenerationResult, contextManifest: object, requestId: string | null) {
    if (result.failureCode) {
      const event = { hypothesisId, scanId, promptVersion: INVARIANT_PROPOSAL_PROMPT_VERSION, category: result.failureCode, reason: safeReason(result.failureCode) };
      if (this.options.logger) this.options.logger(event); else console.warn("[invariant-proposal] rejected", event);
    }
    return createExecutableInvariantProposal(this.options.database, { hypothesisId, scanId, result, contextManifest, requestId });
  }
  async generate(hypothesisId: string): Promise<{ proposal: ExecutableInvariantProposalRow; result: InvariantProposalGenerationResult }> {
    const hypothesis = getVulnerabilityHypothesis(this.options.database, hypothesisId);
    if (!hypothesis) throw new InvariantProposalRequestError("unknown_hypothesis", "Hypothesis not found.");
    if (hypothesis.status === "rejected") throw new InvariantProposalRequestError("invalid_state", "Rejected hypotheses cannot receive invariant proposals.");
    const scan = getScan(this.options.database, hypothesis.scanId), started = Date.now();
    if (!scan || scan.status !== "completed" || !scan.resolvedCommit || !["ready", "cached"].includes(scan.compilerStatus)) throw new InvariantProposalRequestError("invalid_state", "A completed scan with trusted compiler state is required.");
    let context: InvariantProposalContext = { content: "", manifest: emptyManifest }; let response: InvariantProposalProviderResult | null = null; let sourceHashes: Record<string, string> = {};
    const result = (status: InvariantProposalGenerationResult["status"], code: InvariantProposalFailureCode | null, plan: ExecutableInvariantPlan | null = null, rationale: string | null = null, limitations: string[] = [], reasons: string[] = []): InvariantProposalGenerationResult => ({ status, plan, planHash: plan ? invariantPlanHash(plan) : null, rationale, limitations, notPlannableReasons: reasons, failureCode: code,
      provenance: { provider: this.options.provider.id, requestedModel: this.options.requestedModel, actualModel: response?.actualModel ?? null, promptVersion: INVARIANT_PROPOSAL_PROMPT_VERSION, generatedAt: new Date().toISOString(), inputTokens: response?.inputTokens ?? null, outputTokens: response?.outputTokens ?? null, totalTokens: response?.totalTokens ?? null, estimatedCostUsd: this.options.pricing ? calculateAICost(response?.inputTokens ?? null, response?.outputTokens ?? null, this.options.pricing) : null, durationMs: response?.durationMs ?? Date.now() - started, sourceFileCount: context.manifest.files.length, totalSourceBytes: context.manifest.totalSourceBytes, sourceContextTruncated: context.manifest.truncated } });
    let writing = false;
    const finish = (value: InvariantProposalGenerationResult) => { writing = true; return { proposal: this.record(hypothesisId, scan.id, value, { ...context.manifest, sourceHashes }, response?.requestId ?? null), result: value }; };
    try {
      const repository = await safeRepository(this.options.repositoryRoot, scan.id);
      const evidence = sourceEvidence(repository, hypothesis, this.options.database, scan.id);
      if (!evidence.length) return finish(result("failed", "invalid_invariant_source"));
      const analysis = getCurrentProtocolAnalysis(this.options.database, scan.id);
      if (!analysis || analysis.id !== hypothesis.protocolAnalysisId) return finish(result("failed", "invalid_invariant_source"));
      context = new VerificationPlanContextBuilder({ maxSourceBytes: this.options.maxSourceBytes, maxFiles: this.options.maxFiles, maxFileBytes: this.options.maxFileBytes }).build(repository, [...new Set(evidence.map((item) => item.filePath))], {
        hypothesis: { title: hypothesis.title, summary: hypothesis.summary, rootCause: hypothesis.rootCause, affectedContracts: parse(hypothesis.affectedContracts, []), affectedFunctions: parse(hypothesis.affectedFunctions, []), evidence },
        protocol: { name: analysis.protocolName, summary: analysis.summary, architectureSummary: analysis.architectureSummary }, invariants: [], investigations: [],
      }, invariantCapabilityProfile);
      if (!context.manifest.files.length || context.manifest.truncated) return finish(result("failed", "invalid_invariant_source"));
      const sources = await sourcesFor(repository, context);
      sourceHashes = Object.fromEntries([...sources].map(([file, source]) => [file, createHash("sha256").update(source).digest("hex")]));
      const compiler = selectedCompiler(scan.compilerVersions, sources);
      if (!compiler) return finish(result("failed", "ambiguous_trusted_compiler"));
      try { response = await this.options.provider.generateInvariantProposal({ model: this.options.requestedModel, promptVersion: INVARIANT_PROPOSAL_PROMPT_VERSION, systemPrompt: INVARIANT_PROPOSAL_SYSTEM_PROMPT, context, timeoutMs: this.options.timeoutMs }); }
      catch { return finish(result("failed", "invariant_generation_unavailable")); }
      const parsed = invariantProposalSchema.safeParse(response.proposal);
      if (!parsed.success) {
        const unsupported = parsed.error.issues.some((issue) => ["type", "kind"].includes(String(issue.path.at(-1))));
        return finish(result("failed", unsupported ? "unsupported_invariant_semantics" : "invalid_invariant_provider_proposal"));
      }
      if (parsed.data.status === "not_plannable") return finish(result("not_plannable", null, null, parsed.data.rationale, parsed.data.limitations, parsed.data.notPlannableReasons));
      const semantics = parsed.data.semantics!;
      const primaryPaths = [...new Set(evidence.filter((item) => item.contract === semantics.primaryContract && sources.has(item.filePath)).map((item) => item.filePath))];
      if (primaryPaths.length !== 1) return finish(result("failed", "invalid_invariant_source"));
      const setup = semantics.setup.map((operation) => operation.kind === "call" ? { ...operation, caller: operation.caller ?? undefined } : operation);
      const actions = semantics.mode === "fuzz-property" ? { fuzzAction: { ...semantics.fuzzAction, caller: semantics.fuzzAction.caller ?? undefined } } : { handlerActions: semantics.handlerActions.map((action) => ({ ...action, caller: action.caller ?? undefined })) };
      const plan = executableInvariantPlanSchema.safeParse({ ...semantics, ...actions, setup, schemaVersion: EXECUTABLE_INVARIANT_SCHEMA_VERSION, hypothesisId, scanId: scan.id, resolvedCommit: scan.resolvedCommit, compilerVersion: compiler, primarySourcePath: primaryPaths[0], sourceFiles: [primaryPaths[0]] });
      if (!plan.success) return finish(result("failed", "invalid_invariant_plan"));
      try { new ExecutableInvariantGenerator().generate(plan.data, sources); }
      catch (error) { return finish(result("failed", error instanceof SolidityFunctionValidationError ? "invalid_invariant_function_signature" : "invalid_invariant_plan")); }
      return finish(result("generated", null, plan.data, parsed.data.rationale, parsed.data.limitations));
    } catch (error) { if (writing) throw error; return finish(result("failed", "invalid_invariant_source")); }
  }
  async validate(hypothesisId: string, proposalId: string): Promise<{ plan: ExecutableInvariantPlan; planHash: string }> {
    const row = getExecutableInvariantProposal(this.options.database, proposalId);
    if (!row || row.hypothesisId !== hypothesisId) throw new InvariantProposalRequestError("unknown_proposal", "Invariant proposal not found.");
    if (row.status !== "generated" || !row.plan || !row.planHash) throw new InvariantProposalRequestError("invalid_state", "This proposal cannot be executed.");
    const parsed = executableInvariantPlanSchema.safeParse(parse(row.plan, null));
    if (!parsed.success || invariantPlanHash(parsed.data) !== row.planHash) throw new InvariantProposalRequestError("invalid_state", "Persisted invariant plan is invalid.");
    const plan = parsed.data, hypothesis = getVulnerabilityHypothesis(this.options.database, hypothesisId), scan = hypothesis ? getScan(this.options.database, hypothesis.scanId) : null;
    if (!hypothesis || hypothesis.status === "rejected" || !scan || scan.status !== "completed" || scan.resolvedCommit !== plan.resolvedCommit || scan.id !== plan.scanId || plan.hypothesisId !== hypothesisId || !["ready", "cached"].includes(scan.compilerStatus)) throw new InvariantProposalRequestError("invalid_state", "Persisted invariant identity is stale.");
    const repository = await safeRepository(this.options.repositoryRoot, scan.id), contextManifest = parse<InvariantProposalContext["manifest"] & { sourceHashes?: Record<string, string> }>(row.contextManifest, emptyManifest);
    const context: InvariantProposalContext = { content: "", manifest: contextManifest };
    const sources = await sourcesFor(repository, context).catch(() => { throw new InvariantProposalRequestError("invalid_state", "Invariant source is no longer safe."); });
    if (!contextManifest.sourceHashes || Object.keys(contextManifest.sourceHashes).length !== sources.size || [...sources].some(([file, source]) => contextManifest.sourceHashes?.[file] !== createHash("sha256").update(source).digest("hex")) || selectedCompiler(scan.compilerVersions, sources) !== plan.compilerVersion || !sources.has(plan.primarySourcePath)) throw new InvariantProposalRequestError("invalid_state", "Trusted compiler or source mapping changed.");
    try { new ExecutableInvariantGenerator().generate(plan, sources); }
    catch { throw new InvariantProposalRequestError("invalid_state", "Invariant source validation failed."); }
    return { plan, planHash: row.planHash };
  }
}
export function createInvariantProposalService(database: DatabaseClient = getDatabase()): InvariantProposalService {
  const config = loadConfig();
  return new InvariantProposalService({ database, repositoryRoot: config.REPOSITORY_DIR, provider: new OpenAIProvider(config.OPENAI_API_KEY), requestedModel: config.OPENAI_MODEL || "mock-model", timeoutMs: config.AI_VERIFICATION_PLAN_TIMEOUT_MS, maxSourceBytes: config.AI_VERIFICATION_PLAN_MAX_SOURCE_BYTES, maxFiles: config.AI_VERIFICATION_PLAN_MAX_FILES, maxFileBytes: Math.min(config.AI_MAX_FILE_BYTES, config.AI_VERIFICATION_PLAN_MAX_SOURCE_BYTES), pricing: { inputCostPerMillionUsd: config.AI_INPUT_COST_PER_MILLION_USD, outputCostPerMillionUsd: config.AI_OUTPUT_COST_PER_MILLION_USD } });
}
