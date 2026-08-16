import { lstat, readFile, realpath } from "node:fs/promises";
import path from "node:path";
import {
  VERIFICATION_PLAN_PROMPT_VERSION, VERIFICATION_PLAN_SYSTEM_PROMPT, VerificationPlanContextBuilder, loadConfig,
  repositorySolidityPathSchema, sourceEvidenceSchema, stableCompilerVersionSchema, validateEvidence,
  verificationPlanProposalSchema, type VerificationHarnessPlan, type VerificationPlanGenerationResult,
  type VerificationPlanProvider, type VerificationPlanProviderResult,
} from "@contracthunter/core";
import {
  getCurrentProtocolAnalysis, getDatabase, getInvestigation, getInvariant, getScan, getVulnerabilityHypothesis,
  type DatabaseClient, type VulnerabilityHypothesisRow,
} from "@contracthunter/db";
import { VerificationHarnessGenerator } from "@contracthunter/scanners";
import { OpenAIProvider } from "@/lib/ai/openai-provider";

export class VerificationPlanGenerationError extends Error {
  constructor(readonly code: "unknown_hypothesis" | "invalid_state" | "missing_context", message: string) { super(message); this.name = "VerificationPlanGenerationError"; }
}

export type VerificationPlanGenerationServiceOptions = {
  database: DatabaseClient; repositoryRoot: string; provider: VerificationPlanProvider; requestedModel: string;
  timeoutMs: number; maxSourceBytes: number; maxFiles: number; maxFileBytes: number; now?: () => Date;
};

type Evidence = { filePath: string; contract: string | null; functionName: string | null; startLine: number | null; endLine: number | null };
const parse = <T,>(value: string, fallback: T): T => { try { return JSON.parse(value) as T; } catch { return fallback; } };
const escape = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const solidityStructure = (value: string) => value.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/\/\/[^\r\n]*/g, " ").replace(/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g, "");

function acceptedCompilers(raw: string | null): string[] {
  const parsed = stableCompilerVersionSchema.array().min(1).max(32).safeParse(parse(raw ?? "null", null));
  if (!parsed.success) throw new VerificationPlanGenerationError("invalid_state", "The scan has no trusted compiler selection.");
  return [...new Set(parsed.data)];
}

function persistedEvidence(repositoryPath: string, hypothesis: VulnerabilityHypothesisRow): Evidence[] {
  const raw = parse<unknown>(hypothesis.evidence, null); if (!Array.isArray(raw)) throw new VerificationPlanGenerationError("missing_context", "Persisted hypothesis evidence is unavailable.");
  const result: Evidence[] = [];
  for (const item of raw) {
    if (!item || typeof item !== "object") continue; const record = item as Record<string, unknown>;
    const parsed = sourceEvidenceSchema.safeParse({ filePath: record.filePath, contract: record.contract, functionName: record.functionName, startLine: record.startLine, endLine: record.endLine });
    if (parsed.success && repositorySolidityPathSchema.safeParse(parsed.data.filePath).success && validateEvidence(repositoryPath, parsed.data).valid) result.push(parsed.data);
  }
  if (!result.length) throw new VerificationPlanGenerationError("missing_context", "No validated Solidity evidence is available for verification planning.");
  return result;
}

async function repositoryFor(rootPath: string, scanId: string): Promise<string> {
  const root = await realpath(rootPath).catch(() => { throw new VerificationPlanGenerationError("invalid_state", "The repository root is unavailable."); });
  const expected = path.join(root, scanId); const info = await lstat(expected).catch(() => { throw new VerificationPlanGenerationError("missing_context", "The prepared scanned repository is unavailable."); });
  if (!info.isDirectory() || info.isSymbolicLink()) throw new VerificationPlanGenerationError("invalid_state", "The prepared scanned repository is unsafe.");
  const repositoryPath = await realpath(expected);
  if (repositoryPath !== expected || !repositoryPath.startsWith(`${root}${path.sep}`)) throw new VerificationPlanGenerationError("invalid_state", "The prepared scanned repository is unsafe.");
  return repositoryPath;
}

function provenance(options: VerificationPlanGenerationServiceOptions, context: ReturnType<VerificationPlanContextBuilder["build"]>, response: VerificationPlanProviderResult | null, started: number) {
  return {
    provider: options.provider.id, requestedModel: options.requestedModel, actualModel: response?.actualModel ?? null,
    promptVersion: VERIFICATION_PLAN_PROMPT_VERSION, generatedAt: (options.now?.() ?? new Date()).toISOString(),
    inputTokens: response?.inputTokens ?? null, outputTokens: response?.outputTokens ?? null, totalTokens: response?.totalTokens ?? null,
    durationMs: response?.durationMs ?? Date.now() - started, sourceFileCount: context.manifest.files.length,
    totalSourceBytes: context.manifest.totalSourceBytes, sourceContextTruncated: context.manifest.truncated,
  };
}

async function validateStaticPlan(plan: VerificationHarnessPlan, repositoryPath: string, allowlist: Set<string>): Promise<void> {
  if (plan.sourceFiles.some((file) => !allowlist.has(file)) || !allowlist.has(plan.primarySourcePath)) throw new Error("source_not_allowlisted");
  const sources = new Map<string, string>();
  for (const file of plan.sourceFiles) {
    const expected = path.join(repositoryPath, file); const info = await lstat(expected); const real = await realpath(expected);
    if (!info.isFile() || info.isSymbolicLink() || real !== expected || !real.startsWith(`${repositoryPath}${path.sep}`)) throw new Error("source_no_longer_safe");
    sources.set(file, solidityStructure(await readFile(real, "utf8")));
  }
  const primary = sources.get(plan.primarySourcePath)!;
  if (!new RegExp(`\\b(?:contract|library)\\s+${escape(plan.primaryContract)}\\b`).test(primary)) throw new Error("primary_contract_not_found");
  if ([...primary.matchAll(/\bconstructor\s*\(([^)]*)\)/g)].some((match) => match[1].trim())) throw new Error("constructor_arguments_unsupported");
  const combined = [...sources.values()].join("\n");
  const hasUintGetter = (functionName: string) => new RegExp(`\\buint(?:256)?\\s+public\\s+(?:override\\s+)?${escape(functionName)}\\b`).test(combined);
  for (const functionName of plan.relevantFunctions) if (!new RegExp(`\\bfunction\\s+${escape(functionName)}\\s*\\(`).test(combined) && !hasUintGetter(functionName)) throw new Error("function_not_found");
  for (const operation of plan.operations) {
    if (operation.kind === "deploy") continue;
    const signatures = [...combined.matchAll(new RegExp(`\\bfunction\\s+${escape(operation.functionName)}\\s*\\(([^)]*)\\)([^;{]*)`, "g"))];
    const zeroArgument = signatures.filter((match) => !match[1].trim());
    if (!zeroArgument.length && !(operation.kind === "read-uint" && hasUintGetter(operation.functionName))) throw new Error("function_arguments_unsupported");
    if (operation.kind === "read-uint" && !hasUintGetter(operation.functionName) && !zeroArgument.some((match) => /\breturns\s*\(\s*uint(?:256)?\b/.test(match[2]))) throw new Error("unsupported_return_type");
  }
  if (plan.assertions.some((assertion) => assertion.description.trim().length < 12 || /^(?:check|test|assert|verify)(?: it)?[.!]?$/i.test(assertion.description.trim()))) throw new Error("vague_assertion");
  new VerificationHarnessGenerator().generate(plan);
}

export class VerificationPlanGenerationService {
  constructor(private readonly options: VerificationPlanGenerationServiceOptions) {}

  async generate(hypothesisId: string): Promise<VerificationPlanGenerationResult> {
    const hypothesis = getVulnerabilityHypothesis(this.options.database, hypothesisId);
    if (!hypothesis) throw new VerificationPlanGenerationError("unknown_hypothesis", "Vulnerability hypothesis not found.");
    if (hypothesis.status === "rejected") throw new VerificationPlanGenerationError("invalid_state", "Rejected hypotheses cannot receive verification plans.");
    const scan = getScan(this.options.database, hypothesis.scanId);
    if (!scan || scan.status !== "completed" || !scan.resolvedCommit || !["ready", "cached"].includes(scan.compilerStatus)) throw new VerificationPlanGenerationError("invalid_state", "Verification planning requires a completed scan with trusted compiler state.");
    const analysis = getCurrentProtocolAnalysis(this.options.database, scan.id);
    if (!analysis || analysis.id !== hypothesis.protocolAnalysisId) throw new VerificationPlanGenerationError("missing_context", "The persisted protocol analysis for this hypothesis is unavailable.");
    const compilers = acceptedCompilers(scan.compilerVersions); const repositoryPath = await repositoryFor(this.options.repositoryRoot, scan.id); const evidence = persistedEvidence(repositoryPath, hypothesis);
    const invariantIds = parse<string[]>(hypothesis.violatedInvariantIds, []); const investigationIds = parse<string[]>(hypothesis.relatedInvestigationIds, []);
    const invariants = invariantIds.map((id) => getInvariant(this.options.database, id)).filter((item) => item?.scanId === scan.id);
    const investigations = investigationIds.map((id) => getInvestigation(this.options.database, id)).filter((item) => item?.scanId === scan.id);
    const extraEvidence: Evidence[] = [];
    for (const invariant of invariants) for (const item of parse<unknown[]>(invariant!.sourceEvidence, [])) {
      if (!item || typeof item !== "object") continue; const record = item as Record<string, unknown>;
      const parsed = sourceEvidenceSchema.safeParse({ filePath: record.filePath, contract: record.contract, functionName: record.functionName, startLine: record.startLine, endLine: record.endLine }); if (parsed.success && repositorySolidityPathSchema.safeParse(parsed.data.filePath).success && validateEvidence(repositoryPath, parsed.data).valid) extraEvidence.push(parsed.data);
    }
    for (const investigation of investigations) if (investigation?.primaryFilePath) {
      const item = { filePath: investigation.primaryFilePath, contract: investigation.primaryContract, functionName: investigation.primaryFunction, startLine: investigation.startLine, endLine: investigation.endLine };
      const parsed = sourceEvidenceSchema.safeParse(item); if (parsed.success && repositorySolidityPathSchema.safeParse(parsed.data.filePath).success && validateEvidence(repositoryPath, parsed.data).valid) extraEvidence.push(parsed.data);
    }
    const context = new VerificationPlanContextBuilder({ maxSourceBytes: this.options.maxSourceBytes, maxFiles: this.options.maxFiles, maxFileBytes: this.options.maxFileBytes }).build(repositoryPath, [...new Set([...evidence, ...extraEvidence].map((item) => item.filePath))], {
      identity: { hypothesisId: hypothesis.id, scanId: scan.id, resolvedCommit: scan.resolvedCommit, acceptedCompilerVersions: compilers },
      hypothesis: { title: hypothesis.title, category: hypothesis.category, summary: hypothesis.summary, rootCause: hypothesis.rootCause, preconditions: parse(hypothesis.preconditions, []), attackPath: parse(hypothesis.attackPath, []), impact: hypothesis.impact, affectedContracts: parse(hypothesis.affectedContracts, []), affectedFunctions: parse(hypothesis.affectedFunctions, []), evidence, verificationStrategy: parse(hypothesis.verificationStrategy, []) },
      protocol: { name: analysis.protocolName, types: parse(analysis.protocolTypes, []), summary: analysis.summary, architectureSummary: analysis.architectureSummary, limitations: parse(analysis.limitations, []) },
      invariants: invariants.map((item) => item && ({ id: item.id, title: item.title, description: item.description, relatedContracts: parse(item.relatedContracts, []), relatedFunctions: parse(item.relatedFunctions, []), testability: item.testability })),
      investigations: investigations.map((item) => item && ({ id: item.id, title: item.title, category: item.category, summary: parse(item.reasons, []), contract: item.primaryContract, functionName: item.primaryFunction, filePath: item.primaryFilePath })),
    });
    if (!context.manifest.files.length) throw new VerificationPlanGenerationError("missing_context", "No bounded source context is available for verification planning.");
    const started = Date.now(); let response: VerificationPlanProviderResult;
    try {
      response = await this.options.provider.generateVerificationPlan({ model: this.options.requestedModel, promptVersion: VERIFICATION_PLAN_PROMPT_VERSION, systemPrompt: VERIFICATION_PLAN_SYSTEM_PROMPT, context, timeoutMs: this.options.timeoutMs });
    } catch {
      return { status: "failed", plan: null, rationale: null, limitations: [], notPlannableReasons: [], failureCode: "plan_generation_failed", provenance: provenance(this.options, context, null, started) };
    }
    const proposal = verificationPlanProposalSchema.safeParse(response.proposal);
    if (!proposal.success) return { status: "failed", plan: null, rationale: null, limitations: [], notPlannableReasons: [], failureCode: "invalid_plan_proposal", provenance: provenance(this.options, context, response, started) };
    if (proposal.data.status === "not_plannable") return { ...proposal.data, failureCode: null, provenance: provenance(this.options, context, response, started) };
    try {
      const plan = proposal.data.plan!;
      if (plan.hypothesisId !== hypothesis.id || plan.scanId !== scan.id || plan.resolvedCommit !== scan.resolvedCommit || !compilers.includes(plan.compilerVersion)) throw new Error("persisted_identity_mismatch");
      await validateStaticPlan(plan, repositoryPath, new Set(context.manifest.files.map((file) => file.path)));
      const limitations = [...proposal.data.limitations, ...(context.manifest.truncated ? ["The bounded source context was truncated; review the proposal against the repository before execution."] : [])];
      return { ...proposal.data, plan, limitations, failureCode: null, provenance: provenance(this.options, context, response, started) };
    } catch {
      return { status: "failed", plan: null, rationale: null, limitations: [], notPlannableReasons: [], failureCode: "invalid_plan_proposal", provenance: provenance(this.options, context, response, started) };
    }
  }
}

export function createVerificationPlanGenerationService(database: DatabaseClient = getDatabase()): VerificationPlanGenerationService {
  const config = loadConfig();
  return new VerificationPlanGenerationService({ database, repositoryRoot: config.REPOSITORY_DIR, provider: new OpenAIProvider(config.OPENAI_API_KEY), requestedModel: config.OPENAI_MODEL || "mock-model", timeoutMs: config.AI_VERIFICATION_PLAN_TIMEOUT_MS, maxSourceBytes: config.AI_VERIFICATION_PLAN_MAX_SOURCE_BYTES, maxFiles: config.AI_VERIFICATION_PLAN_MAX_FILES, maxFileBytes: Math.min(config.AI_MAX_FILE_BYTES, config.AI_VERIFICATION_PLAN_MAX_SOURCE_BYTES) });
}
