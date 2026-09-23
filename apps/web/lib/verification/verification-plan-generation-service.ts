import { lstat, readFile, realpath } from "node:fs/promises";
import path from "node:path";
import {
  VERIFICATION_PLAN_PROMPT_VERSION, VERIFICATION_PLAN_SYSTEM_PROMPT, VerificationPlanContextBuilder, loadConfig,
  repositorySolidityPathSchema, sourceEvidenceSchema, stableCompilerVersionSchema, validateEvidence,
  verificationHarnessPlanSchema, verificationPlanProposalSchema, type VerificationHarnessPlan, type VerificationPlanGenerationResult,
  type VerificationPlanGenerationFailureCode,
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
  logger?: (event: { hypothesisId: string; scanId: string; promptVersion: string; category: VerificationPlanGenerationFailureCode; reason: string }) => void;
};

type Evidence = { filePath: string; contract: string | null; functionName: string | null; startLine: number | null; endLine: number | null };
const parse = <T,>(value: string, fallback: T): T => { try { return JSON.parse(value) as T; } catch { return fallback; } };
const escape = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const solidityStructure = (value: string) => value.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/\/\/[^\r\n]*/g, " ").replace(/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g, "");

type StaticPlanFailureCode = Exclude<VerificationPlanGenerationFailureCode, "plan_generation_failed" | "ambiguous_trusted_compiler" | "invalid_provider_proposal">;
class StaticPlanValidationError extends Error {
  constructor(readonly code: StaticPlanFailureCode, readonly reason: string) { super(reason); this.name = "StaticPlanValidationError"; }
}
const reject = (code: StaticPlanFailureCode, reason: string): never => { throw new StaticPlanValidationError(code, reason); };
const signatureKind = (parameter: string): "address" | "uint" | "bool" | null => {
  const tokens = parameter.trim().split(/\s+/).filter(Boolean);
  const hasUnsupportedLocation = tokens.some((token) => ["calldata", "memory", "storage"].includes(token));
  if (tokens[0] === "address") {
    if (hasUnsupportedLocation) return null;
    return "address";
  }
  if ((tokens[0] === "uint" || tokens[0] === "uint256") && !hasUnsupportedLocation) return "uint";
  if (tokens[0] === "bool" && !hasUnsupportedLocation) return "bool";
  return null;
};
const parameterKinds = (parameters: string): Array<"address" | "uint" | "bool"> | null => {
  if (!parameters.trim()) return [];
  const result = parameters.split(",").map(signatureKind);
  return result.some((kind) => kind === null) ? null : result as Array<"address" | "uint" | "bool">;
};
const returnKind = (suffix: string): "address" | "uint" | "bool" | null => {
  const match = /\breturns\s*\(([^)]*)\)/.exec(suffix);
  if (!match) return null;
  const kinds = parameterKinds(match[1]);
  return kinds?.length === 1 ? kinds[0] : null;
};

function logRejection(options: VerificationPlanGenerationServiceOptions, hypothesisId: string, scanId: string, category: VerificationPlanGenerationFailureCode, reason: string): void {
  const event = { hypothesisId, scanId, promptVersion: VERIFICATION_PLAN_PROMPT_VERSION, category, reason: reason.slice(0, 96) };
  if (options.logger) options.logger(event);
  else console.warn("[verification-plan] proposal rejected", event);
}

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
  if (plan.sourceFiles.some((file) => !allowlist.has(file)) || !allowlist.has(plan.primarySourcePath)) reject("invalid_plan_source", "source_not_allowlisted");
  const sources = new Map<string, string>();
  for (const file of plan.sourceFiles) {
    const expected = path.join(repositoryPath, file);
    try {
      const info = await lstat(expected); const real = await realpath(expected);
      if (!info.isFile() || info.isSymbolicLink() || real !== expected || !real.startsWith(`${repositoryPath}${path.sep}`)) reject("invalid_plan_source", "source_no_longer_safe");
      sources.set(file, solidityStructure(await readFile(real, "utf8")));
    } catch (error) {
      if (error instanceof StaticPlanValidationError) throw error;
      reject("invalid_plan_source", "source_unavailable");
    }
  }
  const primary = sources.get(plan.primarySourcePath)!;
  if (!new RegExp(`\\b(?:contract|library)\\s+${escape(plan.primaryContract)}\\b`).test(primary)) reject("invalid_plan_source", "primary_contract_not_found");
  if ([...primary.matchAll(/\bconstructor\s*\(([^)]*)\)/g)].some((match) => match[1].trim())) reject("unsupported_function_signature", "constructor_arguments_unsupported");
  const combined = [...sources.values()].join("\n");
  const hasExplicitFunction = (functionName: string) => new RegExp(`\\bfunction\\s+${escape(functionName)}\\s*\\(`).test(combined);
  const hasPublicGetter = (kind: "uint" | "address", functionName: string) => {
    const type = kind === "uint" ? "uint(?:256)?" : "address(?:\\s+payable)?";
    const identifier = /^[A-Za-z_][A-Za-z0-9_]*$/;
    return identifier.test(functionName) && [...combined.matchAll(new RegExp(`\\b${type}\\s+([^;{}]+);`, "g"))].some((match) => {
      const declaration = match[1].split("=", 1)[0].trim().split(/\s+/).filter(Boolean);
      return declaration.includes("public") && declaration.at(-1) === functionName;
    });
  };
  const hasPublicUintGetter = (functionName: string) => hasPublicGetter("uint", functionName);
  const hasPublicAddressGetter = (functionName: string) => hasPublicGetter("address", functionName);
  const hasSupportedRelevantFunction = (functionName: string) => hasExplicitFunction(functionName) || hasPublicUintGetter(functionName) || hasPublicAddressGetter(functionName);
  for (const functionName of plan.relevantFunctions) {
    if (!hasSupportedRelevantFunction(functionName)) reject("invalid_function_signature", "relevant_function_not_found");
  }
  for (const operation of plan.operations) {
    if (operation.kind === "deploy" || operation.kind === "fund" || operation.kind === "read-balance") continue;
    const signatures = [...combined.matchAll(new RegExp(`\\bfunction\\s+${escape(operation.functionName)}\\s*\\(([^)]*)\\)([^;{]*)`, "g"))];
    const expectedArguments = operation.kind === "call" ? (operation.args ?? []).map((argument) => argument.kind) : [];
    const supported = signatures.map((match) => ({ match, kinds: parameterKinds(match[1]) }));
    const matching = supported.filter(({ kinds }) => {
      return kinds !== null && kinds.length === expectedArguments.length && kinds.every((kind, index) => kind === expectedArguments[index]);
    });
    const getterKind = operation.kind === "read-uint" ? "uint" : operation.kind === "read-address" ? "address" : null;
    const getters = getterKind === "uint" ? Number(hasPublicUintGetter(operation.functionName)) : getterKind === "address" ? Number(hasPublicAddressGetter(operation.functionName)) : 0;
    const incompatibleGetters = operation.kind === "read-uint" ? Number(hasPublicAddressGetter(operation.functionName)) : operation.kind === "read-address" ? Number(hasPublicUintGetter(operation.functionName)) : 0;
    if (!signatures.length && !getters && incompatibleGetters) reject("unsupported_function_signature", "unsupported_return_type");
    if (!signatures.length && !getters) reject("invalid_function_signature", "function_not_found");
    if (supported.some(({ kinds }) => kinds === null) && !matching.length && !getters) reject("unsupported_function_signature", "unsupported_parameter_type");
    if (!matching.length && !getters) reject("invalid_function_signature", "argument_shape_mismatch");
    if (operation.kind === "call") {
      if (matching.length !== 1) reject("invalid_function_signature", "ambiguous_function_signature");
      continue;
    }
    const expectedReturn = operation.kind === "read-address" ? "address" : "uint";
    const returnMatches = matching.filter(({ match }) => returnKind(match[2]) === expectedReturn);
    const compatibleTargets = getters + returnMatches.length;
    if (!compatibleTargets) reject("unsupported_function_signature", "unsupported_return_type");
    if (compatibleTargets !== 1) reject("invalid_function_signature", "ambiguous_function_signature");
  }
  if (plan.assertions.some((assertion) => assertion.description.trim().length < 12 || /^(?:check|test|assert|verify)(?: it)?[.!]?$/i.test(assertion.description.trim()))) reject("invalid_harness_plan", "vague_assertion");
  try { new VerificationHarnessGenerator().generate(plan); }
  catch { reject("invalid_harness_plan", "harness_generation_rejected"); }
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
      trustedCompilerVersions: compilers,
      hypothesis: { title: hypothesis.title, category: hypothesis.category, summary: hypothesis.summary, rootCause: hypothesis.rootCause, preconditions: parse(hypothesis.preconditions, []), attackPath: parse(hypothesis.attackPath, []), impact: hypothesis.impact, affectedContracts: parse(hypothesis.affectedContracts, []), affectedFunctions: parse(hypothesis.affectedFunctions, []), evidence, verificationStrategy: parse(hypothesis.verificationStrategy, []) },
      protocol: { name: analysis.protocolName, types: parse(analysis.protocolTypes, []), summary: analysis.summary, architectureSummary: analysis.architectureSummary, limitations: parse(analysis.limitations, []) },
      invariants: invariants.map((item) => item && ({ id: item.id, title: item.title, description: item.description, relatedContracts: parse(item.relatedContracts, []), relatedFunctions: parse(item.relatedFunctions, []), testability: item.testability })),
      investigations: investigations.map((item) => item && ({ id: item.id, title: item.title, category: item.category, summary: parse(item.reasons, []), contract: item.primaryContract, functionName: item.primaryFunction, filePath: item.primaryFilePath })),
    });
    if (!context.manifest.files.length) throw new VerificationPlanGenerationError("missing_context", "No bounded source context is available for verification planning.");
    const started = Date.now();
    if (compilers.length !== 1) {
      logRejection(this.options, hypothesis.id, scan.id, "ambiguous_trusted_compiler", "multiple_trusted_compilers_without_source_mapping");
      return { status: "failed", plan: null, rationale: null, limitations: [], notPlannableReasons: [], failureCode: "ambiguous_trusted_compiler", provenance: provenance(this.options, context, null, started) };
    }
    const trustedCompilerVersion = compilers[0];
    let response: VerificationPlanProviderResult;
    try {
      response = await this.options.provider.generateVerificationPlan({ model: this.options.requestedModel, promptVersion: VERIFICATION_PLAN_PROMPT_VERSION, systemPrompt: VERIFICATION_PLAN_SYSTEM_PROMPT, context, timeoutMs: this.options.timeoutMs });
    } catch {
      logRejection(this.options, hypothesis.id, scan.id, "plan_generation_failed", "provider_request_failed");
      return { status: "failed", plan: null, rationale: null, limitations: [], notPlannableReasons: [], failureCode: "plan_generation_failed", provenance: provenance(this.options, context, null, started) };
    }
    const proposal = verificationPlanProposalSchema.safeParse(response.proposal);
    if (!proposal.success) {
      logRejection(this.options, hypothesis.id, scan.id, "invalid_provider_proposal", "provider_schema_rejected");
      return { status: "failed", plan: null, rationale: null, limitations: [], notPlannableReasons: [], failureCode: "invalid_provider_proposal", provenance: provenance(this.options, context, response, started) };
    }
    if (proposal.data.status === "not_plannable") return {
      status: "not_plannable", plan: null, rationale: proposal.data.rationale, limitations: proposal.data.limitations,
      notPlannableReasons: proposal.data.notPlannableReasons, failureCode: null, provenance: provenance(this.options, context, response, started),
    };
    const generatedPlan = proposal.data.plan!;
    const parsedPlan = verificationHarnessPlanSchema.safeParse({
        ...generatedPlan,
        scanId: scan.id,
        hypothesisId: hypothesis.id,
        resolvedCommit: scan.resolvedCommit,
        compilerVersion: trustedCompilerVersion,
        operations: generatedPlan.operations.map((operation) => operation.kind === "call"
          ? { ...operation, caller: operation.caller ?? undefined }
          : operation),
      });
    if (!parsedPlan.success) {
      logRejection(this.options, hypothesis.id, scan.id, "invalid_harness_plan", "runtime_plan_schema_rejected");
      return { status: "failed", plan: null, rationale: null, limitations: [], notPlannableReasons: [], failureCode: "invalid_harness_plan", provenance: provenance(this.options, context, response, started) };
    }
    const plan = parsedPlan.data;
    try {
      await validateStaticPlan(plan, repositoryPath, new Set(context.manifest.files.map((file) => file.path)));
      const limitations = [...proposal.data.limitations, ...(context.manifest.truncated ? ["The bounded source context was truncated; review the proposal against the repository before execution."] : [])];
      return { ...proposal.data, plan, limitations, failureCode: null, provenance: provenance(this.options, context, response, started) };
    } catch (error) {
      const rejection = error instanceof StaticPlanValidationError ? error : new StaticPlanValidationError("invalid_harness_plan", "unexpected_static_validation_failure");
      logRejection(this.options, hypothesis.id, scan.id, rejection.code, rejection.reason);
      return { status: "failed", plan: null, rationale: null, limitations: [], notPlannableReasons: [], failureCode: rejection.code, provenance: provenance(this.options, context, response, started) };
    }
  }
}

export function createVerificationPlanGenerationService(database: DatabaseClient = getDatabase()): VerificationPlanGenerationService {
  const config = loadConfig();
  return new VerificationPlanGenerationService({ database, repositoryRoot: config.REPOSITORY_DIR, provider: new OpenAIProvider(config.OPENAI_API_KEY), requestedModel: config.OPENAI_MODEL || "mock-model", timeoutMs: config.AI_VERIFICATION_PLAN_TIMEOUT_MS, maxSourceBytes: config.AI_VERIFICATION_PLAN_MAX_SOURCE_BYTES, maxFiles: config.AI_VERIFICATION_PLAN_MAX_FILES, maxFileBytes: Math.min(config.AI_MAX_FILE_BYTES, config.AI_VERIFICATION_PLAN_MAX_SOURCE_BYTES) });
}
