import { z } from "zod";

export const aiAnalysisStatuses = ["disabled", "pending", "running", "completed", "failed"] as const;
export const coverageStatuses = ["complete", "partial"] as const;
export const protocolTypes = ["token", "vault", "lending", "dex", "amm", "staking", "derivatives", "bridge", "governance", "nft", "payment", "oracle", "account-abstraction", "infrastructure", "mixed", "unknown"] as const;
export const invariantStatuses = ["proposed", "accepted", "rejected", "tested", "violated"] as const;
export const invariantCategories = ["accounting", "solvency", "access-control", "authorization", "conservation", "state-transition", "asset-flow", "share-accounting", "collateralization", "oracle", "liquidation", "governance", "upgradeability", "token", "external-interaction", "availability", "other"] as const;
export const invariantTestabilities = ["directly-testable", "fuzz-testable", "stateful-invariant", "requires-external-assumption", "manual-review"] as const;

export type AIAnalysisStatus = (typeof aiAnalysisStatuses)[number];
export type CoverageStatus = (typeof coverageStatuses)[number];
export type InvariantStatus = (typeof invariantStatuses)[number];
export type InvariantCategory = (typeof invariantCategories)[number];
export type InvariantTestability = (typeof invariantTestabilities)[number];

export const sourceEvidenceSchema = z.object({
  filePath: z.string().min(1).max(1000),
  contract: z.string().max(200).nullable(),
  functionName: z.string().max(200).nullable(),
  startLine: z.number().int().positive().nullable(),
  endLine: z.number().int().positive().nullable(),
}).strict();

const evidencedSchema = { evidence: z.array(sourceEvidenceSchema).max(30) };
const text = z.string().trim().min(1).max(5000);
const name = z.string().trim().min(1).max(200);

export const protocolAnalysisResultSchema = z.object({
  protocol: z.object({ name, types: z.array(z.enum(protocolTypes)).min(1).max(5), summary: text, architectureSummary: text, confidence: z.number().int().min(0).max(100) }).strict(),
  assets: z.array(z.object({ name, type: name, relatedContract: z.string().max(200).nullable(), role: text, userFundsDependOnIt: z.boolean(), ...evidencedSchema }).strict()).max(100),
  roles: z.array(z.object({ role: name, relatedContracts: z.array(name).max(30), capabilities: z.array(text).max(30), confidence: z.number().int().min(0).max(100), ...evidencedSchema }).strict()).max(100),
  entryPoints: z.array(z.object({ contract: name, functionName: name, purpose: text, affectedAssetsOrState: z.array(name).max(30), accessAssumptions: z.array(text).max(20), ...evidencedSchema }).strict()).max(150),
  criticalState: z.array(z.object({ name, contract: z.string().max(200).nullable(), purpose: text, securityRelevance: text, ...evidencedSchema }).strict()).max(150),
  externalDependencies: z.array(z.object({ dependency: name, relatedContractOrFunction: z.string().max(300).nullable(), trustAssumption: text, ...evidencedSchema }).strict()).max(100),
  flows: z.array(z.object({ name, steps: z.array(text).min(1).max(30), involvedContractsOrFunctions: z.array(name).max(30), affectedAssetsOrState: z.array(name).max(30), ...evidencedSchema }).strict()).max(100),
  trustAssumptions: z.array(z.object({ assumption: text, rationale: text, ...evidencedSchema }).strict()).max(100),
  invariants: z.array(z.object({ title: name, description: text, category: z.enum(invariantCategories), severityIfViolated: z.enum(["critical", "high", "medium", "low", "informational"]), confidence: z.number().int().min(0).max(100), rationale: text, relatedContracts: z.array(name).max(30), relatedFunctions: z.array(name).max(30), relatedState: z.array(name).max(30), sourceEvidence: z.array(sourceEvidenceSchema).max(30), testability: z.enum(invariantTestabilities) }).strict()).max(150),
  limitations: z.array(text).max(100),
}).strict();

export type ProtocolAnalysisResult = z.infer<typeof protocolAnalysisResultSchema>;
export type SourceEvidence = z.infer<typeof sourceEvidenceSchema>;

export type ContextManifestEntry = { path: string; bytes: number; includedBytes: number; truncated: boolean };
export type AnalysisContext = {
  content: string;
  manifest: { files: ContextManifestEntry[]; totalSourceBytes: number; omittedFileCount: number; includedInvestigationIds: string[]; scannerSummary: Record<string, number>; truncated: boolean; approximateInputBytes: number };
};

export type AIProviderResult = { analysis: ProtocolAnalysisResult; actualModel: string | null; requestId: string | null; inputTokens: number | null; outputTokens: number | null; totalTokens: number | null; durationMs: number };
export type ProtocolAnalysisInput = { model: string; promptVersion: string; systemPrompt: string; context: AnalysisContext; timeoutMs: number };
export interface AIProvider {
  id: string;
  analyzeProtocol(input: ProtocolAnalysisInput): Promise<AIProviderResult>;
  reviewSecurity(input: import("./security-review").SecurityReviewInput): Promise<import("./security-review").SecurityReviewProviderResult>;
}

export type ValidatedEvidence = SourceEvidence & { valid: boolean; validationError: string | null };
