import { executableInvariantEvidenceSchema, executableInvariantPlanSchema, type ExecutableInvariantPlan, type ExecutableInvariantEvidence } from "@contracthunter/core";
import type { ExecutableInvariantProposalRow, ExecutableInvariantRunRow } from "@contracthunter/db";

const parse = (value: string | null): unknown => { try { return JSON.parse(value ?? "null") as unknown; } catch { return null; } };
export type PublicInvariantProposal = {
  id: string; status: ExecutableInvariantProposalRow["status"]; plan: ExecutableInvariantPlan | null; planHash: string | null;
  rationale: string | null; limitations: string[]; notPlannableReasons: string[]; failureCode: string | null;
  provider: string; model: string; promptVersion: string; sourceFileCount: number; totalSourceBytes: number; contextTruncated: boolean;
  inputTokens: number | null; outputTokens: number | null; totalTokens: number | null; estimatedCostUsd: number | null; durationMs: number; createdAt: string;
};
export type PublicInvariantRun = {
  id: string; proposalId: string | null; status: ExecutableInvariantRunRow["status"]; outcome: ExecutableInvariantRunRow["outcome"];
  mode: ExecutableInvariantRunRow["mode"]; planHash: string; compiler: string; configuredRuns: number; configuredDepth: number | null;
  runsExecuted: number | null; testCount: number; passedCount: number; failedCount: number; durationMs: number | null;
  dynamicEvidence: ExecutableInvariantEvidence[]; failureCode: string | null; createdAt: string;
};
export function toPublicInvariantProposal(row: ExecutableInvariantProposalRow): PublicInvariantProposal {
  const parsedPlan = executableInvariantPlanSchema.safeParse(parse(row.plan));
  const manifest = parse(row.contextManifest) as { files?: unknown[]; totalSourceBytes?: number; truncated?: boolean } | null;
  return { id: row.id, status: row.status, plan: parsedPlan.success ? parsedPlan.data : null, planHash: row.planHash, rationale: row.rationale,
    limitations: Array.isArray(parse(row.limitations)) ? parse(row.limitations) as string[] : [], notPlannableReasons: Array.isArray(parse(row.notPlannableReasons)) ? parse(row.notPlannableReasons) as string[] : [], failureCode: row.failureCode,
    provider: row.provider, model: row.actualModel ?? row.requestedModel, promptVersion: row.promptVersion, sourceFileCount: manifest?.files?.length ?? 0, totalSourceBytes: manifest?.totalSourceBytes ?? 0, contextTruncated: manifest?.truncated ?? false,
    inputTokens: row.inputTokens, outputTokens: row.outputTokens, totalTokens: row.totalTokens, estimatedCostUsd: row.estimatedCostUsd, durationMs: row.durationMs, createdAt: row.createdAt.toISOString() };
}
export function toPublicInvariantRun(row: ExecutableInvariantRunRow, proposalId: string | null = null): PublicInvariantRun {
  const evidence = executableInvariantEvidenceSchema.array().max(16).safeParse(parse(row.dynamicEvidence));
  return { id: row.id, proposalId, status: row.status, outcome: row.outcome, mode: row.mode, planHash: row.planHash, compiler: row.compilerVersion,
    configuredRuns: row.configuredRuns, configuredDepth: row.configuredDepth, runsExecuted: row.runsExecuted, testCount: row.testCount, passedCount: row.passedCount, failedCount: row.failedCount, durationMs: row.durationMs,
    dynamicEvidence: evidence.success ? evidence.data : [], failureCode: row.errorCode, createdAt: row.createdAt.toISOString() };
}
