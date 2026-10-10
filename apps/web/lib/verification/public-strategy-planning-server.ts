import { verificationPlanGenerationFailureCodes, verificationHarnessPlanSchema } from "@contracthunter/core";
import type { listVerificationPlanAttempts } from "@contracthunter/db";
import type { VerificationPlanGenerationResult, VerificationPlanReuseResult } from "@contracthunter/core";
import type { PublicVerificationPlanAttempt } from "./public-strategy-planning";

export function toPublicVerificationPlanAttempt(row: ReturnType<typeof listVerificationPlanAttempts>[number]): PublicVerificationPlanAttempt {
  const raw = JSON.parse(row.result) as VerificationPlanGenerationResult | VerificationPlanReuseResult;
  const plan = raw.plan ? verificationHarnessPlanSchema.safeParse(raw.plan) : null;
  if (raw.status !== row.status || raw.failureCode !== row.failureCode || (raw.status === "generated" && !plan?.success) || (raw.failureCode && !verificationPlanGenerationFailureCodes.includes(raw.failureCode))) throw new Error("Persisted verification planning attempt is invalid.");
  if (row.reuseSourceArtifactId ? !("origin" in raw) || raw.origin !== "reused" || !plan?.success || row.plan !== JSON.stringify(plan.data) || JSON.stringify(raw.plan) !== row.plan || "provenance" in raw : "origin" in raw) throw new Error("Persisted planning origin is invalid.");
  return { id: row.id, selectedStrategy: row.selectedStrategy, status: row.status, failureCode: row.failureCode,
    origin: row.reuseSourceArtifactId ? "reused" : row.sourceClosureFingerprintSha256 ? "generated" : "legacy",
    reuseSourceArtifactId: row.reuseSourceArtifactId, reuseTargetId: row.reuseTargetId,
    result: row.reuseSourceArtifactId ? raw as VerificationPlanReuseResult : { ...raw, plan: plan?.success ? plan.data : null } as VerificationPlanGenerationResult,
    sourceClosureFingerprint: row.sourceClosureFingerprintSha256 ? { schema: row.sourceClosureFingerprintSchema!, sha256: row.sourceClosureFingerprintSha256, fileCount: row.sourceClosureFingerprintFileCount!, totalBytes: row.sourceClosureFingerprintTotalBytes! } : null,
    createdAt: row.createdAt.toISOString() };
}
