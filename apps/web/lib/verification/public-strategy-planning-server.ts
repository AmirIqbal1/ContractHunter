import { verificationPlanGenerationFailureCodes, verificationHarnessPlanSchema } from "@contracthunter/core";
import type { listVerificationPlanAttempts } from "@contracthunter/db";
import type { VerificationPlanGenerationResult } from "@contracthunter/core";
import type { PublicVerificationPlanAttempt } from "./public-strategy-planning";

export function toPublicVerificationPlanAttempt(row: ReturnType<typeof listVerificationPlanAttempts>[number]): PublicVerificationPlanAttempt {
  const raw = JSON.parse(row.result) as VerificationPlanGenerationResult;
  const plan = raw.plan ? verificationHarnessPlanSchema.safeParse(raw.plan) : null;
  if (raw.status !== row.status || raw.failureCode !== row.failureCode || (raw.status === "generated" && !plan?.success) || (raw.failureCode && !verificationPlanGenerationFailureCodes.includes(raw.failureCode))) throw new Error("Persisted verification planning attempt is invalid.");
  return { id: row.id, selectedStrategy: row.selectedStrategy, status: row.status, failureCode: row.failureCode, result: { ...raw, plan: plan?.success ? plan.data : null }, createdAt: row.createdAt.toISOString() };
}

