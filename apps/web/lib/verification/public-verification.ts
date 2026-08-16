import { dynamicEvidenceSchema, type DynamicEvidence } from "@contracthunter/core";
import type { HypothesisVerificationRunRow } from "@contracthunter/db";

const publicFailureCodes = new Set([
  "invalid_input", "invalid_workspace", "invalid_manifest", "manifest_mismatch", "unsafe_configuration",
  "network_isolation_unavailable", "execution_timeout", "forge_failed", "execution_error",
  "verification_execution_failed", "invalid_isolation_metadata", "workspace_integrity_or_execution_failed",
  "workspace_generation_failed",
]);

export type PublicHypothesisVerificationRun = {
  id: string;
  hypothesisId: string;
  status: HypothesisVerificationRunRow["status"];
  outcome: HypothesisVerificationRunRow["outcome"];
  verifier: string;
  compiler: string;
  contentFingerprint: string | null;
  createdAt: string;
  startedAt: string | null;
  completedAt: string | null;
  durationMs: number | null;
  isolationBackend: string | null;
  exitCode: number | null;
  timedOut: boolean;
  testCounts: { total: number; passed: number; failed: number };
  dynamicEvidence: DynamicEvidence[];
  failureCode: string | null;
};

function failureCode(error: string | null): string | null {
  if (!error) return null;
  if (publicFailureCodes.has(error)) return error;
  if (error === "Verification interrupted by application restart.") return "verification_interrupted";
  return "verification_failed";
}

function evidence(raw: string): DynamicEvidence[] {
  try {
    const parsed = dynamicEvidenceSchema.array().max(100).safeParse(JSON.parse(raw));
    return parsed.success ? parsed.data : [];
  } catch { return []; }
}

export function toPublicHypothesisVerificationRun(run: HypothesisVerificationRunRow): PublicHypothesisVerificationRun {
  return {
    id: run.id, hypothesisId: run.hypothesisId, status: run.status, outcome: run.outcome,
    verifier: run.verifierId, compiler: run.compilerVersion, contentFingerprint: run.contentFingerprint,
    createdAt: run.createdAt.toISOString(), startedAt: run.startedAt?.toISOString() ?? null,
    completedAt: run.completedAt?.toISOString() ?? null, durationMs: run.durationMs,
    isolationBackend: run.isolationBackend, exitCode: run.executionExitCode, timedOut: run.timedOut,
    testCounts: { total: run.testCount, passed: run.passedTestCount, failed: run.failedTestCount },
    dynamicEvidence: evidence(run.dynamicEvidence), failureCode: failureCode(run.error),
  };
}
