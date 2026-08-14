import { z } from "zod";

export const verificationRunStatuses = ["queued", "running", "completed", "failed"] as const;
export const verificationOutcomes = ["confirmed", "refuted", "inconclusive"] as const;
export const dynamicEvidenceDirections = ["supports", "contradicts", "neutral"] as const;

export type VerificationRunStatus = (typeof verificationRunStatuses)[number];
export type VerificationOutcome = (typeof verificationOutcomes)[number];
export type DynamicEvidenceDirection = (typeof dynamicEvidenceDirections)[number];

const verificationText = z.string().trim().min(1).max(5000);
const verificationName = z.string().trim().min(1).max(300);

export const verificationRunStatusSchema = z.enum(verificationRunStatuses);
export const verificationOutcomeSchema = z.enum(verificationOutcomes);
export const dynamicEvidenceDirectionSchema = z.enum(dynamicEvidenceDirections);

export const dynamicEvidenceSchema = z.object({
  assertionName: verificationName,
  expectedBehavior: verificationText,
  observedBehavior: verificationText,
  direction: dynamicEvidenceDirectionSchema,
  contract: z.string().trim().min(1).max(200).nullable(),
  functionName: z.string().trim().min(1).max(200).nullable(),
  details: verificationText,
}).strict();

export type DynamicEvidence = z.infer<typeof dynamicEvidenceSchema>;

export const createHypothesisVerificationRunSchema = z.object({
  hypothesisId: z.string().uuid(),
  scanId: z.string().uuid(),
  resolvedCommit: z.string().regex(/^[a-f0-9]{40}$/),
  verifierId: verificationName,
  toolName: verificationName,
  toolVersion: z.string().trim().min(1).max(200).nullable(),
  verificationStrategy: z.array(verificationText).min(1).max(30),
}).strict();

export const completeHypothesisVerificationRunSchema = z.object({
  outcome: verificationOutcomeSchema,
  resultSummary: verificationText,
  durationMs: z.number().int().nonnegative(),
  testCount: z.number().int().nonnegative(),
  passedTestCount: z.number().int().nonnegative(),
  failedTestCount: z.number().int().nonnegative(),
  stdoutSummary: z.string().max(20_000),
  stderrSummary: z.string().max(20_000),
  dynamicEvidence: z.array(dynamicEvidenceSchema).max(100),
}).strict().refine((result) => result.passedTestCount + result.failedTestCount <= result.testCount, {
  message: "passed and failed test counts cannot exceed total test count",
  path: ["testCount"],
});

export const failHypothesisVerificationRunSchema = z.object({
  error: verificationText,
  durationMs: z.number().int().nonnegative(),
  stdoutSummary: z.string().max(20_000),
  stderrSummary: z.string().max(20_000),
}).strict();

export const hypothesisVerificationRunSchema = z.object({
  id: z.string().uuid(),
  hypothesisId: z.string().uuid(),
  scanId: z.string().uuid(),
  resolvedCommit: z.string().regex(/^[a-f0-9]{40}$/),
  status: verificationRunStatusSchema,
  outcome: verificationOutcomeSchema.nullable(),
  verifierId: verificationName,
  toolName: verificationName,
  toolVersion: z.string().trim().min(1).max(200).nullable(),
  verificationStrategy: z.array(verificationText).min(1).max(30),
  resultSummary: verificationText.nullable(),
  testCount: z.number().int().nonnegative(),
  passedTestCount: z.number().int().nonnegative(),
  failedTestCount: z.number().int().nonnegative(),
  stdoutSummary: z.string().max(20_000),
  stderrSummary: z.string().max(20_000),
  dynamicEvidence: z.array(dynamicEvidenceSchema).max(100),
  error: verificationText.nullable(),
  createdAt: z.date(),
  startedAt: z.date().nullable(),
  completedAt: z.date().nullable(),
  durationMs: z.number().int().nonnegative().nullable(),
}).strict().superRefine((run, context) => {
  if (run.status === "completed" && run.outcome === null) context.addIssue({ code: z.ZodIssueCode.custom, message: "Completed verification runs require an outcome.", path: ["outcome"] });
  if (run.status !== "completed" && run.outcome !== null) context.addIssue({ code: z.ZodIssueCode.custom, message: "Only completed verification runs may have an outcome.", path: ["outcome"] });
  if (run.status === "failed" && run.error === null) context.addIssue({ code: z.ZodIssueCode.custom, message: "Failed verification runs require an error.", path: ["error"] });
});

export type CreateHypothesisVerificationRunInput = z.infer<typeof createHypothesisVerificationRunSchema>;
export type CompleteHypothesisVerificationRunInput = z.infer<typeof completeHypothesisVerificationRunSchema>;
export type FailHypothesisVerificationRunInput = z.infer<typeof failHypothesisVerificationRunSchema>;
export type HypothesisVerificationRun = z.infer<typeof hypothesisVerificationRunSchema>;

const verificationTransitions: Record<VerificationRunStatus, readonly VerificationRunStatus[]> = {
  queued: ["running"],
  running: ["completed", "failed"],
  completed: [],
  failed: [],
};

export function assertVerificationRunTransition(from: VerificationRunStatus, to: VerificationRunStatus): void {
  if (!verificationTransitions[from].includes(to)) throw new Error(`Invalid verification run transition: ${from} -> ${to}`);
}
