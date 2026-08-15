import { z } from "zod";

export const verificationRunStatuses = ["queued", "running", "completed", "failed"] as const;
export const verificationOutcomes = ["confirmed", "refuted", "inconclusive"] as const;
export const dynamicEvidenceDirections = ["supports", "contradicts", "neutral"] as const;
export const VERIFICATION_HARNESS_MANIFEST = ".contracthunter-verification.json";

export type VerificationRunStatus = (typeof verificationRunStatuses)[number];
export type VerificationOutcome = (typeof verificationOutcomes)[number];
export type DynamicEvidenceDirection = (typeof dynamicEvidenceDirections)[number];

const verificationText = z.string().trim().min(1).max(5000);
const verificationName = z.string().trim().min(1).max(300);
const solidityIdentifier = z.string().regex(/^[A-Za-z_][A-Za-z0-9_]{0,127}$/);
export const stableCompilerVersionSchema = z.string().regex(/^\d+\.\d+\.\d+$/);
const safeRepositoryPathComponent = /^[A-Za-z0-9_@+.-]+$/;
export const repositorySolidityPathSchema = z.string().min(5).max(500).refine((value) => {
  const components = value.split("/");
  return value.endsWith(".sol") && !value.startsWith("/") && !/^[A-Za-z]:/.test(value)
    && components.every((component) => component !== "." && component !== ".." && safeRepositoryPathComponent.test(component));
}, "must be a safe repository-relative Solidity path");
const sha256 = z.string().regex(/^[a-f0-9]{64}$/);

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

export const verificationHarnessOperationSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("deploy"), contractName: solidityIdentifier, instanceName: solidityIdentifier }).strict(),
  z.object({ kind: z.literal("call"), instanceName: solidityIdentifier, functionName: solidityIdentifier }).strict(),
  z.object({ kind: z.literal("read-uint"), instanceName: solidityIdentifier, functionName: solidityIdentifier, resultName: solidityIdentifier }).strict(),
]);

export const verificationHarnessAssertionSchema = z.object({
  kind: z.enum(["uint-eq", "uint-not-eq"]),
  actual: solidityIdentifier,
  expected: z.string().regex(/^\d{1,78}$/),
  description: z.string().trim().min(1).max(300),
}).strict();

export const verificationHarnessPlanSchema = z.object({
  scanId: z.string().uuid(),
  hypothesisId: z.string().uuid(),
  resolvedCommit: z.string().regex(/^[a-f0-9]{40}$/),
  compilerVersion: stableCompilerVersionSchema,
  primaryContract: solidityIdentifier,
  primarySourcePath: repositorySolidityPathSchema,
  relevantFunctions: z.array(solidityIdentifier).min(1).max(20),
  sourceFiles: z.array(repositorySolidityPathSchema).min(1).max(50),
  verificationGoal: verificationText,
  expectedProperty: verificationText,
  verificationSteps: z.array(z.string().trim().min(1).max(1000)).min(1).max(30),
  operations: z.array(verificationHarnessOperationSchema).min(1).max(50),
  assertions: z.array(verificationHarnessAssertionSchema).min(1).max(30),
}).strict().superRefine((plan, context) => {
  if (!plan.sourceFiles.includes(plan.primarySourcePath)) context.addIssue({ code: z.ZodIssueCode.custom, message: "Primary source must be included in sourceFiles.", path: ["sourceFiles"] });
  if (new Set(plan.sourceFiles).size !== plan.sourceFiles.length) context.addIssue({ code: z.ZodIssueCode.custom, message: "Source files must be unique.", path: ["sourceFiles"] });
  if (new Set(plan.relevantFunctions).size !== plan.relevantFunctions.length) context.addIssue({ code: z.ZodIssueCode.custom, message: "Relevant functions must be unique.", path: ["relevantFunctions"] });
});

export const verificationSourceManifestEntrySchema = z.object({
  originalPath: repositorySolidityPathSchema,
  workspacePath: z.string().regex(/^src\/[A-Za-z0-9_@+./-]+\.sol$/).max(504).refine((value) => value.split("/").every((component) => component && component !== "." && component !== ".."), "must remain inside the workspace source directory"),
  byteLength: z.number().int().nonnegative().max(10_485_760),
  sha256,
}).strict().refine((entry) => entry.workspacePath === `src/${entry.originalPath}`, {
  message: "workspace path must preserve the repository-relative source layout",
  path: ["workspacePath"],
});

export const verificationHarnessManifestSchema = z.object({
  formatVersion: z.literal(1),
  verificationRunId: z.string().uuid(),
  scanId: z.string().uuid(),
  hypothesisId: z.string().uuid(),
  resolvedCommit: z.string().regex(/^[a-f0-9]{40}$/),
  compilerVersion: stableCompilerVersionSchema,
  generatorVersion: z.string().regex(/^\d+\.\d+\.\d+$/),
  generatedBy: z.literal("contracthunter"),
  createdAt: z.string().datetime({ offset: true }),
  sourceManifest: z.array(verificationSourceManifestEntrySchema).min(1).max(200),
  generatedHarnessPath: z.literal("test/ContractHunterVerification.t.sol"),
  generatedHarnessSha256: sha256,
  foundryConfigSha256: sha256,
  contentFingerprint: sha256,
}).strict();

export type DynamicEvidence = z.infer<typeof dynamicEvidenceSchema>;
export type VerificationHarnessManifest = z.infer<typeof verificationHarnessManifestSchema>;
export type VerificationHarnessPlan = z.infer<typeof verificationHarnessPlanSchema>;
export type VerificationHarnessOperation = z.infer<typeof verificationHarnessOperationSchema>;
export type VerificationHarnessAssertion = z.infer<typeof verificationHarnessAssertionSchema>;
export type VerificationSourceManifestEntry = z.infer<typeof verificationSourceManifestEntrySchema>;

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
