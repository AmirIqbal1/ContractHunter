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
const prohibitedCapabilityNames = new Set(["ffi", "createFork", "selectFork", "rpc", "readFile", "writeFile", "readDir", "env", "envUint", "broadcast", "startBroadcast", "deriveKey", "prank", "startPrank", "stopPrank", "deal", "hoax"]);
const safeFunctionIdentifier = solidityIdentifier.refine((value) => !prohibitedCapabilityNames.has(value) && !value.startsWith("env"), "must not name a prohibited harness capability");
const uint256Decimal = z.string().regex(/^\d{1,78}$/).refine((value) => BigInt(value) < (1n << 256n), "must fit in uint256");
export const VERIFICATION_MAX_ACTORS = 8;
export const VERIFICATION_MAX_FUNCTION_ARGUMENTS = 8;
export const VERIFICATION_MAX_FUNDING_WEI = "100000000000000000000";
const localFundingWei = z.string().regex(/^\d{1,21}$/).refine((value) => BigInt(value) <= BigInt(VERIFICATION_MAX_FUNDING_WEI), "must not exceed 100 ether");
export const verificationCapabilityProfile = {
  actors: true,
  maxActors: VERIFICATION_MAX_ACTORS,
  callers: true,
  functionArguments: ["address", "uint256", "bool"],
  maxFunctionArguments: VERIFICATION_MAX_FUNCTION_ARGUMENTS,
  observations: ["uint", "address", "native-balance"],
  assertions: ["uint-eq", "uint-not-eq", "address-eq", "address-not-eq"],
  stateSetup: ["native-eth-funding"],
  maxFundingWei: VERIFICATION_MAX_FUNDING_WEI,
  operations: ["deploy", "call", "read-uint", "read-address", "read-balance", "fund"],
  constructorArguments: false,
  rawCalldata: false,
  arbitrarySolidity: false,
  arrays: false,
  structs: false,
  bytes: false,
  timeManipulation: false,
  blockManipulation: false,
  attackerContractGeneration: false,
  erc20Helpers: false,
  rpc: false,
  forks: false,
  liveChain: false,
} as const;
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
  assertionId: z.string().regex(/^[A-Za-z0-9_-]{1,64}$/),
  assertionName: verificationName,
  expectedBehavior: verificationText,
  observedBehavior: verificationText,
  direction: dynamicEvidenceDirectionSchema,
  contract: z.string().trim().min(1).max(200).nullable(),
  functionName: z.string().trim().min(1).max(200).nullable(),
  details: verificationText,
}).strict();

export const verificationAddressReferenceSchema = z.object({
  kind: z.enum(["actor", "instance"]),
  name: solidityIdentifier,
}).strict();

export const verificationTypedValueSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("address"), source: z.enum(["actor", "instance"]), name: solidityIdentifier }).strict(),
  z.object({ kind: z.literal("uint"), value: uint256Decimal }).strict(),
  z.object({ kind: z.literal("bool"), value: z.boolean() }).strict(),
]);

export const verificationHarnessOperationSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("deploy"), contractName: solidityIdentifier, instanceName: solidityIdentifier }).strict(),
  z.object({ kind: z.literal("call"), instanceName: solidityIdentifier, functionName: safeFunctionIdentifier, caller: solidityIdentifier.optional(), args: z.array(verificationTypedValueSchema).max(VERIFICATION_MAX_FUNCTION_ARGUMENTS).optional() }).strict(),
  z.object({ kind: z.literal("read-uint"), instanceName: solidityIdentifier, functionName: safeFunctionIdentifier, resultName: solidityIdentifier }).strict(),
  z.object({ kind: z.literal("read-address"), instanceName: solidityIdentifier, functionName: safeFunctionIdentifier, resultName: solidityIdentifier }).strict(),
  z.object({ kind: z.literal("fund"), target: verificationAddressReferenceSchema, amountWei: localFundingWei }).strict(),
  z.object({ kind: z.literal("read-balance"), target: verificationAddressReferenceSchema, resultName: solidityIdentifier }).strict(),
]);

export const verificationGeneratedHarnessOperationSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("deploy"), contractName: solidityIdentifier, instanceName: solidityIdentifier }).strict(),
  z.object({ kind: z.literal("call"), instanceName: solidityIdentifier, functionName: safeFunctionIdentifier, caller: solidityIdentifier.nullable(), args: z.array(verificationTypedValueSchema).max(VERIFICATION_MAX_FUNCTION_ARGUMENTS) }).strict(),
  z.object({ kind: z.literal("read-uint"), instanceName: solidityIdentifier, functionName: safeFunctionIdentifier, resultName: solidityIdentifier }).strict(),
  z.object({ kind: z.literal("read-address"), instanceName: solidityIdentifier, functionName: safeFunctionIdentifier, resultName: solidityIdentifier }).strict(),
  z.object({ kind: z.literal("fund"), target: verificationAddressReferenceSchema, amountWei: localFundingWei }).strict(),
  z.object({ kind: z.literal("read-balance"), target: verificationAddressReferenceSchema, resultName: solidityIdentifier }).strict(),
]);

const assertionBase = {
  id: z.string().regex(/^[A-Za-z0-9_-]{1,64}$/), actual: solidityIdentifier,
  expectedOutcome: z.enum(["hypothesis-supported", "hypothesis-contradicted"]), description: z.string().trim().min(1).max(300),
} as const;

export const verificationHarnessAssertionSchema = z.discriminatedUnion("kind", [
  z.object({ ...assertionBase, kind: z.enum(["uint-eq", "uint-not-eq"]), expected: uint256Decimal }).strict(),
  z.object({ ...assertionBase, kind: z.enum(["address-eq", "address-not-eq"]), expected: z.object({ kind: z.literal("address"), source: z.enum(["actor", "instance"]), name: solidityIdentifier }).strict() }).strict(),
]);

const verificationPlanSemanticsFields = {
  primaryContract: solidityIdentifier,
  primarySourcePath: repositorySolidityPathSchema,
  relevantFunctions: z.array(solidityIdentifier).min(1).max(20),
  sourceFiles: z.array(repositorySolidityPathSchema).min(1).max(50),
  verificationGoal: verificationText,
  expectedProperty: verificationText,
  verificationSteps: z.array(z.string().trim().min(1).max(1000)).min(1).max(30),
  assertions: z.array(verificationHarnessAssertionSchema).min(1).max(30),
} as const;

const verificationPlanSemanticsShapeSchema = z.object({
  ...verificationPlanSemanticsFields,
  actors: z.array(solidityIdentifier).min(1).max(VERIFICATION_MAX_ACTORS),
  operations: z.array(verificationGeneratedHarnessOperationSchema).min(1).max(50),
}).strict();

type PlanForReferenceValidation = z.infer<typeof verificationPlanSemanticsShapeSchema> | z.infer<typeof verificationHarnessPlanShapeSchema>;

function validatePlanReferences(plan: PlanForReferenceValidation, context: z.RefinementCtx): void {
  if (!plan.sourceFiles.includes(plan.primarySourcePath)) context.addIssue({ code: z.ZodIssueCode.custom, message: "Primary source must be included in sourceFiles.", path: ["sourceFiles"] });
  if (new Set(plan.sourceFiles).size !== plan.sourceFiles.length) context.addIssue({ code: z.ZodIssueCode.custom, message: "Source files must be unique.", path: ["sourceFiles"] });
  if (new Set(plan.relevantFunctions).size !== plan.relevantFunctions.length) context.addIssue({ code: z.ZodIssueCode.custom, message: "Relevant functions must be unique.", path: ["relevantFunctions"] });
  if (new Set(plan.assertions.map((assertion) => assertion.id)).size !== plan.assertions.length) context.addIssue({ code: z.ZodIssueCode.custom, message: "Assertion identifiers must be unique.", path: ["assertions"] });
  const actors = new Set(plan.actors ?? []); const instances = new Set<string>(); const resultTypes = new Map<string, "uint" | "address">();
  if (actors.size !== (plan.actors?.length ?? 0)) context.addIssue({ code: z.ZodIssueCode.custom, message: "Actors must be unique.", path: ["actors"] });
  const reference = (source: "actor" | "instance", name: string, path: Array<string | number>) => {
    if (source === "actor" && !actors.has(name)) context.addIssue({ code: z.ZodIssueCode.custom, message: "Operation references an unknown actor.", path });
    if (source === "instance" && !instances.has(name)) context.addIssue({ code: z.ZodIssueCode.custom, message: "Operation references an undeclared instance.", path });
  };
  plan.operations.forEach((operation, index) => {
    if (operation.kind === "deploy") {
      if (instances.has(operation.instanceName) || actors.has(operation.instanceName)) context.addIssue({ code: z.ZodIssueCode.custom, message: "Deployment instance name is duplicated or ambiguous.", path: ["operations", index, "instanceName"] });
      instances.add(operation.instanceName); return;
    }
    if (operation.kind === "fund" || operation.kind === "read-balance") {
      reference(operation.target.kind, operation.target.name, ["operations", index, "target"]);
      if (operation.kind === "read-balance") {
        if (resultTypes.has(operation.resultName) || instances.has(operation.resultName) || actors.has(operation.resultName)) context.addIssue({ code: z.ZodIssueCode.custom, message: "Read result name is duplicated or ambiguous.", path: ["operations", index, "resultName"] });
        resultTypes.set(operation.resultName, "uint");
      }
      return;
    }
    if (!instances.has(operation.instanceName)) context.addIssue({ code: z.ZodIssueCode.custom, message: "Operation references an undeclared instance.", path: ["operations", index, "instanceName"] });
    if (operation.kind === "call") {
      if (operation.caller && !actors.has(operation.caller)) context.addIssue({ code: z.ZodIssueCode.custom, message: "Call references an unknown actor.", path: ["operations", index, "caller"] });
      operation.args?.forEach((argument, argumentIndex) => { if (argument.kind === "address") reference(argument.source, argument.name, ["operations", index, "args", argumentIndex]); });
      return;
    }
    if (resultTypes.has(operation.resultName) || instances.has(operation.resultName) || actors.has(operation.resultName)) context.addIssue({ code: z.ZodIssueCode.custom, message: "Read result name is duplicated or ambiguous.", path: ["operations", index, "resultName"] });
    resultTypes.set(operation.resultName, operation.kind === "read-address" ? "address" : "uint");
  });
  plan.assertions.forEach((assertion, index) => {
    if (assertion.kind === "address-eq" || assertion.kind === "address-not-eq") reference(assertion.expected.source, assertion.expected.name, ["assertions", index, "expected"]);
  });
}

const verificationHarnessPlanShapeSchema = z.object({
  scanId: z.string().uuid(),
  hypothesisId: z.string().uuid(),
  resolvedCommit: z.string().regex(/^[a-f0-9]{40}$/),
  compilerVersion: stableCompilerVersionSchema,
  ...verificationPlanSemanticsFields,
  actors: z.array(solidityIdentifier).min(1).max(VERIFICATION_MAX_ACTORS).optional(),
  operations: z.array(verificationHarnessOperationSchema).min(1).max(50),
}).strict();

export const verificationHarnessPlanSchema = verificationHarnessPlanShapeSchema.superRefine(validatePlanReferences);
export const verificationPlanSemanticsSchema = verificationPlanSemanticsShapeSchema.superRefine(validatePlanReferences);

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
export type VerificationPlanSemantics = z.infer<typeof verificationPlanSemanticsSchema>;
export type VerificationHarnessOperation = z.infer<typeof verificationHarnessOperationSchema>;
export type VerificationHarnessAssertion = z.infer<typeof verificationHarnessAssertionSchema>;
export type VerificationTypedValue = z.infer<typeof verificationTypedValueSchema>;
export type VerificationAddressReference = z.infer<typeof verificationAddressReferenceSchema>;
export type VerificationSourceManifestEntry = z.infer<typeof verificationSourceManifestEntrySchema>;

export const createHypothesisVerificationRunSchema = z.object({
  hypothesisId: z.string().uuid(),
  scanId: z.string().uuid(),
  resolvedCommit: z.string().regex(/^[a-f0-9]{40}$/),
  compilerVersion: stableCompilerVersionSchema,
  verificationPlan: verificationHarnessPlanSchema,
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
  contentFingerprint: sha256,
  isolationBackend: verificationName,
  executionExitCode: z.number().int(),
  timedOut: z.boolean(),
}).strict().refine((result) => result.passedTestCount + result.failedTestCount <= result.testCount, {
  message: "passed and failed test counts cannot exceed total test count",
  path: ["testCount"],
});

export const failHypothesisVerificationRunSchema = z.object({
  error: verificationText,
  durationMs: z.number().int().nonnegative(),
  stdoutSummary: z.string().max(20_000),
  stderrSummary: z.string().max(20_000),
  contentFingerprint: sha256.nullable(),
  isolationBackend: verificationName.nullable(),
  executionExitCode: z.number().int().nullable(),
  timedOut: z.boolean(),
}).strict();

export const hypothesisVerificationRunSchema = z.object({
  id: z.string().uuid(),
  hypothesisId: z.string().uuid(),
  scanId: z.string().uuid(),
  resolvedCommit: z.string().regex(/^[a-f0-9]{40}$/),
  compilerVersion: stableCompilerVersionSchema,
  verificationPlan: verificationHarnessPlanSchema,
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
  contentFingerprint: sha256.nullable(),
  isolationBackend: verificationName.nullable(),
  executionExitCode: z.number().int().nullable(),
  timedOut: z.boolean(),
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
