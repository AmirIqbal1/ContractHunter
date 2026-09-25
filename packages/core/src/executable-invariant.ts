import { createHash } from "node:crypto";
import { z } from "zod";
import { VERIFICATION_MAX_ACTORS, VERIFICATION_MAX_FUNDING_WEI, repositorySolidityPathSchema, stableCompilerVersionSchema, verificationAddressReferenceSchema, verificationTypedValueSchema } from "./hypothesis-verification";

export const EXECUTABLE_INVARIANT_SCHEMA_VERSION = "contracthunter-invariant-plan-v1" as const;
export const INVARIANT_LIMITS = { actors: VERIFICATION_MAX_ACTORS, sourceFiles: 50, setupOperations: 32, handlerActions: 16, parameters: 8, properties: 16, observations: 16, assertions: 16 } as const;
export const INVARIANT_MODES = ["fuzz-property", "stateful-invariant"] as const;
export const INVARIANT_FUZZ_TYPES = ["uint256", "bool"] as const;
export const invariantCapabilityProfile = {
  modes: INVARIANT_MODES, fuzzParameterTypes: INVARIANT_FUZZ_TYPES, symbolicAddresses: ["actor", "instance"],
  setupOperations: ["deploy", "fund", "call"], observations: ["read-uint", "read-address", "read-balance"],
  assertions: ["uint-eq", "uint-not-eq", "address-eq", "address-not-eq"],
  limits: INVARIANT_LIMITS, constructorArguments: false, arbitrarySolidity: false, arbitraryCheatcodes: false,
  rawAddresses: false, rawCalldata: false, bytes: false, strings: false, arrays: false, tuples: false,
  arbitraryFoundryConfig: false, ffi: false, rpc: false, forks: false, wallets: false, liveChain: false,
} as const;
const reserved = new Set(["address", "uint", "uint256", "bool", "contract", "function", "mapping", "return", "returns", "public", "external", "internal", "private", "new", "delete", "if", "else", "for", "while", "this", "super", "import", "pragma", "receive", "fallback", "event", "error", "struct", "enum", "using", "memory", "storage", "calldata", "payable", "view", "pure", "unchecked", "true", "false", "assembly", "let", "switch", "case", "default", "try", "catch", "handler", "vm", "targetContract", "targetContracts"]);
const identifier = z.string().regex(/^[A-Za-z][A-Za-z0-9_]{0,63}$/).refine((name) => !reserved.has(name) && !/^(?:test|setUp|invariant|action|actor_|ContractHunter|ffi|rpc|createFork|selectFork|broadcast|startBroadcast|readFile|writeFile|env\w*)/.test(name), "reserved identifier");
const uint = z.string().regex(/^(?:0|[1-9]\d{0,77})$/).refine((value) => BigInt(value) < (1n << 256n));
const funding = uint.refine((value) => BigInt(value) <= BigInt(VERIFICATION_MAX_FUNDING_WEI));
const fixedArg = verificationTypedValueSchema;
const addressArg = z.object({ kind: z.literal("address"), source: z.enum(["actor", "instance"]), name: identifier }).strict();
const uintArg = z.object({ kind: z.literal("uint"), value: uint }).strict();
const boolArg = z.object({ kind: z.literal("bool"), value: z.boolean() }).strict();
const parameter = z.object({ name: identifier, type: z.enum(INVARIANT_FUZZ_TYPES) }).strict();
const actionArg = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("parameter"), name: identifier }).strict(),
  addressArg, uintArg, boolArg,
]);
const setupOperation = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("deploy"), contractName: identifier, instanceName: identifier }).strict(),
  z.object({ kind: z.literal("fund"), target: verificationAddressReferenceSchema, amountWei: funding }).strict(),
  z.object({ kind: z.literal("call"), instanceName: identifier, functionName: identifier, caller: identifier.optional(), args: z.array(fixedArg).max(8) }).strict(),
]);
const call = z.object({ instanceName: identifier, functionName: identifier, caller: identifier.optional(), parameters: z.array(parameter).max(INVARIANT_LIMITS.parameters), args: z.array(actionArg).max(INVARIANT_LIMITS.parameters) }).strict();
const observation = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("read-uint"), instanceName: identifier, functionName: identifier, resultName: identifier }).strict(),
  z.object({ kind: z.literal("read-address"), instanceName: identifier, functionName: identifier, resultName: identifier }).strict(),
  z.object({ kind: z.literal("read-balance"), target: verificationAddressReferenceSchema, resultName: identifier }).strict(),
]);
const assertion = z.discriminatedUnion("kind", [
  z.object({ id: identifier, kind: z.enum(["uint-eq", "uint-not-eq"]), actual: identifier, expected: z.union([uint, z.object({ kind: z.literal("result"), name: identifier }).strict()]) }).strict(),
  z.object({ id: identifier, kind: z.enum(["address-eq", "address-not-eq"]), actual: identifier, expected: z.union([z.object({ kind: z.literal("address"), source: z.enum(["actor", "instance"]), name: identifier }).strict(), z.object({ kind: z.literal("result"), name: identifier }).strict()]) }).strict(),
]);
const property = z.object({ name: identifier, observations: z.array(observation).min(1).max(INVARIANT_LIMITS.observations), assertions: z.array(assertion).min(1).max(INVARIANT_LIMITS.assertions) }).strict();
const common = {
  schemaVersion: z.literal(EXECUTABLE_INVARIANT_SCHEMA_VERSION), scanId: z.string().uuid(), hypothesisId: z.string().uuid(), resolvedCommit: z.string().regex(/^[a-f0-9]{40}$/), compilerVersion: stableCompilerVersionSchema,
  primaryContract: identifier, primarySourcePath: repositorySolidityPathSchema, sourceFiles: z.array(repositorySolidityPathSchema).min(1).max(INVARIANT_LIMITS.sourceFiles), actors: z.array(identifier).max(INVARIANT_LIMITS.actors),
  setup: z.array(setupOperation).min(1).max(INVARIANT_LIMITS.setupOperations),
};
const fuzz = z.object({ ...common, mode: z.literal("fuzz-property"), property: property, fuzzAction: call.extend({ parameters: z.array(parameter).min(1).max(INVARIANT_LIMITS.parameters) }) }).strict();
const stateful = z.object({ ...common, mode: z.literal("stateful-invariant"), handlerActions: z.array(call.extend({ name: identifier })).min(1).max(INVARIANT_LIMITS.handlerActions), properties: z.array(property).min(1).max(INVARIANT_LIMITS.properties) }).strict();

type Plan = z.infer<typeof fuzz> | z.infer<typeof stateful>;
function references(plan: Plan, context: z.RefinementCtx): void {
  const issue = (message: string) => context.addIssue({ code: z.ZodIssueCode.custom, message });
  if (!plan.sourceFiles.includes(plan.primarySourcePath) || new Set(plan.sourceFiles).size !== plan.sourceFiles.length) issue("Source paths must be unique and contain the primary source.");
  const actors = new Set(plan.actors), instances = new Set<string>();
  if (actors.size !== plan.actors.length) issue("Duplicate actor identifier.");
  const address = (source: "actor" | "instance", name: string) => { if (!(source === "actor" ? actors : instances).has(name)) issue("Unknown symbolic address reference."); };
  const fixed = (value: z.infer<typeof fixedArg>) => { if (value.kind === "address") address(value.source, value.name); };
  const validateCall = (value: z.infer<typeof call>) => {
    if (!instances.has(value.instanceName)) issue("Call target is not deployed.");
    if (value.caller) address("actor", value.caller);
    const params = new Map(value.parameters.map((p) => [p.name, p.type]));
    if (params.size !== value.parameters.length) issue("Duplicate fuzz parameter.");
    if ([...params.keys()].some((name) => instances.has(name) || actors.has(name))) issue("Fuzz parameter shadows a symbolic reference.");
    for (const arg of value.args) {
      if (arg.kind === "parameter") { if (!params.has(arg.name)) issue("Unknown fuzz parameter."); }
      else fixed(arg);
    }
    if (value.args.filter((a) => a.kind === "parameter").length !== value.parameters.length || new Set(value.args.filter((a) => a.kind === "parameter").map((a) => a.name)).size !== value.parameters.length) issue("Every fuzz parameter must be used exactly once.");
  };
  for (const operation of plan.setup) {
    if (operation.kind === "deploy") { if (operation.contractName !== plan.primaryContract || instances.has(operation.instanceName) || actors.has(operation.instanceName)) issue("Invalid or duplicate deployment."); instances.add(operation.instanceName); }
    else if (operation.kind === "fund") address(operation.target.kind, operation.target.name);
    else { if (!instances.has(operation.instanceName)) issue("Setup call target is not deployed."); if (operation.caller) address("actor", operation.caller); operation.args.forEach(fixed); }
  }
  if (!instances.size) issue("At least one controlled deployment is required.");
  if (plan.setup.filter((op) => op.kind === "fund").reduce((total, op) => total + BigInt(op.amountWei), 0n) > BigInt(VERIFICATION_MAX_FUNDING_WEI)) issue("Aggregate setup funding exceeds 100 ether.");
  const calls = plan.mode === "fuzz-property" ? [plan.fuzzAction] : plan.handlerActions;
  if (plan.mode === "stateful-invariant" && new Set(plan.handlerActions.map((a) => a.name)).size !== plan.handlerActions.length) issue("Duplicate handler action.");
  calls.forEach(validateCall);
  const properties = plan.mode === "fuzz-property" ? [plan.property] : plan.properties;
  if (new Set(properties.map((p) => p.name)).size !== properties.length) issue("Duplicate property identifier.");
  for (const item of properties) {
    const results = new Map<string, "uint" | "address">();
    for (const observation of item.observations) {
      if (results.has(observation.resultName) || actors.has(observation.resultName) || instances.has(observation.resultName)) issue("Duplicate observation identifier.");
      results.set(observation.resultName, observation.kind === "read-address" ? "address" : "uint");
      if (observation.kind === "read-balance") address(observation.target.kind, observation.target.name);
      else if (!instances.has(observation.instanceName)) issue("Observation target is not deployed.");
    }
    if (new Set(item.assertions.map((a) => a.id)).size !== item.assertions.length) issue("Duplicate assertion identifier.");
    if (plan.mode === "fuzz-property" && item.observations.some((observation) => plan.fuzzAction.parameters.some((parameter) => parameter.name === observation.resultName))) issue("Observation shadows a fuzz parameter.");
    for (const a of item.assertions) {
      const type = a.kind.startsWith("uint") ? "uint" : "address";
      if (results.get(a.actual) !== type) issue("Assertion actual has the wrong observation type.");
      if (typeof a.expected === "object") {
        if (a.expected.kind === "result") { if (results.get(a.expected.name) !== type) issue("Assertion expected has the wrong observation type."); }
        else address(a.expected.source, a.expected.name);
      }
    }
  }
}
export const executableInvariantPlanSchema = z.discriminatedUnion("mode", [fuzz, stateful]).superRefine(references);
export type ExecutableInvariantPlan = z.infer<typeof executableInvariantPlanSchema>;
export const invariantFuzzSemanticsSchema = fuzz.omit({ schemaVersion: true, scanId: true, hypothesisId: true, resolvedCommit: true, compilerVersion: true, primarySourcePath: true, sourceFiles: true });
export const invariantStatefulSemanticsSchema = stateful.omit({ schemaVersion: true, scanId: true, hypothesisId: true, resolvedCommit: true, compilerVersion: true, primarySourcePath: true, sourceFiles: true });
export const invariantSemanticsSchema = z.discriminatedUnion("mode", [invariantFuzzSemanticsSchema, invariantStatefulSemanticsSchema]);
export type InvariantSemantics = z.infer<typeof invariantSemanticsSchema>;
// Responses structured outputs require every object field. AI uses explicit null
// for an absent caller; composition converts null to the core plan's omission.
const aiSetupOperation = z.discriminatedUnion("kind", [setupOperation.options[0], setupOperation.options[1], setupOperation.options[2].extend({ caller: identifier.nullable() })]);
const aiSetup = z.array(aiSetupOperation).min(1).max(INVARIANT_LIMITS.setupOperations);
export const invariantAIProposalSemanticsSchema = z.discriminatedUnion("mode", [
  invariantFuzzSemanticsSchema.extend({ setup: aiSetup, fuzzAction: fuzz.shape.fuzzAction.extend({ caller: identifier.nullable() }) }),
  invariantStatefulSemanticsSchema.extend({ setup: aiSetup, handlerActions: z.array(call.extend({ name: identifier, caller: identifier.nullable() })).min(1).max(INVARIANT_LIMITS.handlerActions) }),
]);
export type InvariantCall = z.infer<typeof call>;
export type InvariantProperty = z.infer<typeof property>;
export type InvariantSetupOperation = z.infer<typeof setupOperation>;

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([key, item]) => [key, canonical(item)]));
  return value;
}
export function canonicalInvariantPlan(input: ExecutableInvariantPlan): string { const plan = executableInvariantPlanSchema.parse(input); return JSON.stringify(canonical({ ...plan, sourceFiles: [...plan.sourceFiles].sort() })); }
export function invariantPlanHash(input: ExecutableInvariantPlan): string { return createHash("sha256").update(canonicalInvariantPlan(input)).digest("hex"); }

export const INVARIANT_HARNESS_MANIFEST = ".contracthunter-invariant.json";
const executableInvariantManifestShapeSchema = z.object({
  formatVersion: z.literal(1), workspaceId: z.string().uuid(), planKind: z.literal("executable-invariant"), mode: z.enum(["fuzz-property", "stateful-invariant"]), schemaVersion: z.literal(EXECUTABLE_INVARIANT_SCHEMA_VERSION),
  planHash: z.string().regex(/^[a-f0-9]{64}$/), hypothesisId: z.string().uuid(), scanId: z.string().uuid(), resolvedCommit: z.string().regex(/^[a-f0-9]{40}$/), compilerVersion: stableCompilerVersionSchema,
  generatorVersion: stableCompilerVersionSchema, generatedBy: z.literal("contracthunter"), sourceManifest: z.array(z.object({ originalPath: repositorySolidityPathSchema, workspacePath: z.string().regex(/^src\/[A-Za-z0-9_@+./-]+\.sol$/), byteLength: z.number().int().nonnegative().max(10_485_760), sha256: z.string().regex(/^[a-f0-9]{64}$/) }).strict().refine((entry) => entry.workspacePath === `src/${entry.originalPath}`)).min(1).max(200),
  generatedHarnessPath: z.literal("test/ContractHunterInvariant.t.sol"), generatedHarnessSha256: z.string().regex(/^[a-f0-9]{64}$/), foundryConfigSha256: z.string().regex(/^[a-f0-9]{64}$/),
  foundry: z.object({ fuzzRuns: z.literal(128), invariantRuns: z.literal(64), invariantDepth: z.literal(32), invariantFailOnRevert: z.literal(false), seed: z.string().regex(/^0x[a-f0-9]{64}$/) }).strict(), contentFingerprint: z.string().regex(/^[a-f0-9]{64}$/),
}).strict();
export type ExecutableInvariantManifest = z.infer<typeof executableInvariantManifestShapeSchema>;
export function invariantManifestFingerprint(input: object): string {
  return createHash("sha256").update(JSON.stringify(canonical(input))).digest("hex");
}
export const executableInvariantManifestSchema = executableInvariantManifestShapeSchema.superRefine((manifest, context) => {
  if (manifest.foundry.seed !== `0x${manifest.planHash}`) context.addIssue({ code: z.ZodIssueCode.custom, message: "Foundry seed must match the canonical plan hash." });
  const { contentFingerprint, ...base } = manifest;
  if (contentFingerprint !== invariantManifestFingerprint(base)) context.addIssue({ code: z.ZodIssueCode.custom, message: "Invariant manifest fingerprint is invalid." });
  const paths = manifest.sourceManifest.map((entry) => entry.originalPath);
  if (new Set(paths).size !== paths.length) context.addIssue({ code: z.ZodIssueCode.custom, message: "Duplicate source manifest paths." });
});

// v2 embeds the bounded canonical plan so the isolated worker can independently
// validate identities, source signatures, and generated bytes before executing.
export const executableInvariantExecutionManifestSchema = executableInvariantManifestShapeSchema.extend({
  formatVersion: z.literal(2),
  plan: executableInvariantPlanSchema,
}).superRefine((manifest, context) => {
  const issue = (message: string) => context.addIssue({ code: z.ZodIssueCode.custom, message });
  if (manifest.planHash !== invariantPlanHash(manifest.plan)) issue("Invariant plan hash is invalid.");
  if (manifest.mode !== manifest.plan.mode || manifest.schemaVersion !== manifest.plan.schemaVersion || manifest.hypothesisId !== manifest.plan.hypothesisId || manifest.scanId !== manifest.plan.scanId || manifest.resolvedCommit !== manifest.plan.resolvedCommit || manifest.compilerVersion !== manifest.plan.compilerVersion) issue("Invariant manifest identity differs from its plan.");
  if (manifest.foundry.seed !== `0x${manifest.planHash}`) issue("Invariant seed differs from its plan hash.");
  const { contentFingerprint, ...base } = manifest;
  if (contentFingerprint !== invariantManifestFingerprint(base)) issue("Invariant manifest fingerprint is invalid.");
  const paths = manifest.sourceManifest.map((entry) => entry.originalPath);
  if (new Set(paths).size !== paths.length) issue("Duplicate source manifest paths.");
});
export type ExecutableInvariantExecutionManifest = z.infer<typeof executableInvariantExecutionManifestSchema>;

const invariantEvidenceText = z.string().max(2048);
export const invariantPropertyOutcomes = ["held-within-bounds", "counterexample-found", "execution-failed", "inconclusive"] as const;
export const invariantHypothesisRelations = ["supports", "contradicts", "neutral", "unreviewed"] as const;
export const INVARIANT_COUNTEREXAMPLE_PARSER_VERSION = "foundry-1.7.1-json-v1" as const;
const counterexampleValueSchema = z.discriminatedUnion("type", [
  z.object({ name: identifier, type: z.literal("uint256"), value: uint }).strict(),
  z.object({ name: identifier, type: z.literal("bool"), value: z.boolean() }).strict(),
]);
export const executableInvariantCounterexampleSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("single"), parserVersion: z.literal(INVARIANT_COUNTEREXAMPLE_PARSER_VERSION), parameterValues: z.array(counterexampleValueSchema).max(INVARIANT_LIMITS.parameters), summary: invariantEvidenceText }).strict(),
  z.object({ kind: z.literal("sequence"), parserVersion: z.literal(INVARIANT_COUNTEREXAMPLE_PARSER_VERSION), actions: z.array(z.object({ actionName: identifier, parameterValues: z.array(counterexampleValueSchema).max(INVARIANT_LIMITS.parameters) }).strict()).min(1).max(32), summary: invariantEvidenceText }).strict(),
]);
export const executableInvariantEvidenceSchema = z.object({
  planHash: z.string().regex(/^[a-f0-9]{64}$/), mode: z.enum(["fuzz-property", "stateful-invariant"]), propertyName: z.string().regex(/^[A-Za-z][A-Za-z0-9_]{0,63}$/),
  configuredRuns: z.number().int().min(1).max(1_000), configuredDepth: z.number().int().min(1).max(1_000).nullable(), runsExecuted: z.number().int().nonnegative().max(1_000),
  propertyOutcome: z.enum(invariantPropertyOutcomes), hypothesisRelation: z.enum(invariantHypothesisRelations), compilerVersion: stableCompilerVersionSchema,
  isolationProvider: z.string().min(1).max(100), counterexample: executableInvariantCounterexampleSchema.nullable(), summary: invariantEvidenceText,
}).strict();
export type ExecutableInvariantEvidence = z.infer<typeof executableInvariantEvidenceSchema>;
export type ExecutableInvariantCounterexample = z.infer<typeof executableInvariantCounterexampleSchema>;
