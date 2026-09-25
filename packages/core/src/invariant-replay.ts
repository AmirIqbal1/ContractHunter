import { createHash } from "node:crypto";
import { z } from "zod";
import { executableInvariantCounterexampleSchema, executableInvariantPlanSchema, invariantPlanHash } from "./executable-invariant";
import { stableCompilerVersionSchema } from "./hypothesis-verification";

export const INVARIANT_REPLAY_SCHEMA_VERSION = "contracthunter-invariant-replay-v1" as const;
export const INVARIANT_REPLAY_MANIFEST = ".contracthunter-replay.json" as const;
export const invariantHypothesisExpectationSchema = z.literal("hypothesis-predicts-property-violation");
const sha256 = z.string().regex(/^[a-f0-9]{64}$/);
const uuid = z.string().uuid();

export const invariantReplayPlanSchema = z.object({
  schemaVersion: z.literal(INVARIANT_REPLAY_SCHEMA_VERSION), hypothesisId: uuid, scanId: uuid,
  resolvedCommit: z.string().regex(/^[a-f0-9]{40}$/), compilerVersion: stableCompilerVersionSchema,
  proposalId: uuid, invariantRunId: uuid, invariantPlanHash: sha256, propertyName: z.string().regex(/^[A-Za-z][A-Za-z0-9_]{0,63}$/),
  hypothesisExpectation: invariantHypothesisExpectationSchema, counterexample: executableInvariantCounterexampleSchema, counterexampleHash: sha256,
}).strict().superRefine((plan, context) => {
  if (counterexampleHash(plan.counterexample) !== plan.counterexampleHash) context.addIssue({ code: z.ZodIssueCode.custom, message: "Counterexample hash is invalid." });
});
export type InvariantReplayPlan = z.infer<typeof invariantReplayPlanSchema>;

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => [key, canonical(item)]));
  return value;
}
export function canonicalInvariantCounterexample(value: unknown): string { return JSON.stringify(canonical(executableInvariantCounterexampleSchema.parse(value))); }
export function counterexampleHash(value: unknown): string { return createHash("sha256").update(canonicalInvariantCounterexample(value)).digest("hex"); }
export function canonicalInvariantReplayPlan(value: unknown): string { return JSON.stringify(canonical(invariantReplayPlanSchema.parse(value))); }
export function invariantReplayPlanHash(value: unknown): string { return createHash("sha256").update(canonicalInvariantReplayPlan(value)).digest("hex"); }

export function validateReplayAgainstInvariant(replay: InvariantReplayPlan, invariant: z.infer<typeof executableInvariantPlanSchema>): void {
  const plan = invariantReplayPlanSchema.parse(replay), original = executableInvariantPlanSchema.parse(invariant);
  if (plan.hypothesisId !== original.hypothesisId || plan.scanId !== original.scanId || plan.resolvedCommit !== original.resolvedCommit || plan.compilerVersion !== original.compilerVersion || plan.invariantPlanHash !== invariantPlanHash(original)) throw new Error("replay_identity_mismatch");
  const properties = original.mode === "fuzz-property" ? [original.property] : original.properties;
  if (!properties.some((property) => property.name === plan.propertyName)) throw new Error("replay_property_mismatch");
  if ((original.mode === "fuzz-property") !== (plan.counterexample.kind === "single")) throw new Error("replay_counterexample_mode_mismatch");
  if (original.mode === "fuzz-property") {
    const expected = original.fuzzAction.parameters;
    if (plan.counterexample.kind !== "single" || JSON.stringify(plan.counterexample.parameterValues.map(({ name, type }) => ({ name, type }))) !== JSON.stringify(expected)) throw new Error("replay_counterexample_parameters_mismatch");
  } else if (plan.counterexample.kind === "sequence") {
    for (const step of plan.counterexample.actions) {
      const action = original.handlerActions.find((item) => item.name === step.actionName);
      if (!action || JSON.stringify(step.parameterValues.map(({ name, type }) => ({ name, type }))) !== JSON.stringify(action.parameters)) throw new Error("replay_counterexample_action_mismatch");
    }
  }
}

const replaySourceEntry = z.object({ originalPath: z.string().min(5).max(500), workspacePath: z.string().min(9).max(504), byteLength: z.number().int().nonnegative().max(10_485_760), sha256 }).strict();
export const invariantReplayManifestSchema = z.object({
  formatVersion: z.literal(1), planKind: z.literal("invariant-replay"), workspaceId: uuid, replayPlan: invariantReplayPlanSchema,
  replayPlanHash: sha256, invariantPlan: executableInvariantPlanSchema, hypothesisId: uuid, scanId: uuid, resolvedCommit: z.string().regex(/^[a-f0-9]{40}$/), compilerVersion: stableCompilerVersionSchema,
  sourceManifest: z.array(replaySourceEntry).min(1).max(200), generatedHarnessPath: z.literal("test/ContractHunterReplay.t.sol"), generatedHarnessSha256: sha256, foundryConfigSha256: sha256, generatorVersion: stableCompilerVersionSchema, generatedBy: z.literal("contracthunter"), contentFingerprint: sha256,
}).strict().superRefine((manifest, context) => {
  const issue = (message: string) => context.addIssue({ code: z.ZodIssueCode.custom, message });
  if (manifest.replayPlanHash !== invariantReplayPlanHash(manifest.replayPlan)) issue("Replay plan hash is invalid.");
  if (manifest.hypothesisId !== manifest.replayPlan.hypothesisId || manifest.scanId !== manifest.replayPlan.scanId || manifest.resolvedCommit !== manifest.replayPlan.resolvedCommit || manifest.compilerVersion !== manifest.replayPlan.compilerVersion) issue("Replay manifest identity mismatch.");
  try { validateReplayAgainstInvariant(manifest.replayPlan, manifest.invariantPlan); } catch { issue("Replay does not match invariant plan."); }
  const { contentFingerprint, ...base } = manifest;
  if (createHash("sha256").update(JSON.stringify(canonical(base))).digest("hex") !== contentFingerprint) issue("Replay manifest fingerprint is invalid.");
});
export type InvariantReplayManifest = z.infer<typeof invariantReplayManifestSchema>;
export function invariantReplayManifestFingerprint(value: object): string { return createHash("sha256").update(JSON.stringify(canonical(value))).digest("hex"); }
