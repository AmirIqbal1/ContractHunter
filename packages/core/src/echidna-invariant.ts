import { z } from "zod";
import { EXECUTABLE_INVARIANT_SCHEMA_VERSION, executableInvariantPlanSchema, invariantManifestFingerprint, invariantPlanHash } from "./executable-invariant";
import { repositorySolidityPathSchema, stableCompilerVersionSchema } from "./hypothesis-verification";

export const ECHIDNA_UPSTREAM_VERSION = "2.3.3" as const;
export const ECHIDNA_COMPAT_VERSION = "2.3.3+contracthunter.1" as const;
export const ECHIDNA_BUILD_ID = "contracthunter-echidna-compat-v1" as const;
export const ECHIDNA_BINARY_SHA256 = "b6f84d8d48fcffe4d48b9be0378e65f37a36c304c3325d72aa868fcfac204ff1" as const;
export const ECHIDNA_RESULT_SCHEMA = "contracthunter-echidna-result-v1" as const;
export const ECHIDNA_MANIFEST_FILE = ".contracthunter-echidna.json" as const;
export const ECHIDNA_HARNESS_FILE = "ContractHunterEchidna.sol" as const;
export const ECHIDNA_CONFIG_FILE = "echidna.yaml" as const;
export const ECHIDNA_LIMITS = { testLimit: 128, seqLen: 32, shrinkLimit: 128, workers: 1, timeoutSeconds: 150, wallClockTimeoutMs: 180_000, maxOutputBytes: 2_097_152, maxVirtualMemoryBytes: 2_147_483_648, maxProcesses: 64, maxOpenFiles: 256, maxFileSizeBytes: 67_108_864 } as const;
const sha = z.string().regex(/^[a-f0-9]{64}$/);
const uuid = z.string().uuid();
const settings = z.object({
  testMode: z.literal("property"), testLimit: z.literal(ECHIDNA_LIMITS.testLimit), seqLen: z.literal(ECHIDNA_LIMITS.seqLen), shrinkLimit: z.literal(ECHIDNA_LIMITS.shrinkLimit), workers: z.literal(1), timeout: z.literal(ECHIDNA_LIMITS.timeoutSeconds), format: z.literal("json"), seed: z.number().int().min(0).max(281_474_976_710_655),
}).strict();
export type EchidnaSettings = z.infer<typeof settings>;
export function echidnaSeed(planHash: string): number {
  if (!/^[a-f0-9]{64}$/.test(planHash)) throw new Error("invalid_echidna_seed_source");
  return Number.parseInt(planHash.slice(0, 12), 16);
}
export const echidnaInvariantManifestSchema = z.object({
  formatVersion: z.literal(3), engine: z.literal("echidna"), planKind: z.literal("executable-invariant"), workspaceId: uuid,
  schemaVersion: z.literal(EXECUTABLE_INVARIANT_SCHEMA_VERSION), plan: executableInvariantPlanSchema, planHash: sha,
  hypothesisId: uuid, scanId: uuid, resolvedCommit: z.string().regex(/^[a-f0-9]{40}$/), compilerVersion: stableCompilerVersionSchema,
  generatorVersion: stableCompilerVersionSchema, generatedBy: z.literal("contracthunter"),
  sourceManifest: z.array(z.object({ originalPath: repositorySolidityPathSchema, workspacePath: z.string().regex(/^src\/[A-Za-z0-9_@+./-]+\.sol$/), byteLength: z.number().int().nonnegative().max(10_485_760), sha256: sha }).strict().refine((entry) => entry.workspacePath === `src/${entry.originalPath}`)).min(1).max(200),
  harnessPath: z.literal(ECHIDNA_HARNESS_FILE), harnessHash: sha, configPath: z.literal(ECHIDNA_CONFIG_FILE), configHash: sha,
  echidnaVersion: z.literal(ECHIDNA_UPSTREAM_VERSION), compatibilityVersion: z.literal(ECHIDNA_COMPAT_VERSION), buildId: z.literal(ECHIDNA_BUILD_ID), binaryHash: z.literal(ECHIDNA_BINARY_SHA256),
  settings, executionLimits: z.object({ wallClockTimeoutMs: z.literal(ECHIDNA_LIMITS.wallClockTimeoutMs), maxOutputBytes: z.literal(ECHIDNA_LIMITS.maxOutputBytes), maxVirtualMemoryBytes: z.literal(ECHIDNA_LIMITS.maxVirtualMemoryBytes), maxProcesses: z.literal(64), maxOpenFiles: z.literal(256), maxFileSizeBytes: z.literal(ECHIDNA_LIMITS.maxFileSizeBytes) }).strict(),
  contentFingerprint: sha,
}).strict().superRefine((manifest, ctx) => {
  const fail = (message: string) => ctx.addIssue({ code: z.ZodIssueCode.custom, message });
  if (manifest.plan.mode !== "stateful-invariant") fail("Echidna manifest requires a stateful invariant plan.");
  if (manifest.planHash !== invariantPlanHash(manifest.plan)) fail("Echidna plan hash differs from canonical plan.");
  if (manifest.schemaVersion !== manifest.plan.schemaVersion || manifest.hypothesisId !== manifest.plan.hypothesisId || manifest.scanId !== manifest.plan.scanId || manifest.resolvedCommit !== manifest.plan.resolvedCommit || manifest.compilerVersion !== manifest.plan.compilerVersion) fail("Echidna manifest identity differs from plan.");
  if (manifest.settings.seed !== echidnaSeed(manifest.planHash)) fail("Echidna seed differs from plan hash.");
  if (new Set(manifest.sourceManifest.map((entry) => entry.originalPath)).size !== manifest.sourceManifest.length) fail("Duplicate Echidna source paths.");
  const { contentFingerprint, ...base } = manifest;
  if (contentFingerprint !== invariantManifestFingerprint(base)) fail("Echidna manifest fingerprint differs.");
});
export type EchidnaInvariantManifest = z.infer<typeof echidnaInvariantManifestSchema>;
