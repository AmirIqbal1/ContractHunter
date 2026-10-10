import { z } from "zod";
import { SCAN_SOURCE_LIMITS, scanSourceFileMetadataSchema } from "./scan-source-snapshot";

export const COMPILATION_MANIFEST_SCHEMA = "contracthunter-compilation-manifest-v1" as const;
export const compilationUnsupportedReasons = [
  "dynamic_build_configuration", "unsupported_remapping_behavior", "unsupported_source_layout",
  "ambiguous_compiler", "trusted_compiler_unavailable", "compilation_probe_failed", "source_snapshot_unavailable",
] as const;
export type CompilationUnsupportedReason = typeof compilationUnsupportedReasons[number];

export const compilationSourceUnitSchema = z.object({
  sourceUnitName: scanSourceFileMetadataSchema.shape.sourceKey,
  snapshotSourceKey: scanSourceFileMetadataSchema.shape.sourceKey,
  rawSha256: scanSourceFileMetadataSchema.shape.rawSha256,
  byteLength: scanSourceFileMetadataSchema.shape.byteLength,
  contractNames: z.array(z.string().regex(/^[A-Za-z_$][A-Za-z0-9_$]*$/)).max(100),
}).strict();

export const compilationManifestSchema = z.object({
  schema: z.literal(COMPILATION_MANIFEST_SCHEMA),
  scanId: z.string().uuid(),
  resolvedCommit: z.string().regex(/^[a-f0-9]{40}$/),
  compilationProfileKind: z.literal("plain-solidity-exact-pragma-v1"),
  compiler: z.object({ version: z.string().regex(/^\d+\.\d+\.\d+$/), artifactSha256: z.string().regex(/^[a-f0-9]{64}$/) }).strict(),
  sourceRoots: z.array(z.enum(["src", "contracts"])).min(1).max(2),
  libraryRoots: z.array(z.string()).length(0),
  remappings: z.array(z.string()).length(0),
  sourceUnits: z.array(compilationSourceUnitSchema).min(1).max(SCAN_SOURCE_LIMITS.files),
}).strict().superRefine((manifest, ctx) => {
  const names = new Set<string>(), keys = new Set<string>();
  for (const unit of manifest.sourceUnits) {
    if (names.has(unit.sourceUnitName) || keys.has(unit.snapshotSourceKey) || unit.sourceUnitName !== unit.snapshotSourceKey || !manifest.sourceRoots.some((root) => unit.sourceUnitName.startsWith(`${root}/`))) {
      ctx.addIssue({ code: "custom", message: "Source-unit identity is duplicated, ambiguous, or outside the profile." });
    }
    names.add(unit.sourceUnitName); keys.add(unit.snapshotSourceKey);
  }
});
export type CompilationManifest = z.infer<typeof compilationManifestSchema>;

export type ScannerSourceAlignment = {
  findingId: string; scannerId: string; scannerVersion: string | null; detectorId: string | null;
  reportedSourceIdentity: string | null; status: "aligned" | "unaligned" | "unknown";
  sourceUnitName: string | null; snapshotSourceKey: string | null; targetResolved: boolean;
};
