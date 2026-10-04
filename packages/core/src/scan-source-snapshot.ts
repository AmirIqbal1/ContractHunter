import { z } from "zod";
import { repositorySolidityPathSchema } from "./hypothesis-verification";

export const SCAN_SOURCE_SNAPSHOT_SCHEMA = "contracthunter-scan-source-snapshot-v1" as const;
export const SCAN_SOURCE_ROOTS = ["src", "contracts", "lib", "node_modules"] as const;
export const SCAN_SOURCE_LIMITS = { files: 100, fileBytes: 2_097_152, totalBytes: 5_242_880, sourceKeyLength: 500, visitedEntries: 20_000 } as const;
export const scanSourceFileMetadataSchema = z.object({
  sourceKey: repositorySolidityPathSchema,
  rawSha256: z.string().regex(/^[a-f0-9]{64}$/),
  byteLength: z.number().int().min(0).max(SCAN_SOURCE_LIMITS.fileBytes),
}).strict();
export type ScanSourceFileMetadata = z.infer<typeof scanSourceFileMetadataSchema>;
export type ScanSourceCaptureFile = ScanSourceFileMetadata & { rawBytes: Buffer };
