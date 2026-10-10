import type { CompilationManifest } from "./compilation-provenance";

export const AUTHORITATIVE_SOURCE_CLOSURE_SCHEMA = "contracthunter-authoritative-source-closure-v1" as const;
export type AuthoritativeSourceClosureFile = {
  sourceUnitName: string; snapshotSourceKey: string; rawBytes: Buffer; rawSha256: string; byteLength: number;
};
export type ResolvedAuthoritativeSourceClosure = {
  schema: typeof AUTHORITATIVE_SOURCE_CLOSURE_SCHEMA;
  scanId: string; resolvedCommit: string; compilationProfile: "plain-solidity-exact-pragma-v1";
  compilerIdentity: CompilationManifest["compiler"];
  targetSourceUnit: string;
  files: AuthoritativeSourceClosureFile[];
};
