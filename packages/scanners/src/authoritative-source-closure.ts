import { createHash } from "node:crypto";
import { TextDecoder } from "node:util";
import { AUTHORITATIVE_SOURCE_CLOSURE_SCHEMA, SCAN_SOURCE_LIMITS, compilationManifestSchema,
  type CompilationManifest, type ResolvedAuthoritativeSourceClosure } from "@contracthunter/core";
import { resolveVerificationImport, verificationImportPaths } from "./verification-workspace-builder";

export type AuthoritativeClosureFailure = "unsupported_profile" | "target_unmappable" | "source_missing" | "source_integrity_failed" | "invalid_utf8" | "unsupported_import" | "closure_limit";
export class AuthoritativeClosureError extends Error {
  constructor(readonly code: AuthoritativeClosureFailure) { super(code); this.name = "AuthoritativeClosureError"; }
}

/** Pure graph resolver: callers supply only immutable snapshot rows, never a checkout path. */
export function resolveAuthoritativeSourceClosure(input: {
  manifest: CompilationManifest; targetSourceUnit: string;
  source: (snapshotSourceKey: string) => { rawBytes: Buffer; rawSha256: string; byteLength: number } | null;
}): ResolvedAuthoritativeSourceClosure {
  const parsed = compilationManifestSchema.safeParse(input.manifest);
  if (!parsed.success || parsed.data.compilationProfileKind !== "plain-solidity-exact-pragma-v1" || parsed.data.remappings.length || parsed.data.libraryRoots.length) throw new AuthoritativeClosureError("unsupported_profile");
  const manifest = parsed.data, units = new Map(manifest.sourceUnits.map((unit) => [unit.sourceUnitName, unit]));
  if (!units.has(input.targetSourceUnit)) throw new AuthoritativeClosureError("target_unmappable");
  const pending: Array<{ name: string; depth: number }> = [{ name: input.targetSourceUnit, depth: 0 }], visited = new Map<string, ResolvedAuthoritativeSourceClosure["files"][number]>();
  let totalBytes = 0, operations = 0, importsSeen = 0;
  while (pending.length) {
    if (++operations > SCAN_SOURCE_LIMITS.visitedEntries) throw new AuthoritativeClosureError("closure_limit");
    pending.sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
    const { name, depth } = pending.shift()!;
    if (visited.has(name)) continue;
    if (depth > 64 || visited.size >= SCAN_SOURCE_LIMITS.files) throw new AuthoritativeClosureError("closure_limit");
    const unit = units.get(name);
    if (!unit) throw new AuthoritativeClosureError("source_missing");
    const source = input.source(unit.snapshotSourceKey);
    if (!source) throw new AuthoritativeClosureError("source_missing");
    if (!Buffer.isBuffer(source.rawBytes) || source.byteLength !== unit.byteLength || source.rawSha256 !== unit.rawSha256 || source.rawBytes.length !== unit.byteLength || createHash("sha256").update(source.rawBytes).digest("hex") !== unit.rawSha256) throw new AuthoritativeClosureError("source_integrity_failed");
    totalBytes += source.byteLength;
    if (source.byteLength > SCAN_SOURCE_LIMITS.fileBytes || totalBytes > SCAN_SOURCE_LIMITS.totalBytes) throw new AuthoritativeClosureError("closure_limit");
    let text: string;
    try { text = new TextDecoder("utf-8", { fatal: true }).decode(source.rawBytes); }
    catch { throw new AuthoritativeClosureError("invalid_utf8"); }
    let imports: string[];
    try { imports = verificationImportPaths(text); }
    catch { throw new AuthoritativeClosureError("unsupported_import"); }
    if ((importsSeen += imports.length) > 1_000 || imports.length > 100) throw new AuthoritativeClosureError("closure_limit");
    visited.set(name, { sourceUnitName: name, snapshotSourceKey: unit.snapshotSourceKey, rawBytes: Buffer.from(source.rawBytes), rawSha256: unit.rawSha256, byteLength: unit.byteLength });
    for (const imported of imports) {
      let resolved: string;
      try { resolved = resolveVerificationImport(name, imported, ["src", "contracts"]); }
      catch { throw new AuthoritativeClosureError("unsupported_import"); }
      if (!units.has(resolved)) throw new AuthoritativeClosureError("unsupported_import");
      if (!visited.has(resolved)) pending.push({ name: resolved, depth: depth + 1 });
    }
  }
  return { schema: AUTHORITATIVE_SOURCE_CLOSURE_SCHEMA, scanId: manifest.scanId, resolvedCommit: manifest.resolvedCommit,
    compilationProfile: manifest.compilationProfileKind, compilerIdentity: manifest.compiler, targetSourceUnit: input.targetSourceUnit,
    files: [...visited.values()].sort((a, b) => a.sourceUnitName < b.sourceUnitName ? -1 : a.sourceUnitName > b.sourceUnitName ? 1 : 0) };
}
