import { createHash } from "node:crypto";
import { z } from "zod";
import { protocolRepositoryPathSchema, repositoryClassificationSchema, repositoryClasses } from "./protocol-graph";

export const REPOSITORY_MAP_SCHEMA = "contracthunter-repository-map-v1" as const;
export const REPOSITORY_MAPPER_RULESET = "contracthunter-repository-mapper-v1" as const;
export const REPOSITORY_MAP_LIMITS = {
  entries: 20_000, files: 10_000, solidityFiles: 5_000, roots: 128,
  declarationsPerFile: 128, importsPerFile: 256, reasons: 8, warnings: 256,
  sourceBytes: 2_097_152, metadataBytes: 8_388_608,
} as const;
const hash = z.string().regex(/^[a-f0-9]{64}$/);
const path = protocolRepositoryPathSchema;
const reason = z.string().min(1).max(128).regex(/^[a-z][a-z0-9-]*$/);
const id = z.string().regex(/^rm:[a-f0-9]{64}$/);
const fileId = z.string().regex(/^rf:[a-f0-9]{64}$/);
const declarationId = z.string().regex(/^rd:[a-f0-9]{64}$/);
const source = z.object({ authority: z.enum(["snapshot", "reported", "path-only"]),
  rawSha256: hash.nullable(), byteLength: z.number().int().nonnegative().nullable() }).strict();
const location = z.object({ line: z.number().int().positive(), column: z.number().int().positive() }).strict();
const declaration = z.object({ id: declarationId, name: z.string().regex(/^[A-Za-z_$][A-Za-z0-9_$]{0,199}$/),
  kind: z.enum(["contract", "abstract-contract", "interface", "library"]),
  location, extraction: z.literal("solidity-lexical"),
  inheritance: z.array(z.string().regex(/^[A-Za-z_$][A-Za-z0-9_$.]{0,199}$/)).max(32),
  externalEntryPoint: z.boolean(),
}).strict();
const importRecord = z.object({ imported: z.string().min(1).max(500), resolvedSourceUnit: path.nullable(),
  status: z.enum(["resolved", "unresolved", "unsupported", "ambiguous"]) }).strict();
const root = z.object({ path, kind: z.enum(["project", "dependency"]),
  authority: z.enum(["snapshot", "reported"]), reasons: z.array(reason).min(1).max(REPOSITORY_MAP_LIMITS.reasons) }).strict();
const file = z.object({ id: fileId, path, kind: z.enum(["solidity", "non-solidity"]),
  sourceRoot: path.nullable(), classification: repositoryClassificationSchema,
  source, parseStatus: z.enum(["complete", "incomplete", "not-applicable"]),
  declarations: z.array(declaration).max(REPOSITORY_MAP_LIMITS.declarationsPerFile),
  imports: z.array(importRecord).max(REPOSITORY_MAP_LIMITS.importsPerFile),
  findingRefs: z.array(z.string().uuid()).max(256), targetRefs: z.array(z.string().max(128)).max(32),
}).strict();
export const repositoryMapSchema = z.object({ schema: z.literal(REPOSITORY_MAP_SCHEMA), id,
  scanId: z.string().uuid(), resolvedCommit: z.string().regex(/^[a-f0-9]{40}$/),
  ruleset: z.literal(REPOSITORY_MAPPER_RULESET), sourceUniverseHash: hash,
  roots: z.array(root).max(REPOSITORY_MAP_LIMITS.roots), files: z.array(file).max(REPOSITORY_MAP_LIMITS.files),
  summary: z.object({ solidityFiles: z.number().int().nonnegative(), contracts: z.number().int().nonnegative(),
    classes: z.record(z.enum(repositoryClasses), z.number().int().nonnegative()),
    directories: z.array(z.object({ path, fileCount: z.number().int().positive(), solidityFileCount: z.number().int().nonnegative() }).strict()).max(REPOSITORY_MAP_LIMITS.files),
  }).strict(), warnings: z.array(z.object({ code: reason, path: path.nullable() }).strict()).max(REPOSITORY_MAP_LIMITS.warnings),
}).strict();
export type RepositoryMap = z.infer<typeof repositoryMapSchema>;
export type RepositoryMapFile = RepositoryMap["files"][number];
export type RepositoryMapRoot = RepositoryMap["roots"][number];
export interface RepositoryMapToProtocolGraph { readonly repositoryMap: RepositoryMap; readonly scanId: string; readonly resolvedCommit: string; }

function framed(domain: string, parts: readonly unknown[]): string {
  return createHash("sha256").update(domain).update("\0").update(JSON.stringify(parts)).digest("hex");
}
export function repositoryMapId(scanId: string, resolvedCommit: string, sourceUniverseHash: string): string {
  return `rm:${framed(REPOSITORY_MAP_SCHEMA, [scanId, resolvedCommit, REPOSITORY_MAPPER_RULESET, sourceUniverseHash])}`;
}
export function repositorySourceUniverseHash(files: readonly Pick<RepositoryMapFile, "path" | "kind" | "source">[]): string {
  const ordered = [...files].sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  return createHash("sha256").update(JSON.stringify(ordered.map((file) => [file.path, file.kind,
    file.source.authority, file.source.rawSha256, file.source.byteLength]))).digest("hex");
}
export function repositoryFileId(scanId: string, canonicalPath: string): string {
  path.parse(canonicalPath);
  return `rf:${framed("contracthunter-repository-file-v1", [scanId, canonicalPath])}`;
}
export function repositoryDeclarationId(fileIdentity: string, kind: string, name: string, line: number, column: number): string {
  return `rd:${framed("contracthunter-repository-declaration-v1", [fileIdentity, kind, name, line, column])}`;
}
export function effectiveRepositoryClassification(value: z.infer<typeof repositoryClassificationSchema>): typeof repositoryClasses[number] {
  return value.override?.value ?? value.automatic;
}
export function withRepositoryClassificationOverride(value: z.infer<typeof repositoryClassificationSchema>,
  override: { value: typeof repositoryClasses[number]; reason: string } | null): z.infer<typeof repositoryClassificationSchema> {
  return repositoryClassificationSchema.parse({ ...value, override, effective: override?.value ?? value.automatic });
}

/** Validation is linear in the number of roots, files, declarations and imports. */
export function validateRepositoryMap(input: unknown): RepositoryMap {
  if (input && typeof input === "object") {
    const raw = input as Record<string, unknown>;
    for (const [key, limit] of [["roots", REPOSITORY_MAP_LIMITS.roots], ["files", REPOSITORY_MAP_LIMITS.files],
      ["warnings", REPOSITORY_MAP_LIMITS.warnings]] as const)
      if (Array.isArray(raw[key]) && raw[key].length > limit) throw Error("repository_map_bounds_exceeded");
  }
  const map = repositoryMapSchema.parse(input);
  if (map.sourceUniverseHash !== repositorySourceUniverseHash(map.files)) throw Error("repository_map_source_universe_invalid");
  if (map.id !== repositoryMapId(map.scanId, map.resolvedCommit, map.sourceUniverseHash)) throw Error("repository_map_identity_invalid");
  const roots = new Set<string>(), files = new Set<string>(), ids = new Set<string>();
  let solidity = 0, contracts = 0;
  const counts = Object.fromEntries(repositoryClasses.map((kind) => [kind, 0])) as Record<typeof repositoryClasses[number], number>;
  const directoryCounts = new Map<string, { fileCount: number; solidityFileCount: number }>();
  for (const item of map.roots) {
    if (roots.has(item.path)) throw Error("repository_map_duplicate_root");
    roots.add(item.path);
  }
  for (const item of map.files) {
    if (files.has(item.path) || ids.has(item.id) || item.id !== repositoryFileId(map.scanId, item.path)) throw Error("repository_map_duplicate_or_invalid_file");
    files.add(item.path); ids.add(item.id);
    const slash = item.path.lastIndexOf("/");
    const directory = slash < 0 ? "" : item.path.slice(0, slash);
    if (directory) {
      const count = directoryCounts.get(directory) ?? { fileCount: 0, solidityFileCount: 0 };
      count.fileCount++;
      if (item.kind === "solidity") count.solidityFileCount++;
      directoryCounts.set(directory, count);
    }
    if (item.sourceRoot && (!roots.has(item.sourceRoot) || !(item.path.startsWith(`${item.sourceRoot}/`)))) throw Error("repository_map_root_invalid");
    if (item.source.authority === "snapshot" && (item.kind !== "solidity" || !item.source.rawSha256 || item.source.byteLength === null)) throw Error("repository_map_snapshot_invalid");
    if (item.source.authority === "path-only" && (item.source.rawSha256 || item.source.byteLength !== null)) throw Error("repository_map_source_invalid");
    if (item.kind === "non-solidity" && (item.declarations.length || item.imports.length || item.parseStatus !== "not-applicable")) throw Error("repository_map_non_solidity_invalid");
    if (item.kind === "solidity") {
      if (item.parseStatus === "not-applicable") throw Error("repository_map_solidity_parse_status_invalid");
      solidity++;
      const declarations = new Set<string>();
      for (const decl of item.declarations) {
        if (declarations.has(decl.id) || decl.id !== repositoryDeclarationId(item.id, decl.kind, decl.name, decl.location.line, decl.location.column)) throw Error("repository_map_declaration_invalid");
        declarations.add(decl.id);
        if (decl.kind === "contract" || decl.kind === "abstract-contract") contracts++;
      }
      if (item.parseStatus === "incomplete" && item.declarations.length) throw Error("repository_map_incomplete_declarations");
    }
    counts[item.classification.effective]++;
  }
  if (solidity > REPOSITORY_MAP_LIMITS.solidityFiles || map.summary.solidityFiles !== solidity || map.summary.contracts !== contracts ||
    repositoryClasses.some((kind) => (map.summary.classes[kind] ?? 0) !== counts[kind])) throw Error("repository_map_summary_invalid");
  const reportedDirectories = new Map(map.summary.directories.map((item) => [item.path, item]));
  if (reportedDirectories.size !== directoryCounts.size || map.summary.directories.length !== directoryCounts.size ||
    [...directoryCounts].some(([directory, count]) => {
      const reported = reportedDirectories.get(directory);
      return !reported || reported.fileCount !== count.fileCount || reported.solidityFileCount !== count.solidityFileCount;
    })) throw Error("repository_map_directory_summary_invalid");
  for (const item of map.files) for (const imported of item.imports)
    if (imported.status === "resolved" ? !imported.resolvedSourceUnit || !files.has(imported.resolvedSourceUnit) : imported.resolvedSourceUnit !== null) throw Error("repository_map_import_invalid");
  return map;
}
