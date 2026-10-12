import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, readdir, realpath } from "node:fs/promises";
import nodePath from "node:path";
import { REPOSITORY_MAP_LIMITS, REPOSITORY_MAP_SCHEMA, REPOSITORY_MAPPER_RULESET,
  protocolRepositoryPathSchema, repositoryClasses, repositoryDeclarationId, repositoryFileId,
  repositoryMapId, repositorySourceUniverseHash, validateRepositoryMap, type RepositoryMap, type RepositoryMapFile,
  type RepositoryMapRoot } from "@contracthunter/core";

export interface RepositoryMapperInput {
  scanId: string; resolvedCommit: string; repositoryPath: string;
  /** Persisted immutable scan snapshot bytes take precedence over checkout bytes. */
  snapshotFiles?: readonly { sourceKey: string; rawBytes: Buffer; rawSha256: string; byteLength: number }[];
  findingRefs?: readonly { id: string; sourceUnitName: string }[];
  targetRefs?: readonly { id: string; sourceUnitName: string }[];
}
export class RepositoryMapperError extends Error {}
const excluded = new Set([".git", ".next", "out", "artifacts", "cache", "build", "dist", "coverage", "broadcast"]);
const secretName = /^(?:\.env(?:\..*)?|.*(?:private[-_.]?key|keystore|credentials?)(?:\..*)?|.*\.(?:pem|key|p12|pfx|jks))$/i;
const isSafe = (value: string) => protocolRepositoryPathSchema.safeParse(value).success;
const sort = (a: string, b: string) => a < b ? -1 : a > b ? 1 : 0;
const sha = (bytes: Buffer | string) => createHash("sha256").update(bytes).digest("hex");
const segment = (value: string) => value.split("/");

function rootFor(filePath: string): { path: string; kind: "project" | "dependency"; reason: string } | null {
  const parts = segment(filePath), parent = parts.slice(0, -1);
  if (parent.length === 0) return null;
  if (["node_modules", "vendor"].includes(parts[0])) return { path: parts[0], kind: "dependency", reason: "dependency-root" };
  if (parts[0] === "lib" && parts.length >= 4 && parts[2] === "src") return { path: parts.slice(0, 3).join("/"), kind: "dependency", reason: "vendored-source-root" };
  if (parts[0] === "packages" && parts.length >= 4 && ["src", "contracts", "protocol"].includes(parts[2]))
    return { path: parts.slice(0, 3).join("/"), kind: "project", reason: "package-source-root" };
  if (["src", "contracts", "protocol", "test", "tests", "mocks", "mock", "script", "scripts", "deploy", "deployments", "lib"].includes(parts[0]))
    return { path: parts[0], kind: "project", reason: "conventional-source-root" };
  return null;
}

/** Mask comments and string literals without changing offsets or line breaks. */
function mask(source: string): { text: string; complete: boolean } {
  let out = "", state: "code" | "line" | "block" | "single" | "double" = "code", escaped = false;
  for (let i = 0; i < source.length; i++) {
    const ch = source[i], next = source[i + 1];
    if (state === "code") {
      if (ch === "/" && next === "/") { out += "  "; i++; state = "line"; continue; }
      if (ch === "/" && next === "*") { out += "  "; i++; state = "block"; continue; }
      if (ch === "'" || ch === '"') { out += " "; state = ch === "'" ? "single" : "double"; continue; }
      out += ch; continue;
    }
    if (state === "line") { out += ch === "\n" ? "\n" : " "; if (ch === "\n") state = "code"; continue; }
    if (state === "block") {
      if (ch === "*" && next === "/") { out += "  "; i++; state = "code"; }
      else out += ch === "\n" ? "\n" : " ";
      continue;
    }
    if (escaped) { out += ch === "\n" ? "\n" : " "; escaped = false; continue; }
    if (ch === "\\") { out += " "; escaped = true; continue; }
    if ((state === "single" && ch === "'") || (state === "double" && ch === '"')) { out += " "; state = "code"; continue; }
    out += ch === "\n" ? "\n" : " ";
  }
  return { text: out, complete: state === "code" || state === "line" };
}

function parseSolidity(bytes: Buffer, fileIdentity: string): Pick<RepositoryMapFile, "parseStatus" | "declarations" | "imports"> {
  const source = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  const masked = mask(source), depth = new Int32Array(masked.text.length + 1);
  let current = 0, malformed = !masked.complete;
  for (let i = 0; i < masked.text.length; i++) {
    depth[i] = current;
    if (masked.text[i] === "{") current++;
    if (masked.text[i] === "}") { current--; if (current < 0) malformed = true; }
  }
  if (current !== 0 || malformed) return { parseStatus: "incomplete", declarations: [], imports: [] };
  const declarations: RepositoryMapFile["declarations"] = [];
  const pattern = /\b(abstract\s+contract|contract|interface|library)\s+([A-Za-z_$][A-Za-z0-9_$]*)\b/g;
  for (const match of masked.text.matchAll(pattern)) {
    if (depth[match.index] !== 0) continue;
    if (declarations.length >= REPOSITORY_MAP_LIMITS.declarationsPerFile) throw new RepositoryMapperError("Repository declaration limit exceeded.");
    const kind = match[1] === "abstract contract" ? "abstract-contract" : match[1] as "contract" | "interface" | "library";
    const headEnd = masked.text.indexOf("{", match.index + match[0].length);
    if (headEnd < 0) return { parseStatus: "incomplete", declarations: [], imports: [] };
    const heading = masked.text.slice(match.index + match[0].length, headEnd);
    if (heading.includes(";")) return { parseStatus: "incomplete", declarations: [], imports: [] };
    const inheritMatch = heading.match(/\bis\s+([^{}]+)/);
    const inheritance = inheritMatch ? inheritMatch[1].split(",").map((v) => v.trim().split(/[\s(]/)[0]).filter(Boolean).slice(0, 32) : [];
    let end = headEnd + 1, nesting = 1;
    while (end < masked.text.length && nesting > 0) { if (masked.text[end] === "{") nesting++; if (masked.text[end] === "}") nesting--; end++; }
    if (nesting !== 0) return { parseStatus: "incomplete", declarations: [], imports: [] };
    const before = masked.text.slice(0, match.index), line = before.split("\n").length, column = match.index - before.lastIndexOf("\n");
    const body = masked.text.slice(headEnd + 1, end - 1);
    declarations.push({ id: repositoryDeclarationId(fileIdentity, kind, match[2], line, column), name: match[2], kind, extraction: "solidity-lexical",
      location: { line, column }, inheritance,
      externalEntryPoint: /\bfunction\s+[A-Za-z_$][A-Za-z0-9_$]*\s*\([^)]*\)[^{;]*\b(?:public|external)\b/.test(body) });
  }
  const imports: RepositoryMapFile["imports"] = [];
  for (const match of masked.text.matchAll(/\bimport\b[^;]*;/g)) {
    if (depth[match.index] !== 0) continue;
    if (imports.length >= REPOSITORY_MAP_LIMITS.importsPerFile) throw new RepositoryMapperError("Repository import limit exceeded.");
    const literal = source.slice(match.index, match.index + match[0].length).match(/(?:from\s*)?["']([^"'\n]+)["']\s*;/);
    if (!literal) return { parseStatus: "incomplete", declarations: [], imports: [] };
    imports.push({ imported: literal[1], resolvedSourceUnit: null, status: "unresolved" });
  }
  if ((masked.text.match(/\bimport\b/g) ?? []).length !== imports.length) return { parseStatus: "incomplete", declarations: [], imports: [] };
  return { parseStatus: "complete", declarations, imports };
}

function classify(filePath: string, kind: RepositoryMapFile["kind"], declarations: RepositoryMapFile["declarations"], root: RepositoryMapRoot | undefined): RepositoryMapFile["classification"] {
  const parts = segment(filePath), leaf = parts.at(-1)!;
  let automatic: typeof repositoryClasses[number] = "unknown", automaticOrigin: "path-pattern" | "solidity-lexical" | "unknown" = "unknown";
  let reasons: string[] = ["insufficient-evidence"];
  const pathClass = (value: typeof repositoryClasses[number], why: string) => { automatic = value; automaticOrigin = "path-pattern"; reasons = [why]; };
  if (root?.kind === "dependency") pathClass("dependency", "dependency-root");
  else if (parts.some((p) => p === "test" || p === "tests") || /\.t\.sol$/.test(leaf)) pathClass("test", "test-path-or-suffix");
  else if (parts.some((p) => p === "mocks" || p === "mock")) pathClass("mock", "mock-directory");
  else if (parts.some((p) => ["script", "scripts", "deploy", "deployments"].includes(p)) || /\.s\.sol$/.test(leaf)) pathClass("deployment", "deployment-path-or-suffix");
  else if (kind === "non-solidity") {
    if (parts.some((p) => ["frontend", "web", "app"].includes(p))) pathClass("frontend", "frontend-directory");
    else pathClass("supporting", "non-solidity-file");
  } else if (declarations.length && declarations.every((d) => d.kind === "interface")) { automatic = "interface"; automaticOrigin = "solidity-lexical"; reasons = ["interface-declaration"]; }
  else if (declarations.length && declarations.every((d) => d.kind === "library")) { automatic = "library"; automaticOrigin = "solidity-lexical"; reasons = ["library-declaration"]; }
  else if (parts.some((p) => p === "interfaces") && declarations.length === 0) pathClass("interface", "interface-directory");
  else if (parts.some((p) => p === "libraries") && declarations.length === 0) pathClass("library", "library-directory");
  else if (parts.some((p) => p === "periphery")) pathClass("periphery", "periphery-directory");
  else if (parts.some((p) => p === "core") && declarations.some((d) => d.kind === "contract" && d.externalEntryPoint)) {
    pathClass("core", "explicit-core-directory"); reasons.push("external-entry-point");
  }
  return { effective: automatic, automatic, automaticOrigin, reasons, override: null };
}

export async function mapRepository(input: RepositoryMapperInput): Promise<RepositoryMap> {
  const rootPath = await realpath(input.repositoryPath);
  if ((await lstat(input.repositoryPath)).isSymbolicLink()) throw new RepositoryMapperError("Repository root is a symbolic link.");
  const paths = new Set<string>(), warnings: RepositoryMap["warnings"] = [];
  const warn = (code: string, path: string | null) => {
    if (warnings.length >= REPOSITORY_MAP_LIMITS.warnings) throw new RepositoryMapperError("Repository warning limit exceeded.");
    warnings.push({ code, path });
  };
  let entries = 0;
  async function walk(directory: string): Promise<void> {
    for (const entry of (await readdir(directory, { withFileTypes: true })).sort((a, b) => sort(a.name, b.name))) {
      if (++entries > REPOSITORY_MAP_LIMITS.entries) throw new RepositoryMapperError("Repository traversal limit exceeded.");
      if (excluded.has(entry.name) || secretName.test(entry.name)) continue;
      const absolute = nodePath.join(directory, entry.name), relative = nodePath.relative(rootPath, absolute).split(nodePath.sep).join("/");
      if (!isSafe(relative)) { warn("unsafe-path-skipped", null); continue; }
      const info = await lstat(absolute);
      if (info.isSymbolicLink()) { warn("symlink-skipped", relative); continue; }
      if (info.isDirectory()) {
        // Dependency packages can contain hundreds of thousands of support files.
        // Snapshot-reached Solidity is added below without traversing that tree.
        if (relative === "node_modules") continue;
        await walk(absolute); continue;
      }
      if (info.isFile()) { if (paths.size >= REPOSITORY_MAP_LIMITS.files) throw new RepositoryMapperError("Repository file limit exceeded."); paths.add(relative); }
    }
  }
  await walk(rootPath);
  if ((input.snapshotFiles?.length ?? 0) > REPOSITORY_MAP_LIMITS.solidityFiles) throw new RepositoryMapperError("Snapshot file limit exceeded.");
  const snapshots = new Map((input.snapshotFiles ?? []).map((f) => [f.sourceKey, f]));
  if (snapshots.size !== (input.snapshotFiles?.length ?? 0)) throw new RepositoryMapperError("Duplicate snapshot source key.");
  for (const [sourceKey, file] of snapshots) {
    if (!isSafe(sourceKey) || !sourceKey.endsWith(".sol") || file.byteLength > REPOSITORY_MAP_LIMITS.sourceBytes ||
      sha(file.rawBytes) !== file.rawSha256 || file.rawBytes.length !== file.byteLength)
      throw new RepositoryMapperError("Snapshot source identity is invalid.");
    paths.add(sourceKey);
  }
  if (paths.size > REPOSITORY_MAP_LIMITS.files) throw new RepositoryMapperError("Repository file limit exceeded.");
  const allPaths = [...paths].sort(sort);
  const rootsByPath = new Map<string, RepositoryMapRoot>();
  for (const filePath of allPaths.filter((p) => p.endsWith(".sol"))) {
    const found = rootFor(filePath); if (!found) continue;
    const previous = rootsByPath.get(found.path);
    rootsByPath.set(found.path, { path: found.path, kind: found.kind,
      authority: previous?.authority === "snapshot" || snapshots.has(filePath) ? "snapshot" : "reported", reasons: [found.reason] });
  }
  const roots = [...rootsByPath.values()].sort((a, b) => sort(a.path, b.path));
  if (roots.length > REPOSITORY_MAP_LIMITS.roots) throw new RepositoryMapperError("Repository source root limit exceeded.");
  const files: RepositoryMapFile[] = [];
  let solidityFileCount = 0;
  const findings = new Map<string, string[]>(), targets = new Map<string, string[]>();
  for (const item of input.findingRefs ?? []) findings.set(item.sourceUnitName, [...(findings.get(item.sourceUnitName) ?? []), item.id]);
  for (const item of input.targetRefs ?? []) targets.set(item.sourceUnitName, [...(targets.get(item.sourceUnitName) ?? []), item.id]);
  for (const filePath of allPaths) {
    const solidity = filePath.endsWith(".sol"), snapshot = snapshots.get(filePath);
    const root = rootsByPath.get(rootFor(filePath)?.path ?? "");
    let parsed: Pick<RepositoryMapFile, "parseStatus" | "declarations" | "imports"> = { parseStatus: "not-applicable", declarations: [], imports: [] };
    let source: RepositoryMapFile["source"] = { authority: "path-only", rawSha256: null, byteLength: null };
    if (solidity) {
      if (++solidityFileCount > REPOSITORY_MAP_LIMITS.solidityFiles) throw new RepositoryMapperError("Repository Solidity file limit exceeded.");
      try {
        let bytes: Buffer;
        if (snapshot) bytes = snapshot.rawBytes;
        else {
          const logical = nodePath.join(rootPath, ...segment(filePath));
          const physical = await realpath(logical);
          if (!physical.startsWith(`${rootPath}${nodePath.sep}`)) throw new Error("source escape");
          const info = await lstat(physical);
          if (!info.isFile() || info.isSymbolicLink() || info.size > REPOSITORY_MAP_LIMITS.sourceBytes) throw new Error("unsafe source");
          const handle = await open(physical, constants.O_RDONLY | constants.O_NOFOLLOW);
          try {
            const before = await handle.stat();
            bytes = await handle.readFile();
            const after = await handle.stat();
            if (!before.isFile() || before.dev !== after.dev || before.ino !== after.ino ||
              before.size !== after.size || before.mtimeMs !== after.mtimeMs || bytes.length !== before.size ||
              (await realpath(logical)) !== physical) throw new Error("source changed during read");
          } finally { await handle.close(); }
          if (bytes.length > REPOSITORY_MAP_LIMITS.sourceBytes) throw new Error("source limit");
        }
        source = { authority: snapshot ? "snapshot" : "reported", rawSha256: sha(bytes), byteLength: bytes.length };
        parsed = parseSolidity(bytes, repositoryFileId(input.scanId, filePath));
      } catch {
        parsed = { parseStatus: "incomplete", declarations: [], imports: [] };
        warn("solidity-parse-incomplete", filePath);
      }
    }
    const fileFindings = [...new Set(findings.get(filePath) ?? [])].sort(sort);
    const fileTargets = [...new Set(targets.get(filePath) ?? [])].sort(sort);
    if (fileFindings.length > 256 || fileTargets.length > 32) throw new RepositoryMapperError("Repository link limit exceeded.");
    files.push({ id: repositoryFileId(input.scanId, filePath), path: filePath,
      kind: solidity ? "solidity" : "non-solidity", sourceRoot: root?.path ?? null,
      classification: classify(filePath, solidity ? "solidity" : "non-solidity", parsed.declarations, root),
      source, ...parsed, findingRefs: fileFindings, targetRefs: fileTargets });
  }
  const filePaths = new Set(allPaths);
  for (const file of files) for (const imported of file.imports) {
    const value = imported.imported;
    if (value.startsWith("/") || value.includes("\\") || value.includes(":") || value.includes("\0")) { imported.status = "unsupported"; continue; }
    const resolved = value.startsWith(".") ? nodePath.posix.normalize(nodePath.posix.join(nodePath.posix.dirname(file.path), value)) : value;
    if (!isSafe(resolved)) { imported.status = "unsupported"; continue; }
    if (resolved.endsWith(".sol") && filePaths.has(resolved)) { imported.status = "resolved"; imported.resolvedSourceUnit = resolved; }
    else imported.status = "unresolved";
  }
  const sourceUniverseHash = repositorySourceUniverseHash(files);
  const classes = Object.fromEntries(repositoryClasses.map((kind) => [kind, 0])) as RepositoryMap["summary"]["classes"];
  const dirs = new Map<string, { fileCount: number; solidityFileCount: number }>();
  for (const file of files) {
    classes[file.classification.effective] = (classes[file.classification.effective] ?? 0) + 1;
    const directory = nodePath.posix.dirname(file.path); if (directory === ".") continue;
    const count = dirs.get(directory) ?? { fileCount: 0, solidityFileCount: 0 };
    count.fileCount++; if (file.kind === "solidity") count.solidityFileCount++; dirs.set(directory, count);
  }
  const map: RepositoryMap = { schema: REPOSITORY_MAP_SCHEMA,
    id: repositoryMapId(input.scanId, input.resolvedCommit, sourceUniverseHash), scanId: input.scanId,
    resolvedCommit: input.resolvedCommit, ruleset: REPOSITORY_MAPPER_RULESET, sourceUniverseHash,
    roots, files, summary: { solidityFiles: solidityFileCount,
      contracts: files.reduce((n, f) => n + f.declarations.filter((d) => d.kind === "contract" || d.kind === "abstract-contract").length, 0),
      classes, directories: [...dirs].sort(([a], [b]) => sort(a, b)).map(([path, counts]) => ({ path, ...counts })) },
    warnings: warnings.sort((a, b) => sort(a.path ?? "", b.path ?? "") || sort(a.code, b.code)) };
  const serialized = Buffer.byteLength(JSON.stringify(map));
  if (serialized > REPOSITORY_MAP_LIMITS.metadataBytes) throw new RepositoryMapperError("Repository map metadata limit exceeded.");
  return validateRepositoryMap(map);
}
