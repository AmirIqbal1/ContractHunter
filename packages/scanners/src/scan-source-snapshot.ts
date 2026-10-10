import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, readdir, realpath } from "node:fs/promises";
import path from "node:path";
import { repositorySolidityPathSchema, SCAN_SOURCE_LIMITS, SCAN_SOURCE_ROOTS, type ScanSourceCaptureFile } from "@contracthunter/core";
import { resolveVerificationImport, verificationImportPaths, VERIFICATION_SOURCE_ROOTS } from "./verification-workspace-builder";

export class ScanSourceSnapshotError extends Error {
  constructor(readonly code: "unsafe_source" | "source_unavailable" | "source_limit" | "unsupported_import", message: string) { super(message); this.name = "ScanSourceSnapshotError"; }
}
const excluded = new Set([".git", "out", "artifacts", "cache", "build", "dist", "coverage", "broadcast", ".next"]);
const secret = /^(?:\.env(?:\..*)?|.*(?:private[-_.]?key|keystore|credentials?)(?:\..*)?|.*\.(?:pem|key|p12|pfx|jks))$/i;

export function canonicalScanSourceKey(value: string): string {
  if (value.length > SCAN_SOURCE_LIMITS.sourceKeyLength || !repositorySolidityPathSchema.safeParse(value).success || path.posix.normalize(value) !== value || value.split("/").some((part) => excluded.has(part) || secret.test(part))) {
    throw new ScanSourceSnapshotError("unsafe_source", "Source key is outside the supported Solidity source universe.");
  }
  if (!VERIFICATION_SOURCE_ROOTS.some((root) => value.startsWith(`${root}/`))) throw new ScanSourceSnapshotError("unsafe_source", "Source key is outside approved source roots.");
  return value;
}

function insidePermittedPhysicalRoot(repository: string, physical: string): boolean {
  if (!physical.startsWith(`${repository}${path.sep}`)) return false;
  const relative = path.relative(repository, physical).split(path.sep).join("/");
  return SCAN_SOURCE_ROOTS.some((sourceRoot) => relative === sourceRoot || relative.startsWith(`${sourceRoot}/`));
}

/** Scan-time capture. Only Solidity under src/contracts/lib is seeded; node_modules entries must be reached by supported imports. */
export async function captureScanSourceSnapshot(repositoryPath: string): Promise<ScanSourceCaptureFile[]> {
  const root = await realpath(repositoryPath).catch(() => { throw new ScanSourceSnapshotError("source_unavailable", "Prepared scan repository is unavailable."); });
  if ((await lstat(repositoryPath)).isSymbolicLink()) throw new ScanSourceSnapshotError("unsafe_source", "Prepared scan repository is a symbolic link.");
  const files = new Map<string, ScanSourceCaptureFile>(), physicalKeys = new Map<string, string>(), inodeKeys = new Map<string, string>();
  let totalBytes = 0, visitedEntries = 0;

  async function add(sourceKey: string): Promise<void> {
    canonicalScanSourceKey(sourceKey);
    if (files.has(sourceKey)) return;
    const logical = path.join(root, ...sourceKey.split("/"));
    const info = await lstat(logical).catch(() => { throw new ScanSourceSnapshotError("source_unavailable", "A required Solidity source is unavailable."); });
    if (!info.isFile() || info.isSymbolicLink()) throw new ScanSourceSnapshotError("unsafe_source", "A Solidity source is not a regular file.");
    const physical = await realpath(logical).catch(() => { throw new ScanSourceSnapshotError("unsafe_source", "A Solidity source path cannot be resolved."); });
    if (!insidePermittedPhysicalRoot(root, physical)) throw new ScanSourceSnapshotError("unsafe_source", "A Solidity source escapes permitted roots.");
    const alias = physicalKeys.get(physical);
    if (alias && alias !== sourceKey) throw new ScanSourceSnapshotError("unsafe_source", "Two source keys resolve to the same source file.");
    if (files.size >= SCAN_SOURCE_LIMITS.files || info.size > SCAN_SOURCE_LIMITS.fileBytes || totalBytes + info.size > SCAN_SOURCE_LIMITS.totalBytes) throw new ScanSourceSnapshotError("source_limit", "Scan source snapshot exceeds its safety limits.");
    const handle = await open(physical, constants.O_RDONLY | constants.O_NOFOLLOW).catch(() => { throw new ScanSourceSnapshotError("unsafe_source", "A Solidity source could not be opened safely."); });
    let bytes: Buffer;
    try {
      const before = await handle.stat();
      if (!before.isFile() || before.size > SCAN_SOURCE_LIMITS.fileBytes) throw new ScanSourceSnapshotError("source_limit", "A Solidity source exceeds its byte limit.");
      bytes = await handle.readFile();
      const after = await handle.stat();
      if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs || bytes.length !== before.size) throw new ScanSourceSnapshotError("unsafe_source", "A Solidity source changed during capture.");
      const inodeKey = `${before.dev}:${before.ino}`, inodeAlias = inodeKeys.get(inodeKey);
      if (inodeAlias && inodeAlias !== sourceKey) throw new ScanSourceSnapshotError("unsafe_source", "Two source keys refer to the same source bytes on disk.");
      inodeKeys.set(inodeKey, sourceKey);
    } finally { await handle.close(); }
    totalBytes += bytes.length;
    if (totalBytes > SCAN_SOURCE_LIMITS.totalBytes) throw new ScanSourceSnapshotError("source_limit", "Scan source snapshot exceeds its total byte limit.");
    physicalKeys.set(physical, sourceKey);
    files.set(sourceKey, { sourceKey, rawBytes: bytes, rawSha256: createHash("sha256").update(bytes).digest("hex"), byteLength: bytes.length });
  }

  async function walk(logicalDirectory: string, ancestors: ReadonlySet<string>): Promise<void> {
    const physical = await realpath(logicalDirectory).catch(() => { throw new ScanSourceSnapshotError("unsafe_source", "A source directory cannot be resolved."); });
    if (!insidePermittedPhysicalRoot(root, physical)) throw new ScanSourceSnapshotError("unsafe_source", "A source directory escapes permitted roots.");
    if (ancestors.has(physical)) throw new ScanSourceSnapshotError("unsafe_source", "A source directory contains a symbolic-link loop.");
    const next = new Set(ancestors); next.add(physical);
    for (const entry of (await readdir(logicalDirectory, { withFileTypes: true })).sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0)) {
      if (++visitedEntries > SCAN_SOURCE_LIMITS.visitedEntries) throw new ScanSourceSnapshotError("source_limit", "Source traversal exceeds its entry limit.");
      if (excluded.has(entry.name) || entry.name === "node_modules") continue;
      const absolute = path.join(logicalDirectory, entry.name);
      const info = await lstat(absolute);
      if (info.isDirectory()) { await walk(absolute, next); continue; }
      if (info.isSymbolicLink()) {
        const target = await realpath(absolute).catch(() => { throw new ScanSourceSnapshotError("unsafe_source", "A source symbolic link is broken or cyclic."); });
        if (!insidePermittedPhysicalRoot(root, target)) throw new ScanSourceSnapshotError("unsafe_source", "A source symbolic link escapes permitted roots.");
        if ((await lstat(target)).isDirectory()) { await walk(absolute, next); continue; }
        if (entry.name.endsWith(".sol")) throw new ScanSourceSnapshotError("unsafe_source", "Solidity file symbolic links are not supported.");
        continue;
      }
      if (info.isFile() && entry.name.endsWith(".sol")) await add(path.relative(root, absolute).split(path.sep).join("/"));
    }
  }

  for (const sourceRoot of VERIFICATION_SOURCE_ROOTS.slice(0, 3)) {
    const candidate = path.join(root, sourceRoot);
    const info = await lstat(candidate).catch((error: NodeJS.ErrnoException) => { if (error.code === "ENOENT") return null; throw error; });
    if (info) await walk(candidate, new Set([root]));
  }
  if (!files.size) throw new ScanSourceSnapshotError("source_unavailable", "No supported Solidity source files were found.");
  const pending = [...files.keys()].sort(), parsed = new Set<string>();
  while (pending.length) {
    const sourceKey = pending.shift()!;
    if (parsed.has(sourceKey)) continue;
    parsed.add(sourceKey);
    const source = files.get(sourceKey)!;
    let imports: string[];
    try { imports = verificationImportPaths(source.rawBytes.toString("utf8")); }
    catch { throw new ScanSourceSnapshotError("unsupported_import", "A Solidity import could not be parsed safely."); }
    for (const imported of imports) {
      let resolved: string;
      try { resolved = resolveVerificationImport(sourceKey, imported); canonicalScanSourceKey(resolved); }
      catch { throw new ScanSourceSnapshotError("unsupported_import", "A Solidity import is outside supported source roots."); }
      if (!files.has(resolved)) await add(resolved);
      if (!parsed.has(resolved)) pending.push(resolved);
    }
    pending.sort();
  }
  return [...files.values()].sort((a, b) => a.sourceKey < b.sourceKey ? -1 : a.sourceKey > b.sourceKey ? 1 : 0);
}
