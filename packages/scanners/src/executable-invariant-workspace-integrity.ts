import { lstat, readFile, readdir, realpath } from "node:fs/promises";
import path from "node:path";
import { EXECUTABLE_INVARIANT_SCHEMA_VERSION, INVARIANT_HARNESS_MANIFEST, executableInvariantExecutionManifestSchema, type ExecutableInvariantExecutionManifest } from "@contracthunter/core";
import { ExecutableInvariantGenerator } from "./executable-invariant-generator";
import { sha256Bytes } from "./verification-workspace-integrity";

export class ExecutableInvariantWorkspaceIntegrityError extends Error {
  constructor(message: string) { super(message); this.name = "ExecutableInvariantWorkspaceIntegrityError"; }
}
async function file(root: string, relative: string, limit: number): Promise<Buffer> {
  const absolute = path.join(root, ...relative.split("/"));
  let info;
  try { info = await lstat(absolute); } catch { throw new ExecutableInvariantWorkspaceIntegrityError(`Missing invariant file: ${relative}.`); }
  if (!info.isFile() || info.isSymbolicLink() || info.size > limit || await realpath(absolute) !== absolute) throw new ExecutableInvariantWorkspaceIntegrityError(`Unsafe invariant file: ${relative}.`);
  return readFile(absolute);
}
export async function validateExecutableInvariantWorkspaceIntegrity(workspacePath: string): Promise<ExecutableInvariantExecutionManifest> {
  const root = await realpath(workspacePath).catch(() => { throw new ExecutableInvariantWorkspaceIntegrityError("Invariant workspace is unavailable."); });
  let raw: unknown;
  try { raw = JSON.parse((await file(root, INVARIANT_HARNESS_MANIFEST, 1_048_576)).toString("utf8")); }
  catch { throw new ExecutableInvariantWorkspaceIntegrityError("Invariant manifest is malformed or unavailable."); }
  const parsed = executableInvariantExecutionManifestSchema.safeParse(raw);
  if (!parsed.success) throw new ExecutableInvariantWorkspaceIntegrityError("Invariant manifest is invalid.");
  const manifest = parsed.data;
  if (manifest.planKind !== "executable-invariant" || manifest.schemaVersion !== EXECUTABLE_INVARIANT_SCHEMA_VERSION || path.basename(root) !== manifest.workspaceId) throw new ExecutableInvariantWorkspaceIntegrityError("Invariant manifest identity is invalid.");
  const sources = new Map<string, string>(), allowed = new Set([INVARIANT_HARNESS_MANIFEST, "foundry.toml", manifest.generatedHarnessPath]);
  let bytesTotal = 0;
  for (const entry of manifest.sourceManifest) {
    const bytes = await file(root, entry.workspacePath, 10_485_760);
    bytesTotal += bytes.length;
    if (bytesTotal > 52_428_800 || bytes.length !== entry.byteLength || sha256Bytes(bytes) !== entry.sha256) throw new ExecutableInvariantWorkspaceIntegrityError("Invariant source hash mismatch.");
    sources.set(entry.originalPath, bytes.toString("utf8")); allowed.add(entry.workspacePath);
  }
  let generated;
  try { generated = new ExecutableInvariantGenerator().generate(manifest.plan, sources); }
  catch { throw new ExecutableInvariantWorkspaceIntegrityError("Invariant harness regeneration failed."); }
  if (generated.planHash !== manifest.planHash || generated.harnessHash !== manifest.generatedHarnessSha256 || generated.configHash !== manifest.foundryConfigSha256 || JSON.stringify(generated.settings) !== JSON.stringify(manifest.foundry)) throw new ExecutableInvariantWorkspaceIntegrityError("Invariant generated content differs from manifest.");
  const harness = await file(root, manifest.generatedHarnessPath, 1_048_576), config = await file(root, "foundry.toml", 16_384);
  if (harness.toString("utf8") !== generated.source || config.toString("utf8") !== generated.foundryConfig) throw new ExecutableInvariantWorkspaceIntegrityError("Invariant harness or configuration hash mismatch.");
  async function walk(dir: string): Promise<void> {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const absolute = path.join(dir, entry.name), relative = path.relative(root, absolute).split(path.sep).join("/");
      const info = await lstat(absolute);
      if (info.isSymbolicLink()) throw new ExecutableInvariantWorkspaceIntegrityError("Invariant workspace contains a symlink.");
      if (info.isDirectory()) { if (relative !== "src" && relative !== "test" && relative !== "cache" && relative !== "out" && !relative.startsWith("src/")) throw new ExecutableInvariantWorkspaceIntegrityError("Invariant workspace contains an unexpected directory."); await walk(absolute); }
      else if (!info.isFile() || !allowed.has(relative)) throw new ExecutableInvariantWorkspaceIntegrityError("Invariant workspace contains an unexpected file.");
    }
  }
  await walk(root);
  return manifest;
}
