import { lstat, readFile, readdir, realpath } from "node:fs/promises";
import path from "node:path";
import { ECHIDNA_CONFIG_FILE, ECHIDNA_HARNESS_FILE, ECHIDNA_MANIFEST_FILE, echidnaInvariantManifestSchema, type EchidnaInvariantManifest } from "@contracthunter/core";
import { EchidnaInvariantGenerator } from "./echidna-invariant-generator";
import { sha256Bytes } from "./verification-workspace-integrity";

export class EchidnaWorkspaceIntegrityError extends Error {}
async function file(root: string, relative: string, maximum: number): Promise<Buffer> {
  const absolute = path.join(root, ...relative.split("/"));
  const info = await lstat(absolute).catch(() => { throw new EchidnaWorkspaceIntegrityError("missing_echidna_workspace_file"); });
  if (!info.isFile() || info.isSymbolicLink() || info.size > maximum || await realpath(absolute) !== absolute) throw new EchidnaWorkspaceIntegrityError("unsafe_echidna_workspace_file");
  return readFile(absolute);
}
export async function validateEchidnaInvariantWorkspaceIntegrity(workspacePath: string, options: { allowTemporaryBuildPath?: boolean } = {}): Promise<EchidnaInvariantManifest> {
  const root = await realpath(workspacePath).catch(() => { throw new EchidnaWorkspaceIntegrityError("echidna_workspace_unavailable"); });
  let raw: unknown;
  try { raw = JSON.parse((await file(root, ECHIDNA_MANIFEST_FILE, 1_048_576)).toString("utf8")); }
  catch { throw new EchidnaWorkspaceIntegrityError("echidna_manifest_malformed"); }
  const parsed = echidnaInvariantManifestSchema.safeParse(raw);
  if (!parsed.success) throw new EchidnaWorkspaceIntegrityError("echidna_manifest_invalid");
  const manifest = parsed.data;
  const basename = path.basename(root);
  if (basename !== manifest.workspaceId && !(options.allowTemporaryBuildPath && basename.startsWith(`.tmp-${manifest.workspaceId}-`))) throw new EchidnaWorkspaceIntegrityError("echidna_workspace_identity_mismatch");
  const sources = new Map<string, string>(), allowed = new Set<string>([ECHIDNA_MANIFEST_FILE, ECHIDNA_HARNESS_FILE, ECHIDNA_CONFIG_FILE]);
  let bytesTotal = 0;
  for (const entry of manifest.sourceManifest) {
    const bytes = await file(root, entry.workspacePath, 10_485_760);
    bytesTotal += bytes.length;
    if (bytesTotal > 52_428_800 || bytes.length !== entry.byteLength || sha256Bytes(bytes) !== entry.sha256) throw new EchidnaWorkspaceIntegrityError("echidna_source_hash_mismatch");
    sources.set(entry.originalPath, bytes.toString("utf8")); allowed.add(entry.workspacePath);
  }
  let generated;
  try { generated = new EchidnaInvariantGenerator().generate(manifest.plan, sources, !!manifest.sourceLayout); }
  catch { throw new EchidnaWorkspaceIntegrityError("echidna_harness_regeneration_failed"); }
  if (generated.planHash !== manifest.planHash || generated.harnessHash !== manifest.harnessHash || generated.configHash !== manifest.configHash || JSON.stringify(generated.settings) !== JSON.stringify(manifest.settings)) throw new EchidnaWorkspaceIntegrityError("echidna_generated_hash_mismatch");
  if ((await file(root, ECHIDNA_HARNESS_FILE, 1_048_576)).toString("utf8") !== generated.source || (await file(root, ECHIDNA_CONFIG_FILE, 16_384)).toString("utf8") !== generated.config) throw new EchidnaWorkspaceIntegrityError("echidna_generated_bytes_mismatch");
  async function walk(dir: string): Promise<void> {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const absolute = path.join(dir, entry.name), relative = path.relative(root, absolute).split(path.sep).join("/");
      const info = await lstat(absolute);
      if (info.isSymbolicLink()) throw new EchidnaWorkspaceIntegrityError("echidna_workspace_symlink");
      if (info.isDirectory()) { if (relative !== "src" && !relative.startsWith("src/") && !(manifest.sourceLayout && (relative === "contracts" || relative.startsWith("contracts/")))) throw new EchidnaWorkspaceIntegrityError("echidna_workspace_unexpected_directory"); await walk(absolute); }
      else if (!info.isFile() || !allowed.has(relative)) throw new EchidnaWorkspaceIntegrityError("echidna_workspace_unexpected_file");
    }
  }
  await walk(root);
  return manifest;
}
