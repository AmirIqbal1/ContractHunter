import { lstat, readFile, readdir, realpath } from "node:fs/promises";
import path from "node:path";
import { INVARIANT_REPLAY_MANIFEST, invariantReplayManifestSchema, type InvariantReplayManifest } from "@contracthunter/core";
import { InvariantReplayGenerator } from "./invariant-replay-generator";
import { sha256Bytes } from "./verification-workspace-integrity";

export class InvariantReplayWorkspaceIntegrityError extends Error { constructor(message: string) { super(message); this.name = "InvariantReplayWorkspaceIntegrityError"; } }
async function file(root: string, relative: string, limit: number): Promise<Buffer> {
  const absolute = path.join(root, ...relative.split("/")); let info;
  try { info = await lstat(absolute); } catch { throw new InvariantReplayWorkspaceIntegrityError(`Missing replay file: ${relative}.`); }
  if (!info.isFile() || info.isSymbolicLink() || info.size > limit || await realpath(absolute) !== absolute) throw new InvariantReplayWorkspaceIntegrityError(`Unsafe replay file: ${relative}.`);
  return readFile(absolute);
}
export async function validateInvariantReplayWorkspaceIntegrity(workspacePath: string): Promise<InvariantReplayManifest> {
  const root = await realpath(workspacePath).catch(() => { throw new InvariantReplayWorkspaceIntegrityError("Replay workspace is unavailable."); }); let raw: unknown;
  try { raw = JSON.parse((await file(root, INVARIANT_REPLAY_MANIFEST, 1_048_576)).toString("utf8")); } catch { throw new InvariantReplayWorkspaceIntegrityError("Replay manifest is malformed."); }
  const parsed = invariantReplayManifestSchema.safeParse(raw); if (!parsed.success || path.basename(root) !== parsed.data.workspaceId) throw new InvariantReplayWorkspaceIntegrityError("Replay manifest is invalid.");
  const manifest = parsed.data, sources = new Map<string, string>(), allowed = new Set([INVARIANT_REPLAY_MANIFEST, "foundry.toml", manifest.generatedHarnessPath]); let total = 0;
  for (const entry of manifest.sourceManifest) { const bytes = await file(root, entry.workspacePath, 10_485_760); total += bytes.length; if (total > 52_428_800 || bytes.length !== entry.byteLength || sha256Bytes(bytes) !== entry.sha256) throw new InvariantReplayWorkspaceIntegrityError("Replay source hash mismatch."); sources.set(entry.originalPath, bytes.toString("utf8")); allowed.add(entry.workspacePath); }
  let generated; try { generated = new InvariantReplayGenerator().generate(manifest.replayPlan, manifest.invariantPlan, sources); } catch { throw new InvariantReplayWorkspaceIntegrityError("Replay regeneration failed."); }
  if (generated.replayPlanHash !== manifest.replayPlanHash || generated.harnessHash !== manifest.generatedHarnessSha256 || generated.configHash !== manifest.foundryConfigSha256) throw new InvariantReplayWorkspaceIntegrityError("Replay generated hashes differ.");
  if ((await file(root, manifest.generatedHarnessPath, 1_048_576)).toString("utf8") !== generated.source || (await file(root, "foundry.toml", 16_384)).toString("utf8") !== generated.foundryConfig) throw new InvariantReplayWorkspaceIntegrityError("Replay generated content differs.");
  async function walk(directory: string): Promise<void> { for (const entry of await readdir(directory, { withFileTypes: true })) { const absolute = path.join(directory, entry.name), relative = path.relative(root, absolute).split(path.sep).join("/"), info = await lstat(absolute); if (info.isSymbolicLink()) throw new InvariantReplayWorkspaceIntegrityError("Replay workspace contains a symlink."); if (info.isDirectory()) { if (relative !== "src" && relative !== "test" && relative !== "cache" && relative !== "out" && !relative.startsWith("src/")) throw new InvariantReplayWorkspaceIntegrityError("Replay workspace contains an unexpected directory."); await walk(absolute); } else if (!info.isFile() || !allowed.has(relative)) throw new InvariantReplayWorkspaceIntegrityError("Replay workspace contains an unexpected file."); } }
  await walk(root); return manifest;
}
