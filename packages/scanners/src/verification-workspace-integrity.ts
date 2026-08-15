import { createHash } from "node:crypto";
import { lstat, readFile, readdir, realpath } from "node:fs/promises";
import path from "node:path";
import { VERIFICATION_HARNESS_MANIFEST, verificationHarnessManifestSchema, type VerificationHarnessManifest } from "@contracthunter/core";
import { createContractHunterFoundryConfig } from "./verification-foundry-config";

export class VerificationWorkspaceIntegrityError extends Error {
  constructor(message: string) { super(message); this.name = "VerificationWorkspaceIntegrityError"; }
}

export function sha256Bytes(value: string | Buffer): string { return createHash("sha256").update(value).digest("hex"); }

export function verificationContentFingerprint(input: Pick<VerificationHarnessManifest, "compilerVersion" | "generatorVersion" | "sourceManifest" | "generatedHarnessSha256" | "foundryConfigSha256">): string {
  return sha256Bytes(JSON.stringify({
    compilerVersion: input.compilerVersion,
    generatorVersion: input.generatorVersion,
    sourceManifest: [...input.sourceManifest].sort((a, b) => a.originalPath.localeCompare(b.originalPath)),
    generatedHarnessSha256: input.generatedHarnessSha256,
    foundryConfigSha256: input.foundryConfigSha256,
  }));
}

async function regularFile(root: string, relativePath: string): Promise<Buffer> {
  const absolute = path.join(root, ...relativePath.split("/"));
  let info;
  try { info = await lstat(absolute); }
  catch { throw new VerificationWorkspaceIntegrityError(`Required workspace file is missing: ${relativePath}.`); }
  if (!info.isFile() || info.isSymbolicLink()) throw new VerificationWorkspaceIntegrityError(`Workspace file is unsafe: ${relativePath}.`);
  const canonical = await realpath(absolute);
  if (!canonical.startsWith(`${root}${path.sep}`)) throw new VerificationWorkspaceIntegrityError(`Workspace file escapes its root: ${relativePath}.`);
  return readFile(canonical);
}

async function assertExpectedLayout(root: string, allowedFiles: Set<string>): Promise<void> {
  async function walk(directory: string): Promise<void> {
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      const absolute = path.join(directory, entry.name); const relative = path.relative(root, absolute).split(path.sep).join("/");
      const info = await lstat(absolute);
      if (info.isSymbolicLink()) throw new VerificationWorkspaceIntegrityError(`Workspace contains a symbolic link: ${relative}.`);
      if (info.isDirectory()) { await walk(absolute); continue; }
      if (!info.isFile() || !allowedFiles.has(relative)) throw new VerificationWorkspaceIntegrityError(`Workspace contains an unexpected file: ${relative}.`);
    }
  }
  await walk(root);
}

export async function validateVerificationWorkspaceIntegrity(workspacePath: string, rawManifest?: unknown, options: { allowTemporaryBuildPath?: boolean } = {}): Promise<VerificationHarnessManifest> {
  const root = await realpath(workspacePath).catch(() => { throw new VerificationWorkspaceIntegrityError("Verification workspace is unavailable."); });
  let manifestRaw = rawManifest;
  if (manifestRaw === undefined) {
    const bytes = await regularFile(root, VERIFICATION_HARNESS_MANIFEST);
    try { manifestRaw = JSON.parse(bytes.toString("utf8")); }
    catch { throw new VerificationWorkspaceIntegrityError("Verification manifest is malformed."); }
  }
  const parsed = verificationHarnessManifestSchema.safeParse(manifestRaw);
  if (!parsed.success) throw new VerificationWorkspaceIntegrityError("Verification manifest is invalid.");
  const manifest = parsed.data;
  if (!options.allowTemporaryBuildPath && path.basename(root) !== manifest.verificationRunId) throw new VerificationWorkspaceIntegrityError("Verification workspace does not match its run identifier.");
  const sources = [...manifest.sourceManifest].sort((a, b) => a.originalPath.localeCompare(b.originalPath));
  if (new Set(sources.map((entry) => entry.originalPath)).size !== sources.length || new Set(sources.map((entry) => entry.workspacePath)).size !== sources.length) throw new VerificationWorkspaceIntegrityError("Verification source manifest contains duplicate paths.");
  for (const source of sources) {
    const bytes = await regularFile(root, source.workspacePath);
    if (bytes.length !== source.byteLength || sha256Bytes(bytes) !== source.sha256) throw new VerificationWorkspaceIntegrityError(`Verification source integrity check failed: ${source.originalPath}.`);
  }
  const harness = await regularFile(root, manifest.generatedHarnessPath);
  if (sha256Bytes(harness) !== manifest.generatedHarnessSha256) throw new VerificationWorkspaceIntegrityError("Generated harness integrity check failed.");
  const config = await regularFile(root, "foundry.toml");
  const expectedConfig = createContractHunterFoundryConfig(manifest.compilerVersion);
  if (config.toString("utf8") !== expectedConfig || sha256Bytes(config) !== manifest.foundryConfigSha256) throw new VerificationWorkspaceIntegrityError("Foundry configuration integrity check failed.");
  if (verificationContentFingerprint(manifest) !== manifest.contentFingerprint) throw new VerificationWorkspaceIntegrityError("Verification content fingerprint is invalid.");
  const allowedFiles = new Set([VERIFICATION_HARNESS_MANIFEST, "foundry.toml", manifest.generatedHarnessPath, ...sources.map((entry) => entry.workspacePath)]);
  await assertExpectedLayout(root, allowedFiles);
  return manifest;
}
