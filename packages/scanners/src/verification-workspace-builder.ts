import { randomUUID } from "node:crypto";
import { lstat, mkdir, readFile, realpath, readdir, rename, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import semver from "semver";
import {
  VERIFICATION_HARNESS_MANIFEST, repositorySolidityPathSchema, verificationHarnessManifestSchema, verificationHarnessPlanSchema,
  type VerificationHarnessManifest, type VerificationHarnessPlan, type VerificationSourceManifestEntry,
} from "@contracthunter/core";
import { createContractHunterFoundryConfig } from "./verification-foundry-config";
import { VerificationHarnessGenerator } from "./verification-harness-generator";
import { sha256Bytes, validateVerificationWorkspaceIntegrity, verificationContentFingerprint } from "./verification-workspace-integrity";

const IMPORT = /\bimport\s+(?:(?:[^;"']+?\s+from\s+)?["']([^"']+)["'])\s*;/g;
const SAFE_RUN_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export class VerificationWorkspaceBuildError extends Error {
  constructor(message: string) { super(message); this.name = "VerificationWorkspaceBuildError"; }
}

export type VerificationWorkspaceBuilderOptions = {
  verificationRoot: string;
  repositoryRoot: string;
  acceptedCompilerVersions: string[];
  approvedSourceRoots: string[];
  generatorVersion: string;
  maxSourceFiles?: number;
  maxSourceBytes?: number;
};

export type BuildVerificationWorkspaceInput = { verificationRunId: string; repositoryPath: string; plan: VerificationHarnessPlan; createdAt?: Date };
export type BuiltVerificationWorkspace = { workspacePath: string; manifest: VerificationHarnessManifest; harnessSource: string };

function comparePaths(left: string, right: string): number { return left < right ? -1 : left > right ? 1 : 0; }

function safeSourcePath(value: string): boolean { return repositorySolidityPathSchema.safeParse(value).success; }

function safeSourceRoot(value: string): boolean {
  return value.length <= 500 && !value.startsWith("/") && !/^[A-Za-z]:/.test(value)
    && value.split("/").every((component) => component !== "." && component !== ".." && /^[A-Za-z0-9_@+.-]+$/.test(component));
}

function removeComments(source: string): string { return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\r\n]*/g, ""); }

function importPaths(source: string): string[] {
  const clean = removeComments(source); const matches = [...clean.matchAll(IMPORT)];
  if ((clean.match(/\bimport\b/g) ?? []).length !== matches.length) throw new VerificationWorkspaceBuildError("A Solidity import declaration could not be parsed safely.");
  return matches.map((match) => match[1]);
}

export class VerificationWorkspaceBuilder {
  private readonly maxSourceFiles: number;
  private readonly maxSourceBytes: number;
  private readonly approvedRoots: Set<string>;

  constructor(private readonly options: VerificationWorkspaceBuilderOptions, private readonly generator = new VerificationHarnessGenerator()) {
    this.maxSourceFiles = options.maxSourceFiles ?? 100; this.maxSourceBytes = options.maxSourceBytes ?? 5_242_880;
    this.approvedRoots = new Set(options.approvedSourceRoots);
    if (!Number.isInteger(this.maxSourceFiles) || this.maxSourceFiles < 1 || this.maxSourceFiles > 200 || !Number.isInteger(this.maxSourceBytes) || this.maxSourceBytes < 1_024 || this.maxSourceBytes > 52_428_800) throw new VerificationWorkspaceBuildError("Source closure limits are invalid.");
    if (!options.approvedSourceRoots.length || new Set(options.approvedSourceRoots).size !== options.approvedSourceRoots.length || options.approvedSourceRoots.some((root) => !safeSourceRoot(root))) throw new VerificationWorkspaceBuildError("Approved source roots are invalid.");
    if (!/^\d+\.\d+\.\d+$/.test(options.generatorVersion)) throw new VerificationWorkspaceBuildError("Generator version is invalid.");
  }

  private approved(relativePath: string): boolean {
    return [...this.approvedRoots].some((root) => relativePath === root || relativePath.startsWith(`${root}/`));
  }

  private resolveImport(importer: string, imported: string): string {
    if (!imported || imported.includes("\\") || imported.includes("\0") || imported.startsWith("/") || /^[A-Za-z][A-Za-z0-9+.-]*:/.test(imported) || imported.includes("://") || imported.startsWith("git@") || imported.startsWith("ssh")) throw new VerificationWorkspaceBuildError(`Unsupported Solidity import in ${importer}.`);
    let resolved: string;
    if (imported.startsWith("./") || imported.startsWith("../")) resolved = path.posix.normalize(path.posix.join(path.posix.dirname(importer), imported));
    else resolved = path.posix.normalize(imported);
    if (!safeSourcePath(resolved) || !this.approved(resolved)) throw new VerificationWorkspaceBuildError(`Solidity import escapes approved source roots: ${imported}.`);
    return resolved;
  }

  private async sourceClosure(repository: string, entries: string[]): Promise<Array<{ relativePath: string; bytes: Buffer }>> {
    const pending = [...entries].sort(comparePaths); const visited = new Map<string, Buffer>(); let totalBytes = 0;
    while (pending.length) {
      const relativePath = pending.shift()!;
      if (visited.has(relativePath)) continue;
      if (!safeSourcePath(relativePath) || !this.approved(relativePath)) throw new VerificationWorkspaceBuildError(`Source path is outside approved source roots: ${relativePath}.`);
      const absolute = path.join(repository, ...relativePath.split("/"));
      let info;
      try { info = await lstat(absolute); }
      catch { throw new VerificationWorkspaceBuildError(`Required Solidity source is unavailable: ${relativePath}.`); }
      if (!info.isFile() || info.isSymbolicLink()) throw new VerificationWorkspaceBuildError(`Solidity source is not a regular repository file: ${relativePath}.`);
      const canonical = await realpath(absolute);
      if (!canonical.startsWith(`${repository}${path.sep}`)) throw new VerificationWorkspaceBuildError(`Solidity source escapes the repository: ${relativePath}.`);
      const bytes = await readFile(canonical); totalBytes += bytes.length;
      if (visited.size + 1 > this.maxSourceFiles) throw new VerificationWorkspaceBuildError("Solidity source closure exceeds the file-count limit.");
      if (totalBytes > this.maxSourceBytes) throw new VerificationWorkspaceBuildError("Solidity source closure exceeds the byte limit.");
      visited.set(relativePath, bytes);
      const imports = importPaths(bytes.toString("utf8")).map((item) => this.resolveImport(relativePath, item));
      pending.push(...imports.filter((item) => !visited.has(item))); pending.sort(comparePaths);
    }
    return [...visited.entries()].sort(([a], [b]) => comparePaths(a, b)).map(([relativePath, bytes]) => ({ relativePath, bytes }));
  }

  async build(input: BuildVerificationWorkspaceInput): Promise<BuiltVerificationWorkspace> {
    if (!SAFE_RUN_ID.test(input.verificationRunId)) throw new VerificationWorkspaceBuildError("Verification run identifier is invalid.");
    const plan = verificationHarnessPlanSchema.parse(input.plan);
    if (!this.options.acceptedCompilerVersions.includes(plan.compilerVersion) || !semver.valid(plan.compilerVersion) || semver.prerelease(plan.compilerVersion)) throw new VerificationWorkspaceBuildError("Compiler version was not accepted by ContractHunter compiler management.");
    let verificationRoot: string; let repositoryRoot: string; let repository: string;
    try {
      await mkdir(this.options.verificationRoot, { recursive: true });
      [verificationRoot, repositoryRoot, repository] = await Promise.all([realpath(this.options.verificationRoot), realpath(this.options.repositoryRoot), realpath(input.repositoryPath)]);
    } catch { throw new VerificationWorkspaceBuildError("Verification or repository root is unavailable."); }
    if (repository === repositoryRoot || !repository.startsWith(`${repositoryRoot}${path.sep}`)) throw new VerificationWorkspaceBuildError("Repository path is outside the configured repository root.");
    if (verificationRoot === repositoryRoot || verificationRoot.startsWith(`${repositoryRoot}${path.sep}`) || repositoryRoot.startsWith(`${verificationRoot}${path.sep}`)) throw new VerificationWorkspaceBuildError("Verification and repository roots must be separate.");
    const finalPath = path.join(verificationRoot, input.verificationRunId); const temporaryPath = path.join(verificationRoot, `.tmp-${input.verificationRunId}-${randomUUID()}`); const lockPath = path.join(verificationRoot, `.lock-${input.verificationRunId}`);
    try { await lstat(finalPath); throw new VerificationWorkspaceBuildError("Verification run workspace already exists."); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
    try {
      await writeFile(lockPath, input.verificationRunId, { flag: "wx", mode: 0o600 });
      const closure = await this.sourceClosure(repository, plan.sourceFiles);
      const harnessSource = this.generator.generate(plan); const foundryConfig = createContractHunterFoundryConfig(plan.compilerVersion);
      await mkdir(temporaryPath, { recursive: false });
      await Promise.all(["src", "test", "cache", "out"].map((directory) => mkdir(path.join(temporaryPath, directory))));
      const sourceManifest: VerificationSourceManifestEntry[] = [];
      for (const source of closure) {
        const workspacePath = `src/${source.relativePath}`; const destination = path.join(temporaryPath, ...workspacePath.split("/"));
        await mkdir(path.dirname(destination), { recursive: true }); await writeFile(destination, source.bytes, { flag: "wx", mode: 0o600 });
        sourceManifest.push({ originalPath: source.relativePath, workspacePath, byteLength: source.bytes.length, sha256: sha256Bytes(source.bytes) });
      }
      const harnessPath = "test/ContractHunterVerification.t.sol" as const; const harnessBytes = Buffer.from(harnessSource, "utf8"); const configBytes = Buffer.from(foundryConfig, "utf8");
      await writeFile(path.join(temporaryPath, ...harnessPath.split("/")), harnessBytes, { flag: "wx", mode: 0o600 });
      await writeFile(path.join(temporaryPath, "foundry.toml"), configBytes, { flag: "wx", mode: 0o600 });
      const manifestBase = {
        formatVersion: 1 as const, verificationRunId: input.verificationRunId, scanId: plan.scanId, hypothesisId: plan.hypothesisId, resolvedCommit: plan.resolvedCommit,
        compilerVersion: plan.compilerVersion, generatorVersion: this.options.generatorVersion, generatedBy: "contracthunter" as const, createdAt: (input.createdAt ?? new Date()).toISOString(),
        sourceManifest, generatedHarnessPath: harnessPath, generatedHarnessSha256: sha256Bytes(harnessBytes), foundryConfigSha256: sha256Bytes(configBytes),
      };
      const manifest = verificationHarnessManifestSchema.parse({ ...manifestBase, contentFingerprint: verificationContentFingerprint(manifestBase) });
      await writeFile(path.join(temporaryPath, VERIFICATION_HARNESS_MANIFEST), `${JSON.stringify(manifest, null, 2)}\n`, { flag: "wx", mode: 0o600 });
      await validateVerificationWorkspaceIntegrity(temporaryPath, manifest, { allowTemporaryBuildPath: true });
      try { await lstat(finalPath); throw new VerificationWorkspaceBuildError("Verification run workspace already exists."); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
      await rename(temporaryPath, finalPath);
      return { workspacePath: finalPath, manifest, harnessSource };
    } catch (error) {
      await rm(temporaryPath, { recursive: true, force: true });
      if (error instanceof VerificationWorkspaceBuildError) throw error;
      throw new VerificationWorkspaceBuildError(error instanceof Error ? error.message : "Verification workspace generation failed safely.");
    } finally { await rm(lockPath, { force: true }); }
  }

  async listTemporaryWorkspaces(): Promise<string[]> {
    const root = await realpath(this.options.verificationRoot); return (await readdir(root)).filter((entry) => entry.startsWith(".tmp-")).sort();
  }
}
