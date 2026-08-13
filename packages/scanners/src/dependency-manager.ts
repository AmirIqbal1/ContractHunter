import { lstat, mkdir, readFile, realpath, writeFile } from "node:fs/promises";
import path from "node:path";
import { sanitiseError, type DependencyStatus } from "@contracthunter/core";
import { ProcessOutputLimitError, ProcessTimeoutError, runBoundedProcess, type ProcessRunner } from "./process-runner";

const MAX_MANIFEST_BYTES = 2_097_152;
const MAX_LOCKFILE_BYTES = 20_971_520;
const SAFE_SUBMODULE_NAME = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$/;
const REGISTRY_HOST = "registry.npmjs.org";

export type SubmoduleRequirement = { name: string; path: string; url: string };
export type DependencyMetadata = {
  gitSubmodulesDetected: number;
  gitSubmodulesPrepared: number;
  npmDependenciesDetected: number;
  npmDependenciesPrepared: number;
  packageManager: "npm" | null;
  lockfile: "package-lock.json" | "npm-shrinkwrap.json" | null;
  durationMs: number;
  warnings: string[];
};

export type DependencyPreparation = { status: "ready" | "skipped"; metadata: DependencyMetadata };

export type DependencyManagerOptions = {
  workspaceRoot: string;
  toolHomeDir: string;
  timeoutMs: number;
  maxOutputBytes: number;
  maxSubmoduleDepth: number;
  maxSubmodules: number;
  allowNpm: boolean;
  allowGitSubmodules: boolean;
  allowedGitHosts: string[];
  processRunner?: ProcessRunner;
  onStatus?: (status: DependencyStatus, metadata?: Partial<DependencyMetadata>, error?: string) => void;
};

export class DependencyPreparationError extends Error {
  constructor(message: string) { super(message); this.name = "DependencyPreparationError"; }
}

function parseGitmodules(contents: string): SubmoduleRequirement[] {
  const result: SubmoduleRequirement[] = [];
  let current: Partial<SubmoduleRequirement> | null = null;
  const finish = () => {
    if (!current) return;
    if (!current.name || !current.path || !current.url) throw new DependencyPreparationError("A Git submodule declaration is incomplete.");
    result.push(current as SubmoduleRequirement);
  };
  for (const original of contents.split(/\r?\n/)) {
    const line = original.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) continue;
    const section = line.match(/^\[submodule\s+"([^"]+)"\]$/i);
    if (section) { finish(); current = { name: section[1] }; continue; }
    if (line.startsWith("[")) { finish(); current = null; continue; }
    if (!current) continue;
    const property = line.match(/^([A-Za-z][A-Za-z0-9.-]*)\s*=\s*(.*)$/);
    if (!property) throw new DependencyPreparationError("Unable to parse a Git submodule declaration safely.");
    const key = property[1].toLowerCase();
    const value = property[2].trim();
    if (key === "path") current.path = value;
    if (key === "url") current.url = value;
    if (key === "update" && value.toLowerCase() !== "checkout") throw new DependencyPreparationError("Custom Git submodule update commands are not allowed.");
  }
  finish();
  return result;
}

function validateSubmodule(requirement: SubmoduleRequirement, parent: string, repository: string, allowedHosts: Set<string>): SubmoduleRequirement & { absolutePath: string } {
  if (!SAFE_SUBMODULE_NAME.test(requirement.name)) throw new DependencyPreparationError("A Git submodule has an invalid name.");
  const components = requirement.path.split(/[\\/]+/);
  if (path.isAbsolute(requirement.path) || /^[A-Za-z]:[\\/]/.test(requirement.path) || requirement.path.startsWith("\\\\") || /[\0-\x1f\x7f]/.test(requirement.path) || components.some((component) => !component || component === "." || component === "..")) throw new DependencyPreparationError(`Git submodule ${requirement.name} has an unsafe path.`);
  const absolutePath = path.resolve(parent, requirement.path);
  if (absolutePath === repository || !absolutePath.startsWith(`${repository}${path.sep}`)) throw new DependencyPreparationError(`Git submodule ${requirement.name} escapes the repository workspace.`);
  let url: URL;
  try { url = new URL(requirement.url); }
  catch { throw new DependencyPreparationError(`Git submodule ${requirement.name} does not use an approved HTTPS URL.`); }
  if (url.protocol !== "https:" || url.username || url.password || !allowedHosts.has(url.hostname.toLowerCase()) || url.port || url.search || url.hash) {
    throw new DependencyPreparationError(`Git submodule ${requirement.name} does not use an approved HTTPS dependency host.`);
  }
  if (url.hostname.toLowerCase() === "github.com" && !/^\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:\.git)?\/?$/.test(url.pathname)) {
    throw new DependencyPreparationError(`Git submodule ${requirement.name} has an unsupported GitHub URL.`);
  }
  return { ...requirement, url: url.toString(), absolutePath };
}

function dependencyStrings(manifest: Record<string, unknown>): Map<string, string> {
  const result = new Map<string, string>();
  for (const section of ["dependencies", "devDependencies", "optionalDependencies"] as const) {
    const dependencies = manifest[section];
    if (!dependencies || typeof dependencies !== "object" || Array.isArray(dependencies)) continue;
    for (const [name, value] of Object.entries(dependencies)) if (typeof value === "string") result.set(name, value);
  }
  return result;
}

function trustedGitSpec(spec: string, allowedHosts: Set<string>): boolean {
  if (!spec.startsWith("git+") && !/\.git(?:#.*)?$/i.test(spec)) return false;
  const candidate = spec.startsWith("git+") ? spec.slice(4) : spec;
  try {
    const url = new URL(candidate);
    return url.protocol === "https:" && !url.username && !url.password && !url.port && allowedHosts.has(url.hostname.toLowerCase());
  } catch { return false; }
}

function unsafeDependencyReason(spec: string, allowedHosts: Set<string>): string | null {
  const value = spec.trim();
  if (/^(?:file:|link:|workspace:|portal:|path:|\.\.?[\\/]|[A-Za-z]:[\\/]|\/)/i.test(value)) return "local filesystem dependency";
  if (/^(?:git\+ssh:|ssh:|git:)|^[^/@\s]+@[^:\s]+:/i.test(value)) return "SSH or unsafe Git dependency";
  if (/^(?:github|gitlab|bitbucket):|^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:#.*)?$/i.test(value)) return "non-HTTPS Git dependency";
  if (/^(?:git\+)?https?:/i.test(value) && !trustedGitSpec(value, allowedHosts)) return "unapproved remote dependency";
  if (/^(?:https?:)/i.test(value)) return "remote tarball dependency";
  return null;
}

function validateNpmSources(manifest: Record<string, unknown>, lock: Record<string, unknown>, allowedHosts: Set<string>): number {
  const direct = dependencyStrings(manifest);
  for (const [name, spec] of direct) {
    const reason = unsafeDependencyReason(spec, allowedHosts);
    if (reason) throw new DependencyPreparationError(`npm dependency ${name} uses an unsupported ${reason}.`);
  }
  const packages = lock.packages;
  let count = 0;
  if (packages && typeof packages === "object" && !Array.isArray(packages)) {
    for (const [location, raw] of Object.entries(packages)) {
      if (!location) continue;
      count++;
      if (!raw || typeof raw !== "object" || Array.isArray(raw)) continue;
      const item = raw as Record<string, unknown>;
      if (item.link === true) throw new DependencyPreparationError(`npm lockfile entry ${location} uses an unsupported directory dependency.`);
      const resolved = typeof item.resolved === "string" ? item.resolved : "";
      const version = typeof item.version === "string" ? item.version : "";
      const packageName = location.replace(/^.*node_modules\//, "");
      if (/^(?:file:|link:)/i.test(version) || /^(?:file:|link:)/i.test(resolved)) throw new DependencyPreparationError(`npm lockfile entry ${location} uses an unsupported local dependency.`);
      const versionReason = unsafeDependencyReason(version, allowedHosts);
      const approvedDirectGit = direct.has(packageName) && trustedGitSpec(direct.get(packageName) ?? "", allowedHosts) && trustedGitSpec(version, allowedHosts);
      if (versionReason && !approvedDirectGit) throw new DependencyPreparationError(`npm lockfile entry ${location} uses an unsupported ${versionReason}.`);
      if (trustedGitSpec(version, allowedHosts) && !approvedDirectGit) throw new DependencyPreparationError(`npm lockfile entry ${location} uses an unapproved transitive Git dependency.`);
      if (!resolved) continue;
      if (/^(?:git\+)?https:/i.test(resolved)) {
        let parsed: URL;
        try { parsed = new URL(resolved.startsWith("git+") ? resolved.slice(4) : resolved); }
        catch { throw new DependencyPreparationError(`npm lockfile entry ${location} has an invalid remote source.`); }
        if (parsed.hostname.toLowerCase() === REGISTRY_HOST && parsed.protocol === "https:" && !parsed.username && !parsed.password) continue;
        if (direct.has(packageName) && trustedGitSpec(direct.get(packageName) ?? "", allowedHosts) && trustedGitSpec(resolved, allowedHosts)) continue;
        throw new DependencyPreparationError(`npm lockfile entry ${location} uses an unapproved remote source.`);
      }
      throw new DependencyPreparationError(`npm lockfile entry ${location} uses an unsupported dependency source.`);
    }
    return count;
  }
  const visit = (value: unknown) => {
    if (!value || typeof value !== "object" || Array.isArray(value)) return;
    for (const item of Object.values(value as Record<string, unknown>)) {
      if (!item || typeof item !== "object" || Array.isArray(item)) continue;
      count++;
      const record = item as Record<string, unknown>;
      const resolved = typeof record.resolved === "string" ? record.resolved : "";
      const version = typeof record.version === "string" ? record.version : "";
      if (unsafeDependencyReason(version, allowedHosts)) throw new DependencyPreparationError("npm lockfile contains an unsupported dependency source.");
      if (resolved) {
        let parsed: URL;
        try { parsed = new URL(resolved); } catch { throw new DependencyPreparationError("npm lockfile contains an invalid dependency source."); }
        if (parsed.protocol !== "https:" || parsed.hostname.toLowerCase() !== REGISTRY_HOST || parsed.username || parsed.password) throw new DependencyPreparationError("npm lockfile contains an unapproved dependency source.");
      }
      visit(record.dependencies);
    }
  };
  visit(lock.dependencies);
  return count;
}

export class DependencyManager {
  private readonly processRunner: ProcessRunner;
  constructor(private readonly options: DependencyManagerOptions) { this.processRunner = options.processRunner ?? runBoundedProcess; }

  private environment(home: string): NodeJS.ProcessEnv {
    return {
      NODE_ENV: process.env.NODE_ENV ?? "production",
      PATH: process.env.PATH ?? "/usr/local/bin:/usr/bin:/bin",
      HOME: home,
      TMPDIR: "/tmp",
      LANG: "C.UTF-8",
      LC_ALL: "C.UTF-8",
      GIT_TERMINAL_PROMPT: "0",
      GIT_PROTOCOL_FROM_USER: "0",
      npm_config_cache: path.join(this.options.toolHomeDir, "npm-cache"),
      npm_config_update_notifier: "false",
    };
  }

  private checkedRepository(repositoryPath: string): string {
    const workspace = path.resolve(this.options.workspaceRoot);
    const repository = path.resolve(repositoryPath);
    if (repository === workspace || !repository.startsWith(`${workspace}${path.sep}`)) throw new DependencyPreparationError("Dependency workspace path is outside the configured repository directory.");
    return repository;
  }

  private async readRegularFile(filename: string, maximum: number): Promise<string | null> {
    try {
      const info = await lstat(filename);
      if (!info.isFile() || info.isSymbolicLink() || info.size > maximum) throw new DependencyPreparationError(`${path.basename(filename)} is not a safe supported file.`);
      return await readFile(filename, "utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw error;
    }
  }

  private async prepareSubmodules(repository: string, metadata: DependencyMetadata): Promise<void> {
    const allowedHosts = new Set(this.options.allowedGitHosts);
    const rootReal = await realpath(repository);
    let parents = [repository];
    const visited = new Set<string>();
    let gitChecked = false;
    for (let depth = 0; parents.length; depth++) {
      if (depth >= this.options.maxSubmoduleDepth) throw new DependencyPreparationError(`Git submodules exceed the configured recursion limit of ${this.options.maxSubmoduleDepth}.`);
      const next: string[] = [];
      for (const parent of parents) {
        const contents = await this.readRegularFile(path.join(parent, ".gitmodules"), MAX_MANIFEST_BYTES);
        if (contents === null) continue;
        for (const requirement of parseGitmodules(contents)) {
          const item = validateSubmodule(requirement, parent, repository, allowedHosts);
          if (visited.has(item.absolutePath)) throw new DependencyPreparationError("A duplicate Git submodule path was declared.");
          visited.add(item.absolutePath);
          metadata.gitSubmodulesDetected++;
          if (metadata.gitSubmodulesDetected > this.options.maxSubmodules) throw new DependencyPreparationError(`Git submodules exceed the configured limit of ${this.options.maxSubmodules}.`);
          if (!this.options.allowGitSubmodules) throw new DependencyPreparationError("Git submodules are required but Git dependency preparation is disabled.");
          if (!gitChecked) {
            let version;
            try { version = await this.processRunner({ command: "git", args: ["--version"], timeoutMs: 10_000, maxOutputBytes: 65_536, env: this.environment(this.options.toolHomeDir) }); }
            catch { throw new DependencyPreparationError("Git is not available in the dependency preparation environment."); }
            if (version.exitCode !== 0) throw new DependencyPreparationError("Git is not available in the dependency preparation environment.");
            gitChecked = true;
          }
          this.options.onStatus?.("preparing", metadata);
          const configPrefix = [
            "-c", "protocol.file.allow=never", "-c", "protocol.ssh.allow=never", "-c", "protocol.git.allow=never", "-c", "protocol.ext.allow=never",
            "-c", `submodule.${item.name}.update=checkout`, "-c", `submodule.${item.name}.url=${item.url}`,
          ];
          const statusRequest = { command: "git", args: [...configPrefix, "submodule", "status", "--", requirement.path], cwd: parent, timeoutMs: this.options.timeoutMs, maxOutputBytes: this.options.maxOutputBytes, env: this.environment(this.options.toolHomeDir) };
          const before = await this.processRunner(statusRequest);
          if (before.exitCode !== 0 || !/^ [0-9a-f]{40}\s/im.test(before.stdout)) {
            const result = await this.processRunner({ command: "git", args: [...configPrefix, "submodule", "update", "--init", "--checkout", "--", requirement.path], cwd: parent, timeoutMs: this.options.timeoutMs, maxOutputBytes: this.options.maxOutputBytes, env: this.environment(this.options.toolHomeDir) });
            if (result.exitCode !== 0) throw new DependencyPreparationError(`Git submodule ${item.name} could not be prepared. ${sanitiseError(result.stderr)}`);
            const after = await this.processRunner(statusRequest);
            if (after.exitCode !== 0 || !/^ [0-9a-f]{40}\s/im.test(after.stdout)) throw new DependencyPreparationError(`Git submodule ${item.name} is not checked out at its pinned commit.`);
          }
          const actual = await realpath(item.absolutePath);
          if (actual !== rootReal && !actual.startsWith(`${rootReal}${path.sep}`)) throw new DependencyPreparationError(`Git submodule ${item.name} escaped the repository workspace.`);
          metadata.gitSubmodulesPrepared++;
          next.push(item.absolutePath);
        }
      }
      parents = next;
    }
  }

  private async prepareNpm(repository: string, metadata: DependencyMetadata): Promise<void> {
    const packageText = await this.readRegularFile(path.join(repository, "package.json"), MAX_MANIFEST_BYTES);
    if (packageText === null) return;
    const shrinkwrap = await this.readRegularFile(path.join(repository, "npm-shrinkwrap.json"), MAX_LOCKFILE_BYTES);
    const packageLock = shrinkwrap === null ? await this.readRegularFile(path.join(repository, "package-lock.json"), MAX_LOCKFILE_BYTES) : null;
    const lockText = shrinkwrap ?? packageLock;
    if (lockText === null) {
      metadata.warnings.push("npm dependencies were not installed because no supported lockfile was found.");
      return;
    }
    metadata.packageManager = "npm";
    metadata.lockfile = shrinkwrap !== null ? "npm-shrinkwrap.json" : "package-lock.json";
    if (!this.options.allowNpm) throw new DependencyPreparationError("npm dependencies are required but npm dependency preparation is disabled.");
    const npmrc = await this.readRegularFile(path.join(repository, ".npmrc"), MAX_MANIFEST_BYTES);
    if (npmrc?.split(/\r?\n/).some((line) => line.trim() && !line.trim().startsWith("#") && !line.trim().startsWith(";"))) {
      throw new DependencyPreparationError("Repository .npmrc configuration is not allowed during safe dependency preparation.");
    }
    let manifest: Record<string, unknown>;
    let lock: Record<string, unknown>;
    try {
      manifest = JSON.parse(packageText) as Record<string, unknown>;
      lock = JSON.parse(lockText) as Record<string, unknown>;
    } catch { throw new DependencyPreparationError("Unable to parse npm package metadata safely."); }
    metadata.npmDependenciesDetected = validateNpmSources(manifest, lock, new Set(this.options.allowedGitHosts));
    const home = path.join(this.options.toolHomeDir, "dependency-home");
    const userConfig = path.join(home, "npmrc");
    await mkdir(home, { recursive: true });
    await writeFile(userConfig, `registry=https://${REGISTRY_HOST}/\nignore-scripts=true\naudit=false\nfund=false\n`, { mode: 0o600 });
    let version;
    try { version = await this.processRunner({ command: "npm", args: ["--version"], timeoutMs: 10_000, maxOutputBytes: 65_536, env: this.environment(home) }); }
    catch { throw new DependencyPreparationError("npm is not available in the dependency preparation environment."); }
    if (version.exitCode !== 0) throw new DependencyPreparationError("npm is not available in the dependency preparation environment.");
    this.options.onStatus?.("preparing", metadata);
    const npmMajor = Number.parseInt(version.stdout.trim().split(".")[0] ?? "", 10);
    const result = await this.processRunner({
      command: "npm",
      args: ["ci", "--ignore-scripts", "--no-audit", "--no-fund", ...(npmMajor >= 11 ? ["--allow-git=root"] : []), `--registry=https://${REGISTRY_HOST}/`, `--userconfig=${userConfig}`],
      cwd: repository,
      timeoutMs: this.options.timeoutMs,
      maxOutputBytes: this.options.maxOutputBytes,
      env: this.environment(home),
    });
    if (result.exitCode !== 0) throw new DependencyPreparationError(`npm dependencies could not be prepared. ${sanitiseError(result.stderr)}`);
    metadata.npmDependenciesPrepared = metadata.npmDependenciesDetected;
  }

  async prepare(repositoryPath: string): Promise<DependencyPreparation> {
    const repository = this.checkedRepository(repositoryPath);
    const started = Date.now();
    const metadata: DependencyMetadata = { gitSubmodulesDetected: 0, gitSubmodulesPrepared: 0, npmDependenciesDetected: 0, npmDependenciesPrepared: 0, packageManager: null, lockfile: null, durationMs: 0, warnings: [] };
    this.options.onStatus?.("inspecting", metadata);
    try {
      await mkdir(this.options.toolHomeDir, { recursive: true });
      await this.prepareSubmodules(repository, metadata);
      await this.prepareNpm(repository, metadata);
      metadata.durationMs = Date.now() - started;
      const needed = metadata.gitSubmodulesDetected > 0 || metadata.lockfile !== null;
      const status = needed ? "ready" : "skipped";
      this.options.onStatus?.(status, metadata);
      return { status, metadata };
    } catch (error) {
      metadata.durationMs = Date.now() - started;
      const message = error instanceof ProcessTimeoutError ? `Dependency preparation timed out after ${this.options.timeoutMs} ms.`
        : error instanceof ProcessOutputLimitError ? "Dependency preparation output exceeded the configured limit."
          : sanitiseError(error).split(repository).join(".").split(this.options.toolHomeDir).join("[tool-home]");
      this.options.onStatus?.("failed", metadata, message);
      throw new DependencyPreparationError(message);
    }
  }
}

export const dependencyInternals = { parseGitmodules, validateSubmodule, validateNpmSources };
