import { lstat, readFile, readdir, realpath } from "node:fs/promises";
import path from "node:path";
import semver from "semver";
import { parse as parseToml } from "smol-toml";

const VERSION = /^\d+\.\d+\.\d+$/;
const IGNORED_DIRECTORIES = new Set([".git", "out", "artifacts", "cache", "dist", "build"]);
const MAX_FILES = 20_000;
const MAX_SOURCE_BYTES = 2 * 1024 * 1024;

export type CompilerDetection = {
  source: "foundry-config" | "pragma";
  constraints: string[];
  files: number;
};

export class CompilerResolutionError extends Error {
  constructor(message: string) { super(message); this.name = "CompilerResolutionError"; }
}

export async function detectFoundryCompiler(repositoryPath: string): Promise<string | null> {
  const filename = path.join(repositoryPath, "foundry.toml");
  let content: string;
  try { content = await readFile(filename, "utf8"); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw new CompilerResolutionError("Unable to read foundry.toml.");
  }
  try {
    const config = parseToml(content) as Record<string, unknown>;
    const profile = config.profile as Record<string, unknown> | undefined;
    const defaults = profile?.default as Record<string, unknown> | undefined;
    const value = defaults?.solc_version ?? config.solc_version;
    return typeof value === "string" && VERSION.test(value) ? value : null;
  } catch {
    throw new CompilerResolutionError("Malformed foundry.toml configuration.");
  }
}

function removeSolidityComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\r\n]*/g, "");
}

export function extractSolidityPragmas(source: string): string[] {
  const clean = removeSolidityComments(source);
  return [...clean.matchAll(/\bpragma\s+solidity\s+([^;]+);/gi)].map((match) => match[1].trim()).filter(Boolean);
}

export async function discoverSoliditySources(repositoryPath: string): Promise<Array<{ filePath: string; pragmas: string[] }>> {
  const root = await realpath(repositoryPath);
  const results: Array<{ filePath: string; pragmas: string[] }> = [];
  const walkedDirectories = new Set<string>();
  let visited = 0;

  async function walk(directory: string): Promise<void> {
    const resolvedDirectory = await realpath(directory);
    if (walkedDirectories.has(resolvedDirectory)) return;
    walkedDirectories.add(resolvedDirectory);
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      if (++visited > MAX_FILES) throw new CompilerResolutionError("Repository source traversal exceeded the safety limit.");
      if (entry.isDirectory() && IGNORED_DIRECTORIES.has(entry.name)) continue;
      const candidate = path.join(directory, entry.name);
      const stat = await lstat(candidate);
      if (stat.isSymbolicLink()) {
        const target = await realpath(candidate).catch(() => null);
        if (!target || (target !== root && !target.startsWith(`${root}${path.sep}`))) continue;
        const targetStat = await lstat(target);
        if (targetStat.isDirectory()) await walk(target);
        else if (targetStat.isFile() && entry.name.endsWith(".sol") && targetStat.size <= MAX_SOURCE_BYTES) {
          results.push({ filePath: path.relative(root, candidate), pragmas: extractSolidityPragmas(await readFile(target, "utf8")) });
        }
      } else if (stat.isDirectory()) await walk(candidate);
      else if (stat.isFile() && entry.name.endsWith(".sol") && stat.size <= MAX_SOURCE_BYTES) {
        results.push({ filePath: path.relative(root, candidate), pragmas: extractSolidityPragmas(await readFile(candidate, "utf8")) });
      }
    }
  }

  await walk(root);
  return results;
}

export async function detectCompilerRequirements(repositoryPath: string): Promise<CompilerDetection> {
  const foundry = await detectFoundryCompiler(repositoryPath);
  if (foundry) return { source: "foundry-config", constraints: [foundry], files: 0 };
  const sources = await discoverSoliditySources(repositoryPath);
  if (!sources.length) throw new CompilerResolutionError("No Solidity source files were found.");
  const constraints = [...new Set(sources.map((source) => source.pragmas.join(" ").trim()).filter(Boolean))];
  if (!constraints.length) throw new CompilerResolutionError("Unable to determine a compatible Solidity compiler version.");
  for (const constraint of constraints) {
    if (!semver.validRange(constraint, { includePrerelease: false })) throw new CompilerResolutionError(`Conflicting or unsupported Solidity pragma constraint: ${constraint}`);
  }
  return { source: "pragma", constraints, files: sources.length };
}

export function resolveCompilerVersions(constraints: string[], candidates: string[], maxVersions: number): string[] {
  const stable = [...new Set(candidates.filter((version) => VERSION.test(version) && semver.valid(version) && !semver.prerelease(version)))].sort(semver.rcompare);
  const uncovered = new Set(constraints);
  const selected: string[] = [];
  while (uncovered.size) {
    let best: { version: string; covers: string[] } | undefined;
    for (const version of stable) {
      const covers = [...uncovered].filter((constraint) => semver.satisfies(version, constraint, { includePrerelease: false }));
      if (covers.length && (!best || covers.length > best.covers.length)) best = { version, covers };
    }
    if (!best) throw new CompilerResolutionError(`Unable to determine a compatible Solidity compiler version for: ${[...uncovered].join(", ")}.`);
    selected.push(best.version);
    best.covers.forEach((constraint) => uncovered.delete(constraint));
    if (selected.length > maxVersions) throw new CompilerResolutionError(`Project exceeds the configured limit of ${maxVersions} Solidity compiler versions.`);
  }
  return selected.sort(semver.compare);
}
