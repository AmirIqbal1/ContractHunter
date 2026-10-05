import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { lstat } from "node:fs/promises";
import path from "node:path";
import { TextDecoder } from "node:util";
import { COMPILATION_MANIFEST_SCHEMA, compilationManifestSchema, type CompilationManifest, type CompilationUnsupportedReason, type ScanSourceCaptureFile, type ScannerSourceAlignment } from "@contracthunter/core";
import { extractSolidityPragmas } from "./compiler-detection";
import { resolveTrustedVerificationCompiler } from "./compiler-manager";
import { runBoundedProcess, type ProcessRunner } from "./process-runner";

export type CompilationProvenanceResult = { status: "supported"; manifest: CompilationManifest } | { status: "unsupported"; reason: CompilationUnsupportedReason };
const VERSION = /^\d+\.\d+\.\d+$/;
const configMarkers = ["hardhat.config.js", "hardhat.config.ts", "hardhat.config.cjs", "hardhat.config.mjs", "foundry.toml", "remappings.txt"];

async function existsRegular(root: string, name: string): Promise<boolean> {
  const info = await lstat(path.join(root, name)).catch((error: NodeJS.ErrnoException) => { if (error.code === "ENOENT") return null; throw error; });
  return info !== null;
}

async function artifactHash(filename: string): Promise<string> {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(filename)) hash.update(chunk as Buffer);
  return hash.digest("hex");
}

/** Fixed, no-file-callback standard JSON compilation of immutable captured bytes only. */
export async function deriveAuthoritativeCompilation(input: {
  scanId: string; resolvedCommit: string; repositoryPath: string; toolHomeDir: string;
  snapshotFiles: readonly ScanSourceCaptureFile[]; processRunner?: ProcessRunner;
}): Promise<CompilationProvenanceResult> {
  const { repositoryPath, snapshotFiles } = input;
  if (!snapshotFiles.length) return { status: "unsupported", reason: "source_snapshot_unavailable" };
  if ((await Promise.all(configMarkers.slice(0, 4).map((marker) => existsRegular(repositoryPath, marker)))).some(Boolean)) return { status: "unsupported", reason: "dynamic_build_configuration" };
  if (await existsRegular(repositoryPath, "foundry.toml") || await existsRegular(repositoryPath, "remappings.txt")) return { status: "unsupported", reason: "unsupported_remapping_behavior" };
  if (snapshotFiles.some((file) => !/^(src|contracts)\//.test(file.sourceKey))) return { status: "unsupported", reason: "unsupported_source_layout" };
  let version: string | null = null;
  const sources: Record<string, { content: string }> = {};
  try {
    const decoder = new TextDecoder("utf-8", { fatal: true });
    for (const file of snapshotFiles) {
      if (!Buffer.isBuffer(file.rawBytes) || createHash("sha256").update(file.rawBytes).digest("hex") !== file.rawSha256 || file.rawBytes.length !== file.byteLength || sources[file.sourceKey]) return { status: "unsupported", reason: "source_snapshot_unavailable" };
      const content = decoder.decode(file.rawBytes);
      const pragmas = extractSolidityPragmas(content);
      if (pragmas.length !== 1 || !VERSION.test(pragmas[0]) || (version && version !== pragmas[0])) return { status: "unsupported", reason: "ambiguous_compiler" };
      version = pragmas[0];
      sources[file.sourceKey] = { content };
    }
  } catch { return { status: "unsupported", reason: "source_snapshot_unavailable" }; }
  if (!version) return { status: "unsupported", reason: "ambiguous_compiler" };
  let executable: string, compilerSha256: string;
  try {
    executable = (await resolveTrustedVerificationCompiler({ toolHomeDir: input.toolHomeDir, version, processRunner: input.processRunner })).executablePath;
    compilerSha256 = await artifactHash(executable);
  } catch { return { status: "unsupported", reason: "trusted_compiler_unavailable" }; }
  const standardInput = JSON.stringify({ language: "Solidity", sources, settings: { remappings: [], optimizer: { enabled: false }, outputSelection: { "*": { "*": ["abi"] } } } });
  let output: { errors?: Array<{ severity?: string }>; sources?: Record<string, unknown>; contracts?: Record<string, Record<string, unknown>> };
  try {
    const result = await (input.processRunner ?? runBoundedProcess)({ command: executable, args: ["--standard-json"], stdin: standardInput,
      timeoutMs: 60_000, maxOutputBytes: 16_777_216,
      env: { NODE_ENV: "production", PATH: "/usr/bin:/bin", HOME: input.toolHomeDir, TMPDIR: "/tmp", LANG: "C.UTF-8", LC_ALL: "C.UTF-8" } });
    if (result.exitCode !== 0) throw new Error("solc failed");
    output = JSON.parse(result.stdout) as typeof output;
    const expected = Object.keys(sources).sort();
    if (output.errors?.some((error) => error.severity === "error") || !output.sources || JSON.stringify(Object.keys(output.sources).sort()) !== JSON.stringify(expected) || output.contracts && Object.keys(output.contracts).some((key) => !sources[key])) throw new Error("Compilation membership mismatch");
  } catch { return { status: "unsupported", reason: "compilation_probe_failed" }; }
  const sourceRoots = (["src", "contracts"] as const).filter((root) => snapshotFiles.some((file) => file.sourceKey.startsWith(`${root}/`)));
  const manifest = compilationManifestSchema.parse({
    schema: COMPILATION_MANIFEST_SCHEMA, scanId: input.scanId, resolvedCommit: input.resolvedCommit,
    compilationProfileKind: "plain-solidity-exact-pragma-v1", compiler: { version, artifactSha256: compilerSha256 },
    sourceRoots, libraryRoots: [], remappings: [],
    sourceUnits: snapshotFiles.map((file) => ({ sourceUnitName: file.sourceKey, snapshotSourceKey: file.sourceKey, rawSha256: file.rawSha256,
      byteLength: file.byteLength, contractNames: Object.keys(output.contracts?.[file.sourceKey] ?? {}).sort() })),
  });
  return { status: "supported", manifest };
}

/** Only exact checkout-relative paths or exact compiler source-unit names can align. */
export function alignScannerSource(manifest: CompilationManifest, checkoutRoot: string, reportedSourceIdentity: string | null | undefined,
  contract: string | null, identity: { findingId: string; scannerId: string; scannerVersion: string | null; detectorId: string | null }): ScannerSourceAlignment {
  const base = { ...identity, reportedSourceIdentity: reportedSourceIdentity ?? null, status: "unknown" as const,
    sourceUnitName: null, snapshotSourceKey: null, targetResolved: false };
  if (!reportedSourceIdentity) return base;
  if (reportedSourceIdentity.includes("\0") || reportedSourceIdentity.includes("\\")) return { ...base, status: "unaligned" };
  const root = path.resolve(checkoutRoot), candidate = path.isAbsolute(reportedSourceIdentity) ? path.resolve(reportedSourceIdentity) : null;
  if (candidate && !candidate.startsWith(`${root}${path.sep}`)) return { ...base, reportedSourceIdentity: null, status: "unaligned" };
  const rawName = candidate ? path.relative(root, candidate).split(path.sep).join("/") : reportedSourceIdentity;
  const name = rawName.startsWith("./") ? rawName.slice(2) : rawName;
  if (name.length > 500 || name.includes("//") || name.split("/").includes("..") || path.posix.normalize(name) !== name || name.startsWith("../")) return { ...base, reportedSourceIdentity: null, status: "unaligned" };
  const unit = manifest.sourceUnits.find((item) => item.sourceUnitName === name || item.snapshotSourceKey === name);
  if (!unit) return { ...base, reportedSourceIdentity: name, status: "unaligned" };
  return { ...base, reportedSourceIdentity: name, status: "aligned", sourceUnitName: unit.sourceUnitName,
    snapshotSourceKey: unit.snapshotSourceKey, targetResolved: !!contract && unit.contractNames.includes(contract) };
}
