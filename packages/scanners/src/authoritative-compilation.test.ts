import { afterEach, describe, expect, it } from "vitest";
import { createHash, randomUUID } from "node:crypto";
import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { createDatabase, createScan, finalizeScanCompilation, finalizeScanSourceSnapshot, getFindingCompilationEligibility, getScanCompilation, insertFindings, insertScannerAlignment, listScannerAlignments, closeDatabase } from "@contracthunter/db";
import type { NewFinding } from "@contracthunter/core";
import { alignScannerSource, deriveAuthoritativeCompilation } from "./authoritative-compilation";
import { captureScanSourceSnapshot } from "./scan-source-snapshot";
import type { ProcessRunner } from "./process-runner";

const commit = "a".repeat(40);
const created: string[] = [];
afterEach(async () => { for (const root of created.splice(0)) await rm(root, { recursive: true, force: true }); });
async function fixture(files: Record<string, string>) {
  const root = await mkdtemp(path.join(tmpdir(), "ch-authority-")); created.push(root);
  const checkout = path.join(root, "checkout"), toolHomeDir = path.join(root, "tool-home");
  await mkdir(checkout);
  for (const [name, content] of Object.entries(files)) { await mkdir(path.dirname(path.join(checkout, name)), { recursive: true }); await writeFile(path.join(checkout, name), content); }
  const executable = path.join(toolHomeDir, ".solc-select", "artifacts", "solc-0.8.24", "solc-0.8.24");
  await mkdir(path.dirname(executable), { recursive: true }); await writeFile(executable, "trusted fixture compiler artifact"); await chmod(executable, 0o755);
  const calls: string[] = [];
  const processRunner: ProcessRunner = async (request) => {
    calls.push(request.args.join(" "));
    expect(request.command).toBe(executable);
    if (request.args[0] === "--version") return { exitCode: 0, stdout: "solc, Version: 0.8.24", stderr: "" };
    expect(request.args).toEqual(["--standard-json"]);
    expect(request.stdin).toBeDefined();
    const input = JSON.parse(request.stdin!);
    expect(input.settings.remappings).toEqual([]);
    expect(JSON.stringify(input)).not.toContain(checkout);
    return { exitCode: 0, stderr: "", stdout: JSON.stringify({ sources: Object.fromEntries(Object.keys(input.sources).map((key) => [key, { id: 0 }])), contracts: Object.fromEntries(Object.keys(input.sources).map((key) => [key, { [path.basename(key, ".sol")]: { abi: [] } }])) }) };
  };
  return { root, checkout, toolHomeDir, processRunner, calls, executable };
}
function finding(filePath: string, contract: string): NewFinding {
  return { title: "Fixture", severity: "high", confidence: 80, source: "slither", detectorId: "fixture-rule", fingerprint: createHash("sha256").update(`${filePath}:${contract}`).digest("hex"), contract, functionName: null, filePath, startLine: 1, endLine: 1, rootCause: "Fixture", attackScenario: "", impact: "", evidence: "Fixture", status: "candidate" };
}

describe("authoritative compilation and scanner alignment", () => {
  it("compiles a plain exact-pragma snapshot, persists source and compiler provenance, and survives checkout deletion", async () => {
    const f = await fixture({ "src/Token.sol": "pragma solidity 0.8.24; contract Token {}" });
    const snapshot = await captureScanSourceSnapshot(f.checkout);
    const db = createDatabase(path.join(f.root, "scan.db"));
    const scan = createScan(db, { repositoryUrl: "https://github.com/example/token", repositoryName: "example/token", depth: "quick" });
    db.sqlite.prepare("UPDATE scans SET status='preparing_dependencies',resolved_commit=?,dependency_status='ready' WHERE id=?").run(commit, scan.id);
    finalizeScanSourceSnapshot(db, scan.id, commit, snapshot);
    const result = await deriveAuthoritativeCompilation({ scanId: scan.id, resolvedCommit: commit, repositoryPath: f.checkout, toolHomeDir: f.toolHomeDir, snapshotFiles: snapshot, processRunner: f.processRunner });
    expect(result.status).toBe("supported");
    if (result.status !== "supported") throw new Error("fixture compilation did not succeed");
    expect(f.calls).toEqual(["--version", "--standard-json"]);
    expect(result.manifest.compiler.artifactSha256).toBe(createHash("sha256").update("trusted fixture compiler artifact").digest("hex"));
    expect(() => finalizeScanCompilation(db, scan.id, commit, { status: "supported", manifest: { ...result.manifest,
      sourceUnits: [{ ...result.manifest.sourceUnits[0], snapshotSourceKey: "src/Missing.sol" }] } })).toThrow();
    finalizeScanCompilation(db, scan.id, commit, result);
    const [row] = insertFindings(db, scan.id, [finding("src/Token.sol", "Token")]);
    const aligned = alignScannerSource(result.manifest, f.checkout, path.join(f.checkout, "src/Token.sol"), "Token", { findingId: row.id, scannerId: "slither", scannerVersion: "0.11.0", detectorId: "fixture-rule" });
    expect(aligned).toMatchObject({ status: "aligned", reportedSourceIdentity: "src/Token.sol", snapshotSourceKey: "src/Token.sol", targetResolved: true });
    insertScannerAlignment(db, scan.id, aligned);
    expect(getFindingCompilationEligibility(db, row.id)).toEqual({ eligible: true, sourceUnitName: "src/Token.sol", snapshotSourceKey: "src/Token.sol" });
    const [unresolved] = insertFindings(db, scan.id, [finding("src/Token.sol", "Other")]);
    insertScannerAlignment(db, scan.id, alignScannerSource(result.manifest, f.checkout, "src/Token.sol", "Other", { findingId: unresolved.id, scannerId: "slither", scannerVersion: null, detectorId: "fixture-rule" }));
    expect(getFindingCompilationEligibility(db, unresolved.id)).toEqual({ eligible: false, reason: "ambiguous_target" });
    const [missing] = insertFindings(db, scan.id, [finding("src/Missing.sol", "Token")]);
    insertScannerAlignment(db, scan.id, alignScannerSource(result.manifest, f.checkout, "src/Missing.sol", "Token", { findingId: missing.id, scannerId: "slither", scannerVersion: null, detectorId: "fixture-rule" }));
    expect(getFindingCompilationEligibility(db, missing.id)).toEqual({ eligible: false, reason: "scanner_source_unmappable" });
    await rm(f.checkout, { recursive: true });
    expect(getScanCompilation(db, scan.id)).toEqual({ status: "supported", manifest: result.manifest });
    expect(listScannerAlignments(db, scan.id)).toHaveLength(3);
    expect(listScannerAlignments(db, scan.id)).toContainEqual(aligned);
    expect(() => finalizeScanCompilation(db, scan.id, commit, result)).toThrow();
    expect(() => db.sqlite.prepare("UPDATE scan_compilation_source_units SET raw_sha256=? WHERE scan_id=?").run("b".repeat(64), scan.id)).toThrow();
    db.sqlite.prepare("DELETE FROM scans WHERE id=?").run(scan.id);
    expect(getScanCompilation(db, scan.id)).toEqual({ status: "legacy_or_unavailable" });
    closeDatabase(db);
  });

  it("keeps ambiguous, absent, and outside-checkout scanner paths unaligned", async () => {
    const f = await fixture({ "src/Token.sol": "pragma solidity 0.8.24; contract Token {}", "contracts/Token.sol": "pragma solidity 0.8.24; contract Token {}" });
    const snapshot = await captureScanSourceSnapshot(f.checkout);
    const result = await deriveAuthoritativeCompilation({ scanId: randomUUID(), resolvedCommit: commit, repositoryPath: f.checkout, toolHomeDir: f.toolHomeDir, snapshotFiles: snapshot, processRunner: f.processRunner });
    expect(result.status).toBe("supported"); if (result.status !== "supported") return;
    const identity = { findingId: randomUUID(), scannerId: "aderyn", scannerVersion: "0.6.0", detectorId: "rule" };
    expect(alignScannerSource(result.manifest, f.checkout, "Token.sol", "Token", identity).status).toBe("unaligned");
    expect(alignScannerSource(result.manifest, f.checkout, "./src/Token.sol", "Token", identity)).toMatchObject({ status: "aligned", reportedSourceIdentity: "src/Token.sol" });
    expect(alignScannerSource(result.manifest, f.checkout, "src/Missing.sol", "Token", identity).status).toBe("unaligned");
    expect(alignScannerSource(result.manifest, f.checkout, path.join(f.root, "other/Token.sol"), "Token", identity)).toMatchObject({ status: "unaligned", reportedSourceIdentity: null });
    expect(alignScannerSource(result.manifest, f.checkout, "src/Token.sol", "Other", identity)).toMatchObject({ status: "aligned", targetResolved: false });
    expect(alignScannerSource(result.manifest, f.checkout, null, "Token", identity).status).toBe("unknown");
  });

  it("classifies explicit Foundry and dynamic Hardhat config without running repository code", async () => {
    const source = "pragma solidity 0.8.24; contract Token {}";
    const hardhat = await fixture({ "src/Token.sol": source, "hardhat.config.js": "require('fs').writeFileSync('/tmp/should-not-exist','bad')" });
    const hardhatResult = await deriveAuthoritativeCompilation({ scanId: randomUUID(), resolvedCommit: commit, repositoryPath: hardhat.checkout, toolHomeDir: hardhat.toolHomeDir, snapshotFiles: await captureScanSourceSnapshot(hardhat.checkout), processRunner: hardhat.processRunner });
    expect(hardhatResult).toEqual({ status: "unsupported", reason: "dynamic_build_configuration" }); expect(hardhat.calls).toEqual([]);
    const foundry = await fixture({ "src/Token.sol": source, "foundry.toml": '[profile.default]\nsrc="src"\nsolc_version="0.8.24"\nremappings=["@x/=lib/x/"]' });
    const foundryResult = await deriveAuthoritativeCompilation({ scanId: randomUUID(), resolvedCommit: commit, repositoryPath: foundry.checkout, toolHomeDir: foundry.toolHomeDir, snapshotFiles: await captureScanSourceSnapshot(foundry.checkout), processRunner: foundry.processRunner });
    expect(foundryResult).toEqual({ status: "unsupported", reason: "unsupported_remapping_behavior" }); expect(foundry.calls).toEqual([]);
  });

  it("fails closed on ambiguous compiler and failed compilation probe", async () => {
    const f = await fixture({ "src/Token.sol": "pragma solidity ^0.8.24; contract Token {}" });
    const snapshot = await captureScanSourceSnapshot(f.checkout);
    expect(await deriveAuthoritativeCompilation({ scanId: randomUUID(), resolvedCommit: commit, repositoryPath: f.checkout, toolHomeDir: f.toolHomeDir, snapshotFiles: snapshot, processRunner: f.processRunner })).toEqual({ status: "unsupported", reason: "ambiguous_compiler" });
    const good = await fixture({ "src/Token.sol": "pragma solidity 0.8.24; contract Token {}" });
    expect(await deriveAuthoritativeCompilation({ scanId: randomUUID(), resolvedCommit: commit, repositoryPath: good.checkout, toolHomeDir: good.toolHomeDir, snapshotFiles: await captureScanSourceSnapshot(good.checkout), processRunner: async (request) => request.args[0] === "--version" ? { exitCode: 0, stdout: "Version: 0.8.24", stderr: "" } : { exitCode: 0, stdout: JSON.stringify({ errors: [{ severity: "error" }] }), stderr: "" } })).toEqual({ status: "unsupported", reason: "compilation_probe_failed" });
  });

  it("persists unsupported authority while retaining ordinary static findings and legacy absence", async () => {
    const f = await fixture({ "src/Token.sol": "pragma solidity 0.8.24; contract Token {}", "hardhat.config.ts": "throw new Error('must never execute')" });
    const db = createDatabase(path.join(f.root, "scan.db"));
    const historical = createScan(db, { repositoryUrl: "https://github.com/example/old", repositoryName: "example/old", depth: "quick" });
    expect(getScanCompilation(db, historical.id)).toEqual({ status: "legacy_or_unavailable" });
    const scan = createScan(db, { repositoryUrl: "https://github.com/example/new", repositoryName: "example/new", depth: "quick" });
    db.sqlite.prepare("UPDATE scans SET status='preparing_dependencies',resolved_commit=?,dependency_status='ready' WHERE id=?").run(commit, scan.id);
    const snapshot = await captureScanSourceSnapshot(f.checkout);
    finalizeScanSourceSnapshot(db, scan.id, commit, snapshot);
    const result = await deriveAuthoritativeCompilation({ scanId: scan.id, resolvedCommit: commit, repositoryPath: f.checkout, toolHomeDir: f.toolHomeDir, snapshotFiles: snapshot, processRunner: f.processRunner });
    expect(result).toEqual({ status: "unsupported", reason: "dynamic_build_configuration" });
    finalizeScanCompilation(db, scan.id, commit, result);
    expect(getScanCompilation(db, scan.id)).toEqual({ status: "unsupported", reason: "dynamic_build_configuration", resolvedCommit: commit });
    const [row] = insertFindings(db, scan.id, [finding("src/Token.sol", "Token")]);
    expect(getFindingCompilationEligibility(db, row.id)).toEqual({ eligible: false, reason: "unsupported_compilation" });
    expect(listScannerAlignments(db, scan.id)).toEqual([]);
    closeDatabase(db);
  });
});
