import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it, vi } from "vitest";
import type { ScanContext } from "@contracthunter/core";
import { AderynScanner } from "./aderyn-scanner";
import { ProcessOutputLimitError, ProcessTimeoutError, type ProcessRequest, type ProcessRunner } from "./process-runner";

async function setup() {
  const root = await mkdtemp(path.join(tmpdir(), "aderyn-scanner-"));
  const repositoryPath = path.join(root, "scan");
  await import("node:fs/promises").then(({ mkdir }) => mkdir(repositoryPath));
  await writeFile(path.join(repositoryPath, "Unsafe.sol"), "pragma solidity 0.8.24; contract Unsafe {}");
  const context: ScanContext = { repositoryPath, scan: { id: "123e4567-e89b-42d3-a456-426614174000", repositoryUrl: "https://github.com/example/repo.git", repositoryName: "repo", requestedRef: null, resolvedCommit: "a".repeat(40), status: "scanning", framework: "foundry", depth: "quick", createdAt: new Date(), startedAt: new Date(), completedAt: null, error: null, scannerName: "Slither + Aderyn", scannerStatus: "running", scannerDurationMs: null, compilerConstraints: null, compilerVersions: null, compilerDetectionSource: null, compilerStatus: "ready", compilerError: null, dependencyStatus: "ready", dependencyMetadata: null, dependencyError: null } };
  return { root, repositoryPath, context };
}

const output = (issues: unknown[] = []) => JSON.stringify({ issue_count: { high: issues.length, low: 0 }, high_issues: { issues }, low_issues: { issues: [] } });

function scanner(root: string, runner: ProcessRunner) { return new AderynScanner({ workspaceRoot: root, toolHomeDir: path.join(root, "tools"), timeoutMs: 5_000, maxOutputBytes: 10_000, processRunner: runner }); }

describe("AderynScanner", () => {
  it("reports availability and unavailability", async () => {
    const { root } = await setup();
    expect(await scanner(root, async () => ({ stdout: "aderyn 0.6.8", stderr: "", exitCode: 0 })).isAvailable()).toBe(true);
    expect(await scanner(root, vi.fn().mockRejectedValue(new Error("missing"))).isAvailable()).toBe(false);
  });

  it("runs with supported JSON output arguments and returns findings", async () => {
    const { root, repositoryPath, context } = await setup();
    const calls: ProcessRequest[] = [];
    const runner: ProcessRunner = async (request) => {
      calls.push(request);
      if (request.args[0] === "--version") return { stdout: "aderyn 0.6.8", stderr: "", exitCode: 0 };
      const reportPath = request.args[request.args.indexOf("--output") + 1];
      await writeFile(reportPath, output([{ title: "State Change Without Event", detector_name: "state-change-without-event", instances: [{ contract_path: "Unsafe.sol", line_no: 1 }] }]));
      return { stdout: "Done", stderr: "", exitCode: 0 };
    };
    const result = await scanner(root, runner).scan(context);
    expect(result.findings).toHaveLength(1);
    expect(calls[0]).toMatchObject({ command: "aderyn", cwd: repositoryPath });
    expect(calls[0].args[0]).toBe(".");
    expect(calls[0].args).toContain("--output");
    expect(calls[0].env?.HOME).toBe(path.join(root, "tools"));
  });

  it("accepts a valid zero-finding report", async () => {
    const { root, context } = await setup();
    const runner: ProcessRunner = async (request) => { await writeFile(request.args.at(-1) ?? "", output()); return { stdout: "", stderr: "", exitCode: 0 }; };
    await expect(scanner(root, runner).scan(context)).resolves.toMatchObject({ findings: [] });
  });

  it.each([
    ["timeout", new ProcessTimeoutError(), "timed out"],
    ["oversized", new ProcessOutputLimitError(), "output exceeded"],
  ])("handles %s", async (_name, error, message) => {
    const { root, context } = await setup();
    await expect(scanner(root, async () => { throw error; }).scan(context)).rejects.toThrow(message);
  });

  it("handles non-zero exit, malformed reports, and missing reports", async () => {
    const failed = await setup();
    await expect(scanner(failed.root, async () => ({ stdout: "", stderr: "compile failed", exitCode: 1 })).scan(failed.context)).rejects.toThrow("Aderyn analysis failed");
    const malformed = await setup();
    await expect(scanner(malformed.root, async (request) => { await writeFile(request.args.at(-1) ?? "", "bad-json"); return { stdout: "", stderr: "", exitCode: 0 }; }).scan(malformed.context)).rejects.toThrow("Aderyn parsing error");
    const missing = await setup();
    await expect(scanner(missing.root, async () => ({ stdout: "", stderr: "", exitCode: 0 })).scan(missing.context)).rejects.toThrow("did not produce");
  });
});
