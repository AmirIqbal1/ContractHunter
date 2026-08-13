import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it, vi } from "vitest";
import type { ScanContext } from "@contracthunter/core";
import { ProcessOutputLimitError, ProcessTimeoutError, type ProcessRequest, type ProcessRunner } from "./process-runner";
import { SlitherScanner } from "./slither-scanner";

async function setup(pragmas = ["0.8.24"]) {
  const root = await mkdtemp(path.join(tmpdir(), "contracthunter-slither-"));
  const repositoryPath = path.join(root, "scan");
  await import("node:fs/promises").then(({ mkdir }) => mkdir(repositoryPath));
  for (const [index, pragma] of pragmas.entries()) await writeFile(path.join(repositoryPath, `${index}.sol`), `pragma solidity ${pragma}; contract C${index} {}`);
  const context: ScanContext = {
    repositoryPath,
    scan: {
      id: "123e4567-e89b-42d3-a456-426614174000", repositoryUrl: "https://github.com/example/repo.git", repositoryName: "repo",
      requestedRef: null, resolvedCommit: "a".repeat(40), status: "scanning", framework: "foundry", depth: "quick",
      createdAt: new Date(), startedAt: new Date(), completedAt: null, error: null,
      scannerName: "Slither", scannerStatus: "running", scannerDurationMs: null,
      compilerConstraints: null, compilerVersions: null, compilerDetectionSource: null, compilerStatus: "pending", compilerError: null,
    },
  };
  return { root, context };
}

function processMock(versions = ["0.8.24"], reportedVersion?: string) {
  const calls: ProcessRequest[] = [];
  const runner: ProcessRunner = async (request) => {
    calls.push(request);
    if (request.command === "slither" && request.args[0] === "--version") return { stdout: "0.11.3", stderr: "", exitCode: 0 };
    if (request.command === "solc-select" && request.args[0] === "--version") return { stdout: "1.2.0", stderr: "", exitCode: 0 };
    if (request.command === "solc-select" && request.args[0] === "versions") return { stdout: versions.join("\n"), stderr: "", exitCode: 0 };
    if (request.command === "solc-select" && request.args.length === 1) return { stdout: versions.join(" "), stderr: "", exitCode: 0 };
    if (request.command === "solc") return { stdout: `Version: ${reportedVersion ?? request.env?.SOLC_VERSION}`, stderr: "", exitCode: 0 };
    if (request.command === "slither" && request.args[0] === "--help") return { stdout: "--solc-solcs-select", stderr: "", exitCode: 0 };
    if (request.command === "slither") return { stdout: JSON.stringify({ success: true, results: { detectors: [] } }), stderr: "compiler note", exitCode: 0 };
    throw new Error(`Unexpected process: ${request.command}`);
  };
  return { runner, calls };
}

function scanner(root: string, processRunner: ProcessRunner) {
  return new SlitherScanner({ workspaceRoot: root, timeoutMs: 5_000, maxOutputBytes: 10_000, toolHomeDir: path.join(root, "tools"), installTimeoutMs: 5_000, maxSolcVersions: 8, allowCompilerDownloads: true, processRunner });
}

describe("SlitherScanner compiler integration", () => {
  it("reports Slither available and unavailable", async () => {
    const { root } = await setup();
    expect(await scanner(root, processMock().runner).isAvailable()).toBe(true);
    expect(await scanner(root, vi.fn().mockRejectedValue(new Error("missing"))).isAvailable()).toBe(false);
  });

  it("passes SOLC_VERSION only to child processes and leaves global environment untouched", async () => {
    const { root, context } = await setup(); const mock = processMock();
    const previous = process.env.SOLC_VERSION;
    await scanner(root, mock.runner).scan(context);
    const slitherCall = mock.calls.find((call) => call.command === "slither" && call.args[0] === ".");
    expect(slitherCall?.env?.SOLC_VERSION).toBe("0.8.24");
    expect(process.env.SOLC_VERSION).toBe(previous);
  });

  it("accepts validated successful JSON even when Slither uses a findings exit code", async () => {
    const { root, context } = await setup(); const base = processMock();
    const runner: ProcessRunner = async (request) => request.command === "slither" && request.args[0] === "."
      ? { stdout: JSON.stringify({ success: true, results: { detectors: [] } }), stderr: "", exitCode: 255 }
      : base.runner(request);
    await expect(scanner(root, runner).scan(context)).resolves.toMatchObject({ findings: [] });
  });

  it("passes resolved versions through Slither multi-compiler selection", async () => {
    const { root, context } = await setup(["^0.7.0", "^0.8.20"]); const mock = processMock(["0.7.6", "0.8.24"]);
    await scanner(root, mock.runner).scan(context);
    expect(mock.calls.find((call) => call.command === "slither" && call.args[0] === ".")?.args).toContain("0.7.6,0.8.24");
  });

  it("aborts before Slither when compiler verification is incorrect", async () => {
    const { root, context } = await setup(); const mock = processMock(["0.8.24"], "0.8.23");
    await expect(scanner(root, mock.runner).scan(context)).rejects.toThrow("verification failed");
    expect(mock.calls.some((call) => call.command === "slither" && call.args[0] === ".")).toBe(false);
  });

  it("reports timeout, malformed output, non-zero exit, and oversized output", async () => {
    const { root, context } = await setup();
    const base = processMock();
    const override = (failure: "timeout" | "malformed" | "exit" | "oversized"): ProcessRunner => async (request) => {
      if (request.command === "slither" && request.args[0] === ".") {
        if (failure === "timeout") throw new ProcessTimeoutError();
        if (failure === "oversized") throw new ProcessOutputLimitError();
        if (failure === "malformed") return { stdout: "bad", stderr: "", exitCode: 0 };
        return { stdout: "", stderr: "solc missing", exitCode: 1 };
      }
      return base.runner(request);
    };
    await expect(scanner(root, override("timeout")).scan(context)).rejects.toThrow("timed out");
    await expect(scanner(root, override("malformed")).scan(context)).rejects.toThrow("parsing error");
    await expect(scanner(root, override("exit")).scan(context)).rejects.toThrow("solc missing");
    await expect(scanner(root, override("oversized")).scan(context)).rejects.toThrow("output exceeded");
  });
});
