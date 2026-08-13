import { describe, expect, it, vi } from "vitest";
import type { ScanContext } from "@contracthunter/core";
import { ProcessOutputLimitError, ProcessTimeoutError, type ProcessRunner } from "./process-runner";
import { SlitherScanner } from "./slither-scanner";

const root = "/data/repositories";
const context: ScanContext = {
  repositoryPath: `${root}/123e4567-e89b-42d3-a456-426614174000`,
  scan: {
    id: "123e4567-e89b-42d3-a456-426614174000", repositoryUrl: "https://github.com/example/repo.git", repositoryName: "repo",
    requestedRef: null, resolvedCommit: "a".repeat(40), status: "scanning", framework: "foundry", depth: "quick",
    createdAt: new Date(), startedAt: new Date(), completedAt: null, error: null,
    scannerName: "Slither", scannerStatus: "running", scannerDurationMs: null,
  },
};

function scanner(processRunner: ProcessRunner) {
  return new SlitherScanner({ workspaceRoot: root, timeoutMs: 5_000, maxOutputBytes: 10_000, processRunner });
}

describe("SlitherScanner process behavior", () => {
  it("reports available and unavailable", async () => {
    const available = scanner(vi.fn().mockResolvedValue({ stdout: "0.11.3", stderr: "", exitCode: 0 }));
    const unavailable = scanner(vi.fn().mockResolvedValue({ stdout: "", stderr: "missing", exitCode: 127 }));
    expect(await available.isAvailable()).toBe(true);
    expect(await unavailable.isAvailable()).toBe(false);
  });

  it("runs with explicit safe arguments and accepts valid JSON despite stderr", async () => {
    const runner = vi.fn().mockResolvedValue({ stdout: JSON.stringify({ success: true, results: { detectors: [] } }), stderr: "compiler note", exitCode: 0 });
    const result = await scanner(runner).scan(context);
    expect(result.findings).toEqual([]);
    expect(runner).toHaveBeenCalledWith(expect.objectContaining({ command: "slither", args: [".", "--json", "-", "--disable-color"], cwd: context.repositoryPath }));
  });

  it("reports timeout, non-zero exit, and oversized output cleanly", async () => {
    await expect(scanner(vi.fn().mockRejectedValue(new ProcessTimeoutError())).scan(context)).rejects.toThrow("timed out");
    await expect(scanner(vi.fn().mockResolvedValue({ stdout: "", stderr: "solc missing", exitCode: 1 })).scan(context)).rejects.toThrow("solc missing");
    await expect(scanner(vi.fn().mockRejectedValue(new ProcessOutputLimitError())).scan(context)).rejects.toThrow("output exceeded");
  });

  it("rejects malformed JSON and workspace traversal", async () => {
    await expect(scanner(vi.fn().mockResolvedValue({ stdout: "bad", stderr: "", exitCode: 0 })).scan(context)).rejects.toThrow("parsing error");
    await expect(scanner(vi.fn()).scan({ ...context, repositoryPath: "/etc" })).rejects.toThrow("outside the configured repository directory");
  });
});
