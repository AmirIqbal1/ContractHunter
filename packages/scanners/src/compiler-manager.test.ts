import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it, vi } from "vitest";
import { CompilerManager } from "./compiler-manager";
import { ProcessTimeoutError, type ProcessRequest, type ProcessRunner } from "./process-runner";

async function repository(pragma = "0.8.24") { const root = await mkdtemp(path.join(tmpdir(), "contracthunter-manager-")); await writeFile(path.join(root, "A.sol"), `pragma solidity ${pragma}; contract A {}`); return root; }

function mockRunner(installed: Set<string>, options: { available?: string[]; failInstall?: boolean; delayInstall?: boolean } = {}) {
  const calls: ProcessRequest[] = [];
  const runner: ProcessRunner = async (request) => {
    calls.push(request);
    if (request.command === "solc-select" && request.args[0] === "--version") return { stdout: "1.2.0", stderr: "", exitCode: 0 };
    if (request.command === "solc-select" && request.args[0] === "versions") return { stdout: [...installed].join("\n"), stderr: "", exitCode: 0 };
    if (request.command === "solc-select" && request.args.length === 1) return { stdout: (options.available ?? ["0.8.24"]).join(" "), stderr: "", exitCode: 0 };
    if (request.command === "solc-select" && request.args[0] === "install") {
      if (options.delayInstall) await new Promise((resolve) => setTimeout(resolve, 15));
      if (options.failInstall) return { stdout: "", stderr: "download failed", exitCode: 1 };
      installed.add(request.args[1]); return { stdout: "installed", stderr: "", exitCode: 0 };
    }
    if (request.command === "solc") return { stdout: `Version: ${request.env?.SOLC_VERSION}`, stderr: "", exitCode: 0 };
    throw new Error(`Unexpected ${request.command} ${request.args.join(" ")}`);
  };
  return { runner, calls };
}

async function manager(repo: string, processRunner: ProcessRunner, allowDownloads = true) {
  return new CompilerManager({ workspaceRoot: path.dirname(repo), toolHomeDir: path.join(repo, ".tools"), installTimeoutMs: 5_000, maxOutputBytes: 10_000, maxVersions: 8, allowDownloads, processRunner });
}

describe("CompilerManager and solc-select", () => {
  it("checks availability and unavailability", async () => {
    const repo = await repository(); const { runner } = mockRunner(new Set());
    expect(await (await manager(repo, runner)).isAvailable()).toBe(true);
    expect(await (await manager(repo, vi.fn().mockRejectedValue(new Error("missing")))).isAvailable()).toBe(false);
  });
  it("uses an installed compiler without installing it", async () => {
    const repo = await repository(); const mock = mockRunner(new Set(["0.8.24"]));
    const result = await (await manager(repo, mock.runner)).prepare(repo);
    expect(result.cached).toBe(true);
    expect(mock.calls.filter((call) => call.args[0] === "install" && call.args.length > 1)).toHaveLength(0);
  });
  it("installs a missing compiler and verifies it", async () => {
    const repo = await repository(); const mock = mockRunner(new Set());
    const result = await (await manager(repo, mock.runner)).prepare(repo);
    expect(result.versions).toEqual(["0.8.24"]);
    expect(mock.calls).toContainEqual(expect.objectContaining({ command: "solc-select", args: ["install", "0.8.24"] }));
  });
  it("fails when installation is disabled, times out, or download fails", async () => {
    const repo = await repository();
    await expect((await manager(repo, mockRunner(new Set()).runner, false)).prepare(repo)).rejects.toThrow("downloads are disabled");
    const timeoutRunner: ProcessRunner = async (request) => {
      if (request.command === "solc-select" && request.args[0] === "--version") return { stdout: "1.2.0", stderr: "", exitCode: 0 };
      throw new ProcessTimeoutError();
    };
    await expect((await manager(repo, timeoutRunner)).prepare(repo)).rejects.toThrow("timed out");
    await expect((await manager(repo, mockRunner(new Set(), { failInstall: true }).runner)).prepare(repo)).rejects.toThrow("download failed");
  });
  it("coalesces concurrent installation of the same version", async () => {
    const repo = await repository(); const mock = mockRunner(new Set(), { delayInstall: true });
    const first = await manager(repo, mock.runner); const second = await manager(repo, mock.runner);
    await Promise.all([first.prepare(repo), second.prepare(repo)]);
    expect(mock.calls.filter((call) => call.args[0] === "install" && call.args.length > 1)).toHaveLength(1);
  });
});
