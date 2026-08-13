import { describe, expect, it } from "vitest";
import type { ScanContext } from "@contracthunter/core";
import { MockScanner } from "./mock-scanner";

describe("MockScanner", () => {
  it("is available and returns clearly labelled valid demonstration findings", async () => {
    const scanner = new MockScanner();
    const context = {
      repositoryPath: "/tmp/repository",
      scan: {
        id: crypto.randomUUID(), repositoryUrl: "https://github.com/example/repo.git", repositoryName: "repo",
        requestedRef: null, resolvedCommit: "a".repeat(40), status: "scanning", framework: "foundry", depth: "quick",
        createdAt: new Date(), startedAt: new Date(), completedAt: null, error: null,
        scannerName: "ContractHunter Mock Scanner", scannerStatus: "running", scannerDurationMs: null,
      },
    } satisfies ScanContext;
    expect(await scanner.isAvailable()).toBe(true);
    const result = await scanner.scan(context);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings.every((finding) => finding.title.includes("[MOCK]") && finding.evidence.includes("MOCK DATA"))).toBe(true);
  });
});
