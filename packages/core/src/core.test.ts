import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { canTransition, configSchema, detectFramework, findingSchema, validateGitHubUrl } from "./index";

describe("GitHub URL validation", () => {
  it("normalises an HTTPS repository URL", () => {
    expect(validateGitHubUrl("https://github.com/openzeppelin/openzeppelin-contracts")).toEqual({
      url: "https://github.com/openzeppelin/openzeppelin-contracts.git", name: "openzeppelin-contracts",
    });
  });

  it.each(["http://github.com/org/repo", "https://gitlab.com/org/repo", "https://user:secret@github.com/org/repo", "https://github.com/org/repo/issues"])("rejects unsafe or unsupported URL %s", (url) => {
    expect(() => validateGitHubUrl(url)).toThrow();
  });
});

describe("framework detection", () => {
  it("detects Foundry without executing repository code", () => {
    const directory = mkdtempSync(path.join(tmpdir(), "contracthunter-test-"));
    writeFileSync(path.join(directory, "foundry.toml"), "[profile.default]");
    expect(detectFramework(directory)).toBe("foundry");
  });

  it("detects Hardhat and unknown repositories", () => {
    const hardhat = mkdtempSync(path.join(tmpdir(), "contracthunter-test-"));
    writeFileSync(path.join(hardhat, "hardhat.config.ts"), "throw new Error('must not execute')");
    expect(detectFramework(hardhat)).toBe("hardhat");
    expect(detectFramework(mkdtempSync(path.join(tmpdir(), "contracthunter-test-")))).toBe("unknown");
  });
});

describe("scan transitions", () => {
  it("permits only the declared pipeline and failure exits", () => {
    expect(canTransition("queued", "cloning")).toBe(true);
    expect(canTransition("scanning", "completed")).toBe(true);
    expect(canTransition("detecting", "failed")).toBe(true);
    expect(canTransition("completed", "scanning")).toBe(false);
  });
});

describe("finding validation", () => {
  it("rejects invalid confidence and line ranges", () => {
    const base = {
      id: crypto.randomUUID(), scanId: crypto.randomUUID(), title: "Test", severity: "high", confidence: 101,
      source: "test", contract: null, functionName: null, filePath: null, startLine: 10, endLine: 2,
      rootCause: "Cause", attackScenario: "Scenario", impact: "Impact", evidence: "Evidence", status: "candidate", createdAt: new Date(),
    };
    expect(findingSchema.safeParse(base).success).toBe(false);
  });
});

describe("configuration validation", () => {
  it("requires repository and database paths to remain under DATA_DIR", () => {
    mkdirSync("/tmp/contracthunter-config-test", { recursive: true });
    const valid = { NODE_ENV: "test", DATA_DIR: "/tmp/contracthunter-config-test", REPOSITORY_DIR: "/tmp/contracthunter-config-test/repos", DATABASE_PATH: "/tmp/contracthunter-config-test/db.sqlite", GIT_CLONE_TIMEOUT_MS: 10_000 };
    expect(configSchema.safeParse(valid).success).toBe(true);
    expect(configSchema.safeParse({ ...valid, REPOSITORY_DIR: "/tmp/outside" }).success).toBe(false);
  });
});
