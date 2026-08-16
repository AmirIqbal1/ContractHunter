import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { canTransition, configSchema, detectFramework, findingSchema, loadConfig, validateGitHubUrl } from "./index";

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
    expect(canTransition("detecting", "preparing_dependencies")).toBe(true);
    expect(canTransition("preparing_dependencies", "preparing_compiler")).toBe(true);
    expect(canTransition("preparing_compiler", "scanning")).toBe(true);
    expect(canTransition("completed", "scanning")).toBe(false);
  });
});

describe("finding validation", () => {
  it("rejects invalid confidence and line ranges", () => {
    const base = {
      id: crypto.randomUUID(), scanId: crypto.randomUUID(), title: "Test", severity: "high", confidence: 101,
      source: "test", contract: null, functionName: null, filePath: null, startLine: 10, endLine: 2,
      detectorId: "test-detector", fingerprint: "a".repeat(64),
      rootCause: "Cause", attackScenario: "Scenario", impact: "Impact", evidence: "Evidence", status: "candidate", createdAt: new Date(),
    };
    expect(findingSchema.safeParse(base).success).toBe(false);
  });
});

describe("configuration validation", () => {
  it("requires repository and database paths to remain under DATA_DIR", () => {
    mkdirSync("/tmp/contracthunter-config-test", { recursive: true });
    const valid = { NODE_ENV: "test", DATA_DIR: "/tmp/contracthunter-config-test", REPOSITORY_DIR: "/tmp/contracthunter-config-test/repos", DATABASE_PATH: "/tmp/contracthunter-config-test/db.sqlite", GIT_CLONE_TIMEOUT_MS: 10_000, SLITHER_TIMEOUT_MS: 300_000, SCANNER_MAX_OUTPUT_BYTES: 20_971_520, SOLC_INSTALL_TIMEOUT_MS: 120_000, MAX_SOLC_VERSIONS_PER_SCAN: 8, ALLOW_COMPILER_DOWNLOADS: "true", TOOL_HOME_DIR: "/tmp/contracthunter-config-test/tool-home", DEPENDENCY_PREP_TIMEOUT_MS: 300_000, MAX_DEPENDENCY_OUTPUT_BYTES: 20_971_520, MAX_SUBMODULE_DEPTH: 5, MAX_SUBMODULES_PER_SCAN: 100, ALLOW_NPM_DEPENDENCIES: "true", ALLOW_GIT_SUBMODULES: "true", ALLOWED_GIT_DEPENDENCY_HOSTS: "github.com" };
    expect(configSchema.safeParse(valid).success).toBe(true);
    expect(configSchema.parse(valid).OPENAI_MODEL).toBe("gpt-5.6-luna");
    expect(configSchema.safeParse({ ...valid, REPOSITORY_DIR: "/tmp/outside" }).success).toBe(false);
    expect(configSchema.safeParse({ ...valid, AI_ENABLED: "true", OPENAI_MODEL: "" }).success).toBe(false);
    expect(configSchema.safeParse({ ...valid, AI_ENABLED: "true", OPENAI_MODEL: "gpt-5-mini" }).success).toBe(true);
    expect(configSchema.safeParse({ ...valid, AI_MAX_REVIEWERS: 99 }).success).toBe(false);
    expect(configSchema.safeParse({ ...valid, AI_REVIEW_CONCURRENCY: 0 }).success).toBe(false);
    expect(configSchema.safeParse({ ...valid, AI_REVIEW_MAX_TOTAL_REQUESTS: 0 }).success).toBe(false);
    expect(configSchema.safeParse({ ...valid, AI_VERIFICATION_PLAN_MAX_FILES: 0 }).success).toBe(false);
    expect(configSchema.safeParse({ ...valid, AI_VERIFICATION_PLAN_MAX_SOURCE_BYTES: 100 }).success).toBe(false);
    expect(configSchema.safeParse({ ...valid, AI_VERIFICATION_PLAN_TIMEOUT_MS: 500 }).success).toBe(false);
    expect(configSchema.safeParse({ ...valid, AI_INPUT_COST_PER_MILLION_USD: -1 }).success).toBe(false);
    expect(configSchema.safeParse({ ...valid, AI_OUTPUT_COST_PER_MILLION_USD: "Infinity" }).success).toBe(false);
    expect(configSchema.safeParse({ ...valid, AI_INPUT_COST_PER_MILLION_USD: 10_001 }).success).toBe(false);
  });

  it("parses configured token prices and supplies current-model defaults", () => {
    expect(loadConfig({ NODE_ENV: "test", DATA_DIR: "/tmp/contracthunter-cost-config", REPOSITORY_DIR: "/tmp/contracthunter-cost-config/repos", DATABASE_PATH: "/tmp/contracthunter-cost-config/db.sqlite", TOOL_HOME_DIR: "/tmp/contracthunter-cost-config/tools", AI_INPUT_COST_PER_MILLION_USD: "1.5", AI_OUTPUT_COST_PER_MILLION_USD: "4.25" })).toMatchObject({ AI_INPUT_COST_PER_MILLION_USD: 1.5, AI_OUTPUT_COST_PER_MILLION_USD: 4.25 });
    expect(loadConfig({ NODE_ENV: "test", DATA_DIR: "/tmp/contracthunter-cost-defaults", REPOSITORY_DIR: "/tmp/contracthunter-cost-defaults/repos", DATABASE_PATH: "/tmp/contracthunter-cost-defaults/db.sqlite", TOOL_HOME_DIR: "/tmp/contracthunter-cost-defaults/tools" })).toMatchObject({ AI_INPUT_COST_PER_MILLION_USD: 0.25, AI_OUTPUT_COST_PER_MILLION_USD: 2 });
  });
});
