import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { MockAIProvider, type ProtocolAnalysisResult } from "@contracthunter/core";
import { closeDatabase, createDatabase, createScan, getScan, listInvariants, listProtocolAnalyses } from "@contracthunter/db";
import { runProtocolAnalysis } from "./analysis-service";
import { validAIOutput } from "../../../../packages/core/src/ai-test-fixture";

const directories: string[] = []; const original = { ...process.env };
afterEach(() => { for (const key of Object.keys(process.env)) if (!(key in original)) delete process.env[key]; Object.assign(process.env, original); directories.splice(0).forEach((root) => rmSync(root, { recursive: true, force: true })); });
function setup() {
  const root = mkdtempSync(path.join(tmpdir(), "contracthunter-ai-service-")); directories.push(root); const repository = path.join(root, "repositories", "fixture"); mkdirSync(path.join(repository, "src"), { recursive: true }); writeFileSync(path.join(repository, "src/Vault.sol"), "contract Vault {\nfunction withdraw() external {}\n}\n");
  Object.assign(process.env, { DATA_DIR: root, DATABASE_PATH: path.join(root, "db.sqlite"), REPOSITORY_DIR: path.join(root, "repositories"), TOOL_HOME_DIR: path.join(root, "tools"), AI_ENABLED: "true", OPENAI_API_KEY: "test-only-secret", OPENAI_MODEL: "configured-model" });
  const database = createDatabase(path.join(root, "db.sqlite")); const scan = createScan(database, { repositoryUrl: "https://github.com/example/fixture", repositoryName: "fixture", depth: "quick" }); database.sqlite.prepare("UPDATE scans SET status = 'completed' WHERE id = ?").run(scan.id); return { root, repository, database, scan };
}

describe.sequential("AI analysis pipeline", () => {
  it("persists successful analyses, proposed invariants, metadata, and rerun history", async () => {
    const { repository, database, scan } = setup(); const provider = new MockAIProvider(validAIOutput as unknown as ProtocolAnalysisResult);
    try { await runProtocolAnalysis({ scanId: scan.id, provider, database, repositoryPath: repository }); await runProtocolAnalysis({ scanId: scan.id, provider, database, repositoryPath: repository });
      const history = listProtocolAnalyses(database, scan.id); expect(history).toHaveLength(2); expect(history.filter((item) => item.isLatest)).toHaveLength(1); expect(history[0]).toMatchObject({ requestedModel: "configured-model", promptVersion: "protocol-analysis-v1", totalTokens: 150 });
      expect(listInvariants(database, { scanId: scan.id })[0]).toMatchObject({ status: "proposed", testability: "stateful-invariant" }); expect(provider.calls[0].context.content).toContain("UNTRUSTED_REPOSITORY_DATA"); expect(provider.calls[0].context.content).not.toContain("test-only-secret");
    } finally { closeDatabase(database); }
  });

  it("keeps a completed static scan usable when the provider fails", async () => {
    const { repository, database, scan } = setup();
    try { expect(await runProtocolAnalysis({ scanId: scan.id, provider: new MockAIProvider(new Error("provider unavailable")), database, repositoryPath: repository })).toBeNull(); expect(getScan(database, scan.id)).toMatchObject({ status: "completed", aiStatus: "failed" }); expect(listProtocolAnalyses(database, scan.id)).toHaveLength(0); } finally { closeDatabase(database); }
  });

  it("records disabled state without calling a provider", async () => {
    const { repository, database, scan } = setup(); process.env.AI_ENABLED = "false";
    try { expect(await runProtocolAnalysis({ scanId: scan.id, database, repositoryPath: repository })).toBeNull(); expect(getScan(database, scan.id)?.aiStatus).toBe("disabled"); } finally { closeDatabase(database); }
  });

  it("records an unconfigured provider without affecting static completion", async () => {
    const { repository, database, scan } = setup(); process.env.OPENAI_API_KEY = "";
    try { expect(await runProtocolAnalysis({ scanId: scan.id, database, repositoryPath: repository })).toBeNull(); expect(getScan(database, scan.id)).toMatchObject({ status: "completed", aiStatus: "failed", aiError: "OpenAI is not configured." }); } finally { closeDatabase(database); }
  });
});
