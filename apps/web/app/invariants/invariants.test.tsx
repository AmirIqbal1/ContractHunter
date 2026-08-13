import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { renderToStaticMarkup } from "react-dom/server";
import { afterAll, describe, expect, it, vi } from "vitest";
import { validAIOutput } from "../../../../packages/core/src/ai-test-fixture";

vi.mock("next/navigation", () => ({ notFound: () => { throw new Error("not found"); }, useRouter: () => ({ refresh: vi.fn() }) }));
const directory = mkdtempSync(path.join(tmpdir(), "contracthunter-invariant-ui-")); mkdirSync(path.join(directory, "repositories"));
Object.assign(process.env, { DATA_DIR: directory, DATABASE_PATH: path.join(directory, "ui.db"), REPOSITORY_DIR: path.join(directory, "repositories"), TOOL_HOME_DIR: path.join(directory, "tools") });

import InvariantsPage from "./page";
import InvariantPage from "./[id]/page";
import ProtocolAnalysisPage from "../protocol-analyses/[id]/page";
import { PATCH } from "../api/invariants/[id]/route";
import { closeDatabase, createProtocolAnalysis, createScan, getDatabase, listInvariants } from "@contracthunter/db";

describe("protocol analysis and invariant review UI", () => {
  const database = getDatabase(); const scan = createScan(database, { repositoryUrl: "https://github.com/example/vault", repositoryName: "vault", depth: "quick" });
  const analysis = createProtocolAnalysis(database, { scanId: scan.id, provider: "mock", requestedModel: "mock", actualModel: "mock", promptVersion: "protocol-analysis-v1", result: validAIOutput as never, coverageStatus: "complete", contextManifest: { approximateInputBytes: 1000 }, durationMs: 5, inputTokens: 10, outputTokens: 10, totalTokens: 20, requestId: "mock" });
  const invariant = listInvariants(database, { scanId: scan.id })[0];
  afterAll(() => { closeDatabase(database); rmSync(directory, { recursive: true, force: true }); });

  it("renders list filters, protocol sections, invariant evidence, and manual status changes", async () => {
    const list = renderToStaticMarkup(await InvariantsPage({ searchParams: Promise.resolve({ category: "share-accounting" }) })); expect(list).toContain("Share conservation"); expect(list).toContain("stateful-invariant");
    const model = renderToStaticMarkup(await ProtocolAnalysisPage({ params: Promise.resolve({ id: analysis.id }) })); expect(model).toContain("Protocol summary"); expect(model).toContain("Trust assumptions"); expect(model).toContain("Proposed invariants");
    const detail = renderToStaticMarkup(await InvariantPage({ params: Promise.resolve({ id: invariant.id }) })); expect(detail).toContain("Withdrawals cannot exceed"); expect(detail).toContain("Repository evidence");
    const accepted = await PATCH(new Request("http://localhost", { method: "PATCH", body: JSON.stringify({ status: "accepted" }) }), { params: Promise.resolve({ id: invariant.id }) }); expect(accepted.status).toBe(200);
    const violated = await PATCH(new Request("http://localhost", { method: "PATCH", body: JSON.stringify({ status: "violated" }) }), { params: Promise.resolve({ id: invariant.id }) }); expect(violated.status).toBe(400);
  });
});
