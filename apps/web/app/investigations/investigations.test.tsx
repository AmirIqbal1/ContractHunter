import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { renderToStaticMarkup } from "react-dom/server";
import { afterAll, describe, expect, it, vi } from "vitest";
import type { NewFinding } from "@contracthunter/core";

vi.mock("next/navigation", () => ({
  notFound: () => { throw new Error("not found"); },
  useRouter: () => ({ refresh: vi.fn() }),
}));

const directory = mkdtempSync(path.join(tmpdir(), "contracthunter-ui-"));
process.env.DATA_DIR = directory;
process.env.DATABASE_PATH = path.join(directory, "ui.db");
process.env.REPOSITORY_DIR = path.join(directory, "repositories");
process.env.TOOL_HOME_DIR = path.join(directory, "tool-home");

import InvestigationsPage from "./page";
import InvestigationPage from "./[id]/page";
import { PATCH } from "../api/investigations/[id]/route";
import { closeDatabase, createScan, getDatabase, insertFindings, reconcileInvestigations } from "@contracthunter/db";

const raw = (source: string, fingerprint: string): NewFinding => ({
  title: source === "slither" ? "Missing zero-address validation" : "Address State Variable Set Without Checks",
  severity: "low", confidence: source === "slither" ? 70 : 40, source,
  detectorId: source === "slither" ? "missing-zero-check" : "state-no-address-check", fingerprint,
  contract: source === "slither" ? "Unsafe" : null, functionName: source === "slither" ? "setOwner" : null,
  filePath: "Unsafe.sol", startLine: source === "slither" ? 7 : 8, endLine: 8,
  rootCause: "Address assignment has no zero-address check.", attackScenario: "", impact: "", evidence: `${source} evidence`, status: "candidate",
});

describe("investigation review UI", () => {
  const database = getDatabase();
  const scan = createScan(database, { repositoryUrl: "https://github.com/example/fixture", repositoryName: "example/fixture", depth: "quick" });
  insertFindings(database, scan.id, [raw("slither", "a".repeat(64)), raw("aderyn", "b".repeat(64))]);
  const [investigation] = reconcileInvestigations(database, scan.id);

  afterAll(() => { closeDatabase(database); rmSync(directory, { recursive: true, force: true }); });

  it("renders the ranked list, applies filters, shows raw evidence, and changes status", async () => {
    const list = renderToStaticMarkup(await InvestigationsPage({ searchParams: Promise.resolve({ scan: scan.id, sources: "2" }) }));
    expect(list).toContain("Potential state-management issue in Unsafe.setOwner");
    expect(list).toContain(`${investigation.confidenceScore}%`);
    const filtered = renderToStaticMarkup(await InvestigationsPage({ searchParams: Promise.resolve({ confidence: "90" }) }));
    expect(filtered).toContain("No investigations match these filters");

    const detail = renderToStaticMarkup(await InvestigationPage({ params: Promise.resolve({ id: investigation.id }) }));
    expect(detail).toContain("Why these findings were correlated");
    expect(detail).toContain("missing-zero-check");
    expect(detail).toContain("state-no-address-check");
    expect(detail).toContain("Not supplied by Aderyn");

    const response = await PATCH(new Request(`http://localhost/api/investigations/${investigation.id}`, { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ status: "investigating" }) }), { params: Promise.resolve({ id: investigation.id }) });
    expect(response.status).toBe(200);
    expect((await response.json()).investigation.status).toBe("investigating");
  });
});
