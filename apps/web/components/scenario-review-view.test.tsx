import { describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { scenarioContentHash, scenarioParticipantId, type AssetFlow, type ImpactScenario,
  type ScenarioImpact } from "@contracthunter/core";
import { ScenarioReviewView } from "./scenario-review-view";

vi.mock("next/navigation", () => ({ useRouter: () => ({ push: vi.fn(), refresh: vi.fn() }) }));
const P = `0x${"1".repeat(40)}`, S = `0x${"2".repeat(40)}`, TOKEN = `0x${"a".repeat(40)}`;
const ASSET = `erc20:1:${TOKEN}`;
const flow = (): AssetFlow => ({ schema: "contracthunter-asset-flow-v1",
  scanId: "11111111-1111-4111-8111-111111111111", executionId: "22222222-2222-4222-8222-222222222222",
  contentSha256: "e1-hash", rulesetVersion: "contracthunter-asset-accounting-v1", status: "partial",
  capabilities: { assetAccountingAvailable: true },
  participants: [{ address: P, label: "Mapped protocol contract", contractNodeId: "contract-1" },
    { address: S, label: "Disposable PoC sender", contractNodeId: null }],
  assets: [{ id: ASSET, standard: "erc20", contractAddress: TOKEN, tokenId: null,
    mappedContractNodeId: null, transactions: [0], participantCount: 2 }],
  netPositions: [{ participant: P, assetId: ASSET, incoming: "0", outgoing: "100", netObservedMovement: "-100" },
    { participant: S, assetId: ASSET, incoming: "100", outgoing: "0", netObservedMovement: "100" }],
  ledgerEntries: [{ id: "ledger-1", from: P, to: S, assetId: ASSET, transactionOrdinal: 0 }], attemptedFlows: [],
  transactions: [{ ordinal: 0, hash: "hash", executionCost: { status: "unavailable", gasUsed: "21000",
    effectiveGasPrice: null, amountWei: null } }], reconciliation: [] } as unknown as AssetFlow);
const participantIds = (f: AssetFlow) => Object.fromEntries(f.participants.map((item) =>
  [item.address, scenarioParticipantId(f, item.address)]));
function scenario(f: AssetFlow, status: ImpactScenario["status"]): ImpactScenario {
  const assignments = [{ participantId: scenarioParticipantId(f, P), role: "protocol" as const },
    { participantId: scenarioParticipantId(f, S), role: "scenario-subject" as const }];
  const content = { scenarioId: "33333333-3333-4333-8333-333333333333", revision: 1, revisionOf: null,
    scanId: f.scanId, executionId: f.executionId,
    subject: { type: "finding" as const, id: "44444444-4444-4444-8444-444444444444" },
    assetFlowContentSha256: f.contentSha256, assetAccountingRulesetVersion: f.rulesetVersion,
    assignments, note: "<script>alert(1)</script>" };
  return { schema: "contracthunter-impact-scenario-v1", id: "55555555-5555-4555-8555-555555555555",
    ...content, status, createdAt: 1, reviewedAt: status === "reviewed" ? 2 : null,
    rejectedAt: null, contentSha256: scenarioContentHash(content) };
}
function impact(s: ImpactScenario): ScenarioImpact {
  return { schema: "contracthunter-scenario-impact-v1",
    derivationVersion: "contracthunter-scenario-impact-deriver-v1",
    rulesetVersion: "contracthunter-scenario-impact-ruleset-v1", scenarioId: s.scenarioId,
    revisionId: s.id, revision: 1, scanId: s.scanId, executionId: s.executionId,
    assetFlowContentSha256: s.assetFlowContentSha256,
    assetAccountingRulesetVersion: s.assetAccountingRulesetVersion, preview: s.status === "draft",
    status: "partial", roles: [], rolePositions: [{ transactionOrdinal: null, role: "scenario-subject",
      assetId: ASSET, incoming: "100", outgoing: "0", netObservedMovement: "100", ledgerEntryIds: ["ledger-1"] }],
    directRoleTransfers: [{ transactionOrdinal: null, assetId: ASSET, direction: "protocol-to-subject",
      amount: "100", ledgerEntryIds: ["ledger-1"] }], supplyObservations: [], reconciliation: [],
    executionCosts: [{ status: "unavailable", gasUsed: "21000", effectiveGasPrice: null, amountWei: null }],
    attemptedFlowIds: [], warnings: [], contentSha256: "result-hash" };
}
describe("Scenario review presentation", () => {
  it("shows new E1 participants with no auto-assigned scenario role", () => {
    const f = flow();
    const html = renderToStaticMarkup(<ScenarioReviewView flow={f} labels={{}} participantIds={participantIds(f)} scenario={null}
      impact={null} stale={false} />);
    expect(html).toContain("Create Scenario Draft"); expect(html).toContain("Unassigned");
    expect(html).toContain("Disposable PoC sender"); expect(html).not.toContain("REVIEWED SCENARIO");
  });
  it("separates draft preview from reviewed accounting and escapes hostile labels and notes", () => {
    const f = flow(), draft = scenario(f, "draft"), reviewed = scenario(f, "reviewed");
    const labels = { "contract-1": "<img src=x onerror=alert(1)>" };
    const preview = renderToStaticMarkup(<ScenarioReviewView flow={f} labels={labels} participantIds={participantIds(f)} scenario={draft}
      impact={impact(draft)} stale={false} />);
    expect(preview).toContain("PREVIEW — NOT REVIEWED");
    expect(preview).toContain("Confirm and Review Scenario");
    expect(preview).toContain("&lt;img src=x onerror=alert(1)&gt;");
    expect(preview).not.toContain("<img");
    const final = renderToStaticMarkup(<ScenarioReviewView flow={f} labels={labels} participantIds={participantIds(f)} scenario={reviewed}
      impact={impact(reviewed)} stale={false} />);
    expect(final).toContain("REVIEWED SCENARIO"); expect(final).toContain("ROLE-BASED OBSERVED ACCOUNTING");
    expect(final).toContain("Protocol → Scenario Subject"); expect(final).toContain("100");
    expect(final).not.toContain("<script>");
  });
  it("shows stale binding and suppresses current impact", () => {
    const f = flow(), reviewed = scenario(f, "reviewed");
    const html = renderToStaticMarkup(<ScenarioReviewView flow={f} labels={{}} participantIds={participantIds(f)} scenario={reviewed}
      impact={null} stale />);
    expect(html).toContain("earlier asset-accounting result");
    expect(html).not.toContain("ROLE-BASED OBSERVED ACCOUNTING");
    expect(html).toContain("Create New Draft Revision");
  });
});
