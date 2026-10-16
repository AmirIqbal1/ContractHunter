import { describe, expect, it } from "vitest";
import { deriveScenarioImpact, scenarioContentHash, scenarioParticipantId,
  validateScenarioAssignments, type ImpactScenario, type ScenarioAssignment } from "./impact-scenario";
import type { AssetFlow, AssetFlowEntry, AssetStandard } from "./asset-flow";

const P = `0x${"1".repeat(40)}`, S = `0x${"2".repeat(40)}`, C = `0x${"3".repeat(40)}`,
  U = `0x${"4".repeat(40)}`, P2 = `0x${"5".repeat(40)}`, S2 = `0x${"6".repeat(40)}`,
  ZERO = `0x${"0".repeat(40)}`, TOKEN = `0x${"a".repeat(40)}`;
const HASH = `0x${"f".repeat(64)}`;
function entry(id: string, from: string, to: string, amount: string, standard: AssetStandard = "erc20",
  transactionOrdinal = 0, tokenId: string | null = null): AssetFlowEntry {
  return { id, from, to, amount, standard, transactionOrdinal, transactionHash: HASH,
    assetId: standard === "native" ? "native:1" : `${standard}:1:${TOKEN}${tokenId ? `:${tokenId}` : ""}`,
    movementKind: standard === "native" ? "native-value" : standard === "token-unknown-standard" ?
      "token-transfer-unknown-standard" : `${standard}-transfer`,
    evidenceKind: standard === "native" ? "observed-runtime-value" : "observed-transfer-log",
    orderDomain: standard === "native" ? "trace-preorder" : "receipt-log", evidenceId: id,
    runtimeCallId: standard === "native" ? id : null, logId: standard === "native" ? null : id,
    mappedContractNodeId: null, mappedFunctionNodeId: null, classificationEvidenceId: null,
    tokenId, operator: null };
}
function flow(entries: AssetFlowEntry[], addresses = [P, S, C, U, P2, S2, ZERO]): AssetFlow {
  return { schema: "contracthunter-asset-flow-v1", rulesetVersion: "contracthunter-asset-accounting-v1",
    scanId: "11111111-1111-4111-8111-111111111111", executionId: "22222222-2222-4222-8222-222222222222",
    contentSha256: `sha256:${"a".repeat(64)}`, status: "complete-within-evidence",
    capabilities: { assetAccountingAvailable: true, traceEvidenceAvailable: true, stateEvidenceAvailable: true,
      logEvidenceAvailable: true },
    participants: addresses.map((address) => ({ address, label: address === ZERO ? "Zero address" as const :
      address === S ? "Disposable PoC sender" as const : "Unmapped address" as const, contractNodeId: null })),
    ledgerEntries: entries, attemptedFlows: [{ id: "attempt", assetId: "native:1", from: P, to: S,
      amount: "999", runtimeCallId: "call", reason: "reverted-transaction", transactionHash: HASH, transactionOrdinal: 0 }],
    transactions: [0, 1].map((ordinal) => ({ ordinal, hash: HASH, status: "success", traceId: null,
      committedEntryIds: entries.filter((item) => item.transactionOrdinal === ordinal).map((item) => item.id),
      attemptedFlowIds: ordinal ? [] : ["attempt"],
      executionCost: { status: "unavailable" as const, gasUsed: "21000", effectiveGasPrice: null, amountWei: null } })),
    reconciliation: [{ observationId: "obs", assetId: `erc20:1:${TOKEN}`, participant: P,
      kind: "balance", before: "100", after: "0", observedDelta: "-100", ledgerNet: "-100",
      difference: "0", status: "reconciled", coverage: "complete-within-observed-set",
      preSnapshotId: "pre", postSnapshotId: "post" }], warnings: [] } as unknown as AssetFlow;
}
function review(result: AssetFlow, roles: Array<[string, ScenarioAssignment["role"]]>,
  status: ImpactScenario["status"] = "reviewed"): ImpactScenario {
  const assignments = roles.map(([address, role]) => ({ participantId: scenarioParticipantId(result, address), role }));
  const content = { scenarioId: "33333333-3333-4333-8333-333333333333", revision: 1, revisionOf: null,
    scanId: result.scanId, executionId: result.executionId,
    subject: { type: "finding" as const, id: "44444444-4444-4444-8444-444444444444" },
    assetFlowContentSha256: result.contentSha256, assetAccountingRulesetVersion: result.rulesetVersion,
    assignments, note: "" };
  return { schema: "contracthunter-impact-scenario-v1", id: "55555555-5555-4555-8555-555555555555",
    ...content, status, createdAt: 1, reviewedAt: status === "reviewed" ? 2 : null,
    rejectedAt: status === "rejected" ? 2 : null, contentSha256: scenarioContentHash(content) };
}
function position(result: ReturnType<typeof deriveScenarioImpact>, role: string, asset: string,
  tx: number | null = null) { return result.rolePositions.find((item) => item.role === role && item.assetId === asset &&
    item.transactionOrdinal === tx); }
function direct(result: ReturnType<typeof deriveScenarioImpact>, direction: string, asset: string,
  tx: number | null = null) { return result.directRoleTransfers.find((item) => item.direction === direction &&
    item.assetId === asset && item.transactionOrdinal === tx); }

describe("reviewed scenario accounting", () => {
  it("requires explicit roles, rejects collisions, unknown selectors and zero-address role", () => {
    const f = flow([entry("a", P, S, "100")]);
    expect(review(f, []).assignments).toEqual([]);
    expect(validateScenarioAssignments(f, [{ participantId: scenarioParticipantId(f, S), role: "scenario-subject" }])).toHaveLength(1);
    expect(() => validateScenarioAssignments(f, [
      { participantId: scenarioParticipantId(f, S), role: "scenario-subject" },
      { participantId: scenarioParticipantId(f, S), role: "protocol" }])).toThrow();
    expect(() => validateScenarioAssignments(f, [{ participantId: scenarioParticipantId(f, `0x${"9".repeat(40)}`),
      role: "protocol" }])).toThrow();
    expect(() => validateScenarioAssignments(f, [{ participantId: scenarioParticipantId(f, ZERO),
      role: "protocol" }])).toThrow();
  });
  it("separates exact protocol-to-subject and reverse ERC20 movement", () => {
    const f = flow([entry("forward", P, S, "100"), entry("reverse", S, P, "50")]);
    const result = deriveScenarioImpact(f, review(f, [[P, "protocol"], [S, "scenario-subject"]]));
    const asset = `erc20:1:${TOKEN}`;
    expect(position(result, "protocol", asset)).toMatchObject({ incoming: "50", outgoing: "100", netObservedMovement: "-50" });
    expect(position(result, "scenario-subject", asset)).toMatchObject({ incoming: "100", outgoing: "50", netObservedMovement: "50" });
    expect(direct(result, "protocol-to-subject", asset)).toMatchObject({ amount: "100", ledgerEntryIds: ["forward"] });
    expect(direct(result, "subject-to-protocol", asset)).toMatchObject({ amount: "50", ledgerEntryIds: ["reverse"] });
    expect(JSON.stringify(result)).not.toMatch(/attacker profit|stolen|theft/i);
  });
  it("does not invent direct transfer through assigned or unassigned intermediaries", () => {
    const f = flow([entry("one", P, C, "100"), entry("two", C, S, "100")]);
    const result = deriveScenarioImpact(f, review(f, [[P, "protocol"], [C, "counterparty"], [S, "scenario-subject"]]));
    const asset = `erc20:1:${TOKEN}`;
    expect(position(result, "protocol", asset)?.netObservedMovement).toBe("-100");
    expect(position(result, "scenario-subject", asset)?.netObservedMovement).toBe("100");
    expect(direct(result, "protocol-to-subject", asset)?.amount).toBe("0");
    expect(result.warnings).not.toContain("unassigned-participant-flow");
    const unassigned = deriveScenarioImpact(f, review(f, [[P, "protocol"], [S, "scenario-subject"]]));
    expect(unassigned.warnings).toContain("unassigned-participant-flow");
    expect(position(unassigned, "unassigned", asset)?.netObservedMovement).toBe("0");
  });
  it("aggregates multiple participants per role with exact ledger references", () => {
    const f = flow([entry("p1", P, S, "40"), entry("p2", P2, S, "60"),
      entry("s2", P, S2, "30")]);
    const result = deriveScenarioImpact(f, review(f, [[P, "protocol"], [P2, "protocol"],
      [S, "scenario-subject"], [S2, "scenario-subject"]]));
    const asset = `erc20:1:${TOKEN}`;
    expect(position(result, "protocol", asset)?.netObservedMovement).toBe("-130");
    expect(position(result, "scenario-subject", asset)?.netObservedMovement).toBe("130");
    expect(direct(result, "protocol-to-subject", asset)?.ledgerEntryIds).toEqual(["p1", "p2", "s2"]);
  });
  it("keeps assets and NFT token IDs separate and excludes zero-address context from protocol loss", () => {
    const f = flow([entry("a", P, S, "100"), entry("b", P, S, "2", "native"),
      entry("nft", P, S, "1", "erc721", 0, "42"), entry("multi", P, S, "3", "erc1155", 0, "7"),
      entry("zero", ZERO, S, "5")]);
    const result = deriveScenarioImpact(f, review(f, [[P, "protocol"], [S, "scenario-subject"]]));
    expect(result.rolePositions.filter((item) => item.role === "scenario-subject" && item.transactionOrdinal === null))
      .toHaveLength(4);
    expect(position(result, "scenario-subject", `erc721:1:${TOKEN}:42`)?.incoming).toBe("1");
    expect(position(result, "scenario-subject", `erc1155:1:${TOKEN}:7`)?.incoming).toBe("3");
    expect(direct(result, "protocol-to-subject", `erc20:1:${TOKEN}`)?.amount).toBe("100");
    expect(result.warnings).toContain("unassigned-participant-flow");
  });
  it("excludes reverted attempts and gas, retains transaction and reconciliation boundaries", () => {
    const f = flow([entry("first", P, S, "10"), entry("second", P, S, "20", "erc20", 1)]);
    const result = deriveScenarioImpact(f, review(f, [[P, "protocol"], [S, "scenario-subject"]]));
    const asset = `erc20:1:${TOKEN}`;
    expect(position(result, "scenario-subject", asset)?.netObservedMovement).toBe("30");
    expect(position(result, "scenario-subject", asset, 0)?.netObservedMovement).toBe("10");
    expect(position(result, "scenario-subject", asset, 1)?.netObservedMovement).toBe("20");
    expect(result.attemptedFlowIds).toEqual(["attempt"]);
    expect(result.executionCosts[0]).toMatchObject({ gasUsed: "21000", amountWei: null });
    expect(result.reconciliation[0]?.status).toBe("reconciled");
  });
  it("inherits partial evidence, rejects stale and rejected interpretations, and labels draft preview", () => {
    const f = { ...flow([entry("a", P, S, "100")]), status: "partial" as const,
      warnings: ["ledger-does-not-reconcile-with-captured-balance"] };
    const reviewed = review(f, [[P, "protocol"], [S, "scenario-subject"]]);
    expect(deriveScenarioImpact(f, reviewed).status).toBe("partial");
    expect(deriveScenarioImpact(f, reviewed).warnings).toContain("ledger-does-not-reconcile-with-captured-balance");
    expect(() => deriveScenarioImpact({ ...f, contentSha256: "changed" }, reviewed)).toThrow("scenario_asset_flow_stale");
    expect(() => deriveScenarioImpact(f, { ...reviewed, status: "rejected" })).toThrow("scenario_not_reviewed");
    const draft = review(f, [[P, "protocol"], [S, "scenario-subject"]], "draft");
    expect(deriveScenarioImpact(f, draft, { preview: true }).preview).toBe(true);
    expect(() => deriveScenarioImpact(f, draft)).toThrow("scenario_not_reviewed");
  });
  it("is deterministic, pure, and bounded for a representative large participant set", () => {
    const addresses = Array.from({ length: 300 }, (_, index) => `0x${(index + 1).toString(16).padStart(40, "0")}`);
    const entries = addresses.slice(1).map((address, index) => entry(`e${index}`, addresses[0]!, address, "1"));
    const f = flow(entries, addresses), s = review(f, [[addresses[0]!, "protocol"], [addresses[1]!, "scenario-subject"]]);
    const before = JSON.stringify(f), first = deriveScenarioImpact(f, s), second = deriveScenarioImpact(f, s);
    expect(first).toEqual(second); expect(first.contentSha256).toBe(second.contentSha256);
    expect(first.rolePositions.find((item) => item.role === "protocol" && item.transactionOrdinal === null)?.outgoing).toBe("299");
    expect(JSON.stringify(f)).toBe(before);
  });
});
