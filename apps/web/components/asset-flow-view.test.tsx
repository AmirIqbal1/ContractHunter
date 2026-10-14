import { describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { assetFlowPositionsForTransaction, type AssetFlow, type AssetFlowEntry } from "@contracthunter/core";
import { AssetFlowView } from "./asset-flow-view";

vi.mock("next/navigation", () => ({ useRouter: () => ({ push: vi.fn() }) }));

const A = `0x${"a".repeat(40)}`, B = `0x${"b".repeat(40)}`, TOKEN = `0x${"d".repeat(40)}`;
const H0 = `0x${"1".repeat(64)}`, H1 = `0x${"2".repeat(64)}`;
const assetId = `erc20:1:${TOKEN}`;
function entry(id: string, ordinal: number, standard: AssetFlowEntry["standard"],
  amount: string, tokenId: string | null = null): AssetFlowEntry {
  const asset = standard === "native" ? "native:1" : `${standard}:1:${TOKEN}${tokenId === null ? "" : `:${tokenId}`}`;
  return { id, transactionHash: ordinal ? H1 : H0, transactionOrdinal: ordinal, assetId: asset,
    standard, from: A, to: B, amount, movementKind: standard === "native" ? "native-value" :
      standard === "token-unknown-standard" ? "token-transfer-unknown-standard" : `${standard}-transfer`,
    evidenceKind: standard === "native" ? "observed-runtime-value" : "observed-transfer-log",
    orderDomain: standard === "native" ? "trace-preorder" : "receipt-log", evidenceId: `e:${id}`,
    runtimeCallId: standard === "native" ? `call:${id}` : null, logId: standard === "native" ? null : `log:${id}`,
    mappedContractNodeId: null, mappedFunctionNodeId: null, classificationEvidenceId: null,
    tokenId, operator: null };
}
function fixture(): AssetFlow {
  const ledgerEntries = [entry("one", 0, "erc20", "100"), entry("two", 0, "erc20", "100"),
    entry("three", 0, "erc20", "100"), entry("native", 0, "native", "5"),
    entry("nft", 0, "erc721", "1", "42"), entry("multi", 0, "erc1155", "3", "7"),
    entry("unknown", 0, "token-unknown-standard", "9")];
  const assetIds = [...new Set(ledgerEntries.map((item) => item.assetId))];
  return { schema: "contracthunter-asset-flow-v1", rulesetVersion: "contracthunter-asset-accounting-v1",
    executionId: "00000000-0000-4000-8000-000000000002", scanId: "00000000-0000-4000-8000-000000000001",
    sessionId: "session", chainId: 1,
    forkIdentity: { chainId: 1, baseBlockNumber: 1, baseBlockHash: H0, targetCodeHashes: {} },
    capabilities: { assetAccountingAvailable: true, traceEvidenceAvailable: true, stateEvidenceAvailable: true,
      logEvidenceAvailable: true }, status: "partial",
    transactions: [0, 1].map((ordinal) => ({ ordinal, hash: ordinal ? H1 : H0,
      status: ordinal ? "reverted" : "success", traceId: null,
      committedEntryIds: ledgerEntries.filter((item) => item.transactionOrdinal === ordinal).map((item) => item.id),
      attemptedFlowIds: ordinal ? ["attempt"] : [],
      executionCost: { status: "unavailable" as const, gasUsed: "21000", effectiveGasPrice: null, amountWei: null } })),
    assets: assetIds.map((id) => { const item = ledgerEntries.find((entry) => entry.assetId === id)!;
      return { id, standard: item.standard, contractAddress: item.standard === "native" ? null : TOKEN,
        tokenId: item.tokenId, mappedContractNodeId: null, transactions: [0], participantCount: 2 }; }),
    participants: [{ address: A, label: "Unmapped address", contractNodeId: null },
      { address: B, label: "Unmapped address", contractNodeId: null }],
    ledgerEntries, attemptedFlows: [{ id: "attempt", transactionHash: H1, transactionOrdinal: 1,
      assetId: "native:1", from: A, to: B, amount: "8", runtimeCallId: "reverted-call",
      reason: "reverted-transaction" }],
    netPositions: [{ participant: A, assetId, incoming: "0", outgoing: "300", netObservedMovement: "-300" },
      { participant: B, assetId, incoming: "300", outgoing: "0", netObservedMovement: "300" }],
    reconciliation: [{ observationId: "obs-1", assetId, participant: A, kind: "balance", before: "1000",
      after: "700", observedDelta: "-300", ledgerNet: "-300", difference: "0", status: "reconciled",
      coverage: "complete-within-observed-set", preSnapshotId: "pre", postSnapshotId: "post" },
      { observationId: "obs-2", assetId, participant: B, kind: "balance", before: null,
        after: null, observedDelta: null, ledgerNet: "300", difference: null, status: "unavailable",
        coverage: "insufficient", preSnapshotId: "pre", postSnapshotId: null }],
    summary: { transactionCount: 2, committedEntryCount: 7, attemptedFlowCount: 1, assetCount: 5,
      participantCount: 2, nativeTransferCount: 1, erc20TransferCount: 3, nftTransferCount: 1,
      erc1155TransferCount: 1, reconciledObservationCount: 1, partialOrMismatchedObservationCount: 0 },
    warnings: ["token-standard-unresolved"], provenance: { overlayContentSha256: "hash", traceIds: [],
      traceContentSha256: [], preSnapshotId: "pre", preSnapshotSha256: null, postSnapshotId: "post",
      postSnapshotSha256: null, diffId: null, diffSha256: null, classificationEvidenceIds: [] }, contentSha256: "hash" };
}
const render = (flow = fixture(), options: { tx?: string; status?: string; mode?: string; labels?: Record<string, string> } = {}) =>
  renderToStaticMarkup(<AssetFlowView flow={flow} executionIds={[flow.executionId]}
    txPositions={Object.fromEntries(flow.transactions.map((tx) => [tx.ordinal, assetFlowPositionsForTransaction(flow, tx.ordinal)]))}
    labels={options.labels ?? {}} initialTx={options.tx} initialStatus={options.status} initialMode={options.mode} />);

describe("Asset Flow read-only presentation", () => {
  it("keeps exact standards, raw units, NFT IDs, gas and reconciliation separate", () => {
    const html = render();
    expect(html).toContain("3 canonical entries"); expect(html).toContain("300 raw units");
    expect(html).toContain("ERC721"); expect(html).toContain("token ID 42");
    expect(html).toContain("ERC1155"); expect(html).toContain("token ID 7");
    expect(html).toContain("TOKEN · UNKNOWN STANDARD"); expect(html).toContain("5 wei");
    expect(html).toContain("Execution Cost"); expect(html).toContain("gas cost is unavailable");
    expect(html).toContain("RECONCILED"); expect(html).toContain("UNAVAILABLE");
    expect(html).toContain("PARTIAL ASSET ACCOUNTING");
    expect(html).not.toMatch(/attacker gain|protocol loss|profit|USD|GBP/i);
  });
  it("keeps attempted movement out of committed and transaction net positions", () => {
    const html = render(fixture(), { tx: "1", status: "attempted" });
    expect(html).toContain("No committed asset movements from this transaction");
    expect(html).toContain("ATTEMPTED — REVERTED");
    expect(html).toContain("8 wei");
    expect(html).toContain("No committed positions match this view");
    expect(html).toContain("E1 has no transaction-local balance snapshots");
  });
  it("preserves exact per-transaction positions and escapes untrusted labels", () => {
    const flow = fixture();
    expect(assetFlowPositionsForTransaction(flow, 0).find((item) => item.participant === A && item.assetId === assetId))
      .toMatchObject({ outgoing: "300", netObservedMovement: "-300" });
    expect(assetFlowPositionsForTransaction(flow, 1)).toEqual([]);
    flow.participants[0] = { address: A, label: "Mapped protocol contract", contractNodeId: "contract-1" };
    const html = render(flow, { labels: { "contract-1": "<script>alert(1)</script>" }, mode: "researcher" });
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(html).not.toContain("<script>");
  });
  it("shows historical unavailable accounting without graph or ledger", () => {
    const flow = { ...fixture(), status: "unavailable" as const,
      capabilities: { ...fixture().capabilities, assetAccountingAvailable: false } };
    const html = render(flow);
    expect(html).toContain("Asset accounting unavailable for this execution");
    expect(html).not.toContain("COMMITTED MOVEMENT");
  });
  it("bounds a large flow while retaining the complete paginated ledger", () => {
    const flow = fixture();
    flow.ledgerEntries.push(...Array.from({ length: 100 }, (_, index) => entry(`extra-${index}`, 0, "erc20", "1")));
    const html = render(flow);
    expect(html).toContain("Showing 40 of 107 filtered committed ledger entries");
    expect(html).toContain("Page 1 of 3");
    expect(html).toContain("of 107 entries");
  });
  it("keeps zero address, mismatch and unavailable observations factual", () => {
    const flow = fixture(), zero = `0x${"0".repeat(40)}`;
    flow.participants.push({ address: zero, label: "Zero address", contractNodeId: null });
    flow.ledgerEntries.push({ ...entry("zero", 0, "erc20", "2"), from: zero });
    flow.reconciliation.push({ observationId: "obs-mismatch", assetId, participant: B,
      kind: "balance", before: "1000", after: "850", observedDelta: "-150", ledgerNet: "-100",
      difference: "-50", status: "mismatch", coverage: "partial", preSnapshotId: "pre", postSnapshotId: "post" });
    const html = render(flow, { mode: "researcher" });
    expect(html).toContain("Zero address"); expect(html).toContain("MISMATCH");
    expect(html).toContain("-50"); expect(html).toContain("UNAVAILABLE");
    expect(html).not.toMatch(/minted|burned|vulnerability confirmed/i);
  });
});
