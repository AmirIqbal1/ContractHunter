import { describe, expect, it } from "vitest";
import { deriveAssetFlow, type TrustedAssetStandard } from "./asset-flow";
import { keccak256 } from "./impact-selector";
import type { ImpactOverlay, ObservedOverlayCall, ObservedOverlayLog, ObservedOverlayState } from "./impact-overlay";

const A = `0x${"a".repeat(40)}`, B = `0x${"b".repeat(40)}`, C = `0x${"c".repeat(40)}`;
const TOKEN = `0x${"d".repeat(40)}`, ZERO = `0x${"0".repeat(40)}`;
const hash = (digit: string) => `0x${digit.repeat(64)}`;
const transfer = keccak256("Transfer(address,address,uint256)");
const single = keccak256("TransferSingle(address,address,address,uint256,uint256)");
const batch = keccak256("TransferBatch(address,address,address,uint256[],uint256[])");
const word = (value: bigint | number) => BigInt(value).toString(16).padStart(64, "0");
const addressTopic = (address: string) => `0x${"0".repeat(24)}${address.slice(2)}`;
const data = (hex: string) => ({ byteLength: hex.length / 2, sha256: `sha256:${"e".repeat(64)}`,
  prefix: `0x${hex}`, truncated: false });
const txHash = hash("1");
function overlay(): ImpactOverlay {
  return { schema: "contracthunter-impact-overlay-v1", derivationVersion: "contracthunter-impact-overlay-deriver-v1",
    scanId: "11111111-1111-4111-8111-111111111111", executionId: "22222222-2222-4222-8222-222222222222",
    sessionId: "33333333-3333-4333-8333-333333333333", artifactId: "44444444-4444-4444-8444-444444444444",
    subject: { type: "finding", id: "55555555-5555-4555-8555-555555555555" },
    protocolGraphId: null, investigationPathResultId: null,
    forkIdentity: { chainId: 1, baseBlockNumber: 100, baseBlockHash: hash("2"), targetCodeHashes: {} },
    sourceIdentity: { reviewedArtifactId: "44444444-4444-4444-8444-444444444444", sourceSha256: `sha256:${"3".repeat(64)}` },
    capabilities: { traceAvailable: true, statePreAvailable: true, stateDiffAvailable: true, overlayAvailable: true },
    transactions: [{ ordinal: 0, transactionHash: txHash, sender: A, to: B, valueWei: "0", status: "success",
      gasUsed: "21000", localBlockNumber: 101, localBlockHash: hash("4"), transactionIndex: 0,
      receiptTraceId: "trace-1", traceAvailable: true }],
    observedCalls: [], observedLogs: [], observedState: [], pathComparisons: [],
    coverage: { transactionCount: 1, tracedTransactionCount: 1, observedCallCount: 0,
      contractMappedCallCount: 0, functionMappedCallCount: 0, unmappedCallCount: 0,
      stateObservationCount: 0, changedObservationCount: 0, unavailableObservationCount: 0 }, warnings: [],
    provenance: { traceIds: ["trace-1"], traceContentSha256: [`sha256:${"5".repeat(64)}`],
      preSnapshotId: "pre", preSnapshotSha256: `sha256:${"6".repeat(64)}`,
      postSnapshotId: "post", postSnapshotSha256: `sha256:${"7".repeat(64)}`,
      diffId: "diff", diffSha256: `sha256:${"8".repeat(64)}`, graphContentSha256: null,
      pathContentSha256: null, mappingEvidenceIds: [] }, contentSha256: `sha256:${"9".repeat(64)}` };
}
function call(id: string, from: string, to: string, valueWei: string, parentCallId: string | null = null,
  outcome: ObservedOverlayCall["outcome"] = "success", transactionHash = txHash,
  callType: ObservedOverlayCall["callType"] = "CALL"): ObservedOverlayCall {
  return { id, traceId: "trace-1", transactionHash, transactionOrdinal: transactionHash === txHash ? 0 : 1,
    ordinal: Number(id.replace(/\D/g, "")) || 0, parentCallId, depth: parentCallId ? 1 : 0,
    callType, rawCallType: null, from, to, codeAddress: to, storageContextAddress: to,
    valueWei, outcome, gasSupplied: null, gasUsed: null, selector: null, input: data(""), output: null,
    error: null, revertKind: null, revertDetail: null,
    mapping: { contractNodeId: null, functionNodeId: null, reason: "contract-unmapped", evidenceId: null,
      deployedCodeSha256: null, sourceUnitName: null, sourceRawSha256: null }, staticEdgeId: null,
    relationshipStatus: "root-call", explanationKey: "observed-call" };
}
function log(id: string, topics: string[], hex: string, transactionHash = txHash): ObservedOverlayLog {
  return { id, traceId: "trace-1", transactionHash, ordinal: Number(id.replace(/\D/g, "")) || 0,
    logIndex: Number(id.replace(/\D/g, "")) || 0, address: TOKEN, topics, data: data(hex),
    contractNodeId: null, eventNodeId: null, explanationKey: "observed-log" };
}
function state(kind: ObservedOverlayState["kind"], descriptor: Record<string, string>, before: string | null,
  after: string | null): ObservedOverlayState {
  const id = `${kind}:${Object.values(descriptor).join(":")}`;
  return { observationId: id, kind, descriptor, beforeStatus: before === null ? "unavailable" : "available",
    afterStatus: after === null ? "unavailable" : "available", before, after,
    beforeErrorCode: null, afterErrorCode: null,
    delta: before !== null && after !== null && ["native", "erc20", "erc1155"].includes(kind) ?
      (BigInt(after) - BigInt(before)).toString() : null,
    state: before === null || after === null ? "unavailable" : before === after ? "unchanged" : "changed",
    contractNodeId: null, changeId: before === after ? null : id, preSnapshotId: "pre", postSnapshotId: "post",
    diffId: "diff", explanationKey: "observed-state-change" };
}
const erc20: TrustedAssetStandard[] = [{ address: TOKEN, standard: "erc20", evidenceId: "trusted-erc20" }];
const erc721: TrustedAssetStandard[] = [{ address: TOKEN, standard: "erc721", evidenceId: "trusted-erc721" }];

describe("deterministic asset accounting", () => {
  it("records successful native value, exact net/gross and unavailable gas price", () => {
    const input = overlay(); input.observedCalls.push(call("call-1", A, B, "5"));
    const result = deriveAssetFlow(input);
    expect(result.ledgerEntries).toMatchObject([{ movementKind: "native-value", amount: "5", from: A, to: B }]);
    expect(result.netPositions.map((p) => p.netObservedMovement)).toEqual(["-5", "5"]);
    expect(result.transactions[0]?.executionCost).toEqual({ status: "unavailable", gasUsed: "21000",
      effectiveGasPrice: null, amountWei: null });
  });
  it("retains reverted nested attempts, including successful descendants of a reverted parent", () => {
    const input = overlay(); input.observedCalls.push(call("call-1", A, B, "5", null, "reverted"),
      call("call-2", B, C, "3", "call-1"));
    const result = deriveAssetFlow(input);
    expect(result.ledgerEntries).toHaveLength(0);
    expect(result.attemptedFlows).toHaveLength(2);
    expect(result.attemptedFlows.map((flow) => flow.reason)).toEqual(["reverted-call-or-ancestor", "reverted-call-or-ancestor"]);
  });
  it("top-level revert leaves no committed transfer or log entry", () => {
    const input = overlay(); input.transactions[0] = { ...input.transactions[0]!, status: "reverted" };
    input.observedCalls.push(call("call-1", A, B, "5"));
    input.observedLogs.push(log("log-1", [transfer, addressTopic(A), addressTopic(B)], word(100)));
    const result = deriveAssetFlow(input, { trustedAssetStandards: erc20 });
    expect(result.ledgerEntries).toHaveLength(0);
    expect(result.attemptedFlows).toHaveLength(1);
  });
  it("uses committed ERC20 logs once; snapshots reconcile and calls alone prove no token flow", () => {
    const input = overlay(); input.observedCalls.push(call("call-1", A, TOKEN, "0"));
    input.observedLogs.push(log("log-1", [transfer, addressTopic(A), addressTopic(B)], word(100)));
    input.observedState.push(state("erc20", { token: TOKEN, holder: A }, "1000", "900"),
      state("erc20", { token: TOKEN, holder: B }, "0", "100"));
    const result = deriveAssetFlow(input, { trustedAssetStandards: erc20 });
    expect(result.ledgerEntries).toHaveLength(1);
    expect(result.ledgerEntries[0]?.movementKind).toBe("erc20-transfer");
    expect(result.reconciliation.map((item) => item.status)).toEqual(["reconciled", "reconciled"]);
    const noLog = overlay(); noLog.observedCalls.push(call("call-1", A, TOKEN, "0"));
    expect(deriveAssetFlow(noLog, { trustedAssetStandards: erc20 }).ledgerEntries).toHaveLength(0);
  });
  it("reports a fee-like mismatch without changing the transfer ledger", () => {
    const input = overlay(); input.observedLogs.push(log("log-1", [transfer, addressTopic(A), addressTopic(B)], word(100)));
    input.observedState.push(state("erc20", { token: TOKEN, holder: B }, "0", "99"));
    const result = deriveAssetFlow(input, { trustedAssetStandards: erc20 });
    expect(result.ledgerEntries[0]?.amount).toBe("100");
    expect(result.reconciliation[0]).toMatchObject({ status: "mismatch", difference: "-1" });
  });
  it("retains shared Transfer signature ambiguity and exact zero-address facts", () => {
    const input = overlay(); input.observedLogs.push(log("log-1", [transfer, addressTopic(ZERO), addressTopic(A)], word(7)));
    const result = deriveAssetFlow(input);
    expect(result.ledgerEntries[0]).toMatchObject({ standard: "token-unknown-standard", from: ZERO, amount: "7" });
    expect(result.participants.find((item) => item.address === ZERO)?.label).toBe("Zero address");
  });
  it("records known ERC721 token ID and reconciles ownerOf endpoints", () => {
    const input = overlay(); input.observedLogs.push(log("log-1", [transfer, addressTopic(A), addressTopic(B), `0x${word(42)}`], ""));
    input.observedState.push(state("erc721", { token: TOKEN, tokenId: "42" }, A, B));
    const result = deriveAssetFlow(input, { trustedAssetStandards: erc721 });
    expect(result.ledgerEntries[0]).toMatchObject({ standard: "erc721", tokenId: "42", amount: "1" });
    expect(result.reconciliation[0]?.status).toBe("reconciled");
  });
  it("decodes ERC1155 single and bounded batch atomically", () => {
    const input = overlay();
    input.observedLogs.push(log("log-1", [single, addressTopic(C), addressTopic(A), addressTopic(B)], word(7) + word(3)));
    input.observedLogs.push(log("log-2", [batch, addressTopic(C), addressTopic(A), addressTopic(B)],
      word(64) + word(160) + word(2) + word(8) + word(9) + word(2) + word(4) + word(5)));
    const result = deriveAssetFlow(input);
    expect(result.ledgerEntries.map((item) => [item.tokenId, item.amount, item.operator])).toEqual([
      ["7", "3", C], ["8", "4", C], ["9", "5", C]]);
    const bad = overlay(); bad.observedLogs.push(log("log-1", [batch, addressTopic(C), addressTopic(A), addressTopic(B)],
      word(64) + word(128) + word(1) + word(8) + word(2) + word(4) + word(5)));
    expect(deriveAssetFlow(bad).ledgerEntries).toHaveLength(0);
    expect(deriveAssetFlow(bad).warnings).toContain("erc1155-batch-malformed-or-oversized");
  });
  it("keeps identical logs separate and cumulative positions across transactions", () => {
    const input = overlay(); const second = hash("a");
    input.transactions.push({ ...input.transactions[0]!, ordinal: 1, transactionHash: second, sender: B, to: C });
    input.observedLogs.push(log("log-1", [transfer, addressTopic(A), addressTopic(B)], word(100)),
      log("log-2", [transfer, addressTopic(A), addressTopic(B)], word(100)),
      log("log-3", [transfer, addressTopic(B), addressTopic(C)], word(40), second));
    const result = deriveAssetFlow(input, { trustedAssetStandards: erc20 });
    expect(result.ledgerEntries).toHaveLength(3);
    expect(result.transactions.map((tx) => tx.committedEntryIds.length)).toEqual([2, 1]);
    expect(Object.fromEntries(result.netPositions.map((item) => [item.participant, item.netObservedMovement])))
      .toEqual({ [A]: "-200", [B]: "160", [C]: "40" });
  });
  it("retains unchanged, unavailable and total-supply observations without movement", () => {
    const input = overlay(); input.observedState.push(state("erc20", { token: TOKEN, holder: A }, "5", "5"),
      state("erc20", { token: TOKEN, holder: B }, null, null),
      state("view", { kind: "erc20_totalSupply", target: TOKEN }, "10", "15"));
    const result = deriveAssetFlow(input);
    expect(result.ledgerEntries).toHaveLength(0);
    expect(result.reconciliation.map((item) => item.status)).toEqual(["reconciled", "unavailable", "insufficient-observation"]);
    expect(result.reconciliation[2]?.observedDelta).toBe("5");
  });
  it("reports historical and partial evidence explicitly", () => {
    const input = overlay(); input.capabilities.traceAvailable = false; input.capabilities.statePreAvailable = false;
    input.capabilities.stateDiffAvailable = false; input.transactions.length = 0;
    const result = deriveAssetFlow(input);
    expect(result.status).toBe("unavailable");
    expect(result.capabilities.assetAccountingAvailable).toBe(false);
  });
  it("is deterministic, immutable and bounded under a large D1 flow set", () => {
    const input = overlay(); for (let i = 0; i < 256; i++) input.observedCalls.push(call(`call-${i}`, A, B, "1"));
    const before = JSON.stringify(input), first = deriveAssetFlow(input), second = deriveAssetFlow(input);
    expect(first.contentSha256).toBe(second.contentSha256);
    expect(first.ledgerEntries).toHaveLength(256);
    expect(JSON.stringify(input)).toBe(before);
  });
  it("keeps hostile strings out of generated labels and omits secrets", () => {
    const input = overlay(); input.observedCalls.push({ ...call("call-1", A, B, "1"), error: "<script>alert(1)</script>" });
    const result = deriveAssetFlow(input);
    expect(JSON.stringify(result)).not.toContain("<script>");
    expect(JSON.stringify(result)).not.toContain("runtimeTokenSha256");
  });
});
