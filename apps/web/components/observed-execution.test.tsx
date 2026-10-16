import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import type { ImpactOverlay } from "@contracthunter/core";
import { ObservedExecution } from "./observed-execution";

const overlay = (): ImpactOverlay => ({
  schema: "contracthunter-impact-overlay-v1", derivationVersion: "contracthunter-impact-overlay-deriver-v1",
  scanId: "00000000-0000-4000-8000-000000000001", executionId: "00000000-0000-4000-8000-000000000002",
  sessionId: "s", artifactId: "a", subject: { type: "finding", id: "f" }, protocolGraphId: null,
  investigationPathResultId: null, forkIdentity: { chainId: 1, baseBlockNumber: 100, baseBlockHash: "0xabc", targetCodeHashes: {} },
  sourceIdentity: { reviewedArtifactId: "a", sourceSha256: "sha" },
  capabilities: { traceAvailable: true, statePreAvailable: true, stateDiffAvailable: true, overlayAvailable: true },
  transactions: [0, 1].map((ordinal) => ({ ordinal, transactionHash: `0x${String(ordinal + 1).repeat(64)}`,
    sender: "0x1111", to: "0x2222", valueWei: "0", status: ordinal ? "reverted" as const : "success" as const,
    gasUsed: "21000", localBlockNumber: 101 + ordinal, localBlockHash: "0x123", transactionIndex: ordinal,
    receiptTraceId: `t${ordinal}`, traceAvailable: true })),
  observedCalls: [0, 1].map((transactionOrdinal) => ({ id: `t${transactionOrdinal}:0`, traceId: `t${transactionOrdinal}`,
    transactionHash: `0x${String(transactionOrdinal + 1).repeat(64)}`, transactionOrdinal, ordinal: 0, parentCallId: null,
    depth: 0, callType: transactionOrdinal ? "DELEGATECALL" as const : "CALL" as const, rawCallType: null,
    from: "0x1111", to: transactionOrdinal ? "0x9999999999999999999999999999999999999999" : "0x2222",
    codeAddress: null, storageContextAddress: null, valueWei: "0", outcome: transactionOrdinal ? "reverted" as const : "success" as const,
    gasSupplied: null, gasUsed: null, selector: null,
    input: { byteLength: 3, prefix: "0x3c7363", sha256: "sha256:abc", truncated: false }, output: null,
    error: "<script>alert(1)</script>", revertKind: null, revertDetail: null,
    mapping: { contractNodeId: null, functionNodeId: null, reason: "contract-unmapped" as const,
      evidenceId: null, deployedCodeSha256: null, sourceUnitName: null, sourceRawSha256: null },
    staticEdgeId: null, relationshipStatus: "unmapped-runtime-call" as const, explanationKey: "unmapped-runtime-call" as const })),
  observedLogs: [], observedState: [{ observationId: "native:0x1111", kind: "native", descriptor: { address: "0x1111" },
    beforeStatus: "available", afterStatus: "available", before: "10", after: "9", beforeErrorCode: null, afterErrorCode: null,
    delta: "-1", state: "changed", contractNodeId: null, changeId: "c", preSnapshotId: "pre", postSnapshotId: "post",
    diffId: "diff", explanationKey: "observed-state-change" }], pathComparisons: [],
  coverage: { transactionCount: 2, tracedTransactionCount: 2, observedCallCount: 2, contractMappedCallCount: 0,
    functionMappedCallCount: 0, unmappedCallCount: 2, stateObservationCount: 1, changedObservationCount: 1,
    unavailableObservationCount: 0 }, warnings: [],
  provenance: { traceIds: [], traceContentSha256: [], preSnapshotId: "pre", preSnapshotSha256: null,
    postSnapshotId: "post", postSnapshotSha256: null, diffId: "diff", diffSha256: null,
    graphContentSha256: null, pathContentSha256: null, mappingEvidenceIds: [] }, contentSha256: "hash",
});
const render = (value = overlay(), tx = 0, state = "changed") => renderToStaticMarkup(<ObservedExecution overlay={value} initialTx={tx} initialState={state} researcher />);

describe("Observed Execution read-only presentation", () => {
  it("keeps transaction boundaries and reverted nested evidence visible", () => {
    const first = render(), second = render(overlay(), 1);
    expect(first).toContain("CALL</strong>"); expect(first).not.toContain("DELEGATECALL</strong>");
    expect(second).toContain("DELEGATECALL</strong>"); expect(second).toContain("REVERTED LOCAL TRANSACTION");
    expect(second).toContain("STATIC IDENTITY UNRESOLVED");
  });
  it("preserves exact state values and unavailable PRE/POST semantics", () => {
    const value = overlay();
    expect(render(value)).toContain("PRE 10 → POST 9 · delta -1");
    const partial = { ...value, capabilities: { ...value.capabilities, stateDiffAvailable: false },
      observedState: [{ ...value.observedState[0]!, after: null, afterStatus: "not-captured" as const,
        delta: null, state: "post-unavailable" as const }] };
    const html = render(partial, 0, "unavailable");
    expect(html).toContain("POST or state diff unavailable"); expect(html).toContain("POST UNAVAILABLE");
    expect(html).not.toContain("POST 0");
  });
  it("escapes hostile runtime strings and bounds shown calldata", () => {
    const value = overlay();
    const html = render({ ...value, observedCalls: [{ ...value.observedCalls[0]!, revertDetail: "<img src=x onerror=alert(1)>" }] ,
      observedLogs: [{ id: "log", traceId: "t0", transactionHash: value.transactions[0]!.transactionHash,
        ordinal: 0, logIndex: 0, address: "0x2222", topics: [], data: value.observedCalls[0]!.input,
        contractNodeId: null, eventNodeId: null, explanationKey: "observed-log" }] }, 0);
    expect(html).not.toContain("<img src=x"); expect(html).toContain("0x3c7363");
    expect(html).toContain("Unknown/Unmapped log");
  });
  it("collapses large traces and exposes textual search and filters", () => {
    const value = overlay();
    const many = Array.from({ length: 80 }, (_, ordinal) => ({ ...value.observedCalls[0]!, id: `t0:${ordinal}`, ordinal }));
    const html = render({ ...value, observedCalls: many });
    expect(html).toContain("20 calls hidden"); expect(html).toContain("Search observed calls");
    expect(html).toContain("Runtime-only"); expect(html).toContain("Mapped to Static");
  });
});
