import { describe, expect, it } from "vitest";
import { impactTraceHash, verifyImpactTraceShape, type ImpactStateProvenance } from "@contracthunter/core";
import { parseImpactTransactionTrace } from "./impact-trace";

const sender = `0x${"a".repeat(40)}`, target = `0x${"1".repeat(40)}`, child = `0x${"2".repeat(40)}`;
const txHash = `0x${"3".repeat(64)}`, blockHash = `0x${"4".repeat(64)}`;
const provenance: ImpactStateProvenance = { executionId: "00000000-0000-4000-8000-000000000001",
  sessionId: "00000000-0000-4000-8000-000000000002", runtimeTokenSha256: "a".repeat(64),
  chainId: 31337, forkBlock: 1, forkBlockHash: `0x${"b".repeat(64)}`,
  targetCodeHashes: { [target]: `sha256:${"c".repeat(64)}` },
  artifactId: "00000000-0000-4000-8000-000000000003", sourceSha256: `sha256:${"d".repeat(64)}`,
  planSha256: `sha256:${"e".repeat(64)}` };
const receipt = { transactionHash: txHash, from: sender, to: target, blockNumber: "0x2",
  blockHash, transactionIndex: "0x0", status: "0x1", gasUsed: "0x100",
  contractAddress: null, logs: [{ address: child, topics: [`0x${"5".repeat(64)}`],
    data: "0x1234", logIndex: "0x0", transactionHash: txHash, blockHash, blockNumber: "0x2" }] };
const block = { number: "0x2", hash: blockHash };
const nested = { type: "CALL", from: sender, to: target, input: "0x12345678", value: "0x1",
  gas: "0x1000", gasUsed: "0x100", calls: [{ type: "DELEGATECALL", from: target,
    to: child, input: "0xabcdef01", value: "0x0", gas: "0x500", gasUsed: "0x80" }] };

describe("Impact D1 strict local callTracer parser", () => {
  it("preserves nested and delegate calls, exact values, receipt logs and canonical hashing", () => {
    const trace = parseImpactTransactionTrace(nested, receipt, block, provenance, txHash, 0, sender);
    expect(trace.nodes.map((node) => [node.ordinal, node.parentOrdinal, node.depth, node.callType]))
      .toEqual([[0, null, 0, "CALL"], [1, 0, 1, "DELEGATECALL"]]);
    expect(trace.nodes[0]?.inputSelector).toBe("0x12345678");
    expect(trace.nodes[0]?.valueWei).toBe("1");
    expect(trace.nodes[0]?.targetAddress).toBe(target);
    expect(trace.receipt).toMatchObject({ transactionHash: txHash, blockNumber: 2, blockHash, status: 1 });
    expect(trace.logs[0]).toMatchObject({ address: child, topics: [`0x${"5".repeat(64)}`] });
    expect(trace.contentSha256).toBe(impactTraceHash(trace));
    expect(() => verifyImpactTraceShape(trace)).not.toThrow();
    const missingParent = { ...trace, nodes: [trace.nodes[0]!, { ...trace.nodes[1]!, parentOrdinal: 99 }] };
    expect(() => verifyImpactTraceShape({ ...missingParent, contentSha256: impactTraceHash(missingParent) }))
      .toThrow("impact_trace_integrity_failed");
    const duplicateOrdinal = { ...trace, nodes: [trace.nodes[0]!, { ...trace.nodes[1]!, ordinal: 0 }] };
    expect(() => verifyImpactTraceShape({ ...duplicateOrdinal, contentSha256: impactTraceHash(duplicateOrdinal) }))
      .toThrow("impact_trace_integrity_failed");
  });

  it("bounds calldata and decodes a standard reverted Error without pretending it succeeded", () => {
    const message = Buffer.from("fixture revert", "utf8").toString("hex");
    const output = "0x08c379a0" + "20".padStart(64, "0") +
      "e".padStart(64, "0") + message.padEnd(64, "0");
    const reverted = parseImpactTransactionTrace({ type: "CALL", from: sender, to: target,
      input: "0x" + "ab".repeat(300), output, error: "execution reverted",
      gas: "0x1000", gasUsed: "0x100" },
    { ...receipt, status: "0x0", logs: [] }, block, provenance, txHash, 0, sender);
    expect(reverted.nodes[0]).toMatchObject({ outcome: "reverted", revertKind: "Error",
      revertDetail: "fixture revert" });
    expect(reverted.nodes[0]?.input).toMatchObject({ byteLength: 300, truncated: true });
    expect(reverted.nodes[0]?.input.prefix.length).toBe(514);
    expect(reverted.receipt.status).toBe(0);
  });

  it("rejects wrong hash, local block, malformed nodes and oversized trees", () => {
    expect(() => parseImpactTransactionTrace(nested, { ...receipt, transactionHash: blockHash },
      block, provenance, txHash, 0, sender)).toThrow();
    expect(() => parseImpactTransactionTrace(nested, receipt, { ...block, hash: txHash },
      provenance, txHash, 0, sender)).toThrow();
    expect(() => parseImpactTransactionTrace({ ...nested, from: "invalid" }, receipt,
      block, provenance, txHash, 0, sender)).toThrow();
    expect(() => parseImpactTransactionTrace({ ...nested, calls: [{ ...nested, input: "bad" }] },
      receipt, block, provenance, txHash, 0, sender)).toThrow();
    let tree: Record<string, unknown> = { type: "CALL", from: sender, to: target, input: "0x" };
    for (let i = 0; i < 26; i++) tree = { type: "CALL", from: sender, to: target, input: "0x", calls: [tree] };
    expect(() => parseImpactTransactionTrace(tree, { ...receipt, logs: [] }, block,
      provenance, txHash, 0, sender)).toThrow("impact_trace_tree_oversized");
  });
});
