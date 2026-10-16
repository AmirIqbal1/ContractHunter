import { createHash } from "node:crypto";
import { canonicalImpactHash, provenanceFrame, type ImpactStateProvenance } from "./impact-state";

export const IMPACT_TRACE_LIMITS = {
  transactions: 4, nodes: 256, depth: 24, logs: 64, topics: 4,
  dataBytes: 65_536, retainedBytes: 256, totalLogDataBytes: 131_072,
  rpcResponseBytes: 1_048_576, totalStorageBytes: 524_288,
  perTransactionMs: 10_000, totalCaptureMs: 30_000,
} as const;

export type ImpactTraceData = Readonly<{ byteLength: number; sha256: string; prefix: string; truncated: boolean }>;
export type ImpactTraceCallType = "CALL" | "STATICCALL" | "DELEGATECALL" | "CALLCODE" |
  "CREATE" | "CREATE2" | "SELFDESTRUCT" | "UNKNOWN";
export type ImpactTraceNode = Readonly<{
  ordinal: number; parentOrdinal: number | null; depth: number;
  callType: ImpactTraceCallType; rawCallType: string | null;
  from: string; to: string | null; valueWei: string | null;
  gasSupplied: string | null; gasUsed: string | null;
  outcome: "success" | "reverted" | "failed"; error: string | null;
  inputSelector: string | null; input: ImpactTraceData; output: ImpactTraceData | null;
  revertKind: "Error" | "Panic" | "Custom" | "Unknown" | null;
  revertDetail: string | null;
  targetAddress: string | null;
}>;
export type ImpactTraceLog = Readonly<{
  ordinal: number; logIndex: number; address: string; topics: string[]; data: ImpactTraceData;
}>;
export type ImpactTraceReceipt = Readonly<{
  transactionHash: string; blockNumber: number; blockHash: string; transactionIndex: number;
  status: 0 | 1; gasUsed: string; contractAddress: string | null;
}>;
export type ImpactTraceStats = Readonly<{
  nodeCount: number; maxDepth: number; revertedCallCount: number; targetCallCount: number;
  createdContractCount: number; logCount: number;
}>;
export type ImpactTransactionTrace = Readonly<{
  schema: "impact-transaction-trace-v1"; id: string; provenance: ImpactStateProvenance;
  transactionOrdinal: number; localTransactionHash: string; receipt: ImpactTraceReceipt;
  nodes: ImpactTraceNode[]; logs: ImpactTraceLog[]; stats: ImpactTraceStats;
  contentSha256: string;
}>;

export function impactTraceData(raw: string): ImpactTraceData {
  if (!/^0x(?:[0-9a-fA-F]{2})*$/.test(raw) || (raw.length - 2) / 2 > IMPACT_TRACE_LIMITS.dataBytes)
    throw Error("impact_trace_data_invalid");
  const bytes = Buffer.from(raw.slice(2), "hex");
  return { byteLength: bytes.length, sha256: `sha256:${createHash("sha256").update(bytes).digest("hex")}`,
    prefix: `0x${bytes.subarray(0, IMPACT_TRACE_LIMITS.retainedBytes).toString("hex")}`,
    truncated: bytes.length > IMPACT_TRACE_LIMITS.retainedBytes };
}
export function traceDataFrame(data: ImpactTraceData | null): unknown[] | null {
  return data ? [data.byteLength, data.sha256, data.prefix, data.truncated] : null;
}
export function traceNodeFrame(node: ImpactTraceNode): unknown[] {
  return [node.ordinal, node.parentOrdinal, node.depth, node.callType, node.rawCallType,
    node.from, node.to, node.valueWei, node.gasSupplied, node.gasUsed, node.outcome,
    node.error, node.inputSelector, traceDataFrame(node.input), traceDataFrame(node.output), node.revertKind,
    node.revertDetail, node.targetAddress];
}
export function traceLogFrame(log: ImpactTraceLog): unknown[] {
  return [log.ordinal, log.logIndex, log.address, log.topics, traceDataFrame(log.data)];
}
export function impactTraceHash(trace: Omit<ImpactTransactionTrace, "contentSha256">): string {
  const receipt = trace.receipt;
  return canonicalImpactHash(trace.schema, [provenanceFrame(trace.provenance), trace.transactionOrdinal,
    trace.localTransactionHash, [receipt.transactionHash, receipt.blockNumber, receipt.blockHash,
      receipt.transactionIndex, receipt.status, receipt.gasUsed, receipt.contractAddress],
    trace.nodes.map(traceNodeFrame), trace.logs.map(traceLogFrame),
    [trace.stats.nodeCount, trace.stats.maxDepth, trace.stats.revertedCallCount,
      trace.stats.targetCallCount, trace.stats.createdContractCount, trace.stats.logCount]]);
}

export function verifyImpactTraceShape(trace: ImpactTransactionTrace): void {
  if (trace.schema !== "impact-transaction-trace-v1" || trace.nodes.length < 1 ||
    trace.nodes.length > IMPACT_TRACE_LIMITS.nodes || trace.logs.length > IMPACT_TRACE_LIMITS.logs ||
    trace.transactionOrdinal < 0 || trace.transactionOrdinal >= IMPACT_TRACE_LIMITS.transactions ||
    trace.localTransactionHash !== trace.receipt.transactionHash ||
    !/^0x[0-9a-f]{64}$/.test(trace.localTransactionHash) ||
    trace.contentSha256 !== impactTraceHash(trace) ||
    !/^0x[0-9a-f]{64}$/.test(trace.receipt.blockHash) ||
    !Number.isSafeInteger(trace.receipt.blockNumber) ||
    trace.receipt.blockNumber <= trace.provenance.forkBlock ||
    !Number.isSafeInteger(trace.receipt.transactionIndex) || trace.receipt.transactionIndex < 0 ||
    ![0, 1].includes(trace.receipt.status) || !validDecimal(trace.receipt.gasUsed) ||
    trace.receipt.contractAddress !== null && !validAddress(trace.receipt.contractAddress))
    throw Error("impact_trace_integrity_failed");
  const targets = new Set(Object.keys(trace.provenance.targetCodeHashes));
  for (let index = 0; index < trace.nodes.length; index++) {
    const node = trace.nodes[index]!;
    const parent = node.parentOrdinal === null ? null : trace.nodes[node.parentOrdinal];
    if (node.ordinal !== index || node.depth > IMPACT_TRACE_LIMITS.depth ||
      index === 0 && (node.parentOrdinal !== null || node.depth !== 0) ||
      index > 0 && (!parent || node.parentOrdinal! >= index || node.depth !== parent.depth + 1) ||
      node.targetAddress !== (node.to && targets.has(node.to) ? node.to : null) ||
      !["CALL", "STATICCALL", "DELEGATECALL", "CALLCODE", "CREATE", "CREATE2", "SELFDESTRUCT", "UNKNOWN"]
        .includes(node.callType) ||
      !validAddress(node.from) || node.to !== null && !validAddress(node.to) ||
      node.valueWei !== null && !validDecimal(node.valueWei) ||
      node.gasSupplied !== null && !validDecimal(node.gasSupplied) ||
      node.gasUsed !== null && !validDecimal(node.gasUsed) ||
      !["success", "reverted", "failed"].includes(node.outcome) ||
      node.error !== null && (node.error.length > 128 || /[\x00-\x1f]/.test(node.error)))
      throw Error("impact_trace_integrity_failed");
    if (node.inputSelector !== (node.input.byteLength >= 4 ? node.input.prefix.slice(0, 10) : null))
      throw Error("impact_trace_integrity_failed");
    for (const data of [node.input, node.output]) if (data && !validData(data))
      throw Error("impact_trace_integrity_failed");
  }
  for (let index = 0; index < trace.logs.length; index++) {
    const log = trace.logs[index]!;
    if (log.ordinal !== index || log.topics.length > IMPACT_TRACE_LIMITS.topics ||
      index > 0 && log.logIndex <= trace.logs[index - 1]!.logIndex || !validData(log.data) ||
      !validAddress(log.address) || log.topics.some((topic) => !/^0x[0-9a-f]{64}$/.test(topic)))
      throw Error("impact_trace_integrity_failed");
  }
  const stats = trace.stats;
  if (stats.nodeCount !== trace.nodes.length || stats.logCount !== trace.logs.length ||
    stats.maxDepth !== Math.max(...trace.nodes.map((node) => node.depth)) ||
    stats.revertedCallCount !== trace.nodes.filter((node) => node.outcome === "reverted").length ||
    stats.targetCallCount !== trace.nodes.filter((node) => node.targetAddress !== null).length ||
    stats.createdContractCount !== trace.nodes.filter((node) =>
      ["CREATE", "CREATE2"].includes(node.callType) && node.to !== null).length)
    throw Error("impact_trace_integrity_failed");
}

function validAddress(value: string): boolean { return /^0x[0-9a-f]{40}$/.test(value); }
function validDecimal(value: string): boolean { return /^(?:0|[1-9][0-9]*)$/.test(value); }

function validData(data: ImpactTraceData): boolean {
  return Number.isInteger(data.byteLength) && data.byteLength >= 0 &&
    data.byteLength <= IMPACT_TRACE_LIMITS.dataBytes &&
    /^sha256:[0-9a-f]{64}$/.test(data.sha256) &&
    /^0x(?:[0-9a-f]{2})*$/.test(data.prefix) &&
    (data.prefix.length - 2) / 2 === Math.min(data.byteLength, IMPACT_TRACE_LIMITS.retainedBytes) &&
    data.truncated === (data.byteLength > IMPACT_TRACE_LIMITS.retainedBytes);
}
