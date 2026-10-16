import { randomUUID } from "node:crypto";
import { IMPACT_TRACE_LIMITS, impactTraceData, impactTraceHash, type ImpactStateProvenance,
  type ImpactTraceNode, type ImpactTraceLog, type ImpactTraceReceipt, type ImpactTransactionTrace,
  type ImpactTraceCallType } from "@contracthunter/core";

const addressPattern = /^0x[0-9a-fA-F]{40}$/;
const hashPattern = /^0x[0-9a-fA-F]{64}$/;
const hexNumber = /^0x[0-9a-fA-F]+$/;
const types = new Set(["CALL", "STATICCALL", "DELEGATECALL", "CALLCODE", "CREATE", "CREATE2", "SELFDESTRUCT"]);
const traceFields = new Set(["type", "from", "to", "input", "output", "value", "gas", "gasUsed",
  "error", "revertReason", "calls"]);
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw Error("impact_trace_invalid");
  return value as Record<string, unknown>;
}
function address(value: unknown): string {
  if (typeof value !== "string" || !addressPattern.test(value)) throw Error("impact_trace_address_invalid");
  return value.toLowerCase();
}
function hash(value: unknown): string {
  if (typeof value !== "string" || !hashPattern.test(value)) throw Error("impact_trace_hash_invalid");
  return value.toLowerCase();
}
function integer(value: unknown): bigint {
  if (typeof value !== "string" || !hexNumber.test(value) || value.length > 66)
    throw Error("impact_trace_integer_invalid");
  return BigInt(value);
}
function smallInteger(value: unknown): number {
  const number = Number(integer(value));
  if (!Number.isSafeInteger(number)) throw Error("impact_trace_integer_invalid");
  return number;
}
function optionalInteger(value: unknown): string | null {
  return value === undefined ? null : integer(value).toString();
}
function decodedRevert(data: unknown): { kind: ImpactTraceNode["revertKind"]; detail: string | null } {
  if (typeof data !== "string" || !/^0x(?:[0-9a-fA-F]{2})*$/.test(data)) return { kind: "Unknown", detail: null };
  const raw = data.toLowerCase();
  if (raw.startsWith("0x4e487b71") && raw.length === 74)
    return { kind: "Panic", detail: BigInt(`0x${raw.slice(10)}`).toString() };
  if (raw.startsWith("0x08c379a0") && raw.length >= 138) {
    const offset = BigInt(`0x${raw.slice(10, 74)}`);
    const length = BigInt(`0x${raw.slice(74, 138)}`);
    if (offset === 32n && length <= 128n && raw.length >= 138 + Number(length) * 2) {
      const bytes = Buffer.from(raw.slice(138, 138 + Number(length) * 2), "hex");
      try { return { kind: "Error", detail: new TextDecoder("utf-8", { fatal: true }).decode(bytes) }; }
      catch { /* Keep the raw identity only. */ }
    }
    return { kind: "Error", detail: null };
  }
  return { kind: raw.length >= 10 ? "Custom" : "Unknown", detail: null };
}

export function parseImpactTransactionTrace(rawTrace: unknown, rawReceipt: unknown, rawBlock: unknown,
  provenance: ImpactStateProvenance, transactionHash: string, transactionOrdinal: number,
  disposableSender: string): ImpactTransactionTrace {
  if (!Number.isInteger(transactionOrdinal) || transactionOrdinal < 0 ||
    transactionOrdinal >= IMPACT_TRACE_LIMITS.transactions) throw Error("impact_trace_ordinal_invalid");
  const txHash = hash(transactionHash), sender = address(disposableSender);
  const receiptRaw = object(rawReceipt), blockRaw = object(rawBlock);
  const receiptHash = hash(receiptRaw.transactionHash);
  const blockHash = hash(receiptRaw.blockHash);
  const blockNumber = smallInteger(receiptRaw.blockNumber);
  if (receiptHash !== txHash || address(receiptRaw.from) !== sender ||
    hash(blockRaw.hash) !== blockHash || smallInteger(blockRaw.number) !== blockNumber ||
    blockNumber <= provenance.forkBlock) throw Error("impact_trace_receipt_mismatch");
  const statusNumber = smallInteger(receiptRaw.status);
  if (statusNumber !== 0 && statusNumber !== 1) throw Error("impact_trace_receipt_invalid");
  const receipt: ImpactTraceReceipt = { transactionHash: txHash, blockNumber, blockHash,
    transactionIndex: smallInteger(receiptRaw.transactionIndex), status: statusNumber as 0 | 1,
    gasUsed: integer(receiptRaw.gasUsed).toString(),
    contractAddress: receiptRaw.contractAddress === null ? null : address(receiptRaw.contractAddress) };
  const receiptTo = receiptRaw.to === null ? null : address(receiptRaw.to);
  const rawLogs = receiptRaw.logs;
  if (!Array.isArray(rawLogs) || rawLogs.length > IMPACT_TRACE_LIMITS.logs) throw Error("impact_trace_logs_invalid");
  let logDataBytes = 0;
  const logs: ImpactTraceLog[] = rawLogs.map((item, ordinal) => {
    const log = object(item);
    const topics = log.topics;
    if (!Array.isArray(topics) || topics.length > IMPACT_TRACE_LIMITS.topics) throw Error("impact_trace_logs_invalid");
    if (log.transactionHash !== undefined && hash(log.transactionHash) !== txHash ||
      log.blockHash !== undefined && hash(log.blockHash) !== blockHash ||
      log.blockNumber !== undefined && smallInteger(log.blockNumber) !== blockNumber)
      throw Error("impact_trace_logs_invalid");
    const data = impactTraceData(String(log.data));
    logDataBytes += data.byteLength;
    if (logDataBytes > IMPACT_TRACE_LIMITS.totalLogDataBytes) throw Error("impact_trace_logs_oversized");
    return { ordinal, logIndex: smallInteger(log.logIndex), address: address(log.address),
      topics: topics.map(hash), data };
  });
  if (logs.some((log, index) => index > 0 && log.logIndex <= logs[index - 1]!.logIndex))
    throw Error("impact_trace_logs_invalid");

  const nodes: ImpactTraceNode[] = [];
  const targets = new Set(Object.keys(provenance.targetCodeHashes).map((item) => address(item)));
  function walk(value: unknown, parentOrdinal: number | null, depth: number): void {
    if (depth > IMPACT_TRACE_LIMITS.depth || nodes.length >= IMPACT_TRACE_LIMITS.nodes)
      throw Error("impact_trace_tree_oversized");
    const call = object(value);
    if (Object.keys(call).some((key) => !traceFields.has(key)) || typeof call.type !== "string" ||
      !/^[A-Z][A-Z0-9_]{0,31}$/.test(call.type)) throw Error("impact_trace_node_invalid");
    const callType: ImpactTraceCallType = types.has(call.type) ? call.type as ImpactTraceCallType : "UNKNOWN";
    const from = address(call.from);
    const to = call.to === undefined || call.to === null ? null : address(call.to);
    if (!to && !["CREATE", "CREATE2", "SELFDESTRUCT"].includes(callType) ||
      typeof call.input !== "string") throw Error("impact_trace_node_invalid");
    const error = call.error === undefined ? null : call.error;
    if (error !== null && (typeof error !== "string" || error.length > 128 || /[\x00-\x1f]/.test(error)))
      throw Error("impact_trace_node_invalid");
    const outcome: ImpactTraceNode["outcome"] = error === null ? "success" :
      /revert/i.test(error) ? "reverted" : "failed";
    const output = call.output === undefined ? null : impactTraceData(String(call.output));
    const revert = error === null ? { kind: null, detail: null } : decodedRevert(call.output);
    const ordinal = nodes.length;
    const input = impactTraceData(call.input);
    nodes.push({ ordinal, parentOrdinal, depth, callType,
      rawCallType: callType === "UNKNOWN" ? call.type : null,
      from, to, valueWei: optionalInteger(call.value), gasSupplied: optionalInteger(call.gas),
      gasUsed: optionalInteger(call.gasUsed), outcome, error,
      inputSelector: input.byteLength >= 4 ? input.prefix.slice(0, 10) : null, input,
      output, revertKind: revert.kind, revertDetail: revert.detail,
      targetAddress: to && targets.has(to) ? to : null });
    if (call.calls !== undefined) {
      if (!Array.isArray(call.calls)) throw Error("impact_trace_node_invalid");
      for (const child of call.calls) walk(child, ordinal, depth + 1);
    }
  }
  walk(rawTrace, null, 0);
  const root = nodes[0]!;
  const rootTargetMatches = receiptTo === null
    ? ["CREATE", "CREATE2"].includes(root.callType) && (root.to === null || root.to === receipt.contractAddress)
    : root.to === receiptTo;
  if (root.from !== sender || !rootTargetMatches ||
    receipt.status === 1 && root.outcome !== "success" ||
    receipt.status === 0 && root.outcome === "success") throw Error("impact_trace_receipt_mismatch");
  const stats = { nodeCount: nodes.length, maxDepth: Math.max(...nodes.map((node) => node.depth)),
    revertedCallCount: nodes.filter((node) => node.outcome === "reverted").length,
    targetCallCount: nodes.filter((node) => node.targetAddress !== null).length,
    createdContractCount: nodes.filter((node) => ["CREATE", "CREATE2"].includes(node.callType) && node.to !== null).length,
    logCount: logs.length };
  const trace: Omit<ImpactTransactionTrace, "contentSha256"> = { schema: "impact-transaction-trace-v1",
    id: randomUUID(), provenance, transactionOrdinal, localTransactionHash: txHash, receipt, nodes, logs, stats };
  if (Buffer.byteLength(JSON.stringify(trace)) > IMPACT_TRACE_LIMITS.totalStorageBytes)
    throw Error("impact_trace_storage_oversized");
  return { ...trace, contentSha256: impactTraceHash(trace) };
}
