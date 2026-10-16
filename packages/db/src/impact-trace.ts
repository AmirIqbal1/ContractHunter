import { impactTraceHash, verifyImpactTraceShape, type ImpactTransactionTrace,
  type ImpactStateProvenance, type ImpactTraceNode, type ImpactTraceLog,
  type ImpactTraceReceipt, type ImpactTraceStats } from "@contracthunter/core";
import type { DatabaseClient } from "./index";
import { readImpactPoCExecution } from "./impact-poc";

function sameProvenance(a: ImpactStateProvenance, b: ImpactStateProvenance): boolean {
  return a.executionId === b.executionId && a.sessionId === b.sessionId &&
    a.runtimeTokenSha256 === b.runtimeTokenSha256 && a.chainId === b.chainId &&
    a.forkBlock === b.forkBlock && a.forkBlockHash === b.forkBlockHash &&
    a.artifactId === b.artifactId && a.sourceSha256 === b.sourceSha256 &&
    a.planSha256 === b.planSha256 &&
    JSON.stringify(Object.entries(a.targetCodeHashes).sort()) ===
      JSON.stringify(Object.entries(b.targetCodeHashes).sort());
}
function executionProvenance(execution: NonNullable<ReturnType<typeof readImpactPoCExecution>>): ImpactStateProvenance {
  return { executionId: execution.id, sessionId: execution.sessionId,
    runtimeTokenSha256: execution.runtimeTokenSha256, chainId: execution.chainId,
    forkBlock: execution.forkBlock, forkBlockHash: execution.forkBlockHash,
    targetCodeHashes: execution.targetCodeHashes, artifactId: execution.artifactId,
    sourceSha256: execution.sourceSha256, planSha256: execution.observationPlanSha256 ?? "" };
}
function validHashes(hashes: string[]): boolean {
  return hashes.length <= 4 && new Set(hashes).size === hashes.length &&
    hashes.every((hash) => /^0x[0-9a-f]{64}$/.test(hash));
}

export function persistImpactTraceCapture(database: DatabaseClient, executionId: string,
  transactionHashes: string[], traces: ImpactTransactionTrace[] | null): void {
  database.sqlite.transaction(() => {
    const execution = readImpactPoCExecution(database, executionId);
    if (!execution || execution.status !== "running" || execution.traceCaptureStatus !== null ||
      !execution.observationPlanSha256 || !validHashes(transactionHashes) ||
      traces && (traces.length !== transactionHashes.length ||
        traces.some((trace, index) => trace.transactionOrdinal !== index ||
          trace.localTransactionHash !== transactionHashes[index] ||
          !sameProvenance(trace.provenance, executionProvenance(execution)))))
      throw Error("impact_trace_binding_invalid");
    if (traces) for (const trace of traces) verifyImpactTraceShape(trace);
    const status = traces ? "finalized" : "failed";
    const count = traces?.length ?? null;
    const nodeCount = traces?.reduce((sum, trace) => sum + trace.nodes.length, 0) ?? null;
    if (database.sqlite.prepare(`UPDATE impact_poc_executions
      SET transaction_hashes=?,trace_capture_status=?,trace_count=?,trace_node_count=?,trace_error_code=?
      WHERE id=? AND trace_capture_status IS NULL`).run(JSON.stringify(transactionHashes), status, count,
      nodeCount, traces ? null : "impact_trace_capture_failed", executionId).changes !== 1)
      throw Error("impact_trace_binding_invalid");
    if (!traces) return;
    const insertTrace = database.sqlite.prepare(`INSERT INTO impact_transaction_traces
      (id,schema,execution_id,transaction_ordinal,transaction_hash,session_id,runtime_token_sha256,
       chain_id,fork_block,fork_block_hash,target_code_hashes,artifact_id,source_sha256,plan_sha256,
       receipt_json,stats_json,node_count,log_count,content_sha256,status)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'finalized')`);
    const insertNode = database.sqlite.prepare(`INSERT INTO impact_trace_nodes
      (trace_id,ordinal,parent_ordinal,depth,payload) VALUES (?,?,?,?,?)`);
    const insertLog = database.sqlite.prepare(`INSERT INTO impact_trace_logs
      (trace_id,ordinal,payload) VALUES (?,?,?)`);
    for (const trace of traces) {
      const p = trace.provenance;
      insertTrace.run(trace.id, trace.schema, executionId, trace.transactionOrdinal, trace.localTransactionHash,
        p.sessionId, p.runtimeTokenSha256, p.chainId, p.forkBlock, p.forkBlockHash,
        JSON.stringify(p.targetCodeHashes), p.artifactId, p.sourceSha256, p.planSha256,
        JSON.stringify(trace.receipt), JSON.stringify(trace.stats), trace.nodes.length, trace.logs.length,
        trace.contentSha256);
      for (const node of trace.nodes) insertNode.run(trace.id, node.ordinal, node.parentOrdinal,
        node.depth, JSON.stringify(node));
      for (const log of trace.logs) insertLog.run(trace.id, log.ordinal, JSON.stringify(log));
    }
  })();
}

export function readImpactTransactionTrace(database: DatabaseClient, id: string): ImpactTransactionTrace | null {
  const row = database.sqlite.prepare("SELECT * FROM impact_transaction_traces WHERE id=? AND status='finalized'")
    .get(id) as Record<string, unknown> | undefined;
  if (!row) return null;
  const nodes = (database.sqlite.prepare("SELECT * FROM impact_trace_nodes WHERE trace_id=? ORDER BY ordinal")
    .all(id) as Array<Record<string, unknown>>).map((item) => {
      const node = JSON.parse(String(item.payload)) as ImpactTraceNode;
      if (node.ordinal !== item.ordinal || node.parentOrdinal !== item.parent_ordinal || node.depth !== item.depth)
        throw Error("impact_trace_integrity_failed");
      return node;
    });
  const logs = (database.sqlite.prepare("SELECT * FROM impact_trace_logs WHERE trace_id=? ORDER BY ordinal")
    .all(id) as Array<Record<string, unknown>>).map((item) => {
      const log = JSON.parse(String(item.payload)) as ImpactTraceLog;
      if (log.ordinal !== item.ordinal) throw Error("impact_trace_integrity_failed");
      return log;
    });
  const provenance: ImpactStateProvenance = { executionId: String(row.execution_id),
    sessionId: String(row.session_id), runtimeTokenSha256: String(row.runtime_token_sha256),
    chainId: Number(row.chain_id), forkBlock: Number(row.fork_block), forkBlockHash: String(row.fork_block_hash),
    targetCodeHashes: JSON.parse(String(row.target_code_hashes)) as Record<string, string>,
    artifactId: String(row.artifact_id), sourceSha256: String(row.source_sha256), planSha256: String(row.plan_sha256) };
  const trace: ImpactTransactionTrace = { schema: "impact-transaction-trace-v1", id,
    provenance, transactionOrdinal: Number(row.transaction_ordinal),
    localTransactionHash: String(row.transaction_hash),
    receipt: JSON.parse(String(row.receipt_json)) as ImpactTraceReceipt,
    stats: JSON.parse(String(row.stats_json)) as ImpactTraceStats,
    nodes, logs, contentSha256: String(row.content_sha256) };
  if (row.schema !== trace.schema || nodes.length !== row.node_count || logs.length !== row.log_count ||
    trace.receipt.transactionHash !== trace.localTransactionHash ||
    impactTraceHash(trace) !== trace.contentSha256) throw Error("impact_trace_integrity_failed");
  verifyImpactTraceShape(trace);
  return trace;
}

export function readImpactExecutionTraces(database: DatabaseClient, executionId: string) {
  const execution = readImpactPoCExecution(database, executionId);
  if (!execution) return null;
  const traces = execution.traceIds.map((id) => readImpactTransactionTrace(database, id));
  if (traces.some((trace) => !trace) ||
    execution.traceCaptureStatus === "finalized" &&
      (traces.length !== execution.traceCount ||
        traces.length !== execution.transactionHashes.length ||
        traces.reduce((sum, trace) => sum + trace!.nodes.length, 0) !== execution.traceNodeCount) ||
    execution.traceCaptureStatus !== "finalized" && traces.length !== 0 ||
    traces.some((trace, index) => trace!.transactionOrdinal !== index ||
      trace!.localTransactionHash !== execution.transactionHashes[index] ||
      !sameProvenance(trace!.provenance, executionProvenance(execution))))
    throw Error("impact_trace_integrity_failed");
  return { executionId, status: execution.traceCaptureStatus, traces };
}
