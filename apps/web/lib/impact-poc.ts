import { createHash, randomUUID } from "node:crypto";
import { chmod, unlink } from "node:fs/promises";
import { createServer, request as httpRequest, type Server } from "node:http";
import path from "node:path";
import { IMPACT_TRACE_LIMITS, impactPoCExecutionSchema, impactPoCReviewSchema, makeImpactObservationPlan, planHash,
  type ImpactForkSession, type ImpactStateProvenance, type ImpactStateSnapshot,
  type ImpactTransactionTrace, type ImpactObservationPlan } from "@contracthunter/core";
import { createImpactPoCArtifact, createImpactPoCExecution, getDatabase, readImpactPoCArtifact,
  readImpactPoCExecution, reviewImpactPoCArtifact, updateImpactPoCExecution, persistImpactStateArtifacts,
  readImpactExecutionState, readImpactExecutionTraces, persistImpactTraceCapture, type DatabaseClient } from "@contracthunter/db";
import { type ImpactForkHandle, type ImpactForkService } from "@contracthunter/scanners";
import { createImpactForkService, resolveImpactHandle } from "./impact-lab";
import { captureImpactState, makeImpactStateDiff } from "./impact-state";
import { parseImpactTransactionTrace } from "./impact-trace";

const IPC_DIR = process.env.IMPACT_POC_IPC_DIR ?? "/run/impact-poc";
if (IPC_DIR !== "/run/impact-poc" && !(process.env.NODE_ENV === "test" && IPC_DIR.startsWith("/tmp/")))
  throw Error("impact_poc_ipc_configuration_invalid");
const CONTROL = path.join(IPC_DIR, "control.sock");
const BRIDGE = path.join(IPC_DIR, "fork.sock");
const METHODS = new Set(["eth_chainId", "eth_blockNumber", "eth_getBlockByNumber", "eth_getBlockByHash", "eth_getCode",
  "eth_getBalance", "eth_getStorageAt", "eth_call", "eth_getLogs", "eth_getTransactionByHash", "eth_getTransactionReceipt",
  "eth_getTransactionCount", "eth_feeHistory", "eth_gasPrice", "eth_maxPriorityFeePerGas",
  "eth_estimateGas", "eth_sendTransaction"]);
const MAX_TX = 4;
let activeJob: string | null = null;
/** Reserves the existing single PoC controller across all replay iterations. */
export function reserveImpactReplayController(runId: string): () => void {
  if (activeJob) throw Error("impact_worker_busy");
  activeJob = runId;
  return () => { if (activeJob === runId) activeJob = null; };
}
export function transferImpactReplayController(fromId: string, runId: string): () => void {
  if (activeJob !== fromId) throw Error("impact_replay_lease_invalid");
  activeJob = runId;
  return () => { if (activeJob === runId) activeJob = null; };
}
function hashToken(token: string): string { return createHash("sha256").update(token).digest("hex"); }
async function boundedBody(input: AsyncIterable<Uint8Array>, max: number): Promise<Buffer> {
  const chunks: Uint8Array[] = []; let bytes = 0;
  for await (const chunk of input) { bytes += chunk.length; if (bytes > max) throw Error("impact_rpc_body_oversized"); chunks.push(chunk); }
  return Buffer.concat(chunks);
}
async function boundedFetchBody(input: ReadableStream<Uint8Array> | null, max: number): Promise<Buffer> {
  if (!input) throw Error("impact_rpc_response_invalid");
  const reader = input.getReader(), chunks: Uint8Array[] = []; let bytes = 0;
  try { for (;;) { const part = await reader.read(); if (part.done) break; bytes += part.value.length;
    if (bytes > max) throw Error("impact_rpc_response_oversized"); chunks.push(part.value); }
    return Buffer.concat(chunks); }
  finally { await reader.cancel().catch(() => undefined); }
}
async function callWorker(payload: object): Promise<Record<string, unknown>> {
  const raw = Buffer.from(JSON.stringify(payload));
  if (raw.length > 20 * 1024) throw Error("impact_worker_request_oversized");
  return new Promise((resolve, reject) => {
    const outgoing = httpRequest({ socketPath: CONTROL, path: "/run", method: "POST", timeout: 36_000,
      headers: { "content-type": "application/json", "content-length": raw.length } }, async (response) => {
      try {
        const body = await boundedBody(response, 20 * 1024);
        if (response.statusCode !== 200) {
          const failure = JSON.parse(body.toString("utf8")) as { error?: unknown };
          throw Error(typeof failure.error === "string" && /^(?:impact_|trusted_compiler_)[a-z_]+$/.test(failure.error) ? failure.error : "impact_worker_failed");
        }
        resolve(JSON.parse(body.toString("utf8")) as Record<string, unknown>);
      } catch (error) { reject(error); }
    });
    outgoing.on("error", reject); outgoing.end(raw);
  });
}
export function validateImpactLocalCalls(raw: Buffer, sender: string, remaining: number): { count: number; calls: Array<Record<string, unknown>> } {
  const parsed = JSON.parse(raw.toString("utf8")) as unknown;
  const calls = Array.isArray(parsed) ? parsed : [parsed];
  if (!calls.length || calls.length > 10) throw Error("impact_local_rpc_rejected");
  let count = 0;
  for (const item of calls) {
    if (!item || typeof item !== "object" || Array.isArray(item)) throw Error("impact_local_rpc_rejected");
    const call = item as Record<string, unknown>;
    if (call.jsonrpc !== "2.0" || typeof call.method !== "string" || call.method.length > 64 ||
      !METHODS.has(call.method) || !(call.params === undefined || Array.isArray(call.params)) ||
      (Array.isArray(call.params) && call.params.length > 16) ||
      !(typeof call.id === "number" && Number.isSafeInteger(call.id) || typeof call.id === "string" && call.id.length <= 64))
      throw Error("impact_local_rpc_rejected");
    if (call.method === "eth_sendTransaction") {
      const params = call.params as unknown[] | undefined;
      const tx = params?.[0];
      if (params?.length !== 1 || !tx || typeof tx !== "object" || Array.isArray(tx) ||
        typeof (tx as Record<string, unknown>).from !== "string" ||
        ((tx as Record<string, unknown>).from as string).toLowerCase() !== sender.toLowerCase())
        throw Error("impact_local_sender_rejected");
      count++;
    }
  }
  if (count > remaining) throw Error("impact_local_transaction_limit");
  return { count, calls: calls as Array<Record<string, unknown>> };
}
async function startBridge(sessionId: string, token: string, sender: string,
  resolveHandle: (id: string) => ImpactForkHandle | undefined, service: ImpactForkService,
  collect: string[]): Promise<{ server: Server; close(): Promise<void> }> {
  await unlink(BRIDGE).catch((error: NodeJS.ErrnoException) => { if (error.code !== "ENOENT") throw error; });
  let active = true, submitted = 0;
  const handle = resolveHandle(sessionId);
  if (!handle || handle.token !== token) throw Error("impact_session_stale");
  const server = createServer(async (request, response) => {
    let deniedId: string | number | null = null;
    try {
      if (!active || request.method !== "POST" || request.url !== "/") throw Error("bridge closed");
      const body = await boundedBody(request, 64 * 1024);
      try { const parsed = JSON.parse(body.toString("utf8"));
        if (!Array.isArray(parsed) && typeof parsed?.method === "string" &&
          (typeof parsed.id === "string" || typeof parsed.id === "number")) deniedId = parsed.id;
      } catch { /* handled by validation */ }
      const validated = validateImpactLocalCalls(body, sender, MAX_TX - submitted);
      submitted += validated.count; // Reserve before any await so concurrent requests share one bound.
      if (resolveHandle(handle.id)?.token !== token) throw Error("impact_session_stale");
      const session = await service.assertSafeImpactExecutionEndpoint(handle);
      const upstream = await fetch(session.localRpcEndpoint!, { method: "POST", headers: { "content-type": "application/json" },
        body: new Uint8Array(body), signal: AbortSignal.timeout(5000), redirect: "manual" });
      if (upstream.status !== 200) throw Error("local fork unavailable");
      const result = await boundedFetchBody(upstream.body, 256 * 1024);
      if (validated.count) {
        const parsed = JSON.parse(result.toString("utf8")) as unknown;
        const answers = Array.isArray(parsed) ? parsed : [parsed];
        for (let i = 0; i < validated.calls.length; i++) if (validated.calls[i]?.method === "eth_sendTransaction") {
          const txHash = (answers[i] as { result?: unknown } | undefined)?.result;
          if (typeof txHash === "string" && /^0x[0-9a-fA-F]{64}$/.test(txHash)) collect.push(txHash.toLowerCase());
        }
      }
      response.writeHead(200, { "content-type": "application/json" }).end(result);
    } catch {
      if (deniedId !== null) {
        response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ jsonrpc: "2.0", id: deniedId,
          error: { code: -32601, message: "Method not found" } }));
        return;
      }
      response.writeHead(503).end();
    }
  });
  server.maxConnections = 32; server.requestTimeout = 6000;
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(BRIDGE, resolve); });
  await chmod(BRIDGE, process.env.NODE_ENV === "test" && process.env.IMPACT_POC_TEST_SOCKET_MODE === "0666" ? 0o666 : 0o660);
  return { server, close: async () => { active = false; server.closeAllConnections(); await new Promise<void>((resolve) => server.close(() => resolve()));
    await unlink(BRIDGE).catch(() => undefined); } };
}

export function submitManualPoC(input: unknown) { return createImpactPoCArtifact(getDatabase(), input); }
export function getManualPoC(id: string) { return readImpactPoCArtifact(getDatabase(), id); }
export function reviewManualPoC(id: string, input: unknown) {
  const { decision } = impactPoCReviewSchema.parse(input);
  return reviewImpactPoCArtifact(getDatabase(), id, decision);
}
export function getManualPoCExecution(id: string) { return readImpactPoCExecution(getDatabase(), id); }
export function getManualPoCExecutionState(id: string) { return readImpactExecutionState(getDatabase(), id); }
export function getManualPoCExecutionTraces(id: string) { return readImpactExecutionTraces(getDatabase(), id); }
export async function executeManualPoC(sessionId: string, input: unknown, deps: {
  database?: DatabaseClient; service?: ImpactForkService; resolveHandle?: (id: string) => ImpactForkHandle | undefined;
  replayLeaseId?: string; resetBefore?: boolean; resetAfter?: boolean;
  reviewedObservationPlan?: ImpactObservationPlan;
} = {}) {
  const { pocArtifactId, observations } = impactPoCExecutionSchema.parse(input);
  const database = deps.database ?? getDatabase();
  const artifact = readImpactPoCArtifact(database, pocArtifactId);
  const handleFor = deps.resolveHandle ?? resolveImpactHandle;
  const handle = handleFor(sessionId);
  if (!artifact || artifact.reviewState !== "reviewed" || !handle) throw Error("impact_poc_not_reviewed_or_session_missing");
  const service = deps.service ?? createImpactForkService();
  const session: ImpactForkSession = await service.assertSafeImpactExecutionEndpoint(handle);
  if (session.status !== "ready" || session.id !== sessionId ||
    artifact.findingId !== session.findingId || artifact.hypothesisId !== session.hypothesisId ||
    artifact.sourceSha256 !== createHash("sha256").update(Buffer.from(artifact.source, "utf8")).digest("hex").replace(/^/, "sha256:"))
    throw Error("impact_poc_identity_invalid");
  const plan = deps.reviewedObservationPlan ??
    makeImpactObservationPlan(session.disposableAccounts[0]!, session.targetContracts, observations);
  if (deps.reviewedObservationPlan &&
    JSON.stringify(makeImpactObservationPlan(session.disposableAccounts[0]!, session.targetContracts, {
      nativeBalances: plan.nativeBalances.filter((address) => address !== session.disposableAccounts[0] &&
        !session.targetContracts.includes(address)),
      erc20Balances: plan.erc20Balances, erc721Owners: plan.erc721Owners,
      erc1155Balances: plan.erc1155Balances, storageSlots: plan.storageSlots, viewCalls: plan.viewCalls,
    })) !== JSON.stringify(plan)) throw Error("impact_replay_observation_plan_invalid");
  if (activeJob && activeJob !== deps.replayLeaseId) throw Error("impact_worker_busy");
  if (deps.replayLeaseId && activeJob !== deps.replayLeaseId) throw Error("impact_replay_lease_invalid");
  const executionId = randomUUID(), token = handle.token;
  const provenance: ImpactStateProvenance = { executionId, sessionId, runtimeTokenSha256: hashToken(token),
    chainId: session.chainId, forkBlock: session.resolvedForkBlock, forkBlockHash: session.forkBlockHash!,
    targetCodeHashes: session.targetCodeHashes, artifactId: artifact.id, sourceSha256: artifact.sourceSha256,
    planSha256: planHash(plan) };
  createImpactPoCExecution(database, { id: executionId, artifactId: artifact.id,
    sourceSha256: artifact.sourceSha256, sessionId, runtimeTokenSha256: hashToken(token), chainId: session.chainId,
    forkBlock: session.resolvedForkBlock, forkBlockHash: session.forkBlockHash!, targetCodeHashes: session.targetCodeHashes,
    forgeVersion: null, forgeSha256: null }, deps.replayLeaseId);
  if (!deps.replayLeaseId) activeJob = executionId;
  const txHashes: string[] = [];
  let bridge: Awaited<ReturnType<typeof startBridge>> | null = null;
  let result: Record<string, unknown> | null = null;
  let failureCode: string | null = null;
  let pre: ImpactStateSnapshot | null = null;
  let post: ImpactStateSnapshot | null = null;
  let traces: ImpactTransactionTrace[] | null | undefined;
  let workerInvoked = false;
  let stage: "reset" | "pre" | "worker" | "trace" | "post" | "persist" = "reset";
  const read = (method: string, params: unknown[]) => service.readLocalImpactState(handle, method, params);
  try {
    if (deps.resetBefore !== false) await service.resetForkSession(handle);
    stage = "pre";
    pre = await captureImpactState(plan, provenance, "pre", read);
    stage = "worker";
    bridge = await startBridge(sessionId, token, session.disposableAccounts[0]!, handleFor, service, txHashes);
    updateImpactPoCExecution(database, executionId, "running");
    workerInvoked = true;
    result = await callWorker({ operation: "run", executionId, sessionId, runtimeTokenSha256: hashToken(token),
      source: artifact.source, sourceSha256: artifact.sourceSha256, entryContract: artifact.entryContract,
      sender: session.disposableAccounts[0], chainId: session.chainId, forkBlock: session.resolvedForkBlock,
      forkBlockHash: session.forkBlockHash });
  } catch { failureCode = stage === "pre" ? "impact_pre_capture_failed" : "impact_execution_failed"; }
  finally {
    try {
      try { await bridge?.close(); }
      catch { failureCode = "impact_bridge_cleanup_failed"; }
      if (pre) {
        if (txHashes.length || workerInvoked && result?.compiled === true) {
          stage = "trace";
          try {
            const deadline = Date.now() + IMPACT_TRACE_LIMITS.totalCaptureMs;
            traces = [];
            for (let index = 0; index < txHashes.length; index++) {
              const remaining = deadline - Date.now();
              if (remaining <= 0) throw Error("impact_trace_timeout");
              const raw = await service.traceLocalImpactTransaction(handle, txHashes[index]!,
                Math.min(remaining, IMPACT_TRACE_LIMITS.perTransactionMs));
              traces.push(parseImpactTransactionTrace(raw.trace, raw.receipt, raw.block,
                provenance, txHashes[index]!, index, session.disposableAccounts[0]!));
            }
          } catch { traces = null; }
        }
        if (workerInvoked && (result?.compiled === true || result?.executed === true || result === null)) {
          stage = "post";
          try { post = await captureImpactState(plan, provenance, "post", read); }
          catch { failureCode = "impact_post_capture_failed"; }
        }
        stage = "persist";
        try { persistImpactStateArtifacts(database, plan, pre, post,
          post ? makeImpactStateDiff(pre, post) : null); }
        catch { failureCode = "impact_state_persist_failed"; }
        if (traces !== undefined) {
          try { persistImpactTraceCapture(database, executionId, txHashes, traces); }
          catch { failureCode = "impact_trace_persist_failed"; }
        }
      }
    }
    finally {
      if (deps.resetAfter !== false) {
        try { await service.resetForkSession(handle); }
        catch { failureCode = "impact_reset_failed"; await service.stopForkSession(handle).catch(() => undefined); }
      }
      if (!deps.replayLeaseId) activeJob = null;
    }
  }
  const forge = result?.forge as Record<string, unknown> | undefined;
  return updateImpactPoCExecution(database, executionId, !failureCode && result?.status === "completed" ? "completed" : "failed",
    { exitCode: typeof result?.exitCode === "number" ? result.exitCode : null,
      compiled: result?.compiled === true, executed: result?.executed === true,
      stdout: typeof result?.stdout === "string" ? result.stdout : "", stderr: typeof result?.stderr === "string" ? result.stderr : "",
      transactionHashes: txHashes, errorCode: failureCode ?? (typeof result?.errorCode === "string" ? result.errorCode : null),
      forgeVersion: typeof forge?.version === "string" ? forge.version : "unknown",
      forgeSha256: typeof forge?.sha256 === "string" ? forge.sha256 : "unknown" });
}
