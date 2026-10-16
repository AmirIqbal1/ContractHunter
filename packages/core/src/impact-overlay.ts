import { createHash } from "node:crypto";
import { deriveImpactChanges, diffHash, impactChangeFrame, provenanceFrame, snapshotHash,
  type ImpactObservation, type ImpactStateDiff, type ImpactStateSnapshot, type ImpactStateProvenance } from "./impact-state";
import { IMPACT_TRACE_LIMITS, verifyImpactTraceShape,
  type ImpactTransactionTrace, type ImpactTraceCallType, type ImpactTraceData } from "./impact-trace";
import { validateStaticProtocolGraphArtifact, type StaticProtocolGraphArtifact } from "./static-protocol-graph";
import { validateInvestigationPathResult, type InvestigationPathResult } from "./investigation-path";
import { canonicalFunctionSelector } from "./impact-selector";
import type { ProtocolGraphNode, ProtocolGraphEdge } from "./protocol-graph";

export const IMPACT_OVERLAY_SCHEMA = "contracthunter-impact-overlay-v1" as const;
export const IMPACT_OVERLAY_DERIVATION_VERSION = "contracthunter-impact-overlay-deriver-v1" as const;
export const IMPACT_OVERLAY_EXPLANATION_KEYS = ["observed-call", "observed-state-change", "runtime-only-call",
  "static-edge-observed", "static-edge-not-observed", "reverted-transaction", "unmapped-runtime-call", "observed-log"] as const;

export type ImpactOverlayExecution = Readonly<{ id: string; artifactId: string; sourceSha256: string;
  sessionId: string; runtimeTokenSha256: string; chainId: number; forkBlock: number; forkBlockHash: string;
  targetCodeHashes: Record<string, string>; status: string; executed: boolean;
  transactionScope: "local-impact-lab"; transactionHashes: string[];
  observationPlanSha256: string | null; preSnapshotId: string | null; postSnapshotId: string | null;
  stateDiffId: string | null; traceCaptureStatus: "finalized" | "failed" | null; traceIds: string[] }>;
export type ImpactOverlayArtifact = Readonly<{ id: string; findingId: string | null; hypothesisId: string | null;
  sourceSha256: string; reviewState: "draft" | "reviewed" | "rejected" }>;
export type ImpactOverlaySession = Readonly<{ id: string; findingId: string | null; hypothesisId: string | null;
  chainId: number; resolvedForkBlock: number; forkBlockHash: string | null;
  targetCodeHashes: Record<string, string>; targetContracts: string[] }>;
/** Accepted only from a trusted server adapter with an independently verified exact deployed-code/source witness.
 * The current database has no such witness, so the production resolver supplies no bindings. */
export type ExactDeploymentBinding = Readonly<{ address: string; deployedCodeSha256: string;
  contractNodeId: string; sourceUnitName: string; sourceRawSha256: string;
  evidenceId: string; evidenceKind: "exact-deployed-bytecode-source-link" }>;
export type ImpactOverlayEvidence = Readonly<{ scanId: string; execution: ImpactOverlayExecution;
  artifact: ImpactOverlayArtifact; session: ImpactOverlaySession;
  pre: ImpactStateSnapshot | null; post: ImpactStateSnapshot | null; diff: ImpactStateDiff | null;
  traces: readonly ImpactTransactionTrace[]; graph?: StaticProtocolGraphArtifact | null;
  investigationPath?: InvestigationPathResult | null;
  trustedDeploymentBindings?: readonly ExactDeploymentBinding[] }>;

type Mapping = { contractNodeId: string | null; functionNodeId: string | null;
  reason: "exact-deployed-bytecode-source-link" | "unique-canonical-selector" | "proven-receive" |
    "proven-fallback" | "contract-unmapped" | "function-unresolved";
  evidenceId: string | null; deployedCodeSha256: string | null;
  sourceUnitName: string | null; sourceRawSha256: string | null };
export type ObservedOverlayCall = Readonly<{ id: string; traceId: string; transactionHash: string;
  transactionOrdinal: number; ordinal: number; parentCallId: string | null; depth: number;
  callType: ImpactTraceCallType; rawCallType: string | null; from: string; to: string | null; codeAddress: string | null;
  storageContextAddress: string | null; valueWei: string | null; outcome: "success" | "reverted" | "failed";
  gasSupplied: string | null; gasUsed: string | null; selector: string | null;
  input: ImpactTraceData; output: ImpactTraceData | null; error: string | null;
  revertKind: string | null; revertDetail: string | null;
  mapping: Mapping; staticEdgeId: string | null;
  relationshipStatus: "root-call" | "observed-static-edge" | "matched-contract-only" |
    "runtime-only-observed" | "ambiguous-static-edge" | "unmapped-runtime-call";
  explanationKey: (typeof IMPACT_OVERLAY_EXPLANATION_KEYS)[number] }>;
export type ObservedOverlayTransaction = Readonly<{ ordinal: number; transactionHash: string;
  sender: string | null; to: string | null; valueWei: string | null;
  status: "success" | "reverted" | "trace-unavailable"; gasUsed: string | null;
  localBlockNumber: number | null; localBlockHash: string | null; transactionIndex: number | null;
  receiptTraceId: string | null; traceAvailable: boolean }>;
export type ObservedOverlayLog = Readonly<{ id: string; traceId: string; transactionHash: string;
  ordinal: number; logIndex: number; address: string; topics: string[]; data: ImpactTraceData;
  contractNodeId: string | null; eventNodeId: null; explanationKey: "observed-log" }>;
export type ObservedOverlayState = Readonly<{ observationId: string; kind: ImpactObservation["kind"];
  descriptor: Record<string, string>; beforeStatus: ImpactObservation["status"];
  afterStatus: ImpactObservation["status"] | "not-captured"; before: string | null; after: string | null;
  beforeErrorCode: string | null; afterErrorCode: string | null; delta: string | null;
  state: "changed" | "unchanged" | "unavailable" | "post-unavailable";
  contractNodeId: string | null; changeId: string | null; preSnapshotId: string; postSnapshotId: string | null;
  diffId: string | null; explanationKey: "observed-state-change" }>;
export type ImpactPathComparison = Readonly<{ pathId: string; subjectType: string; subjectId: string;
  steps: Array<{ nodeId: string; status: "observed-in-this-local-execution" | "not-observed-in-this-execution" |
    "comparison-unresolved" | "static-context-only" }>;
  edges: Array<{ edgeId: string; status: "observed-in-this-local-execution" | "not-observed-in-this-execution" |
    "comparison-unresolved" | "static-context-only" }>;
  runtimeOnlyCallIds: string[] }>;
export type ImpactOverlay = Readonly<{ schema: typeof IMPACT_OVERLAY_SCHEMA;
  derivationVersion: typeof IMPACT_OVERLAY_DERIVATION_VERSION; scanId: string; executionId: string;
  sessionId: string; artifactId: string; subject: { type: "finding" | "hypothesis"; id: string };
  protocolGraphId: string | null; investigationPathResultId: string | null;
  forkIdentity: { chainId: number; baseBlockNumber: number; baseBlockHash: string; targetCodeHashes: Record<string, string> };
  sourceIdentity: { reviewedArtifactId: string; sourceSha256: string };
  capabilities: { traceAvailable: boolean; statePreAvailable: boolean; stateDiffAvailable: boolean; overlayAvailable: boolean };
  transactions: ObservedOverlayTransaction[]; observedCalls: ObservedOverlayCall[];
  observedLogs: ObservedOverlayLog[]; observedState: ObservedOverlayState[];
  pathComparisons: ImpactPathComparison[];
  coverage: { transactionCount: number; tracedTransactionCount: number; observedCallCount: number;
    contractMappedCallCount: number; functionMappedCallCount: number; unmappedCallCount: number;
    stateObservationCount: number; changedObservationCount: number; unavailableObservationCount: number };
  warnings: string[];
  provenance: { traceIds: string[]; traceContentSha256: string[]; preSnapshotId: string | null;
    preSnapshotSha256: string | null; postSnapshotId: string | null; postSnapshotSha256: string | null;
    diffId: string | null; diffSha256: string | null; graphContentSha256: string | null;
    pathContentSha256: string | null; mappingEvidenceIds: string[] };
  contentSha256: string }>;

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const txHash = /^0x[0-9a-f]{64}$/;
const sha256 = /^sha256:[0-9a-f]{64}$/;
// B1 executions created before the prefixed provenance fix stored the same digest as bare hex.
const runtimeTokenHash = /^(?:sha256:)?[0-9a-f]{64}$/;
function sameProvenance(a: ImpactStateProvenance, b: ImpactStateProvenance): boolean {
  return JSON.stringify(provenanceFrame(a)) === JSON.stringify(provenanceFrame(b));
}
function expectedProvenance(e: ImpactOverlayExecution): ImpactStateProvenance {
  return { executionId: e.id, sessionId: e.sessionId, runtimeTokenSha256: e.runtimeTokenSha256,
    chainId: e.chainId, forkBlock: e.forkBlock, forkBlockHash: e.forkBlockHash,
    targetCodeHashes: e.targetCodeHashes, artifactId: e.artifactId,
    sourceSha256: e.sourceSha256, planSha256: e.observationPlanSha256 ?? "" };
}
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) =>
    `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`).join(",")}}`;
  return JSON.stringify(value);
}
function contentHash(value: unknown): string {
  return createHash("sha256").update(IMPACT_OVERLAY_SCHEMA).update("\0").update(canonical(value)).digest("hex");
}
function exactObject(a: Record<string, string>, b: Record<string, string>): boolean { return canonical(a) === canonical(b); }
function evidenceBound(input: ImpactOverlayEvidence): { graph: StaticProtocolGraphArtifact | null;
  path: InvestigationPathResult | null; bindings: Map<string, ExactDeploymentBinding> } {
  const { execution: e, artifact: a, session: s, pre, post, diff } = input;
  if (!uuid.test(input.scanId) || !uuid.test(e.id) || !uuid.test(e.sessionId) || !uuid.test(e.artifactId) ||
    !Number.isSafeInteger(e.chainId) || e.chainId < 1 || !Number.isSafeInteger(e.forkBlock) || e.forkBlock < 0 ||
    !txHash.test(e.forkBlockHash) || !runtimeTokenHash.test(e.runtimeTokenSha256) || !sha256.test(e.sourceSha256) ||
    e.observationPlanSha256 !== null && !sha256.test(e.observationPlanSha256) ||
    Object.keys(e.targetCodeHashes).length < 1 || Object.keys(e.targetCodeHashes).length > 20 ||
    Object.entries(e.targetCodeHashes).some(([address, hash]) =>
      !/^0x[0-9a-f]{40}$/.test(address) || !sha256.test(hash)) ||
    e.transactionScope !== "local-impact-lab" || !["completed", "failed", "cancelled"].includes(e.status) ||
    a.reviewState !== "reviewed" || a.id !== e.artifactId || a.sourceSha256 !== e.sourceSha256 ||
    s.id !== e.sessionId || s.chainId !== e.chainId || s.resolvedForkBlock !== e.forkBlock ||
    s.forkBlockHash !== e.forkBlockHash || !exactObject(s.targetCodeHashes, e.targetCodeHashes) ||
    canonical([...s.targetContracts].sort()) !== canonical(Object.keys(e.targetCodeHashes).sort()) ||
    (a.findingId === null) === (a.hypothesisId === null) ||
    a.findingId !== null && !uuid.test(a.findingId) || a.hypothesisId !== null && !uuid.test(a.hypothesisId) ||
    a.findingId !== s.findingId || a.hypothesisId !== s.hypothesisId ||
    e.transactionHashes.length > IMPACT_TRACE_LIMITS.transactions ||
    new Set(e.transactionHashes).size !== e.transactionHashes.length ||
    e.transactionHashes.some((hash) => !txHash.test(hash)) ||
    e.traceCaptureStatus === "finalized" && (input.traces.length !== e.transactionHashes.length ||
      e.traceIds.length !== input.traces.length) ||
    e.traceCaptureStatus !== "finalized" && (input.traces.length > 0 || e.traceIds.length > 0) ||
    Boolean(post) !== Boolean(diff) || Boolean(post) && !pre || Boolean(e.preSnapshotId) !== Boolean(pre) ||
    Boolean(e.postSnapshotId) !== Boolean(post) || Boolean(e.stateDiffId) !== Boolean(diff))
    throw Error("impact_overlay_evidence_binding_invalid");
  const p = expectedProvenance(e);
  for (let i = 0; i < input.traces.length; i++) {
    const trace = input.traces[i]!; verifyImpactTraceShape(trace);
    if (trace.id !== e.traceIds[i] || trace.transactionOrdinal !== i ||
      trace.localTransactionHash !== e.transactionHashes[i] || !sameProvenance(trace.provenance, p))
      throw Error("impact_overlay_trace_binding_invalid");
  }
  if (pre) {
    if (pre.id !== e.preSnapshotId || pre.phase !== "pre" || pre.contentSha256 !== snapshotHash(pre) ||
      !sameProvenance(pre.provenance, p) || pre.observations.length > 64 ||
      new Set(pre.observations.map((item) => item.id)).size !== pre.observations.length)
      throw Error("impact_overlay_state_binding_invalid");
  }
  if (post && diff && pre) {
    if (post.id !== e.postSnapshotId || post.phase !== "post" || post.contentSha256 !== snapshotHash(post) ||
      !sameProvenance(post.provenance, p) || post.observations.length > 64 ||
      new Set(post.observations.map((item) => item.id)).size !== post.observations.length ||
      diff.id !== e.stateDiffId || diff.changeCount !== diff.changes.length ||
      new Set(diff.changes.map((item) => item.id)).size !== diff.changes.length ||
      diff.contentSha256 !== diffHash(diff) || !sameProvenance(diff.provenance, p) ||
      diff.preSnapshotId !== pre.id || diff.postSnapshotId !== post.id ||
      diff.preSnapshotSha256 !== pre.contentSha256 || diff.postSnapshotSha256 !== post.contentSha256 ||
      canonical(diff.changes.map(impactChangeFrame)) !== canonical(deriveImpactChanges(pre, post).map(impactChangeFrame)))
      throw Error("impact_overlay_state_binding_invalid");
  }
  const graph = input.graph ? validateStaticProtocolGraphArtifact(input.graph) : null;
  if (graph && graph.graph.scanId !== input.scanId) throw Error("impact_overlay_graph_binding_invalid");
  const path = input.investigationPath ? validateInvestigationPathResult(input.investigationPath) : null;
  if (path && (!graph || path.scanId !== input.scanId || path.protocolGraphId !== graph.graph.id ||
    path.graphContentSha256 !== graph.contentSha256 || path.subject.id !== (a.findingId ?? a.hypothesisId) ||
    path.subject.type !== (a.findingId ? "finding" : "hypothesis")))
    throw Error("impact_overlay_path_binding_invalid");
  const bindings = new Map<string, ExactDeploymentBinding>();
  for (const item of input.trustedDeploymentBindings ?? []) {
    const node = graph?.graph.nodes.find((candidate) => candidate.id === item.contractNodeId);
    const unit = graph?.graph.sourceUnits.find((candidate) => candidate.sourceUnitName === item.sourceUnitName);
    if (!node || !["contract", "interface", "library"].includes(node.kind) ||
      node.source?.sourceUnitName !== item.sourceUnitName || unit?.identityStatus !== "authoritative" ||
      unit.rawSha256 !== item.sourceRawSha256 || e.targetCodeHashes[item.address] !== item.deployedCodeSha256 ||
      item.evidenceKind !== "exact-deployed-bytecode-source-link" || !item.evidenceId ||
      bindings.has(item.address)) throw Error("impact_overlay_deployment_binding_invalid");
    bindings.set(item.address, item);
  }
  return { graph, path, bindings };
}
function descriptor(observation: ImpactObservation): Record<string, string> {
  const parts = observation.id.split(":");
  if (observation.kind === "native" && parts.length === 2) return { address: parts[1]! };
  if (observation.kind === "erc20" && parts.length === 3) return { token: parts[1]!, holder: parts[2]! };
  if (observation.kind === "erc721" && parts.length === 3) return { token: parts[1]!, tokenId: parts[2]! };
  if (observation.kind === "erc1155" && parts.length === 4) return { token: parts[1]!, holder: parts[2]!, tokenId: parts[3]! };
  if (observation.kind === "storage" && parts.length === 3) return { contract: parts[1]!, slot: parts[2]! };
  if (observation.kind === "view" && parts.length === 3 && parts[1] === "erc20_totalSupply")
    return { kind: parts[1], target: parts[2]! };
  throw Error("impact_overlay_observation_identity_invalid");
}
function mappedFunction(node: ProtocolGraphNode, selector: string | null, inputLength: number,
  functionsByContract: Map<string, ProtocolGraphNode[]>, selectorCache: Map<string, string | null>):
  { id: string; reason: Mapping["reason"] } | null {
  if (node.kind !== "contract" && node.kind !== "interface" && node.kind !== "library") return null;
  const owned = functionsByContract.get(node.id) ?? [];
  if (inputLength === 0) {
    const receive = owned.filter((item) => item.kind === "function" && item.signature === "receive()");
    if (receive.length === 1) return { id: receive[0]!.id, reason: "proven-receive" };
  }
  if (selector) {
    const matches = owned.filter((item) => item.kind === "function" && selectorCache.get(item.id) === selector);
    if (matches.length === 1) return { id: matches[0]!.id, reason: "unique-canonical-selector" };
    if (matches.length > 1) return null;
  }
  if (inputLength < 4) {
    const fallback = owned.filter((item) => item.kind === "function" && item.signature === "fallback()");
    if (fallback.length === 1) return { id: fallback[0]!.id, reason: "proven-fallback" };
  }
  return null;
}
function edgeCandidates(edgesByPair: Map<string, ProtocolGraphEdge[]>, from: string, to: string,
  callType: ImpactTraceCallType): ProtocolGraphEdge[] {
  const kinds = callType === "DELEGATECALL" ? ["delegates"] :
    ["CALL", "STATICCALL"].includes(callType) ? ["calls", "external-call"] : [];
  return kinds.flatMap((kind) => edgesByPair.get(`${from}:${to}:${kind}`) ?? []);
}
export function compareInvestigationPathToImpactOverlay(path: InvestigationPathResult,
  overlay: ImpactOverlay): ImpactPathComparison[] {
  if (path.scanId !== overlay.scanId || path.protocolGraphId !== overlay.protocolGraphId ||
    path.contentSha256 !== overlay.investigationPathResultId ||
    path.subject.id !== overlay.subject.id || path.subject.type !== overlay.subject.type)
    throw Error("impact_overlay_path_comparison_binding_invalid");
  const functions = new Set(overlay.observedCalls.flatMap((call) => call.mapping.functionNodeId ? [call.mapping.functionNodeId] : []));
  const contracts = new Set(overlay.observedCalls.flatMap((call) => call.mapping.contractNodeId ? [call.mapping.contractNodeId] : []));
  const edges = new Set(overlay.observedCalls.flatMap((call) => call.staticEdgeId ? [call.staticEdgeId] : []));
  const comparisonUnresolved = !overlay.capabilities.traceAvailable || overlay.observedCalls.some((call) =>
    ["CALL", "STATICCALL", "DELEGATECALL", "CALLCODE"].includes(call.callType) && !call.mapping.functionNodeId);
  const runtimeOnlyCallIds = overlay.observedCalls.filter((call) => call.relationshipStatus === "runtime-only-observed").map((call) => call.id);
  return path.paths.map((item) => ({ pathId: item.id, subjectType: path.subject.type, subjectId: path.subject.id,
    steps: item.steps.map((step) => ({ nodeId: step.nodeId,
      status: functions.has(step.nodeId) || contracts.has(step.nodeId) ? "observed-in-this-local-execution" as const :
        !["function", "contract", "interface", "library"].includes(step.nodeKind) ? "static-context-only" as const :
          comparisonUnresolved ? "comparison-unresolved" as const :
        "not-observed-in-this-execution" as const })),
    edges: item.edgeIds.map((edgeId, index) => ({ edgeId, status:
      !["calls", "external-call", "delegates"].includes(item.steps[index + 1]?.relationship ?? "") ?
        "static-context-only" as const : edges.has(edgeId) ? "observed-in-this-local-execution" as const :
          comparisonUnresolved ? "comparison-unresolved" as const : "not-observed-in-this-execution" as const })),
    runtimeOnlyCallIds }));
}
export function deriveImpactOverlay(input: ImpactOverlayEvidence): ImpactOverlay {
  const { graph, path, bindings } = evidenceBound(input), e = input.execution;
  const subject = input.artifact.findingId ? { type: "finding" as const, id: input.artifact.findingId } :
    { type: "hypothesis" as const, id: input.artifact.hypothesisId! };
  const byId = new Map(graph?.graph.nodes.map((node) => [node.id, node]) ?? []);
  const functionsByContract = new Map<string, ProtocolGraphNode[]>();
  const selectorCache = new Map<string, string | null>();
  for (const node of graph?.graph.nodes ?? []) if (node.kind === "function") {
    const owned = functionsByContract.get(node.contractId) ?? [];
    owned.push(node); functionsByContract.set(node.contractId, owned);
    selectorCache.set(node.id, canonicalFunctionSelector(node.signature));
  }
  const edgesByPair = new Map<string, ProtocolGraphEdge[]>();
  for (const edge of graph?.graph.edges ?? []) if (edge.origin === "static" &&
    edge.fromFunctionId && edge.toFunctionId && edge.from === edge.fromFunctionId && edge.to === edge.toFunctionId) {
    const key = `${edge.from}:${edge.to}:${edge.kind}`, candidates = edgesByPair.get(key) ?? [];
    candidates.push(edge); edgesByPair.set(key, candidates);
  }
  const mapAddress = (address: string | null): Mapping => {
    const binding = address ? bindings.get(address) : null, contract = binding ? byId.get(binding.contractNodeId) : null;
    return { contractNodeId: contract?.id ?? null, functionNodeId: null,
      reason: binding ? "exact-deployed-bytecode-source-link" : "contract-unmapped",
      evidenceId: binding?.evidenceId ?? null, deployedCodeSha256: binding?.deployedCodeSha256 ?? null,
      sourceUnitName: binding?.sourceUnitName ?? null, sourceRawSha256: binding?.sourceRawSha256 ?? null };
  };
  const calls: ObservedOverlayCall[] = [], transactions: ObservedOverlayTransaction[] = [], logs: ObservedOverlayLog[] = [];
  for (let tx = 0; tx < e.transactionHashes.length; tx++) {
    const hash = e.transactionHashes[tx]!, trace = input.traces[tx] ?? null;
    transactions.push({ ordinal: tx, transactionHash: hash, sender: trace?.nodes[0]?.from ?? null,
      to: trace?.nodes[0]?.to ?? null, valueWei: trace?.nodes[0]?.valueWei ?? null,
      status: trace ? trace.receipt.status === 0 ? "reverted" : "success" : "trace-unavailable",
      gasUsed: trace?.receipt.gasUsed ?? null, localBlockNumber: trace?.receipt.blockNumber ?? null,
      localBlockHash: trace?.receipt.blockHash ?? null, transactionIndex: trace?.receipt.transactionIndex ?? null,
      receiptTraceId: trace?.id ?? null, traceAvailable: trace !== null });
    if (!trace) continue;
    const callsByOrdinal = new Map<number, ObservedOverlayCall>();
    for (const node of trace.nodes) {
      const parent = node.parentOrdinal === null ? null : callsByOrdinal.get(node.parentOrdinal) ?? null;
      const id = `${trace.id}:${node.ordinal}`, mapping = mapAddress(node.to), contract = mapping.contractNodeId ? byId.get(mapping.contractNodeId) : null;
      const fn = contract && ["CALL", "STATICCALL", "DELEGATECALL", "CALLCODE"].includes(node.callType) ?
        mappedFunction(contract, node.inputSelector, node.input.byteLength,
        functionsByContract, selectorCache) : null;
      if (fn) { mapping.functionNodeId = fn.id; mapping.reason = fn.reason; }
      else if (mapping.contractNodeId) mapping.reason = "function-unresolved";
      const candidates = parent?.mapping.functionNodeId && mapping.functionNodeId ?
        edgeCandidates(edgesByPair, parent.mapping.functionNodeId, mapping.functionNodeId, node.callType) : [];
      const staticEdgeId = candidates.length === 1 ? candidates[0]!.id : null;
      const relationshipStatus: ObservedOverlayCall["relationshipStatus"] = node.parentOrdinal === null ? "root-call" :
        staticEdgeId ? "observed-static-edge" : candidates.length > 1 ? "ambiguous-static-edge" :
          parent?.mapping.functionNodeId && mapping.functionNodeId ? "runtime-only-observed" :
            parent?.mapping.contractNodeId && mapping.contractNodeId ? "matched-contract-only" : "unmapped-runtime-call";
      const storageContextAddress = ["DELEGATECALL", "CALLCODE"].includes(node.callType) ?
        parent?.storageContextAddress ?? null : node.to;
      const observedCall: ObservedOverlayCall = { id, traceId: trace.id, transactionHash: hash, transactionOrdinal: tx,
        ordinal: node.ordinal, parentCallId: parent?.id ?? null, depth: node.depth,
        callType: node.callType, rawCallType: node.rawCallType, from: node.from, to: node.to,
        codeAddress: ["CREATE", "CREATE2", "SELFDESTRUCT", "UNKNOWN"].includes(node.callType) ? null : node.to,
        storageContextAddress, valueWei: node.valueWei, outcome: node.outcome,
        gasSupplied: node.gasSupplied, gasUsed: node.gasUsed, selector: node.inputSelector,
        input: node.input, output: node.output, error: node.error,
        revertKind: node.revertKind, revertDetail: node.revertDetail,
        mapping, staticEdgeId, relationshipStatus,
        explanationKey: relationshipStatus === "observed-static-edge" ? "static-edge-observed" :
          relationshipStatus === "runtime-only-observed" ? "runtime-only-call" :
            mapping.contractNodeId ? "observed-call" : "unmapped-runtime-call" };
      calls.push(observedCall); callsByOrdinal.set(node.ordinal, observedCall);
    }
    for (const log of trace.logs) logs.push({ id: `${trace.id}:log:${log.ordinal}`, traceId: trace.id,
      transactionHash: hash, ordinal: log.ordinal, logIndex: log.logIndex, address: log.address,
      topics: log.topics, data: log.data, contractNodeId: mapAddress(log.address).contractNodeId,
      eventNodeId: null, explanationKey: "observed-log" });
  }
  const observedState: ObservedOverlayState[] = [];
  if (input.pre) {
    const after = new Map(input.post?.observations.map((item) => [item.id, item]) ?? []);
    const changes = new Map(input.diff?.changes.map((item) => [item.id, item]) ?? []);
    for (const before of input.pre.observations) {
      const last = after.get(before.id), change = changes.get(before.id), detail = descriptor(before);
      const address = detail.address ?? detail.contract ?? detail.token ?? detail.target ?? null;
      const state: ObservedOverlayState["state"] = !input.post ? "post-unavailable" :
        before.status === "unavailable" || last?.status === "unavailable" ? "unavailable" :
          change ? "changed" : "unchanged";
      observedState.push({ observationId: before.id, kind: before.kind, descriptor: detail,
        beforeStatus: before.status, afterStatus: last?.status ?? "not-captured", before: before.value,
        after: last?.value ?? null, beforeErrorCode: before.errorCode, afterErrorCode: last?.errorCode ?? null,
        delta: change?.delta ?? null, state, contractNodeId: mapAddress(address).contractNodeId,
        changeId: change?.id ?? null, preSnapshotId: input.pre.id, postSnapshotId: input.post?.id ?? null,
        diffId: input.diff?.id ?? null, explanationKey: "observed-state-change" });
    }
    observedState.sort((a, b) => a.observationId.localeCompare(b.observationId));
  }
  const warnings = new Set<string>();
  if (!graph) warnings.add("static-graph-unavailable");
  else if (!bindings.size) warnings.add("authoritative-deployment-link-unavailable");
  if (!path) warnings.add("static-investigation-path-unavailable");
  if (e.traceCaptureStatus !== "finalized") warnings.add(e.traceCaptureStatus === "failed" ? "trace-capture-failed" : "trace-unavailable");
  if (!input.pre) warnings.add("state-pre-unavailable");
  else if (!input.diff) warnings.add("state-post-or-diff-unavailable");
  if (calls.some((call) => call.relationshipStatus === "runtime-only-observed")) warnings.add("runtime-only-calls-observed");
  const content = { schema: IMPACT_OVERLAY_SCHEMA, derivationVersion: IMPACT_OVERLAY_DERIVATION_VERSION,
    scanId: input.scanId, executionId: e.id, sessionId: e.sessionId, artifactId: e.artifactId, subject,
    protocolGraphId: graph?.graph.id ?? null, investigationPathResultId: path?.contentSha256 ?? null,
    forkIdentity: { chainId: e.chainId, baseBlockNumber: e.forkBlock, baseBlockHash: e.forkBlockHash,
      targetCodeHashes: e.targetCodeHashes },
    sourceIdentity: { reviewedArtifactId: e.artifactId, sourceSha256: e.sourceSha256 },
    capabilities: { traceAvailable: input.traces.length > 0, statePreAvailable: !!input.pre,
      stateDiffAvailable: !!input.diff, overlayAvailable: input.traces.length > 0 || !!input.pre },
    transactions, observedCalls: calls, observedLogs: logs, observedState, pathComparisons: [] as ImpactPathComparison[],
    coverage: { transactionCount: transactions.length, tracedTransactionCount: input.traces.length,
      observedCallCount: calls.length, contractMappedCallCount: calls.filter((call) => call.mapping.contractNodeId).length,
      functionMappedCallCount: calls.filter((call) => call.mapping.functionNodeId).length,
      unmappedCallCount: calls.filter((call) => !call.mapping.contractNodeId).length,
      stateObservationCount: observedState.length, changedObservationCount: observedState.filter((item) => item.state === "changed").length,
      unavailableObservationCount: observedState.filter((item) => ["unavailable", "post-unavailable"].includes(item.state)).length },
    warnings: [...warnings].sort(),
    provenance: { traceIds: input.traces.map((trace) => trace.id), traceContentSha256: input.traces.map((trace) => trace.contentSha256),
      preSnapshotId: input.pre?.id ?? null, preSnapshotSha256: input.pre?.contentSha256 ?? null,
      postSnapshotId: input.post?.id ?? null, postSnapshotSha256: input.post?.contentSha256 ?? null,
      diffId: input.diff?.id ?? null, diffSha256: input.diff?.contentSha256 ?? null,
      graphContentSha256: graph?.contentSha256 ?? null, pathContentSha256: path?.contentSha256 ?? null,
      mappingEvidenceIds: [...bindings.values()].map((binding) => binding.evidenceId).sort() } };
  const withPaths = { ...content, pathComparisons: path ? compareInvestigationPathToImpactOverlay(path,
    { ...content, contentSha256: "" }) : [] };
  return { ...withPaths, contentSha256: contentHash([expectedProvenance(e),
    [...bindings.values()].sort((a, b) => a.address.localeCompare(b.address)), withPaths]) };
}
