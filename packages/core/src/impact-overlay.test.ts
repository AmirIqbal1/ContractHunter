import { describe, expect, it } from "vitest";
import { randomUUID } from "node:crypto";
import { contractGraphKey, functionGraphKey, protocolEdgeId, protocolGraphId, protocolNodeId,
  type ProtocolGraphNode, type ProtocolGraphEdge, type ProtocolSourceLocation } from "./protocol-graph";
import { staticProtocolGraphContentHash, type StaticProtocolGraphArtifact } from "./static-protocol-graph";
import { deriveInvestigationPaths } from "./investigation-path";
import { deriveImpactChanges, diffHash, snapshotHash, type ImpactObservation, type ImpactStateSnapshot,
  type ImpactStateDiff, type ImpactStateProvenance } from "./impact-state";
import { impactTraceData, impactTraceHash, type ImpactTraceNode, type ImpactTransactionTrace } from "./impact-trace";
import { canonicalFunctionSelector, keccak256 } from "./impact-selector";
import { compareInvestigationPathToImpactOverlay, deriveImpactOverlay, type ImpactOverlayEvidence,
  type ExactDeploymentBinding } from "./impact-overlay";

const scanId = "00000000-0000-4000-8000-000000000001", findingId = "11111111-1111-4111-8111-111111111111";
const executionId = "22222222-2222-4222-8222-222222222222", artifactId = "33333333-3333-4333-8333-333333333333";
const sessionId = "44444444-4444-4444-8444-444444444444";
const routerAddress = `0x${"1".repeat(40)}`, vaultAddress = `0x${"2".repeat(40)}`;
const unknownAddress = `0x${"3".repeat(40)}`, sender = `0x${"4".repeat(40)}`;
const hash = (char: string) => `sha256:${char.repeat(64)}`;
const txHash = (char: string) => `0x${char.repeat(64)}`;
const source = (unit: string, line: number): ProtocolSourceLocation => ({ sourceUnitName: unit, startLine: line,
  endLine: line, startColumn: 0, endColumn: 5, startByte: line * 10, endByte: line * 10 + 5 });
const evidence = (at: ProtocolSourceLocation) => [{ origin: "compiler" as const, producerVersion: "fixture", source: at, referenceId: "42" }];
function contract(name: string): ProtocolGraphNode {
  const at = source(`src/${name}.sol`, 1), key = contractGraphKey(at.sourceUnitName, name);
  return { kind: "contract", id: protocolNodeId(scanId, "contract", key), key, name,
    qualifiedName: `${at.sourceUnitName}:${name}`, contractKind: "contract", source: at, evidence: evidence(at),
    characteristics: [], repositoryClassification: { effective: "core", automatic: "core",
      automaticOrigin: "path-pattern", reasons: ["source-root"], override: null } };
}
function fn(owner: ProtocolGraphNode, signature: string, line: number): ProtocolGraphNode {
  const at = source(owner.source!.sourceUnitName, line), key = functionGraphKey(owner.key, signature);
  return { kind: "function", id: protocolNodeId(scanId, "function", key), key, name: signature.split("(")[0]!,
    signature, contractId: owner.id, source: at, evidence: evidence(at), characteristics: [],
    visibility: "external", mutability: "nonpayable", modifiers: [], entryPoint: "yes" };
}
function edge(from: ProtocolGraphNode, to: ProtocolGraphNode, kind: ProtocolGraphEdge["kind"] = "external-call"): ProtocolGraphEdge {
  const at = source(from.source!.sourceUnitName, 6), key = `${from.id}:${to.id}:${kind}`;
  return { id: protocolEdgeId(scanId, kind, from.id, to.id, key), key, kind, from: from.id, to: to.id,
    origin: "static", reasons: ["typed-contract-member-call"], evidence: evidence(at), source: at,
    fromFunctionId: from.id, toFunctionId: to.id };
}
function graph(nodes: ProtocolGraphNode[], edges: ProtocolGraphEdge[], targetId: string): StaticProtocolGraphArtifact {
  const repositoryMapId = `rm:${"a".repeat(64)}`;
  const sorted = [...nodes].sort((a, b) => a.id.localeCompare(b.id));
  const graphValue = { schema: "contracthunter-protocol-graph-v1" as const,
    id: protocolGraphId(scanId, "b".repeat(40), `fixture:${repositoryMapId}`, [{ origin: "compiler", version: "fixture" }]), scanId,
    resolvedCommit: "b".repeat(40), extractorVersion: `fixture:${repositoryMapId}`, producers: [{ origin: "compiler" as const, version: "fixture" }],
    sourceUnits: [...new Set(nodes.flatMap((node) => node.source ? [node.source.sourceUnitName] : []))].sort().map((sourceUnitName) =>
      ({ sourceUnitName, snapshotSourceKey: sourceUnitName, rawSha256: "c".repeat(64), byteLength: 1000,
        identityStatus: "authoritative" as const })),
    nodes: sorted, edges: [...edges].sort((a, b) => a.id.localeCompare(b.id)), classifications: [], warnings: [] };
  const content = { schema: "contracthunter-static-protocol-graph-v1" as const, repositoryMapId,
    graph: graphValue, functionFacts: [], findingLinks: [{ findingId, nodeId: targetId }], unresolved: [],
    summary: { contracts: nodes.filter((node) => node.kind === "contract").length, interfaces: 0, libraries: 0,
      functions: nodes.filter((node) => node.kind === "function").length, edges: edges.length,
      externalCalls: edges.filter((item) => item.kind === "external-call").length,
      entryPoints: nodes.filter((node) => node.kind === "function" && node.entryPoint === "yes").length,
      proxies: 0, delegatecalls: edges.filter((item) => item.kind === "delegates").length,
      findingsLinkedNodes: 1, unresolvedRelationships: 0 } };
  return { ...content, contentSha256: staticProtocolGraphContentHash(content) };
}
const router = contract("Router"), vault = contract("Vault"), routerDeposit = fn(router, "deposit()", 5),
  vaultDeposit = fn(vault, "deposit(uint256)", 6), vaultOther = fn(vault, "deposit()", 9);
const staticEdge = edge(routerDeposit, vaultDeposit);
const artifact = graph([router, vault, routerDeposit, vaultDeposit, vaultOther], [staticEdge], vaultDeposit.id);
const path = deriveInvestigationPaths(artifact, { type: "finding", id: findingId, findingIds: [findingId] });
const provenance: ImpactStateProvenance = { executionId, sessionId, runtimeTokenSha256: hash("d"),
  chainId: 31337, forkBlock: 100, forkBlockHash: txHash("e"),
  targetCodeHashes: { [routerAddress]: hash("1"), [vaultAddress]: hash("2") },
  artifactId, sourceSha256: hash("a"), planSha256: hash("f") };
const obs = (id: string, kind: ImpactObservation["kind"], value: string | null,
  status: ImpactObservation["status"] = "available"): ImpactObservation =>
  ({ id, kind, value, status, errorCode: status === "unavailable" ? "rpc_error" : null });
function snapshot(phase: "pre" | "post", observations: ImpactObservation[]): ImpactStateSnapshot {
  const value = { schema: "impact-state-snapshot-v1" as const, id: phase === "pre" ? randomUUID() : randomUUID(),
    phase, provenance, observedAtBlock: phase === "pre" ? 100 : 101,
    observedAtTimestamp: phase === "pre" ? "2026-01-01T00:00:00.000Z" : "2026-01-01T00:01:00.000Z",
    observations: [...observations].sort((a, b) => a.id.localeCompare(b.id)) };
  return { ...value, contentSha256: snapshotHash(value) };
}
const pre = snapshot("pre", [obs(`native:${vaultAddress}`, "native", "100"),
  obs(`storage:${vaultAddress}:0x${"0".repeat(64)}`, "storage", `0x${"0".repeat(63)}2`),
  obs(`erc20:${vaultAddress}:${sender}`, "erc20", "1000"),
  obs(`erc721:${vaultAddress}:1`, "erc721", sender), obs(`erc1155:${vaultAddress}:${sender}:2`, "erc1155", "5"),
  obs(`view:erc20_totalSupply:${vaultAddress}`, "view", null, "unavailable")]);
const post = snapshot("post", [obs(`native:${vaultAddress}`, "native", "99"),
  obs(`storage:${vaultAddress}:0x${"0".repeat(64)}`, "storage", `0x${"0".repeat(63)}3`),
  obs(`erc20:${vaultAddress}:${sender}`, "erc20", "900"),
  obs(`erc721:${vaultAddress}:1`, "erc721", sender), obs(`erc1155:${vaultAddress}:${sender}:2`, "erc1155", "5"),
  obs(`view:erc20_totalSupply:${vaultAddress}`, "view", null, "unavailable")]);
const diffBase = { schema: "impact-state-diff-v1" as const, id: randomUUID(), provenance,
  preSnapshotId: pre.id, postSnapshotId: post.id, preSnapshotSha256: pre.contentSha256,
  postSnapshotSha256: post.contentSha256, changes: deriveImpactChanges(pre, post), changeCount: deriveImpactChanges(pre, post).length };
const diff: ImpactStateDiff = { ...diffBase, contentSha256: diffHash(diffBase) };
function node(ordinal: number, parentOrdinal: number | null, to: string, selector: string | null,
  callType: ImpactTraceNode["callType"] = "CALL", from = routerAddress): ImpactTraceNode {
  const input = impactTraceData(selector ? selector : "0x");
  return { ordinal, parentOrdinal, depth: parentOrdinal === null ? 0 : 1, callType, rawCallType: null,
    from, to, valueWei: "0", gasSupplied: "100000", gasUsed: "21000", outcome: "success", error: null,
    inputSelector: selector, input, output: impactTraceData("0x"), revertKind: null, revertDetail: null,
    targetAddress: provenance.targetCodeHashes[to] ? to : null };
}
function trace(nodes: ImpactTraceNode[], ordinal = 0, hashValue = txHash("a"), reverted = false): ImpactTransactionTrace {
  const traceId = randomUUID(), value = { schema: "impact-transaction-trace-v1" as const, id: traceId, provenance,
    transactionOrdinal: ordinal, localTransactionHash: hashValue,
    receipt: { transactionHash: hashValue, blockNumber: 101 + ordinal, blockHash: txHash("b"),
      transactionIndex: ordinal, status: reverted ? 0 as const : 1 as const, gasUsed: "42000", contractAddress: null },
    nodes, logs: [{ ordinal: 0, logIndex: 0, address: vaultAddress, topics: [txHash("c")], data: impactTraceData("0x1234") }],
    stats: { nodeCount: nodes.length, maxDepth: Math.max(...nodes.map((item) => item.depth)),
      revertedCallCount: nodes.filter((item) => item.outcome === "reverted").length,
      targetCallCount: nodes.filter((item) => item.targetAddress !== null).length,
      createdContractCount: 0, logCount: 1 } };
  return { ...value, contentSha256: impactTraceHash(value) };
}
const root = () => node(0, null, routerAddress, canonicalFunctionSelector("deposit()"), "CALL", sender);
const child = () => node(1, 0, vaultAddress, canonicalFunctionSelector("deposit(uint256)"));
const bindings: ExactDeploymentBinding[] = [
  { address: routerAddress, deployedCodeSha256: provenance.targetCodeHashes[routerAddress]!,
    contractNodeId: router.id, sourceUnitName: "src/Router.sol", sourceRawSha256: "c".repeat(64),
    evidenceId: "fixture:router", evidenceKind: "exact-deployed-bytecode-source-link" },
  { address: vaultAddress, deployedCodeSha256: provenance.targetCodeHashes[vaultAddress]!,
    contractNodeId: vault.id, sourceUnitName: "src/Vault.sol", sourceRawSha256: "c".repeat(64),
    evidenceId: "fixture:vault", evidenceKind: "exact-deployed-bytecode-source-link" },
];
function fixture(traces: ImpactTransactionTrace[] = [trace([root(), child()])], withBindings = true): ImpactOverlayEvidence {
  return { scanId, artifact: { id: artifactId, findingId, hypothesisId: null, sourceSha256: provenance.sourceSha256,
    reviewState: "reviewed" }, session: { id: sessionId, findingId, hypothesisId: null,
      chainId: provenance.chainId, resolvedForkBlock: provenance.forkBlock, forkBlockHash: provenance.forkBlockHash,
      targetCodeHashes: provenance.targetCodeHashes, targetContracts: [routerAddress, vaultAddress] },
    execution: { id: executionId, artifactId, sourceSha256: provenance.sourceSha256, sessionId,
      runtimeTokenSha256: provenance.runtimeTokenSha256, chainId: provenance.chainId,
      forkBlock: provenance.forkBlock, forkBlockHash: provenance.forkBlockHash,
      targetCodeHashes: provenance.targetCodeHashes, status: "completed", executed: true,
      transactionScope: "local-impact-lab", transactionHashes: traces.map((item) => item.localTransactionHash),
      observationPlanSha256: provenance.planSha256, preSnapshotId: pre.id, postSnapshotId: post.id,
      stateDiffId: diff.id, traceCaptureStatus: "finalized", traceIds: traces.map((item) => item.id) },
    pre, post, diff, traces, graph: artifact, investigationPath: path,
    trustedDeploymentBindings: withBindings ? bindings : [] };
}
type DeepMutable<T> = T extends ReadonlyArray<infer U> ? DeepMutable<U>[] :
  T extends object ? { -readonly [K in keyof T]: DeepMutable<T[K]> } : T;
const mutableFixture = (traces?: ImpactTransactionTrace[], withBindings?: boolean): DeepMutable<ImpactOverlayEvidence> =>
  structuredClone(fixture(traces, withBindings)) as DeepMutable<ImpactOverlayEvidence>;

describe("Phase 10A deterministic Impact Overlay", () => {
  it("uses exact Keccak selectors and leaves unsupported signatures unresolved", () => {
    expect(keccak256("")).toBe(`0x${"c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"}`);
    expect(canonicalFunctionSelector("transfer(address,uint256)")).toBe("0xa9059cbb");
    expect(canonicalFunctionSelector("foo(contract Vault)")).toBeNull();
  });
  it("matches one exact static edge, preserves fork/local blocks and never mutates input", () => {
    const input = fixture(), original = structuredClone(input), result = deriveImpactOverlay(input);
    expect(result.observedCalls[1]?.staticEdgeId).toBe(staticEdge.id);
    expect(result.observedCalls[1]?.relationshipStatus).toBe("observed-static-edge");
    expect(result.pathComparisons.some((item) => item.edges.some((edge) => edge.edgeId === staticEdge.id &&
      edge.status === "observed-in-this-local-execution"))).toBe(true);
    expect(result.forkIdentity.baseBlockNumber).toBe(100);
    expect(result.transactions[0]?.localBlockNumber).toBe(101);
    expect(input).toEqual(original);
    expect(deriveImpactOverlay(input).contentSha256).toBe(result.contentSha256);
  });
  it("accepts exact historical bare runtime-token digests without weakening evidence binding", () => {
    const input = mutableFixture(), legacyDigest = hash("d").slice("sha256:".length);
    input.execution.runtimeTokenSha256 = legacyDigest;
    for (const snapshot of [input.pre!, input.post!]) {
      snapshot.provenance.runtimeTokenSha256 = legacyDigest;
      snapshot.contentSha256 = snapshotHash(snapshot);
    }
    input.diff!.provenance.runtimeTokenSha256 = legacyDigest;
    input.diff!.preSnapshotSha256 = input.pre!.contentSha256;
    input.diff!.postSnapshotSha256 = input.post!.contentSha256;
    input.diff!.contentSha256 = diffHash(input.diff!);
    for (const trace of input.traces) {
      trace.provenance.runtimeTokenSha256 = legacyDigest;
      trace.contentSha256 = impactTraceHash(trace);
    }
    expect(deriveImpactOverlay(input).transactions).toHaveLength(1);
    input.traces[0]!.provenance.runtimeTokenSha256 = "0".repeat(64);
    input.traces[0]!.contentSha256 = impactTraceHash(input.traces[0]!);
    expect(() => deriveImpactOverlay(input)).toThrow("impact_overlay_trace_binding_invalid");
  });
  it("marks static edges not observed without claiming absence and retains runtime-only calls", () => {
    const omitted = trace([root()]);
    const first = deriveImpactOverlay(fixture([omitted]));
    expect(first.pathComparisons.some((item) => item.edges.some((edge) => edge.edgeId === staticEdge.id &&
      edge.status === "not-observed-in-this-execution"))).toBe(true);
    const runtime = trace([root(), node(1, 0, vaultAddress, canonicalFunctionSelector("deposit()"))]);
    const second = deriveImpactOverlay(fixture([runtime]));
    expect(second.observedCalls[1]?.relationshipStatus).toBe("runtime-only-observed");
    expect(second.observedCalls[1]?.staticEdgeId).toBeNull();
  });
  it("keeps unknown addresses observed but unmapped, and resolves overloads only by unique selector", () => {
    const withUnknown = trace([root(), node(1, 0, unknownAddress, null)]);
    const result = deriveImpactOverlay(fixture([withUnknown]));
    expect(result.observedCalls[1]?.to).toBe(unknownAddress);
    expect(result.observedCalls[1]?.mapping.contractNodeId).toBeNull();
    expect(result.observedCalls[1]?.relationshipStatus).toBe("unmapped-runtime-call");
    const overloaded = deriveImpactOverlay(fixture([trace([root(), node(1, 0, vaultAddress,
      canonicalFunctionSelector("deposit()"))])]));
    expect(overloaded.observedCalls[1]?.mapping.functionNodeId).toBe(vaultOther.id);
    const noSelector = deriveImpactOverlay(fixture([trace([root(), node(1, 0, vaultAddress, null)])]));
    expect(noSelector.observedCalls[1]?.mapping.contractNodeId).toBe(vault.id);
    expect(noSelector.observedCalls[1]?.mapping.functionNodeId).toBeNull();
  });
  it("maps proven receive and short-calldata fallback only in exact contract context", () => {
    const receive = fn(vault, "receive()", 12), fallback = fn(vault, "fallback()", 13);
    const withReceive = mutableFixture([trace([root(), node(1, 0, vaultAddress, null)])]);
    withReceive.graph = graph([router, vault, routerDeposit, vaultDeposit, vaultOther, receive, fallback],
      [staticEdge], vaultDeposit.id);
    withReceive.investigationPath = deriveInvestigationPaths(withReceive.graph,
      { type: "finding", id: findingId, findingIds: [findingId] });
    expect(deriveImpactOverlay(withReceive).observedCalls[1]?.mapping.functionNodeId).toBe(receive.id);
    const withFallback = mutableFixture([trace([root(), node(1, 0, vaultAddress, null)])]);
    withFallback.graph = graph([router, vault, routerDeposit, vaultDeposit, vaultOther, fallback],
      [staticEdge], vaultDeposit.id);
    withFallback.investigationPath = deriveInvestigationPaths(withFallback.graph,
      { type: "finding", id: findingId, findingIds: [findingId] });
    expect(deriveImpactOverlay(withFallback).observedCalls[1]?.mapping.functionNodeId).toBe(fallback.id);
  });
  it("preserves delegatecall code and storage contexts without state causation", () => {
    const delegated = deriveImpactOverlay(fixture([trace([root(), node(1, 0, vaultAddress,
      canonicalFunctionSelector("deposit(uint256)"), "DELEGATECALL")])]));
    expect(delegated.observedCalls[1]?.callType).toBe("DELEGATECALL");
    expect(delegated.observedCalls[1]?.codeAddress).toBe(vaultAddress);
    expect(delegated.observedCalls[1]?.storageContextAddress).toBe(routerAddress);
    expect(delegated.observedState.every((item) => !Object.hasOwn(item, "causedByCallId"))).toBe(true);
  });
  it("preserves exact native/ERC20/storage deltas, NFT and unchanged/unavailable observations", () => {
    const result = deriveImpactOverlay(fixture());
    expect(result.observedState.find((item) => item.kind === "native")?.delta).toBe("-1");
    expect(result.observedState.find((item) => item.kind === "erc20")?.delta).toBe("-100");
    expect(result.observedState.find((item) => item.kind === "storage")?.descriptor.slot).toBe(`0x${"0".repeat(64)}`);
    expect(result.observedState.find((item) => item.kind === "erc721")?.state).toBe("unchanged");
    expect(result.observedState.find((item) => item.kind === "erc1155")?.state).toBe("unchanged");
    expect(result.observedState.find((item) => item.kind === "view")?.state).toBe("unavailable");
    expect(result.observedState.find((item) => item.kind === "view")?.before).toBeNull();
  });
  it("leaves logs as observed logs because graph has no event declarations", () => {
    const result = deriveImpactOverlay(fixture());
    expect(result.observedLogs[0]?.contractNodeId).toBe(vault.id);
    expect(result.observedLogs[0]?.eventNodeId).toBeNull();
    expect(result.observedLogs[0]?.data.prefix).toBe("0x1234");
  });
  it("keeps reverted transaction and trace evidence", () => {
    const reverted = trace([root(), child()], 0, txHash("a"), true);
    const result = deriveImpactOverlay(fixture([reverted]));
    expect(result.transactions[0]?.status).toBe("reverted");
    expect(result.observedCalls).toHaveLength(2);
  });
  it("represents trace failure and PRE-only state without fake empty traces or diffs", () => {
    const input = mutableFixture([]); input.execution.transactionHashes = [txHash("a")];
    input.execution.traceCaptureStatus = "failed"; input.pre = pre; input.post = null; input.diff = null;
    input.execution.postSnapshotId = null; input.execution.stateDiffId = null;
    const result = deriveImpactOverlay(input);
    expect(result.transactions[0]?.status).toBe("trace-unavailable");
    expect(result.observedCalls).toHaveLength(0);
    expect(result.observedState.every((item) => item.state === "post-unavailable")).toBe(true);
    expect(result.capabilities.stateDiffAvailable).toBe(false);
  });
  it("keeps two transactions separate and ordered", () => {
    const result = deriveImpactOverlay(fixture([trace([root()], 0, txHash("a")), trace([root()], 1, txHash("d"))]));
    expect(result.transactions.map((item) => item.transactionHash)).toEqual([txHash("a"), txHash("d")]);
    expect(result.observedCalls.map((item) => item.transactionOrdinal)).toEqual([0, 1]);
  });
  it("rejects wrong execution, session, source, fork and path bindings", () => {
    const wrong = mutableFixture(); wrong.session.id = randomUUID();
    expect(() => deriveImpactOverlay(wrong)).toThrow();
    const wrongSource = mutableFixture(); wrongSource.artifact.sourceSha256 = hash("0");
    expect(() => deriveImpactOverlay(wrongSource)).toThrow();
    const wrongPath = mutableFixture(); wrongPath.investigationPath = { ...path, scanId: randomUUID() };
    expect(() => deriveImpactOverlay(wrongPath)).toThrow();
  });
  it("refuses an unproven deployment binding and leaves production-style addresses unmapped", () => {
    const noBindings = deriveImpactOverlay(fixture(undefined, false));
    expect(noBindings.coverage.contractMappedCallCount).toBe(0);
    expect(noBindings.warnings).toContain("authoritative-deployment-link-unavailable");
    expect(noBindings.pathComparisons.some((item) => item.edges.some((edge) => edge.edgeId === staticEdge.id &&
      edge.status === "comparison-unresolved"))).toBe(true);
    const bad = mutableFixture(); bad.trustedDeploymentBindings = [{ ...bindings[0]!, deployedCodeSha256: hash("9") }];
    expect(() => deriveImpactOverlay(bad)).toThrow();
  });
  it("represents historical B1 executions without C1/D1 artifacts", () => {
    const old = mutableFixture([]); old.execution.transactionHashes = []; old.execution.traceCaptureStatus = null;
    old.pre = null; old.post = null; old.diff = null; old.execution.preSnapshotId = null;
    old.execution.postSnapshotId = null; old.execution.stateDiffId = null;
    const result = deriveImpactOverlay(old);
    expect(result.capabilities).toEqual({ traceAvailable: false, statePreAvailable: false,
      stateDiffAvailable: false, overlayAvailable: false });
    expect(result.transactions).toHaveLength(0); expect(result.observedState).toHaveLength(0);
    expect(result.pathComparisons.some((item) => item.edges.some((edge) => edge.edgeId === staticEdge.id &&
      edge.status === "comparison-unresolved"))).toBe(true);
  });
  it("rejects mismatched path comparison and remains bounded on a large trace", () => {
    const nodes = [root(), ...Array.from({ length: 255 }, (_, i) => node(i + 1, 0, unknownAddress, null))];
    const large = deriveImpactOverlay(fixture([trace(nodes)]));
    expect(large.observedCalls).toHaveLength(256);
    expect(large.observedCalls[255]?.ordinal).toBe(255);
    expect(() => compareInvestigationPathToImpactOverlay(path, { ...large, scanId: randomUUID() })).toThrow();
  });
  it("keeps hostile trace data as inert JSON values", () => {
    const hostileNode = { ...child(), revertDetail: "<script>alert(1)</script>" };
    const result = deriveImpactOverlay(fixture([trace([root(), hostileNode])]));
    expect(result.observedCalls[1]?.revertDetail).toBe("<script>alert(1)</script>");
    expect(JSON.stringify(result)).not.toContain("<div");
  });
  it("excludes runtime authority and endpoint fields from the public overlay", () => {
    const payload = JSON.stringify(deriveImpactOverlay(fixture()));
    for (const field of ["runtimeTokenSha256", "privateKey", "rpcUrl", "dockerSocket", "workerSecret",
      "hostPath", "upstreamUrl"]) expect(payload).not.toContain(`"${field}"`);
  });
});
