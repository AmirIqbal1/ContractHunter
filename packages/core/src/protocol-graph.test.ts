import { describe, expect, it } from "vitest";
import { randomUUID } from "node:crypto";
import { contractGraphKey, functionGraphKey, protocolEdgeId, protocolGraphId, protocolNodeId,
  validateProtocolGraph, validateProtocolGraphOverlay, type ProtocolGraph,
  type ProtocolGraphNode, type ProtocolSourceLocation } from "./protocol-graph";

const scanId = "00000000-0000-4000-8000-000000000001";
const commit = "a".repeat(40);
const source = (sourceUnitName: string, line: number): ProtocolSourceLocation => ({
  sourceUnitName, startLine: line, endLine: line, startColumn: 0, endColumn: 20,
  startByte: null, endByte: null,
});
const evidence = (at: ProtocolSourceLocation | null = null) => [{
  origin: "compiler" as const, producerVersion: "0.8.36", source: at, referenceId: null,
}];
const classification = { effective: "core" as const, automatic: "core" as const,
  automaticOrigin: "path-pattern" as const, reasons: ["contracts-root"], override: null };
const producers = [{ origin: "compiler" as const, version: "0.8.36" }];
const key = (unit: string, name: string) => contractGraphKey(unit, name);

function contract(unit: string, name: string, line: number): ProtocolGraphNode {
  const nodeKey = key(unit, name), at = source(unit, line);
  return { kind: "contract", id: protocolNodeId(scanId, "contract", nodeKey), key: nodeKey,
    name, qualifiedName: `${unit}:${name}`, contractKind: "contract", repositoryClassification: classification,
    source: at, evidence: evidence(at), characteristics: [] };
}
function func(owner: ProtocolGraphNode, name: string, signature: string, line: number): ProtocolGraphNode {
  const nodeKey = functionGraphKey(owner.key, signature), at = source(owner.source!.sourceUnitName, line);
  return { kind: "function", id: protocolNodeId(scanId, "function", nodeKey), key: nodeKey, name,
    contractId: owner.id, signature, source: at, evidence: evidence(at), characteristics: [],
    visibility: "internal", mutability: "view", modifiers: [], entryPoint: "no" };
}
function concept(kind: "external-actor" | "token", name: string): ProtocolGraphNode {
  return { kind, id: protocolNodeId(scanId, kind, name), key: name, name, source: null,
    evidence: evidence(), characteristics: [], identityState: "unknown", representedContractId: null };
}
function fixture(): ProtocolGraph {
  const vault = contract("src/Vault.sol", "Vault", 1), oracle = contract("src/Oracle.sol", "Oracle", 1);
  const calc = func(vault, "_calculateShares", "_calculateShares()", 12);
  const price = func(oracle, "getPrice", "getPrice()", 7);
  const callsite = source("src/Vault.sol", 14);
  return { schema: "contracthunter-protocol-graph-v1",
    id: protocolGraphId(scanId, commit, "phase1-v1", producers), scanId, resolvedCommit: commit,
    extractorVersion: "phase1-v1", producers,
    sourceUnits: ["src/Vault.sol", "src/Oracle.sol"].map((sourceUnitName) => ({ sourceUnitName,
      snapshotSourceKey: sourceUnitName, rawSha256: "b".repeat(64), byteLength: 1_000,
      identityStatus: "authoritative" as const })),
    nodes: [vault, oracle, calc, price],
    edges: [{ kind: "calls", key: "Vault._calculateShares:callsite-14:0", from: vault.id, to: oracle.id,
      id: protocolEdgeId(scanId, "calls", vault.id, oracle.id, "Vault._calculateShares:callsite-14:0"),
      origin: "static", reasons: ["oracle-dependency"], source: callsite,
      fromFunctionId: calc.id, toFunctionId: price.id, evidence: evidence(callsite) }],
    classifications: [{ repositoryPath: "src/Vault.sol", value: classification }], warnings: [] };
}

describe("ProtocolGraph Phase 1", () => {
  it("links unique source units, contracts and functions without basename guessing", () => {
    const graph = fixture();
    const sameName = contract("contracts/Vault.sol", "Vault", 1);
    graph.sourceUnits.push({ sourceUnitName: "contracts/Vault.sol", snapshotSourceKey: "contracts/Vault.sol",
      rawSha256: "c".repeat(64), byteLength: 1_000, identityStatus: "authoritative" });
    graph.nodes.push(sameName);
    expect(validateProtocolGraph(graph).nodes[2]).toMatchObject({ kind: "function",
      contractId: graph.nodes[0]!.id, source: { sourceUnitName: "src/Vault.sol", startLine: 12 } });
    expect(sameName.id).not.toBe(graph.nodes[0]!.id);
  });

  it("explains Vault._calculateShares to Oracle.getPrice from a callsite", () => {
    const graph = validateProtocolGraph(fixture());
    expect(graph.edges[0]).toMatchObject({ kind: "calls", from: graph.nodes[0]!.id, to: graph.nodes[1]!.id,
      fromFunctionId: graph.nodes[2]!.id, toFunctionId: graph.nodes[3]!.id,
      reasons: ["oracle-dependency"], source: { sourceUnitName: "src/Vault.sol", startLine: 14 } });
    expect(protocolGraphId(scanId, commit, "phase1-v1", [...producers, {
      origin: "slither", version: "0.11.3" }])).toBe(protocolGraphId(scanId, commit, "phase1-v1", [
      { origin: "slither", version: "0.11.3" }, ...producers]));
  });

  it("keeps finding, C1 state and D1 call-path overlays separate from the base graph", () => {
    const graph = fixture(), base = JSON.stringify(graph);
    const finding = validateProtocolGraphOverlay(graph, { schema: "contracthunter-protocol-overlay-v1",
      kind: "finding", graphId: graph.id, executionId: null,
      entries: [{ findingId: randomUUID(), nodeId: graph.nodes[0]!.id, edgeId: null }] });
    expect(finding.kind).toBe("finding");
    const state = validateProtocolGraphOverlay(graph, { schema: "contracthunter-protocol-overlay-v1",
      kind: "impact-state", graphId: graph.id, executionId: randomUUID(),
      entries: [{ diffId: randomUUID(), changeId: `native:0x${"0".repeat(40)}`,
        nodeId: graph.nodes[0]!.id }] });
    expect(state.kind).toBe("impact-state");
    const user = concept("external-actor", "disposable-user"), token = concept("token", "unknown-token");
    graph.nodes.push(user, token);
    const trace = validateProtocolGraphOverlay(graph, { schema: "contracthunter-protocol-overlay-v1",
      kind: "impact-trace", graphId: graph.id, executionId: randomUUID(),
      entries: [{ traceId: randomUUID(), transactionHash: `0x${"1".repeat(64)}`,
        nodeOrdinal: 0, fromNodeId: user.id, toNodeId: graph.nodes[0]!.id },
      { traceId: randomUUID(), transactionHash: `0x${"1".repeat(64)}`,
        nodeOrdinal: 1, fromNodeId: graph.nodes[0]!.id, toNodeId: token.id }] });
    expect(trace.kind).toBe("impact-trace");
    graph.nodes.pop(); graph.nodes.pop();
    expect(JSON.stringify(graph)).toBe(base);
    expect(() => validateProtocolGraphOverlay(graph, { schema: "contracthunter-protocol-overlay-v1",
      kind: "finding", graphId: graph.id, executionId: null,
      entries: [{ findingId: randomUUID(), nodeId: protocolNodeId(scanId, "contract", "missing"), edgeId: null }] }))
      .toThrow("protocol_graph_overlay_target_invalid");
  });

  it("supports cycles, distinct callsites and a representative large graph", () => {
    const graph = fixture();
    const count = 3_000;
    for (let index = 0; index < count; index++) graph.nodes.push(concept("external-actor", `actor-${index}`));
    for (let index = 0; index < count; index++) {
      const from = graph.nodes[4 + index]!.id, to = graph.nodes[4 + ((index + 1) % count)]!.id;
      const edgeKey = `callsite-${index}`;
      graph.edges.push({ id: protocolEdgeId(scanId, "calls", from, to, edgeKey), key: edgeKey,
        kind: "calls", from, to, origin: "static", reasons: ["callsite"],
        evidence: evidence(), source: null, fromFunctionId: null, toFunctionId: null });
    }
    expect(validateProtocolGraph(graph).edges).toHaveLength(count + 1);
    const first = graph.edges[0]!;
    graph.edges.push({ ...first, key: "second-callsite", id: protocolEdgeId(scanId, "calls",
      first.from, first.to, "second-callsite") });
    expect(validateProtocolGraph(graph).edges).toHaveLength(count + 2);
  });

  it("rejects duplicates, dangling endpoints, wrong ownership/source and bounds", () => {
    const bad = (change: (graph: ProtocolGraph) => void) => {
      const graph = fixture(); change(graph); expect(() => validateProtocolGraph(graph)).toThrow();
    };
    bad((graph) => graph.nodes.push(graph.nodes[0]!));
    bad((graph) => graph.edges.push(graph.edges[0]!));
    bad((graph) => { graph.edges[0] = { ...graph.edges[0]!, to: protocolNodeId(scanId, "contract", "missing") }; });
    bad((graph) => { graph.nodes[2] = { ...graph.nodes[2]!, contractId: graph.nodes[1]!.id } as ProtocolGraphNode; });
    bad((graph) => { graph.nodes[0] = { ...graph.nodes[0]!, qualifiedName: "src/Oracle.sol:Vault" } as ProtocolGraphNode; });
    bad((graph) => { graph.nodes[2] = { ...graph.nodes[2]!, name: "notTheFunction" } as ProtocolGraphNode; });
    bad((graph) => { graph.nodes[2] = { ...graph.nodes[2]!, source: source("src/Missing.sol", 2) } as ProtocolGraphNode; });
    bad((graph) => { graph.nodes[0] = { ...graph.nodes[0]!, source: {
      ...source("src/Vault.sol", 2), endLine: 1 } } as ProtocolGraphNode; });
    bad((graph) => { graph.sourceUnits[0] = { ...graph.sourceUnits[0]!, sourceUnitName: "src/../Vault.sol" }; });
    bad((graph) => { graph.edges[0] = { ...graph.edges[0]!, origin: "runtime" }; });
    bad((graph) => { graph.producers.push({ origin: "impact-trace", version: "v1" });
      graph.id = protocolGraphId(scanId, commit, graph.extractorVersion, graph.producers);
      graph.nodes[0] = { ...graph.nodes[0]!, evidence: [{ origin: "impact-trace",
        producerVersion: "v1", source: null, referenceId: null }] } as ProtocolGraphNode; });
    bad((graph) => { graph.nodes = Array(20_001).fill(graph.nodes[0]!); });
    bad((graph) => { graph.edges = Array(100_001).fill(graph.edges[0]!); });
    bad((graph) => { graph.edges[0] = { ...graph.edges[0]!, kind: "invented" } as never; });
  });

  it("requires explicit classification override provenance and rejects overlay mutation attempts", () => {
    const graph = fixture();
    graph.classifications[0]!.value = { ...classification, effective: "test", override: null };
    expect(() => validateProtocolGraph(graph)).toThrow();
    graph.classifications[0]!.value = { ...classification, effective: "test", override: {
      value: "test", reason: "researcher-override" } };
    graph.classifications.push({ repositoryPath: "app/page.tsx", value: {
      effective: "frontend", automatic: "frontend", automaticOrigin: "path-pattern",
      reasons: ["frontend-root"], override: null } });
    expect(validateProtocolGraph(graph).classifications[0]!.value.effective).toBe("test");
    expect(() => validateProtocolGraphOverlay(graph, { schema: "contracthunter-protocol-overlay-v1",
      kind: "impact-state", graphId: graph.id, executionId: randomUUID(), entries: [],
      nodes: [{ id: graph.nodes[0]!.id }] })).toThrow();
  });
});
