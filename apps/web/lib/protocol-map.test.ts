import { describe, expect, it } from "vitest";
import type { ProtocolGraphEdge, ProtocolGraphNode, StaticProtocolGraphArtifact } from "@contracthunter/core";
import { defaultOptions, edgeDetails, findingIds, layoutMap, nodeDetails, searchMap, visibleModel } from "./protocol-map";

const location = (sourceUnitName: string, startLine = 1) => ({ sourceUnitName, startLine, endLine: startLine,
  startColumn: 0, endColumn: 1, startByte: 0, endByte: 1 });
const evidence = (unit: string) => [{ origin: "compiler" as const, producerVersion: "0.8.24",
  source: location(unit), referenceId: null }];
const classification = (effective: string) => ({ effective, automatic: effective,
  automaticOrigin: "path-pattern", reasons: ["explicit-directory"], override: null });
function fixture(): StaticProtocolGraphArtifact {
  const unit = "src/core/Vault.sol", oracleUnit = "src/interfaces/IOracle.sol";
  const contract = (id: string, name: string, source: string, kind: "contract" | "interface" | "library",
    cls: string, traits: string[] = []) => ({ id, key: id, kind, name, qualifiedName: `${source}:${name}`,
      contractKind: kind, repositoryClassification: classification(cls), source: location(source),
      evidence: evidence(source), characteristics: traits.map((trait) => ({ kind: trait, evidence: evidence(source) })) });
  const vault = contract("vault", "Vault", unit, "contract", "core");
  const oracle = contract("oracle", "IOracle", oracleUnit, "interface", "interface");
  const library = contract("library", "Mathish", "src/libraries/Mathish.sol", "library", "library");
  const proxy = contract("proxy", "VaultProxy", "src/core/VaultProxy.sol", "contract", "core", ["proxy", "upgradeable"]);
  const delegateOnly = contract("delegate", "Dispatcher", "src/Dispatcher.sol", "contract", "periphery", ["delegatecall"]);
  const role = { id: "role", key: "role", kind: "role", name: "owner", source: location(unit),
    evidence: evidence(unit), characteristics: [], identityState: "known", representedContractId: "vault" };
  const unknown = { id: "unknown", key: "unknown", kind: "external-actor", name: "Unresolved external target",
    source: null, evidence: evidence(unit), characteristics: [], identityState: "unknown", representedContractId: null };
  const functionNode = (id: string, name: string, signature: string, owner: string, source: string,
    visibility: string, entryPoint: string) => ({ id, key: id, kind: "function", name, signature, contractId: owner,
      source: location(source, 12), evidence: evidence(source), characteristics: [], visibility,
      mutability: "nonpayable", modifiers: [], entryPoint });
  const calculate = functionNode("calculate", "_calculateShares", "_calculateShares()", "vault", unit, "internal", "no");
  const withdraw = functionNode("withdraw", "withdraw", "withdraw()", "vault", unit, "external", "yes");
  const price = functionNode("price", "getPrice", "getPrice()", "oracle", oracleUnit, "external", "yes");
  const edge = (id: string, kind: string, from: string, to: string, fromFn: string | null = null,
    toFn: string | null = null): ProtocolGraphEdge => ({ id, key: id, kind, from, to, origin: "static",
      reasons: ["compiler-reference"], evidence: evidence(unit), source: location(unit, 18),
      fromFunctionId: fromFn, toFunctionId: toFn }) as ProtocolGraphEdge;
  return { schema: "contracthunter-static-protocol-graph-v1", repositoryMapId: "rm:" + "a".repeat(64),
    graph: { schema: "contracthunter-protocol-graph-v1", id: "pg:" + "b".repeat(64), scanId: "a", resolvedCommit: "a".repeat(40),
      extractorVersion: "fixture", producers: [], sourceUnits: [], nodes: [vault, oracle, library, proxy, delegateOnly,
        role, unknown, calculate, withdraw, price] as ProtocolGraphNode[], edges: [
        edge("call", "calls", "calculate", "price", "calculate", "price"),
        edge("external", "external-call", "calculate", "price", "calculate", "price"),
        edge("control", "controls", "role", "withdraw", null, "withdraw"),
        edge("library-edge", "uses-library", "vault", "library"),
        edge("proxy-edge", "delegates", "proxy", "unknown"),
        edge("unknown-edge", "external-call", "withdraw", "unknown", "withdraw"),
      ], classifications: [], warnings: [] },
    functionFacts: [], findingLinks: [{ findingId: "11111111-1111-4111-8111-111111111111", nodeId: "withdraw" }],
    unresolved: [{ callerFunctionId: "withdraw", source: location(unit, 20), kind: "external-call",
      reason: "dynamic-target", expression: "call" }], summary: { contracts: 3, interfaces: 1, libraries: 1,
      functions: 3, edges: 6, externalCalls: 2, entryPoints: 2, proxies: 1, delegatecalls: 0,
      findingsLinkedNodes: 1, unresolvedRelationships: 1 }, contentSha256: "c".repeat(64) } as StaticProtocolGraphArtifact;
}

describe("Protocol Map adapter", () => {
  it("collapses function endpoints while retaining source-backed edge identity, findings, proxy and role", () => {
    const artifact = fixture(), options = defaultOptions(artifact), view = visibleModel(artifact, options);
    expect(view.nodes.some((item) => item.id === "calculate")).toBe(false);
    expect(view.nodes.find((item) => item.id === "vault")?.data.findingCount).toBe(1);
    expect(view.nodes.find((item) => item.id === "proxy")?.data.badges).toContain("PROXY");
    expect(view.nodes.find((item) => item.id === "delegate")?.data.badges).not.toContain("PROXY");
    expect(view.nodes.some((item) => item.id === "role")).toBe(true);
    expect(view.edges.find((item) => item.id === "call")).toMatchObject({ source: "vault", target: "oracle" });
    expect(edgeDetails(artifact, "call")).toMatchObject({ from: { name: "Vault" }, to: { name: "IOracle" },
      fromFunction: { signature: "_calculateShares()" }, toFunction: { signature: "getPrice()" },
      edge: { source: { sourceUnitName: "src/core/Vault.sol", startLine: 18 } } });
    expect(findingIds(artifact, "oracle")).toEqual([]);
  });
  it("applies presets and filters without changing source facts", () => {
    const artifact = fixture(), original = JSON.stringify(artifact);
    expect(visibleModel(artifact, { ...defaultOptions(artifact), preset: "core" }).nodes.some((node) => node.id === "vault")).toBe(true);
    expect(visibleModel(artifact, { ...defaultOptions(artifact), preset: "findings" }).nodes.map((node) => node.id)).toEqual(["vault"]);
    expect(visibleModel(artifact, { ...defaultOptions(artifact), hideInterfaces: true }).nodes.some((node) => node.id === "oracle")).toBe(false);
    expect(visibleModel(artifact, { ...defaultOptions(artifact), preset: "external" }).nodes.some((node) => node.id === "unknown")).toBe(true);
    expect(visibleModel(artifact, { ...defaultOptions(artifact), preset: "upgrade" }).nodes.some((node) => node.id === "proxy")).toBe(true);
    expect(JSON.stringify(artifact)).toBe(original);
  });
  it("searches contract, signature and canonical source path and returns contract selections", () => {
    const artifact = fixture();
    expect(searchMap(artifact, "Vault").map((node) => node.id)).toContain("vault");
    expect(searchMap(artifact, "_calculateShares()").map((node) => node.id)).toEqual(["vault"]);
    expect(searchMap(artifact, "src/interfaces/IOracle.sol").map((node) => node.id)).toEqual(["oracle"]);
  });
  it("returns textual callers, callees, functions, unresolved facts and exact finding links", () => {
    const detail = nodeDetails(fixture(), "vault")!;
    expect(detail.callers.map((node) => node.name)).toContain("owner");
    expect(detail.callees.map((node) => node.name)).toContain("IOracle");
    expect(detail.functions.map((node) => node.name)).toContain("withdraw");
    expect(detail.unresolved).toHaveLength(1);
    expect(detail.findingIds).toHaveLength(1);
  });
  it("caps large views and gives stable deterministic layout positions", () => {
    const artifact = fixture();
    const extra = Array.from({ length: 650 }, (_, i) => ({ ...artifact.graph.nodes[0], id: `extra-${i}`,
      key: `extra-${i}`, name: `Contract${i}`, qualifiedName: `src/C${i}.sol:Contract${i}` })) as ProtocolGraphNode[];
    artifact.graph.nodes.push(...extra);
    const view = visibleModel(artifact, defaultOptions(artifact));
    expect(view.totalNodes).toBeGreaterThan(600);
    expect(view.nodes.length).toBeLessThanOrEqual(600);
    expect(view.clipped).toBe(true);
    expect(layoutMap(view).nodes).toHaveLength(view.nodes.length);
    const small = visibleModel(fixture(), defaultOptions(fixture()));
    expect(layoutMap(small).nodes.map((node) => node.position)).toEqual(layoutMap(small).nodes.map((node) => node.position));
  });
});
