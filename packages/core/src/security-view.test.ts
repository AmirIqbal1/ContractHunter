import { describe, expect, it } from "vitest";
import { contractGraphKey, functionGraphKey, protocolEdgeId, protocolGraphId, protocolNodeId,
  type ProtocolGraphEdge, type ProtocolGraphNode, type ProtocolSourceLocation } from "./protocol-graph";
import { staticProtocolGraphContentHash, type StaticProtocolGraphArtifact } from "./static-protocol-graph";
import { deriveAllSecurityViews, deriveSecurityView, securityViewTypes, validateSecurityView } from "./security-view";

const scanId = "00000000-0000-4000-8000-000000000001", mapId = `rm:${"a".repeat(64)}`;
const commit = "b".repeat(40), version = `fixture-v1:${mapId}`;
const loc = (unit: string, byte: number): ProtocolSourceLocation => ({ sourceUnitName: unit, startLine: byte + 1,
  endLine: byte + 1, startColumn: 0, endColumn: 5, startByte: byte, endByte: byte + 5 });
const evidence = (source: ProtocolSourceLocation | null = null) => [{ origin: "compiler" as const,
  producerVersion: "0.8.24", source, referenceId: null }];
const classification = { effective: "core" as const, automatic: "core" as const,
  automaticOrigin: "path-pattern" as const, reasons: ["source-root"], override: null };
function contract(name: string, kind: "contract" | "interface" = "contract"): ProtocolGraphNode {
  const unit = `src/${name}.sol`, key = contractGraphKey(unit, name), source = loc(unit, 0);
  return { kind, id: protocolNodeId(scanId, kind, key), key, name, qualifiedName: `${unit}:${name}`,
    contractKind: kind, repositoryClassification: classification, source, evidence: evidence(source), characteristics: [] };
}
function fn(owner: ProtocolGraphNode, name: string, signature: string, byte: number,
  mutability: "view" | "payable" | "nonpayable" = "nonpayable"): ProtocolGraphNode {
  const key = functionGraphKey(owner.key, signature), source = loc(owner.source!.sourceUnitName, byte);
  return { kind: "function", id: protocolNodeId(scanId, "function", key), key, name, signature,
    contractId: owner.id, source, evidence: evidence(source), characteristics: [], visibility: "external",
    mutability, modifiers: [], entryPoint: "yes" };
}
function actor(name: string): ProtocolGraphNode {
  return { kind: "external-actor", id: protocolNodeId(scanId, "external-actor", name), key: name,
    name, source: null, evidence: evidence(), characteristics: [], identityState: "unknown", representedContractId: null };
}
function edge(kind: ProtocolGraphEdge["kind"], from: ProtocolGraphNode, to: ProtocolGraphNode,
  byte: number, why: string, fromFunctionId: string | null = null, toFunctionId: string | null = null): ProtocolGraphEdge {
  const source = from.source ? loc(from.source.sourceUnitName, byte) : to.source ? loc(to.source.sourceUnitName, byte) : null;
  const key = `${kind}:${from.id}:${to.id}:${byte}:${why}`;
  return { id: protocolEdgeId(scanId, kind, from.id, to.id, key), key, kind, from: from.id, to: to.id,
    origin: "static", reasons: [why], evidence: evidence(source), source, fromFunctionId, toFunctionId };
}
function finalize(artifact: StaticProtocolGraphArtifact): StaticProtocolGraphArtifact {
  artifact.graph.nodes.sort((a, b) => a.id.localeCompare(b.id));
  artifact.graph.edges.sort((a, b) => a.id.localeCompare(b.id));
  artifact.functionFacts.sort((a, b) => a.functionId.localeCompare(b.functionId));
  artifact.findingLinks.sort((a, b) => `${a.nodeId}:${a.findingId}`.localeCompare(`${b.nodeId}:${b.findingId}`));
  const nodes = artifact.graph.nodes;
  const count = (kind: string) => nodes.filter((node) => node.kind === kind).length;
  artifact.summary = { contracts: count("contract"), interfaces: count("interface"), libraries: count("library"),
    functions: count("function"), edges: artifact.graph.edges.length,
    externalCalls: artifact.graph.edges.filter((item) => item.kind === "external-call").length,
    entryPoints: nodes.filter((node) => node.kind === "function" && node.entryPoint === "yes").length,
    proxies: nodes.filter((node) => node.kind === "contract" && node.characteristics.some((item) => item.kind === "proxy")).length,
    delegatecalls: artifact.functionFacts.reduce((sum, item) => sum + item.lowLevelCalls.filter((kind) => kind === "delegatecall").length, 0),
    findingsLinkedNodes: new Set(artifact.findingLinks.map((item) => item.nodeId)).size,
    unresolvedRelationships: artifact.unresolved.length };
  const content = Object.fromEntries(Object.entries(artifact).filter(([key]) => key !== "contentSha256")) as
    Omit<StaticProtocolGraphArtifact, "contentSha256">;
  artifact.contentSha256 = staticProtocolGraphContentHash(content);
  return artifact;
}
function fixture() {
  const vault = contract("Vault"), token = contract("IERC20", "interface"), oracle = contract("OracleThing"),
    proxy = contract("Proxy"), moneyName = contract("MoneyVault"), unknown = actor("runtime-target");
  const withdraw = fn(vault, "withdraw", "withdraw(uint256)", 10),
    send = fn(vault, "sendValue", "sendValue()", 20, "payable"),
    readonly = fn(vault, "peek", "peek()", 30, "view"),
    transfer = fn(token, "transfer", "transfer(address,uint256)", 10),
    getPrice = fn(oracle, "getPrice", "getPrice()", 10),
    sameName = fn(moneyName, "withdraw", "withdraw(uint256)", 10);
  const ownerKey = "owner-role", owner: ProtocolGraphNode = { kind: "role", id: protocolNodeId(scanId, "role", ownerKey),
    key: ownerKey, name: "owner", source: loc("src/Vault.sol", 2), evidence: evidence(loc("src/Vault.sol", 2)),
    characteristics: [], identityState: "known", representedContractId: vault.id };
  withdraw.characteristics.push({ kind: "token-transfer", evidence: evidence(loc("src/Vault.sol", 50)) });
  send.characteristics.push({ kind: "native-transfer", evidence: evidence(loc("src/Vault.sol", 60)) });
  proxy.characteristics.push({ kind: "proxy", evidence: evidence(loc("src/Proxy.sol", 3)) },
    { kind: "upgradeable", evidence: evidence(loc("src/Proxy.sol", 3)) });
  const findingId = "11111111-1111-4111-8111-111111111111";
  const graph = { schema: "contracthunter-protocol-graph-v1" as const,
    id: protocolGraphId(scanId, commit, version, [{ origin: "compiler", version: "0.8.24" }]),
    scanId, resolvedCommit: commit, extractorVersion: version, producers: [{ origin: "compiler" as const, version: "0.8.24" }],
    sourceUnits: [vault, token, oracle, proxy, moneyName].map((node) => ({ sourceUnitName: node.source!.sourceUnitName,
      snapshotSourceKey: node.source!.sourceUnitName, rawSha256: "c".repeat(64), byteLength: 10_000,
      identityStatus: "authoritative" as const })),
    nodes: [vault, token, oracle, proxy, moneyName, unknown, owner, withdraw, send, readonly, transfer, getPrice, sameName],
    edges: [edge("external-call", withdraw, transfer, 50, "typed-contract-member-call", withdraw.id, transfer.id),
      edge("external-call", withdraw, unknown, 70, "low-level-call", withdraw.id),
      edge("delegates", withdraw, unknown, 80, "low-level-delegatecall", withdraw.id),
      edge("external-call", withdraw, unknown, 85, "low-level-staticcall", withdraw.id),
      edge("external-call", withdraw, getPrice, 90, "typed-contract-member-call", withdraw.id, getPrice.id),
      edge("controls", owner, withdraw, 15, "msg-sender-owner-guard", null, withdraw.id),
      edge("delegates", proxy, unknown, 3, "eip1967-slot-and-delegatecall"),
      edge("calls", getPrice, withdraw, 25, "compiler-reference", getPrice.id, withdraw.id)],
    classifications: [], warnings: [] };
  const artifact: StaticProtocolGraphArtifact = { schema: "contracthunter-static-protocol-graph-v1", repositoryMapId: mapId,
    graph, functionFacts: [{ functionId: withdraw.id, stateReads: [], stateWrites: [{ variable: "balances",
      contractId: vault.id, declarationId: 7, source: loc("src/Vault.sol", 40) }], tokenTransferLike: true,
      nativeValueTransfer: false, modifierInvocations: [], lowLevelCalls: ["call", "delegatecall", "staticcall"] },
      { functionId: send.id, stateReads: [], stateWrites: [], tokenTransferLike: false, nativeValueTransfer: true,
        modifierInvocations: [], lowLevelCalls: [] }],
    functionSyntax: [{ functionId: withdraw.id, truncated: false, operations: [{ kind: "assembly",
      source: loc("src/Vault.sol", 100), astNodeId: 100, label: "inline assembly", expressionSha256: null,
      excerpt: "assembly", excerptTruncated: false }] }],
    findingLinks: [{ findingId, nodeId: withdraw.id }], unresolved: [{ callerFunctionId: withdraw.id,
      source: loc("src/Vault.sol", 70), kind: "external-call", reason: "dynamic-target", expression: "call" }],
    summary: {} as StaticProtocolGraphArtifact["summary"], contentSha256: "d".repeat(64) };
  return { artifact: finalize(artifact), vault, token, oracle, proxy, moneyName, unknown, owner,
    withdraw, send, readonly, transfer, getPrice, sameName, findingId };
}
const has = (view: ReturnType<typeof deriveSecurityView>, id: string) => view.nodes.some((item) => item.id === id);
const metric = (view: ReturnType<typeof deriveSecurityView>, key: string) =>
  view.summary.metrics.find((item) => item.key === key)?.value ?? 0;

describe("deterministic Security Views", () => {
  it("projects token/native movement without naming assets, direction, or movement from a contract name", () => {
    const f = fixture(), view = deriveSecurityView(f.artifact, "money-flow");
    expect(has(view, f.vault.id)).toBe(true); expect(has(view, f.withdraw.id)).toBe(true);
    expect(has(view, f.moneyName.id)).toBe(false);
    expect(view.edges.some((item) => item.id === f.artifact.graph.edges.find((edge) => edge.to === f.transfer.id)?.id)).toBe(true);
    expect(view.annotations.map((item) => item.kind)).toEqual(expect.arrayContaining(["token-transfer-like", "native-value-transfer"]));
    expect(view.annotations.every((item) => item.assetDirection === "unresolved")).toBe(true);
    expect(metric(view, "tokenOperations")).toBe(1); expect(metric(view, "nativeTransfers")).toBe(1);
    expect(view.warnings).toContainEqual(expect.objectContaining({ code: "asset-direction-unresolved" }));
  });
  it("uses exact owner-control edges and leaves AccessControl extraction unavailable", () => {
    const f = fixture(), view = deriveSecurityView(f.artifact, "permissions");
    expect(has(view, f.owner.id)).toBe(true); expect(has(view, f.withdraw.id)).toBe(true);
    expect(view.edges[0]?.reasons[0]?.code).toBe("owner-controlled");
    expect(metric(view, "controlledFunctions")).toBe(1);
    expect(view.warnings).toContainEqual({ code: "access-control-extraction-unavailable", count: 1 });
  });
  it("requires explicit oracle evidence and keeps unrelated oracle-like names out", () => {
    const f = fixture();
    expect(deriveSecurityView(f.artifact, "oracle-flow").nodes).toHaveLength(0);
    f.oracle.characteristics.push({ kind: "oracle-like", evidence: evidence(loc("src/OracleThing.sol", 5)) });
    finalize(f.artifact);
    const view = deriveSecurityView(f.artifact, "oracle-flow");
    expect(has(view, f.oracle.id)).toBe(true); expect(has(view, f.withdraw.id)).toBe(true);
    expect(metric(view, "oracleCallSites")).toBe(1);
    expect(view.edges.every((item) => f.artifact.graph.edges.some((edge) => edge.id === item.id))).toBe(true);
  });
  it("separates external, low-level, delegatecall and unresolved targets", () => {
    const f = fixture(), view = deriveSecurityView(f.artifact, "external-calls");
    expect(metric(view, "resolvedCalls")).toBe(2); expect(metric(view, "unresolvedCalls")).toBe(3);
    expect(metric(view, "lowLevelCalls")).toBe(3); expect(metric(view, "delegatecalls")).toBe(1);
    expect(view.annotations.filter((item) => item.kind === "unresolved-call")).toHaveLength(3);
    expect(view.edges.map((item) => item.callType)).toEqual(expect.arrayContaining(["high-level", "call", "staticcall", "delegatecall"]));
    expect(view.nodes.every((item) => f.artifact.graph.nodes.some((node) => node.id === item.id))).toBe(true);
  });
  it("recognizes only proven proxy structure, including an unresolved implementation", () => {
    const f = fixture(), view = deriveSecurityView(f.artifact, "upgradeability");
    expect(has(view, f.proxy.id)).toBe(true); expect(has(view, f.withdraw.id)).toBe(false);
    expect(metric(view, "proxies")).toBe(1);
    expect(view.annotations).toContainEqual(expect.objectContaining({ kind: "proxy-target-unresolved" }));
    expect(view.warnings).toContainEqual({ code: "proxy-target-unresolved", count: 1 });
  });
  it("includes upgrade authority only when a control edge protects an explicit upgrade edge", () => {
    const f = fixture();
    f.artifact.graph.edges.push(edge("upgrades", f.withdraw, f.proxy, 110, "explicit-upgrade",
      f.withdraw.id));
    finalize(f.artifact);
    const view = deriveSecurityView(f.artifact, "upgradeability");
    expect(metric(view, "upgradeControls")).toBe(1);
    expect(view.edges.some((item) => item.reasons.some((why) => why.code === "upgrade-authority"))).toBe(true);
  });
  it("projects entry points, payable/state-changing facts, assembly, findings and view-function semantics", () => {
    const f = fixture(), view = deriveSecurityView(f.artifact, "attack-surface");
    expect(metric(view, "entryPoints")).toBe(6);
    expect(metric(view, "payableEntryPoints")).toBe(1);
    expect(metric(view, "stateChangingEntryPoints")).toBe(1);
    expect(metric(view, "assemblyFunctions")).toBe(1);
    expect(view.annotations.some((item) => item.nodeId === f.readonly.id && item.kind === "state-write")).toBe(false);
    expect(has(view, f.withdraw.id)).toBe(true);
  });
  it("links only exact finding identities and keeps markup as inert data", () => {
    const f = fixture(), view = deriveSecurityView(f.artifact, "findings", [{ id: f.findingId,
      detectorId: "x", title: "<script>alert(1)</script>", status: "open", source: "slither" }]);
    expect(has(view, f.withdraw.id)).toBe(true); expect(has(view, f.sameName.id)).toBe(false);
    expect(metric(view, "contractsWithFindings")).toBe(1); expect(metric(view, "functionsWithFindings")).toBe(1);
    expect(view.findingMetadata[0]?.title).toBe("<script>alert(1)</script>");
    expect(JSON.stringify(view)).not.toContain("<div>");
  });
  it("terminates on cyclic relationships, sorts deterministically and leaves base facts unchanged", () => {
    const f = fixture(), before = JSON.stringify(f.artifact);
    const views = deriveAllSecurityViews(f.artifact);
    expect(views.map((item) => item.viewType)).toEqual([...securityViewTypes]);
    expect(deriveAllSecurityViews(f.artifact)).toEqual(views);
    expect(JSON.stringify(f.artifact)).toBe(before);
    for (const view of views) expect(validateSecurityView(f.artifact, view)).toEqual(view);
  });
  it("rejects unknown view logic, forged graph references and arbitrary extension fields", () => {
    const f = fixture(), view = deriveSecurityView(f.artifact, "findings");
    expect(() => deriveSecurityView(f.artifact, "custom" as never)).toThrow("security_view_type_invalid");
    expect(() => validateSecurityView(f.artifact, { ...view, extra: "not-closed" })).toThrow();
    const forged = structuredClone(view);
    forged.nodes[0]!.id = `pn:${"f".repeat(64)}`;
    expect(() => validateSecurityView(f.artifact, forged)).toThrow("security_view_integrity_invalid");
  });
  it("derives seven views for a representative large cyclic graph with bounded output", () => {
    const f = fixture();
    for (let index = 0; index < 1_200; index++) {
      const node = actor(`actor-${index}`);
      f.artifact.graph.nodes.push(node);
      const next = actor(`actor-${(index + 1) % 1_200}`);
      f.artifact.graph.edges.push(edge("calls", node, next, index, "compiler-reference"));
    }
    finalize(f.artifact);
    const views = deriveAllSecurityViews(f.artifact);
    expect(views).toHaveLength(7);
    expect(views.every((view) => view.nodes.length <= 5_000 && view.edges.length <= 20_000)).toBe(true);
    expect(deriveAllSecurityViews(f.artifact)).toEqual(views);
  });
});
