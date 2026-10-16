import { describe, expect, it } from "vitest";
import { contractGraphKey, functionGraphKey, protocolEdgeId, protocolGraphId, protocolNodeId,
  type ProtocolGraphEdge, type ProtocolGraphNode, type ProtocolSourceLocation } from "./protocol-graph";
import { staticProtocolGraphContentHash, type StaticProtocolGraphArtifact } from "./static-protocol-graph";
import { deriveAllSecurityViews } from "./security-view";
import { AUDIT_PRIORITY_CATALOG_VERSION, AUDIT_PRIORITY_RULESET_VERSION, auditConcepts, auditFactorRules,
  auditPriorityContentHash, deriveAuditPriority, validateAuditPriority } from "./audit-priority";

const scanId = "00000000-0000-4000-8000-000000000001", mapId = `rm:${"a".repeat(64)}`;
const commit = "b".repeat(40), version = `fixture-v1:${mapId}`;
const loc = (unit: string, byte: number): ProtocolSourceLocation => ({ sourceUnitName: unit,
  startLine: byte + 1, endLine: byte + 1, startColumn: 0, endColumn: 5, startByte: byte, endByte: byte + 5 });
const evidence = (source: ProtocolSourceLocation | null = null) => [{ origin: "compiler" as const,
  producerVersion: "0.8.24", source, referenceId: null }];
const cls = (effective: "core" | "periphery" = "core") => ({ effective, automatic: effective,
  automaticOrigin: "path-pattern" as const, reasons: ["source-root"], override: null });
function contract(name: string, classification: "core" | "periphery" = "core"): ProtocolGraphNode {
  const unit = `src/${name}.sol`, key = contractGraphKey(unit, name), source = loc(unit, 0);
  return { kind: "contract", id: protocolNodeId(scanId, "contract", key), key, name, qualifiedName: `${unit}:${name}`,
    contractKind: "contract", repositoryClassification: cls(classification), source, evidence: evidence(source), characteristics: [] };
}
function fn(owner: ProtocolGraphNode, name: string, signature: string, byte: number,
  entry = true, mutability: "view" | "payable" | "nonpayable" = "nonpayable"): ProtocolGraphNode {
  const key = functionGraphKey(owner.key, signature), source = loc(owner.source!.sourceUnitName, byte);
  return { kind: "function", id: protocolNodeId(scanId, "function", key), key, name, signature,
    contractId: owner.id, source, evidence: evidence(source), characteristics: [], visibility: entry ? "external" : "internal",
    mutability, modifiers: [], entryPoint: entry ? "yes" : "no" };
}
function edge(kind: ProtocolGraphEdge["kind"], from: ProtocolGraphNode, to: ProtocolGraphNode,
  byte: number, why: string): ProtocolGraphEdge {
  const source = loc(from.source!.sourceUnitName, byte), key = `${kind}:${from.id}:${to.id}:${byte}:${why}`;
  return { id: protocolEdgeId(scanId, kind, from.id, to.id, key), key, kind, from: from.id, to: to.id,
    origin: "static", reasons: [why], evidence: evidence(source), source,
    fromFunctionId: from.kind === "function" ? from.id : null, toFunctionId: to.kind === "function" ? to.id : null };
}
function finalize(artifact: StaticProtocolGraphArtifact) {
  artifact.graph.nodes.sort((a, b) => a.id.localeCompare(b.id));
  artifact.graph.edges.sort((a, b) => a.id.localeCompare(b.id));
  artifact.functionFacts.sort((a, b) => a.functionId.localeCompare(b.functionId));
  artifact.findingLinks.sort((a, b) => `${a.nodeId}:${a.findingId}`.localeCompare(`${b.nodeId}:${b.findingId}`));
  const nodes = artifact.graph.nodes, count = (kind: string) => nodes.filter((node) => node.kind === kind).length;
  artifact.summary = { contracts: count("contract"), interfaces: count("interface"), libraries: count("library"),
    functions: count("function"), edges: artifact.graph.edges.length,
    externalCalls: artifact.graph.edges.filter((item) => item.kind === "external-call").length,
    entryPoints: nodes.filter((node) => node.kind === "function" && node.entryPoint === "yes").length,
    proxies: nodes.filter((node) => node.kind === "contract" && node.characteristics.some((item) => item.kind === "proxy")).length,
    delegatecalls: artifact.functionFacts.reduce((sum, item) => sum + item.lowLevelCalls.filter((kind) => kind === "delegatecall").length, 0),
    findingsLinkedNodes: new Set(artifact.findingLinks.map((link) => link.nodeId)).size,
    unresolvedRelationships: artifact.unresolved.length };
  const content = Object.fromEntries(Object.entries(artifact).filter(([key]) => key !== "contentSha256")) as
    Omit<StaticProtocolGraphArtifact, "contentSha256">;
  artifact.contentSha256 = staticProtocolGraphContentHash(content);
  return artifact;
}
function fixture() {
  const vault = contract("Vault"), helper = contract("Helper", "periphery"), moneyName = contract("MoneyVault", "periphery"),
    oracle = contract("OracleThing", "periphery"), proxy = contract("Proxy", "periphery"),
    dispatcher = contract("Dispatcher", "periphery"), token = contract("Token", "periphery");
  const withdraw = fn(vault, "withdraw", "withdraw(uint256)", 10), balance = fn(vault, "balanceOf", "balanceOf(address)", 20, true, "view"),
    internal = fn(helper, "assist", "assist()", 10, false), transfer = fn(token, "transfer", "transfer(address,uint256)", 10),
    dispatch = fn(dispatcher, "dispatch", "dispatch()", 10), moneyFn = fn(moneyName, "withdraw", "withdraw(uint256)", 10);
  const owner: ProtocolGraphNode = { kind: "role", id: protocolNodeId(scanId, "role", "owner-role"), key: "owner-role",
    name: "owner", source: loc("src/Vault.sol", 2), evidence: evidence(loc("src/Vault.sol", 2)),
    characteristics: [], identityState: "known", representedContractId: vault.id };
  const unknown: ProtocolGraphNode = { kind: "external-actor", id: protocolNodeId(scanId, "external-actor", "runtime"),
    key: "runtime", name: "runtime target", source: null, evidence: evidence(), characteristics: [],
    identityState: "unknown", representedContractId: null };
  withdraw.characteristics.push({ kind: "token-transfer", evidence: evidence(loc("src/Vault.sol", 40)) });
  proxy.characteristics.push({ kind: "proxy", evidence: evidence(loc("src/Proxy.sol", 2)) },
    { kind: "upgradeable", evidence: evidence(loc("src/Proxy.sol", 2)) });
  const findingId = "11111111-1111-4111-8111-111111111111";
  const contractNodes = [vault, helper, moneyName, oracle, proxy, dispatcher, token];
  const graph = { schema: "contracthunter-protocol-graph-v1" as const,
    id: protocolGraphId(scanId, commit, version, [{ origin: "compiler", version: "0.8.24" }]), scanId,
    resolvedCommit: commit, extractorVersion: version, producers: [{ origin: "compiler" as const, version: "0.8.24" }],
    sourceUnits: contractNodes.map((node) => ({ sourceUnitName: node.source!.sourceUnitName,
      snapshotSourceKey: node.source!.sourceUnitName, rawSha256: "c".repeat(64), byteLength: 10_000,
      identityStatus: "authoritative" as const })),
    nodes: [...contractNodes, owner, unknown, withdraw, balance, internal, transfer, dispatch, moneyFn],
    edges: [edge("external-call", withdraw, transfer, 40, "typed-contract-member-call"),
      edge("external-call", withdraw, unknown, 50, "low-level-call"),
      edge("delegates", dispatch, unknown, 60, "low-level-delegatecall"),
      edge("controls", owner, withdraw, 12, "msg-sender-owner-guard"),
      edge("delegates", proxy, unknown, 2, "eip1967-slot-and-delegatecall")],
    classifications: [], warnings: [] };
  const artifact: StaticProtocolGraphArtifact = { schema: "contracthunter-static-protocol-graph-v1",
    repositoryMapId: mapId, graph, functionFacts: [{ functionId: withdraw.id, stateReads: [], stateWrites: [{ variable: "balances",
      contractId: vault.id, declarationId: 7, source: loc("src/Vault.sol", 70) }], tokenTransferLike: true,
      nativeValueTransfer: false, modifierInvocations: [], lowLevelCalls: ["call"] }],
    functionSyntax: [{ functionId: withdraw.id, truncated: false, operations: [{ kind: "assembly",
      source: loc("src/Vault.sol", 80), astNodeId: 80, label: "assembly", expressionSha256: null,
      excerpt: "assembly", excerptTruncated: false }] }],
    findingLinks: [{ findingId, nodeId: withdraw.id }], unresolved: [{ callerFunctionId: withdraw.id,
      source: loc("src/Vault.sol", 50), kind: "external-call", reason: "dynamic-target", expression: "call" }],
    summary: {} as StaticProtocolGraphArtifact["summary"], contentSha256: "d".repeat(64) };
  return { artifact: finalize(artifact), vault, helper, moneyName, oracle, proxy, dispatcher, withdraw, balance,
    internal, dispatch, findingId };
}
const run = (artifact: StaticProtocolGraphArtifact) => deriveAuditPriority(artifact, deriveAllSecurityViews(artifact));
const factor = (result: ReturnType<typeof run>, name: string, id: string) =>
  result.rankedContracts.find((item) => item.name === name)?.factors.find((item) => item.id === id);

describe("explainable audit priority", () => {
  it("ranks evidence-rich Vault over helper and gives exact source-backed reasons", () => {
    const f = fixture(), result = run(f.artifact);
    expect(result.schema).toBe("contracthunter-audit-priority-v1");
    expect(result.rulesetVersion).toBe(AUDIT_PRIORITY_RULESET_VERSION);
    expect(result.explanationCatalogVersion).toBe(AUDIT_PRIORITY_CATALOG_VERSION);
    expect(result.rankedContracts[0].id).toBe(f.vault.id);
    expect(factor(result, "Vault", "token-transfer")?.evidence[0].source?.sourceUnitName).toBe("src/Vault.sol");
    expect(result.scoreMeaning).toContain("does not mean a vulnerability");
  });
  it("makes every score the exact sum of awarded factor points with quantity caps", () => {
    const f = fixture();
    for (let i = 0; i < 100; i++) f.artifact.graph.nodes.push(fn(f.helper, `entry${i}`, `entry${i}()`, i + 100));
    finalize(f.artifact);
    const result = run(f.artifact), helper = result.rankedContracts.find((item) => item.id === f.helper.id)!;
    expect(helper.factors.find((item) => item.id === "external-entry-points")?.points).toBeLessThanOrEqual(9);
    for (const contract of result.rankedContracts) {
      expect(contract.score).toBe(contract.factors.reduce((sum, item) => sum + item.points, 0));
      for (const fn of contract.recommendedFunctions)
        expect(fn.score).toBe(fn.factors.reduce((sum, item) => sum + item.points, 0));
    }
  });
  it("does not infer money or oracle status from names", () => {
    const f = fixture(), result = run(f.artifact);
    expect(factor(result, "MoneyVault", "token-transfer")).toBeUndefined();
    expect(factor(result, "OracleThing", "oracle-dependent")).toBeUndefined();
    expect(result.warnings.some((item) => item.code === "oracle-evidence-unavailable")).toBe(true);
  });
  it("adds an oracle factor only when a proven oracle-like source is called", () => {
    const f = fixture(), getPrice = fn(f.oracle, "getPrice", "getPrice()", 10);
    f.oracle.characteristics.push({ kind: "oracle-like", evidence: evidence(loc("src/OracleThing.sol", 5)) });
    f.artifact.graph.nodes.push(getPrice);
    f.artifact.graph.edges.push(edge("external-call", f.withdraw, getPrice, 90, "typed-contract-member-call"));
    finalize(f.artifact);
    expect(factor(run(f.artifact), "Vault", "oracle-dependent")).toBeDefined();
  });
  it("separates proven proxy from standalone delegatecall and exact owner control from names", () => {
    const f = fixture(), result = run(f.artifact);
    expect(factor(result, "Proxy", "proxy")).toBeDefined();
    expect(factor(result, "Dispatcher", "delegatecall")).toBeDefined();
    expect(factor(result, "Dispatcher", "proxy")).toBeUndefined();
    expect(factor(result, "Vault", "owner-controlled")).toBeDefined();
  });
  it("caps finding contribution and prioritizes the operation over a view getter", () => {
    const f = fixture();
    for (let i = 0; i < 20; i++) f.artifact.findingLinks.push({ findingId: `${String(i).padStart(8, "0")}-0000-4000-8000-000000000000`, nodeId: f.withdraw.id });
    finalize(f.artifact);
    const result = run(f.artifact), vault = result.rankedContracts.find((item) => item.id === f.vault.id)!;
    expect(vault.factors.find((item) => item.id === "finding-linked")?.points).toBeLessThanOrEqual(5);
    expect(vault.checklist.find((item) => item.conceptKey === "finding")?.findingIds.length).toBeGreaterThan(0);
    expect(vault.recommendedFunctions[0].id).toBe(f.withdraw.id);
    expect(vault.recommendedFunctions[0].score).toBeGreaterThan(vault.recommendedFunctions.find((item) => item.id === f.balance.id)!.score);
  });
  it("labels write-after-call as source order and retains partial warnings", () => {
    const result = run(fixture().artifact);
    expect(factor(result, "Vault", "write-after-external-call-source-order")).toBeDefined();
    expect(auditConcepts["source-order"].meaning).toContain("not proven runtime path");
    expect(result.analysisStatus).toBe("partial");
    expect(result.warnings.some((item) => item.code === "call-target-unresolved")).toBe(true);
  });
  it("uses exact Security View membership and validates evidence links/content identity", () => {
    const f = fixture(), views = deriveAllSecurityViews(f.artifact), result = deriveAuditPriority(f.artifact, views);
    const vault = result.rankedContracts.find((item) => item.id === f.vault.id)!;
    expect(vault.securityViews).toContain("money-flow");
    expect(result.rankedContracts.find((item) => item.id === f.moneyName.id)!.securityViews).not.toContain("money-flow");
    expect(validateAuditPriority(f.artifact, views, result)).toEqual(result);
    const altered = structuredClone(result);
    altered.rankedContracts[0].factors[0].evidence[0].id = "pn:" + "f".repeat(64);
    const alteredContent = Object.fromEntries(Object.entries(altered).filter(([key]) => key !== "contentSha256")) as
      Omit<typeof altered, "contentSha256">;
    altered.contentSha256 = auditPriorityContentHash(alteredContent);
    expect(() => validateAuditPriority(f.artifact, views, altered)).toThrow();
  });
  it("is deterministic, immutable, bounded and preserves hostile labels as data", () => {
    const f = fixture();
    const evilName = "Helper<script>alert(1)</script>", evilUnit = "src/Evil.sol";
    const evilKey = contractGraphKey(evilUnit, evilName), evilSource = loc(evilUnit, 0);
    f.artifact.graph.nodes.push({ kind: "contract", id: protocolNodeId(scanId, "contract", evilKey), key: evilKey,
      name: evilName, qualifiedName: `${evilUnit}:${evilName}`, contractKind: "contract", repositoryClassification: cls(),
      source: evilSource, evidence: evidence(evilSource), characteristics: [] });
    f.artifact.graph.sourceUnits.push({ sourceUnitName: evilUnit, snapshotSourceKey: evilUnit,
      rawSha256: "c".repeat(64), byteLength: 10_000, identityStatus: "authoritative" });
    for (let i = 0; i < 400; i++) {
      const node = contract(`Extra${i}`, "periphery");
      f.artifact.graph.nodes.push(node);
      f.artifact.graph.sourceUnits.push({ sourceUnitName: node.source!.sourceUnitName,
        snapshotSourceKey: node.source!.sourceUnitName, rawSha256: "c".repeat(64), byteLength: 10_000,
        identityStatus: "authoritative" });
    }
    finalize(f.artifact);
    const before = JSON.stringify(f.artifact), views = deriveAllSecurityViews(f.artifact), beforeViews = JSON.stringify(views);
    const one = deriveAuditPriority(f.artifact, views), two = deriveAuditPriority(f.artifact, views);
    expect(one).toEqual(two);
    expect(one.rankedContracts).toHaveLength(10);
    expect(one.rankedContracts.every((item) => item.recommendedFunctions.length <= 5 && item.checklist.length <= 12)).toBe(true);
    expect(JSON.stringify(f.artifact)).toBe(before);
    expect(JSON.stringify(views)).toBe(beforeViews);
    expect(JSON.stringify(one)).toContain(evilName);
    expect(JSON.stringify(one)).not.toContain("<div>");
  });
  it("covers every score factor with fixed educational copy and deterministic ties", () => {
    for (const rule of Object.values(auditFactorRules)) expect(auditConcepts[rule.concept]).toBeDefined();
    const f = fixture(), result = run(f.artifact);
    const equal = result.rankedContracts.filter((item) => item.score === 0);
    expect(equal.map((item) => item.source.sourceUnitName)).toEqual([...equal.map((item) => item.source.sourceUnitName)].sort());
  });
});
