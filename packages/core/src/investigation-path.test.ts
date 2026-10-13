import { describe, expect, it } from "vitest";
import { contractGraphKey, functionGraphKey, protocolEdgeId, protocolGraphId, protocolNodeId,
  type ProtocolGraphNode, type ProtocolGraphEdge, type ProtocolSourceLocation } from "./protocol-graph";
import { staticProtocolGraphContentHash, type StaticProtocolGraphArtifact } from "./static-protocol-graph";
import { deriveInvestigationPaths, INVESTIGATION_PATH_LIMITS, validateInvestigationPathResult,
  validateInvestigationPathOverlayReferences } from "./investigation-path";

const scanId = "00000000-0000-4000-8000-000000000001", findingId = "11111111-1111-4111-8111-111111111111";
const mapId = `rm:${"a".repeat(64)}`, commit = "b".repeat(40), version = `fixture-v1:${mapId}`;
const loc = (unit: string, line: number): ProtocolSourceLocation => ({ sourceUnitName: unit, startLine: line,
  endLine: line, startColumn: 0, endColumn: 5, startByte: line * 10, endByte: line * 10 + 5 });
const evidence = (source: ProtocolSourceLocation | null) => [{ origin: "compiler" as const,
  producerVersion: "fixture", source, referenceId: null }];
function contract(name: string): ProtocolGraphNode {
  const source = loc(`src/${name}.sol`, 1), key = contractGraphKey(source.sourceUnitName, name);
  return { kind: "contract", id: protocolNodeId(scanId, "contract", key), key, name, qualifiedName: `${source.sourceUnitName}:${name}`,
    contractKind: "contract", repositoryClassification: { effective: "core", automatic: "core", automaticOrigin: "path-pattern",
      reasons: ["source-root"], override: null }, source, evidence: evidence(source), characteristics: [] };
}
function fn(owner: ProtocolGraphNode, signature: string, line: number, entry = false): ProtocolGraphNode {
  const source = loc(owner.source!.sourceUnitName, line), key = functionGraphKey(owner.key, signature);
  return { kind: "function", id: protocolNodeId(scanId, "function", key), key, name: signature.split("(")[0], signature,
    contractId: owner.id, source, evidence: evidence(source), characteristics: [], visibility: entry ? "external" : "internal",
    mutability: "nonpayable", modifiers: [], entryPoint: entry ? "yes" : "no" };
}
function edge(kind: ProtocolGraphEdge["kind"], from: ProtocolGraphNode, to: ProtocolGraphNode, line: number): ProtocolGraphEdge {
  const source = loc(from.source!.sourceUnitName, line), key = `${kind}:${from.id}:${to.id}:${line}`;
  return { id: protocolEdgeId(scanId, kind, from.id, to.id, key), key, kind, from: from.id, to: to.id,
    origin: "static", reasons: [kind === "controls" ? "msg-sender-owner-guard" : "typed-contract-member-call"],
    evidence: evidence(source), source, fromFunctionId: from.kind === "function" ? from.id : null,
    toFunctionId: to.kind === "function" ? to.id : null };
}
function fixture(nodes: ProtocolGraphNode[], edges: ProtocolGraphEdge[], targetIds: string[],
  unresolved: StaticProtocolGraphArtifact["unresolved"] = [],
  functionSyntax?: NonNullable<StaticProtocolGraphArtifact["functionSyntax"]>): StaticProtocolGraphArtifact {
  const graph = { schema: "contracthunter-protocol-graph-v1" as const,
    id: protocolGraphId(scanId, commit, version, [{ origin: "compiler", version: "fixture" }]), scanId,
    resolvedCommit: commit, extractorVersion: version, producers: [{ origin: "compiler" as const, version: "fixture" }],
    sourceUnits: [...new Set(nodes.flatMap((node) => node.source ? [node.source.sourceUnitName] : []))]
      .map((sourceUnitName) => ({ sourceUnitName, snapshotSourceKey: sourceUnitName, rawSha256: "c".repeat(64),
        byteLength: 10000, identityStatus: "authoritative" as const })).sort((a, b) => a.sourceUnitName.localeCompare(b.sourceUnitName)),
    nodes: [...nodes].sort((a, b) => a.id.localeCompare(b.id)), edges: [...edges].sort((a, b) => a.id.localeCompare(b.id)),
    classifications: [], warnings: [] };
  const findingLinks = targetIds.map((nodeId) => ({ findingId, nodeId })).sort((a, b) => a.nodeId.localeCompare(b.nodeId));
  const summary = { contracts: nodes.filter((node) => node.kind === "contract").length, interfaces: 0, libraries: 0,
    functions: nodes.filter((node) => node.kind === "function").length, edges: edges.length,
    externalCalls: edges.filter((item) => item.kind === "external-call").length,
    entryPoints: nodes.filter((node) => node.kind === "function" && node.entryPoint === "yes").length,
    proxies: nodes.filter((node) => node.kind === "contract" && node.characteristics.some((trait) => trait.kind === "proxy")).length,
    delegatecalls: 0, findingsLinkedNodes: new Set(targetIds).size, unresolvedRelationships: unresolved.length };
  const content = { schema: "contracthunter-static-protocol-graph-v1" as const, repositoryMapId: mapId, graph,
    functionFacts: [], ...(functionSyntax ? { functionSyntax } : {}), findingLinks, unresolved, summary };
  return { ...content, contentSha256: staticProtocolGraphContentHash(content) };
}
const subject = { type: "finding" as const, id: findingId, findingIds: [findingId] };
function basic() {
  const router = contract("Router"), vault = contract("Vault"), token = contract("Token"), oracle = contract("PriceFeed");
  const deposit = fn(router, "deposit(uint256)", 5, true), vaultDeposit = fn(vault, "deposit(uint256)", 8),
    helper = fn(vault, "_calculateShares(uint256)", 14), transfer = fn(token, "transfer(address,uint256)", 6),
    price = fn(oracle, "latestAnswer()", 4);
  return { router, vault, token, oracle, deposit, vaultDeposit, helper, transfer, price };
}

describe("deterministic Investigation Paths", () => {
  it("connects exact direct context, caller chain, entry point and callee without exploit claims", () => {
    const n = basic(), nodes = Object.values(n);
    const edges = [edge("calls", n.deposit, n.vaultDeposit, 6), edge("calls", n.vaultDeposit, n.helper, 10),
      edge("external-call", n.vaultDeposit, n.transfer, 11)];
    const artifact = fixture(nodes, edges, [n.vaultDeposit.id]);
    const original = structuredClone(artifact), result = deriveInvestigationPaths(artifact, subject);
    expect(result.mapping).toBe("mapped");
    expect(result.paths.some((path) => path.kind === "local-context" && path.nodeIds.join() === [n.deposit.id, n.vaultDeposit.id].join())).toBe(true);
    expect(result.paths.some((path) => path.kind === "caller-chain" && path.nodeIds[0] === n.deposit.id)).toBe(true);
    expect(result.paths.some((path) => path.kind === "callee-chain" && path.nodeIds.at(-1) === n.transfer.id)).toBe(true);
    expect(result.paths.every((path) => path.steps.every((step) => step.provenance.length > 0))).toBe(true);
    expect(result.paths.find((path) => path.edgeIds.includes(edges[0].id))?.steps.at(-1)?.source).toEqual(edges[0].source);
    expect(JSON.stringify(result)).not.toMatch(/exploitable|fund theft|vulnerable/);
    expect(artifact).toEqual(original); expect(validateInvestigationPathResult(result)).toEqual(result);
    expect(deriveInvestigationPaths(artifact, subject)).toEqual(result);
  });
  it("keeps overloaded names and contract-level fallback distinct", () => {
    const n = basic(), other = contract("Other"), same = fn(other, "deposit(uint256)", 20);
    const artifact = fixture([...Object.values(n), other, same], [], [n.vaultDeposit.id]);
    const result = deriveInvestigationPaths(artifact, subject);
    expect(result.targetNodeIds).toEqual([n.vaultDeposit.id]); expect(result.paths.every((path) => !path.nodeIds.includes(same.id))).toBe(true);
    const contractLevel = deriveInvestigationPaths(fixture(Object.values(n), [], [n.vault.id]), subject);
    expect(contractLevel.warnings).toContain("contract-level-only");
    expect(contractLevel.paths.every((path) => path.nodeIds.every((id) => id !== n.vaultDeposit.id))).toBe(true);
  });
  it("includes exact privilege and proven oracle context; names alone do not qualify", () => {
    const n = basic(), roleSource = loc("src/Vault.sol", 2), role: ProtocolGraphNode = { kind: "role",
      id: protocolNodeId(scanId, "role", "owner"), key: "owner", name: "owner", source: roleSource,
      evidence: evidence(roleSource), characteristics: [], identityState: "known", representedContractId: n.vault.id };
    n.oracle.characteristics.push({ kind: "oracle-like", evidence: evidence(n.oracle.source) });
    const nodes = [...Object.values(n), role], edges = [edge("controls", role, n.vaultDeposit, 3),
      edge("external-call", n.vaultDeposit, n.price, 11)];
    const result = deriveInvestigationPaths(fixture(nodes, edges, [n.vaultDeposit.id]), subject);
    expect(result.paths.some((path) => path.kind === "privilege-context" && path.nodeIds[0] === role.id)).toBe(true);
    expect(result.paths.some((path) => path.kind === "oracle-context" && path.edgeIds.includes(edges[1].id))).toBe(true);
    n.oracle.characteristics = [];
    expect(deriveInvestigationPaths(fixture(nodes, edges, [n.vaultDeposit.id]), subject).paths.some((path) => path.kind === "oracle-context")).toBe(false);
  });
  it("requires proven upgrade relationships; delegatecall-only is not a proxy", () => {
    const n = basic(), n2 = Object.values(n); n.vault.characteristics.push({ kind: "proxy", evidence: evidence(n.vault.source) });
    const upgrade = edge("upgrades", n.vault, n.token, 2);
    expect(deriveInvestigationPaths(fixture(n2, [upgrade], [n.vault.id]), subject).paths.some((path) => path.kind === "upgrade-context")).toBe(true);
    n.vault.characteristics = [];
    expect(deriveInvestigationPaths(fixture(n2, [edge("delegates", n.vaultDeposit, n.transfer, 9)], [n.vault.id]), subject)
      .paths.some((path) => path.kind === "upgrade-context")).toBe(false);
  });
  it("terminates unresolved calls and cycles within bounds", () => {
    const n = basic(), source = loc("src/Vault.sol", 12), unknown: ProtocolGraphNode = { kind: "external-actor",
      id: protocolNodeId(scanId, "external-actor", "unknown"), key: "unknown", name: "runtime target", source: null,
      evidence: evidence(null), characteristics: [], identityState: "unknown", representedContractId: null };
    const edges = [edge("calls", n.vaultDeposit, n.helper, 10), edge("calls", n.helper, n.vaultDeposit, 15),
      edge("external-call", n.vaultDeposit, unknown, 12)];
    const unresolved = [{ callerFunctionId: n.vaultDeposit.id, source, kind: "external-call" as const,
      reason: "dynamic-target" as const, expression: "target" }];
    const result = deriveInvestigationPaths(fixture([...Object.values(n), unknown], edges, [n.vaultDeposit.id], unresolved), subject);
    expect(result.warnings).toContain("unresolved-call-target");
    expect(result.paths.some((path) => path.completeness === "unresolved" && path.nodeIds.at(-1) === unknown.id)).toBe(true);
    expect(result.paths.every((path) => new Set(path.nodeIds).size === path.nodeIds.length)).toBe(true);
  });
  it("keeps multiple entry chains stable and limits branching output", () => {
    const n = basic(), entries = Array.from({ length: 35 }, (_, i) => fn(n.router, `entry${i}()`, 30 + i, true));
    const edges = entries.map((entry, i) => edge("calls", entry, n.vaultDeposit, 30 + i));
    const result = deriveInvestigationPaths(fixture([...Object.values(n), ...entries], edges, [n.vaultDeposit.id]), subject);
    expect(result.paths.length).toBeLessThanOrEqual(INVESTIGATION_PATH_LIMITS.paths);
    expect(result.warnings).toContain("path-limit-reached");
    expect(result.coverage).toBe("truncated");
    expect(deriveInvestigationPaths(fixture([...Object.values(n), ...entries], edges, [n.vaultDeposit.id]), subject)).toEqual(result);
  });
  it("shows a bounded multi-hop static entry chain without turning it into runtime proof", () => {
    const n = basic(), edges = [edge("calls", n.deposit, n.vaultDeposit, 6), edge("calls", n.vaultDeposit, n.helper, 10)];
    const result = deriveInvestigationPaths(fixture(Object.values(n), edges, [n.helper.id]), subject);
    expect(result.paths.some((path) => path.kind === "caller-chain" &&
      path.nodeIds.join() === [n.deposit.id, n.vaultDeposit.id, n.helper.id].join())).toBe(true);
    expect(result.warnings).toContain("static-only");
  });
  it("uses exact Money Flow annotation and Function Explorer operation identities", () => {
    const n = basic(), at = loc("src/Vault.sol", 8);
    n.vaultDeposit.characteristics.push({ kind: "token-transfer", evidence: evidence(at) });
    const syntax = [{ functionId: n.vaultDeposit.id, truncated: false, operations: [{ kind: "condition" as const,
      source: at, astNodeId: 19, label: "amount > 0", expressionSha256: null, excerpt: "amount > 0",
      excerptTruncated: false }] }];
    const result = deriveInvestigationPaths(fixture(Object.values(n), [], [n.vaultDeposit.id], [], syntax), subject);
    expect(result.paths.some((path) => path.kind === "asset-operation-context" && path.steps[0].source?.startLine === 8)).toBe(true);
    expect(result.operations.some((item) => item.kind === "condition" && item.operationId.startsWith("fo:"))).toBe(true);
  });
  it("reports unmapped and partially mapped subjects without guessing", () => {
    const n = basic(), artifact = fixture(Object.values(n), [], []);
    expect(deriveInvestigationPaths(artifact, subject).mapping).toBe("unmapped");
    expect(deriveInvestigationPaths(artifact, subject).coverage).toBe("partial");
    const otherId = "22222222-2222-4222-8222-222222222222";
    const partial = deriveInvestigationPaths(fixture(Object.values(n), [], [n.vaultDeposit.id]),
      { type: "investigation", id: otherId, findingIds: [findingId, otherId] });
    expect(partial.mapping).toBe("partially-mapped");
    expect(partial.warnings).toContain("finding-partially-mapped");
  });
  it("keeps two exact finding targets and a representative cyclic graph bounded", () => {
    const n = basic(), extra = Array.from({ length: 220 }, (_, i) => fn(n.vault, `step${i}()`, 100 + i));
    const edges = extra.map((item, i) => edge("calls", item, extra[(i + 1) % extra.length], 100 + i));
    edges.push(edge("calls", n.deposit, extra[0], 5));
    const artifact = fixture([...Object.values(n), ...extra], edges, [extra[0].id, extra[1].id]);
    const started = Date.now(), result = deriveInvestigationPaths(artifact, subject);
    expect(result.targetNodeIds).toHaveLength(2);
    expect(result.paths.length).toBeLessThanOrEqual(INVESTIGATION_PATH_LIMITS.paths);
    expect(result.paths.every((path) => path.nodeIds.length <= INVESTIGATION_PATH_LIMITS.steps)).toBe(true);
    expect(Date.now() - started).toBeLessThan(4000);
    expect(deriveInvestigationPaths(artifact, subject)).toEqual(result);
  });
  it("treats hostile labels as data and retains lifecycle-independent refs", () => {
    const n = basic(), hostile = fn(n.vault, "f<script>()", 22);
    const result = deriveInvestigationPaths(fixture([...Object.values(n), hostile], [], [hostile.id]), subject);
    expect(result.paths[0].steps[0].label).toBe("f<script>()");
    expect(JSON.stringify(result)).not.toContain("<a href=");
    expect(result.subject).toEqual(subject);
  });
  it("reserves exact C1/D1 overlay attachment without changing static paths", () => {
    const n = basic(), result = deriveInvestigationPaths(fixture(Object.values(n), [], [n.vaultDeposit.id]), subject);
    const ref = { kind: "impact-trace" as const, executionId: findingId, artifactId: findingId,
      pathId: result.paths[0].id, nodeId: n.vaultDeposit.id, operationId: null };
    validateInvestigationPathOverlayReferences(result, [ref]);
    expect(() => validateInvestigationPathOverlayReferences(result, [{ ...ref, nodeId: n.token.id }])).toThrow();
    expect(result.runtimeOverlay).toEqual({ executionTrace: "not-attached", stateDiff: "not-attached" });
  });
});
