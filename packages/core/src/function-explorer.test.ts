import { describe, expect, it } from "vitest";
import { randomUUID } from "node:crypto";
import { contractGraphKey, functionGraphKey, protocolNodeId, protocolEdgeId, protocolGraphId,
  type ProtocolGraph, type ProtocolGraphNode, type ProtocolSourceLocation } from "./protocol-graph";
import type { StaticProtocolGraphArtifact } from "./static-protocol-graph";
import { buildFunctionExplorerModel, FUNCTION_EXPLORER_LIMITS, validateFunctionExplorerModel,
  validateFunctionOverlayReferences } from "./function-explorer";

const scanId = "00000000-0000-4000-8000-000000000001";
const location = (unit: string, start: number): ProtocolSourceLocation => ({ sourceUnitName: unit,
  startByte: start, endByte: start + 5, startLine: start + 1, endLine: start + 1,
  startColumn: 0, endColumn: 5 });
const evidence = (source: ProtocolSourceLocation) => [{ origin: "compiler" as const,
  producerVersion: "0.8.24", source, referenceId: null }];
const classification = { effective: "core" as const, automatic: "core" as const,
  automaticOrigin: "path-pattern" as const, reasons: ["contracts-root"], override: null };
function fixture() {
  const unit = "src/Vault.sol", oracleUnit = "src/Oracle.sol";
  const vaultKey = contractGraphKey(unit, "Vault"), oracleKey = contractGraphKey(oracleUnit, "Oracle");
  const vaultId = protocolNodeId(scanId, "contract", vaultKey), oracleId = protocolNodeId(scanId, "contract", oracleKey);
  const vault: Extract<ProtocolGraphNode, { kind: "contract" }> = { kind: "contract", id: vaultId, key: vaultKey,
    name: "Vault", qualifiedName: `${unit}:Vault`, contractKind: "contract", abstract: false,
    repositoryClassification: classification, source: location(unit, 0), evidence: evidence(location(unit, 0)), characteristics: [] };
  const oracle: Extract<ProtocolGraphNode, { kind: "contract" }> = { ...vault, id: oracleId, key: oracleKey,
    name: "Oracle", qualifiedName: `${oracleUnit}:Oracle`, source: location(oracleUnit, 0) };
  const makeFunction = (name: string, signature: string, start: number, owner = vault): Extract<ProtocolGraphNode, { kind: "function" }> => {
    const key = functionGraphKey(owner.key, signature), source = location(owner.source!.sourceUnitName, start);
    return { kind: "function", id: protocolNodeId(scanId, "function", key), key, name, signature,
      contractId: owner.id, source, evidence: evidence(source), characteristics: [], visibility: "external",
      mutability: "nonpayable", modifiers: [], entryPoint: "yes" };
  };
  const withdraw = makeFunction("withdraw", "withdraw(uint256)", 10);
  const calc = makeFunction("_calculateShares", "_calculateShares()", 20);
  const getPrice = makeFunction("getPrice", "getPrice()", 30, oracle);
  const edge = (kind: "calls" | "external-call", from: typeof withdraw, to: typeof withdraw, at: number) => {
    const source = location(unit, at), key = `${from.id}:${to.id}:${at}:${kind}`;
    return { kind, id: protocolEdgeId(scanId, kind, from.id, to.id, key), key, from: from.id, to: to.id,
      origin: "static" as const, reasons: ["compiler-reference"], source, fromFunctionId: from.id,
      toFunctionId: to.id, evidence: evidence(source) };
  };
  const graph: ProtocolGraph = { schema: "contracthunter-protocol-graph-v1",
    id: protocolGraphId(scanId, "a".repeat(40), "fixture-v1", [{ origin: "compiler", version: "0.8.24" }]),
    scanId, resolvedCommit: "a".repeat(40), extractorVersion: "fixture-v1",
    producers: [{ origin: "compiler", version: "0.8.24" }],
    sourceUnits: [unit, oracleUnit].map((sourceUnitName) => ({ sourceUnitName, snapshotSourceKey: sourceUnitName,
      rawSha256: "b".repeat(64), byteLength: 1_000, identityStatus: "authoritative" as const })),
    nodes: [vault, oracle, withdraw, calc, getPrice],
    edges: [edge("calls", withdraw, calc, 40), edge("external-call", calc, getPrice, 50)],
    classifications: [], warnings: [] };
  const artifact = { graph, repositoryMapId: `rm:${"a".repeat(64)}`, schema: "contracthunter-static-protocol-graph-v1",
    functionFacts: [{ functionId: withdraw.id, stateReads: [{ variable: "balances", contractId: vault.id,
      declarationId: 9, source: location(unit, 60) }], stateWrites: [{ variable: "balances", contractId: vault.id,
      declarationId: 9, source: location(unit, 60) }], tokenTransferLike: false, nativeValueTransfer: false,
      modifierInvocations: [{ name: "onlyOwner", declarationId: 8, source: location(unit, 12) }], lowLevelCalls: [] }],
    functionSyntax: [{ functionId: withdraw.id, truncated: false, operations: [{ kind: "condition", source: location(unit, 25),
      astNodeId: 100, label: "require", expressionSha256: "c".repeat(64), excerpt: "amount > 0",
      excerptTruncated: false }] }], findingLinks: [{ findingId: randomUUID(), nodeId: withdraw.id }],
    unresolved: [], summary: {} as StaticProtocolGraphArtifact["summary"], contentSha256: "d".repeat(64),
  } as StaticProtocolGraphArtifact;
  return { artifact, vault, withdraw, calc, getPrice, edge };
}

describe("Function Explorer model", () => {
  it("binds exact function, source, modifier, condition, state, calls and finding", () => {
    const f = fixture(), model = buildFunctionExplorerModel(f.artifact, f.vault.id, f.withdraw.id)!;
    expect(model.schema).toBe("contracthunter-function-explorer-v1");
    expect(model.sourceOrderOnly).toBe(true); expect(model.cfgStatus).toBe("unavailable");
    expect(model.function).toMatchObject({ signature: "withdraw(uint256)", entryPoint: "yes" });
    expect(model.modifiers[0]?.name).toBe("onlyOwner");
    expect(model.operations.map((item) => item.kind)).toContain("condition");
    expect(model.operations.map((item) => item.kind)).toContain("state-write");
    expect(model.callees[0]?.toFunctionId).toBe(f.calc.id);
    expect(model.findings).toHaveLength(1);
    expect(model.operations.every((item) => item.source.sourceUnitName === "src/Vault.sol")).toBe(true);
    expect(validateFunctionExplorerModel(model)).toEqual(model);
    expect(buildFunctionExplorerModel(f.artifact, f.vault.id, f.withdraw.id)).toEqual(model);
    expect(buildFunctionExplorerModel(f.artifact, f.calc.id, f.withdraw.id)).toBeNull();
    expect(buildFunctionExplorerModel(f.artifact, f.getPrice.contractId, f.withdraw.id)).toBeNull();
  });

  it("keeps resolved external calls, overloads and source-order cues distinct", () => {
    const f = fixture(), calc = buildFunctionExplorerModel(f.artifact, f.vault.id, f.calc.id)!;
    expect(calc.operations).toContainEqual(expect.objectContaining({ kind: "external-call", targetFunctionId: f.getPrice.id }));
    expect(calc.callers[0]?.fromFunctionId).toBe(f.withdraw.id);
    const overloadKey = functionGraphKey(f.vault.key, "withdraw(address,uint256)");
    const overloadId = protocolNodeId(scanId, "function", overloadKey);
    expect(overloadId).not.toBe(f.withdraw.id);
    const before = buildFunctionExplorerModel(f.artifact, f.vault.id, f.withdraw.id)!;
    expect(before.reviewCues).not.toContain("state-write-before-external-call-source-order");
    f.artifact.graph.edges.push(f.edge("external-call", f.withdraw, f.getPrice, 55));
    const after = buildFunctionExplorerModel(f.artifact, f.vault.id, f.withdraw.id)!;
    expect(after.reviewCues).toContain("state-write-after-external-call-source-order");
    f.artifact.graph.edges.push(f.edge("external-call", f.withdraw, f.getPrice, 70));
    const both = buildFunctionExplorerModel(f.artifact, f.vault.id, f.withdraw.id)!;
    expect(both.callees).toHaveLength(3);
    expect(both.reviewCues).toContain("state-write-before-external-call-source-order");
  });

  it("marks legacy/partial artifacts, enforces limits and rejects tampering", () => {
    const f = fixture(); delete f.artifact.functionSyntax;
    const legacy = buildFunctionExplorerModel(f.artifact, f.vault.id, f.withdraw.id)!;
    expect(legacy.analysisStatus).toBe("partial");
    expect(legacy.warnings).toContain("syntax-facts-unavailable");
    const tampered = structuredClone(legacy); tampered.operations[0]!.detail = "changed";
    expect(() => validateFunctionExplorerModel(tampered)).toThrow("function_explorer_integrity_invalid");
    expect(() => validateFunctionOverlayReferences(legacy, [{ functionId: legacy.functionId,
      operationId: "fo:bad", kind: "impact-trace", executionId: randomUUID(), artifactId: randomUUID() }])).toThrow();
    f.artifact.functionSyntax = [{ functionId: f.withdraw.id, truncated: true,
      operations: Array.from({ length: FUNCTION_EXPLORER_LIMITS.operations + 10 }, (_, index) => ({
        kind: "condition" as const, source: location("src/Vault.sol", index + 100), astNodeId: index + 1,
        label: "require", expressionSha256: "c".repeat(64), excerpt: "<script>alert(1)</script>",
        excerptTruncated: false })) }];
    const large = buildFunctionExplorerModel(f.artifact, f.vault.id, f.withdraw.id)!;
    expect(large.operations).toHaveLength(FUNCTION_EXPLORER_LIMITS.operations);
    expect(large.analysisStatus).toBe("partial");
    expect(large.operations.some((item) => item.detail === "<script>alert(1)</script>")).toBe(true);
  });

  it("retains unresolved delegatecall, transfer-like facts and control separately from callers", () => {
    const f = fixture(), at = location("src/Vault.sol", 80);
    const actorKey = "runtime-target", roleKey = "owner-role";
    const actorId = protocolNodeId(scanId, "external-actor", actorKey);
    const roleId = protocolNodeId(scanId, "role", roleKey);
    f.artifact.graph.nodes.push({ kind: "external-actor", id: actorId, key: actorKey,
      name: "Unresolved external target", source: null, evidence: evidence(at), characteristics: [],
      identityState: "unknown", representedContractId: null });
    f.artifact.graph.nodes.push({ kind: "role", id: roleId, key: roleKey, name: "owner", source: at,
      evidence: evidence(at), characteristics: [], identityState: "known", representedContractId: f.vault.id });
    const delegateKey = "delegate:80", controlKey = "control:90";
    f.artifact.graph.edges.push({ kind: "delegates", id: protocolEdgeId(scanId, "delegates", f.withdraw.id, actorId, delegateKey),
      key: delegateKey, from: f.withdraw.id, to: actorId, origin: "static", reasons: ["low-level-delegatecall"],
      source: at, fromFunctionId: f.withdraw.id, toFunctionId: null, evidence: evidence(at) });
    f.artifact.graph.edges.push({ kind: "controls", id: protocolEdgeId(scanId, "controls", roleId, f.withdraw.id, controlKey),
      key: controlKey, from: roleId, to: f.withdraw.id, origin: "static", reasons: ["msg-sender-owner-guard"],
      source: location("src/Vault.sol", 90), fromFunctionId: null, toFunctionId: f.withdraw.id,
      evidence: evidence(location("src/Vault.sol", 90)) });
    const fn = f.artifact.graph.nodes.find((node) => node.id === f.withdraw.id)!;
    fn.characteristics.push({ kind: "token-transfer", evidence: evidence(location("src/Vault.sol", 95)) },
      { kind: "native-transfer", evidence: evidence(location("src/Vault.sol", 100)) });
    const model = buildFunctionExplorerModel(f.artifact, f.vault.id, f.withdraw.id)!;
    expect(model.operations).toContainEqual(expect.objectContaining({ kind: "delegatecall", resolution: "unresolved" }));
    expect(model.operations.map((item) => item.kind)).toEqual(expect.arrayContaining(["token-transfer-like", "native-transfer"]));
    expect(model.reviewCues).toEqual(expect.arrayContaining(["delegatecall-present", "unresolved-external-call",
      "token-transfer", "native-value-transfer", "privileged"]));
    expect(model.controls).toHaveLength(1);
    expect(model.callers).toHaveLength(0);
    expect(f.vault.characteristics.some((item) => item.kind === "proxy")).toBe(false);
  });
});
