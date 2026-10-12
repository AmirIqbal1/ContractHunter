import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import type { ProtocolGraphNode, ProtocolGraphEdge, StaticProtocolGraphArtifact } from "@contracthunter/core";
import { contractExplorerView } from "./contract-explorer";
import { ContractFunctions, filterContractFunctions } from "@/components/contract-functions";

const unit = "src/core/Vault.sol";
const at = (sourceUnitName: string, line: number) => ({ sourceUnitName, startLine: line, endLine: line,
  startColumn: 0, endColumn: 10, startByte: line, endByte: line + 10 });
const evidence = (sourceUnitName: string) => [{ origin: "compiler" as const, producerVersion: "0.8.36",
  source: at(sourceUnitName, 1), referenceId: null }];
const cls = { effective: "core" as const, automatic: "core" as const, automaticOrigin: "path-pattern" as const,
  reasons: ["explicit-source-root"], override: null };
function fixture(many = 0) {
  const contract = (id: string, name: string, source: string, traits: string[] = []) => ({
    id, key: id, name, kind: "contract", qualifiedName: `${source}:${name}`, contractKind: "contract",
    repositoryClassification: cls, source: at(source, 1), evidence: evidence(source),
    characteristics: traits.map((kind) => ({ kind, evidence: evidence(source) })) });
  const fn = (id: string, name: string, signature: string, contractId: string, line: number,
    visibility: string, traits: string[] = []) => ({ id, key: id, kind: "function", name, signature, contractId,
      visibility, mutability: "nonpayable", modifiers: id === "withdraw" ? ["onlyOwner"] : [],
      entryPoint: visibility === "public" || visibility === "external" ? "yes" : "no", source: at(unit, line),
      evidence: evidence(unit), characteristics: traits.map((kind) => ({ kind, evidence: evidence(unit) })) });
  const vault = contract("vault", "Vault", unit), router = contract("router", "Router", "src/Router.sol");
  const token = contract("token", "Token", "src/Token.sol");
  const proxy = contract("proxy", "VaultProxy", "src/VaultProxy.sol", ["proxy", "upgradeable"]);
  const delegateOnly = contract("dispatcher", "Dispatcher", "src/Dispatcher.sol", ["delegatecall"]);
  const role = { id: "role", kind: "role", name: "owner", key: "role", identityState: "known",
    representedContractId: "vault", source: at(unit, 2), evidence: evidence(unit), characteristics: [] };
  const funcs = [fn("deposit", "deposit", "deposit()", "vault", 10, "external"),
    fn("withdraw", "withdraw", "withdraw()", "vault", 20, "public", ["token-transfer"]),
    fn("internal", "_account", "_account()", "vault", 30, "internal"),
    fn("fooA", "foo", "foo(uint256)", "vault", 40, "external"),
    fn("fooB", "foo", "foo(address)", "vault", 50, "external"),
    fn("routerDeposit", "deposit", "deposit()", "router", 12, "external"),
    fn("transfer", "transfer", "transfer(address,uint256)", "token", 5, "external"),
    ...Array.from({ length: many }, (_, i) => fn(`extra${i}`, `extra${i}`, `extra${i}()`, "vault", 100 + i, "internal"))];
  const edge = (id: string, kind: string, from: string, to: string, fromFunctionId: string | null,
    toFunctionId: string | null): ProtocolGraphEdge => ({ id, key: id, kind, from, to, fromFunctionId,
      toFunctionId, origin: "static", reasons: ["compiler-reference"], source: at(unit, 25),
      evidence: evidence(unit) }) as ProtocolGraphEdge;
  const nodes = [vault, router, token, proxy, delegateOnly, role, ...funcs] as ProtocolGraphNode[];
  const edges = [edge("router-call", "calls", "routerDeposit", "deposit", "routerDeposit", "deposit"),
    edge("token-call", "external-call", "withdraw", "transfer", "withdraw", "transfer"),
    edge("internal-call", "calls", "deposit", "internal", "deposit", "internal"),
    edge("owner-control", "controls", "role", "withdraw", null, "withdraw"),
    edge("proxy-upgrade", "upgrades", "proxy", "vault", null, null),
    edge("delegate-only", "delegates", "dispatcher", "router", null, null)];
  const artifact = { schema: "contracthunter-static-protocol-graph-v1", repositoryMapId: "rm:" + "a".repeat(64),
    graph: { schema: "contracthunter-protocol-graph-v1", id: "pg:" + "b".repeat(64), scanId: "scan-one",
      resolvedCommit: "a".repeat(40), extractorVersion: "fixture", producers: [], sourceUnits: [], nodes,
      edges, classifications: [], warnings: [] },
    functionFacts: [{ functionId: "withdraw", stateReads: [{ variable: "balances", contractId: "vault",
      declarationId: 7, source: at(unit, 22) }], stateWrites: [], tokenTransferLike: true,
      nativeValueTransfer: false, modifierInvocations: [], lowLevelCalls: [] }],
    findingLinks: [{ findingId: "11111111-1111-4111-8111-111111111111", nodeId: "withdraw" }],
    unresolved: [{ callerFunctionId: "withdraw", source: at(unit, 24), kind: "external-call",
      reason: "dynamic-target", expression: "call" }], summary: {} as never, contentSha256: "c".repeat(64) } as StaticProtocolGraphArtifact;
  const findings = [{ id: "11111111-1111-4111-8111-111111111111", title: "Exact finding", source: "slither",
    detectorId: "reentrancy", status: "open", filePath: unit, startLine: 20 },
    { id: "22222222-2222-4222-8222-222222222222", title: "Wrong contract", source: "slither",
      detectorId: null, status: "open", filePath: "src/Router.sol", startLine: 12 }];
  return { artifact, findings };
}

describe("Contract Explorer read model", () => {
  it("builds a bounded factual Vault overview and exact entry point list", () => {
    const { artifact, findings } = fixture(), view = contractExplorerView(artifact, "vault", findings)!;
    expect(view.contract.repositoryClassification.effective).toBe("core");
    expect(view.contract.source?.sourceUnitName).toBe(unit);
    expect(view.counts.entryPoints).toBe(4);
    expect(view.functions[0].node.entryPoint).toBe("yes");
    expect(view.functions.at(-1)?.node.signature).toBe("_account()");
    expect(view.cues).toContain("4 externally callable entry points");
  });
  it("resolves caller and callee function identity without inventing targets", () => {
    const { artifact } = fixture(), view = contractExplorerView(artifact, "vault", [])!;
    expect(view.incoming[0]).toMatchObject({ fromFunction: { signature: "deposit()", contractId: "router" },
      toFunction: { signature: "deposit()", contractId: "vault" } });
    expect(view.outgoing[0]).toMatchObject({ toFunction: { signature: "transfer(address,uint256)" } });
    expect(view.localCalls[0].toFunction?.signature).toBe("_account()");
    expect(view.unresolved[0]).toMatchObject({ caller: { signature: "withdraw()" }, reason: "dynamic-target" });
  });
  it("keeps overloaded functions distinct and preserves canonical source locations", () => {
    const view = contractExplorerView(fixture().artifact, "vault", [])!;
    expect(view.functions.filter((item) => item.node.name === "foo").map((item) => item.node.signature)).toEqual(["foo(address)", "foo(uint256)"]);
    expect(view.functions.find((item) => item.node.id === "fooA")?.node.source?.startLine).toBe(40);
    expect(view.outgoing[0].edge.source?.sourceUnitName).toBe(unit);
  });
  it("keeps proven proxy, delegatecall-only and control identities separate", () => {
    const { artifact } = fixture();
    expect(contractExplorerView(artifact, "proxy", [])?.proxy.map((item) => item.edge.kind)).toEqual(["upgrades"]);
    expect(contractExplorerView(artifact, "dispatcher", [])?.proxy).toEqual([]);
    expect(contractExplorerView(artifact, "vault", [])?.control[0].toFunction?.modifiers).toEqual(["onlyOwner"]);
  });
  it("attaches only exact finding IDs and rejects another scan's contract ID", () => {
    const { artifact, findings } = fixture(), view = contractExplorerView(artifact, "vault", findings)!;
    expect(view.findings.map((item) => item.title)).toEqual(["Exact finding"]);
    expect(view.functions.find((item) => item.node.id === "withdraw")?.findings).toHaveLength(1);
    expect(contractExplorerView(artifact, "pn:" + "f".repeat(64), findings)).toBeNull();
    expect(contractExplorerView(artifact, "withdraw", findings)).toBeNull();
  });
  it("keeps large function lists filterable and renders hostile labels as escaped text", () => {
    const { artifact, findings } = fixture(500);
    const view = contractExplorerView(artifact, "vault", findings)!;
    expect(view.functions).toHaveLength(505);
    expect(filterContractFunctions(view.functions, "foo(address)", "all")).toHaveLength(1);
    expect(filterContractFunctions(view.functions, "", "findings")).toHaveLength(1);
    const hostile = { ...view.functions[0], node: { ...view.functions[0].node, signature: '<script>alert("x")</script>' } };
    const html = renderToStaticMarkup(<ContractFunctions items={[hostile]} scanId="scan-one" />);
    expect(html).toContain("&lt;script&gt;");
    expect(html).not.toContain('<script>alert("x")</script>');
    const fullHtml = renderToStaticMarkup(<ContractFunctions items={view.functions} scanId="scan-one" />);
    expect(fullHtml.match(/id="function-/g)?.length).toBe(60);
    expect(fullHtml).toContain("src/core/Vault.sol");
  });
});
