import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { InvestigationPathResult, ProtocolSourceLocation } from "@contracthunter/core";
import { InvestigationPathView, relationshipLabel } from "./investigation-path-view";
import type { PathNodeDetail } from "@/lib/investigation-path-view";

const scan = "00000000-0000-4000-8000-000000000001", finding = "11111111-1111-4111-8111-111111111111";
const contractA = `pn:${"a".repeat(64)}`, contractB = `pn:${"b".repeat(64)}`;
const router = `pn:${"c".repeat(64)}`, helper = `pn:${"d".repeat(64)}`, target = `pn:${"e".repeat(64)}`;
const external = `pn:${"f".repeat(64)}`, edgeA = `pe:${"1".repeat(64)}`, edgeB = `pe:${"2".repeat(64)}`;
const source = (unit: string, line: number): ProtocolSourceLocation => ({ sourceUnitName: unit, startLine: line,
  endLine: line, startColumn: 0, endColumn: 3, startByte: line * 10, endByte: line * 10 + 3 });
const nodes: PathNodeDetail[] = [
  { id: router, kind: "function", name: "deposit", contractId: contractA, contractName: "Router", entryPoint: true,
    source: source("src/Router.sol", 5), reviewCues: ["externally-callable"] },
  { id: helper, kind: "function", name: "_forward", contractId: contractA, contractName: "Router", entryPoint: false,
    source: source("src/Router.sol", 10), reviewCues: [] },
  { id: target, kind: "function", name: "deposit", contractId: contractB, contractName: "Vault", entryPoint: false,
    source: source("src/Vault.sol", 20), reviewCues: ["unresolved-external-call", "token-transfer"] },
  { id: external, kind: "external-actor", name: "runtime target", contractId: null, contractName: null,
    entryPoint: false, source: null, reviewCues: [] },
];
type Path = InvestigationPathResult["paths"][number];
function step(id: string, ordinal: number, via: string | null, relationship: string | null,
  uncertain: "resolved" | "unresolved-target" = "resolved"): Path["steps"][number] {
  return { ordinal, nodeId: id, nodeKind: id === external ? "external-actor" : "function",
    label: id === target ? "deposit(uint256)" : id === router ? "deposit()" : id === helper ? "_forward()" : "runtime target",
    viaEdgeId: via, relationship, explanationKey: relationship === "external-call" ? "external-call" : "review-cue",
    reasons: ["typed-contract-member-call"], source: id === external ? null : nodes.find((node) => node.id === id)!.source,
    provenance: [{ origin: "compiler", producerVersion: "fixture", source: nodes.find((node) => node.id === id)?.source ?? null,
      referenceId: "ast:42" }], findingIds: id === target ? [finding] : [], uncertainty: uncertain };
}
function path(id: string, kind: Path["kind"], ids: string[], edges: string[], completeness: Path["completeness"] = "complete-within-bounds"): Path {
  return { id, kind, targetNodeId: target, nodeIds: ids, edgeIds: edges,
    steps: ids.map((nodeId, i) => step(nodeId, i, edges[i - 1] ?? null, i ? edges[i - 1] === edgeB ? "external-call" : "calls" : null,
      nodeId === external ? "unresolved-target" : "resolved")), completeness,
    securityViews: kind === "oracle-context" ? ["oracle-flow"] : ["findings", "external-calls"] };
}
const pathA = path(`ip:${"a".repeat(64)}`, "caller-chain", [router, helper, target], [edgeA, edgeB]);
const pathB = path(`ip:${"b".repeat(64)}`, "local-context", [target], []);
function result(paths: Path[] = [pathB, pathA]): InvestigationPathResult {
  return { schema: "contracthunter-investigation-path-v1", derivationVersion: "contracthunter-investigation-path-deriver-v1",
    scanId: scan, protocolGraphId: `pg:${"a".repeat(64)}`, graphContentSha256: "a".repeat(64),
    subject: { type: "finding", id: finding, findingIds: [finding] }, mapping: "mapped", coverage: "complete-within-bounds",
    targetNodeIds: [target], paths, operations: [{ functionId: target, operationId: `fo:${"a".repeat(64)}`,
      kind: "token-transfer-like", source: source("src/Vault.sol", 23), resolution: "unresolved" }],
    warnings: ["static-only"], runtimeOverlay: { executionTrace: "not-attached", stateDiff: "not-attached" },
    contentSha256: "b".repeat(64) };
}
const render = (value = result(), props: Partial<Parameters<typeof InvestigationPathView>[0]> = {}) =>
  renderToStaticMarkup(<InvestigationPathView result={value} nodes={nodes} title="Unchecked call" status="candidate"
    confidence={null} repositoryName="Fixture" {...props} />);

describe("static Investigation Path UI", () => {
  it("renders a bounded entry chain, exact finding marker, source and Explorer links", () => {
    const html = render();
    expect(html).toContain("STATIC INVESTIGATION PATH"); expect(html).toContain("EXTERNAL ENTRY POINT");
    expect(html).toContain("FINDING ATTACHED HERE"); expect(html).toContain("STATIC");
    expect(html).toContain("/source?unit=src%2FVault.sol&amp;line=20");
    expect(html).toContain(`/contracts/${encodeURIComponent(contractB)}/functions/${encodeURIComponent(target)}`);
    expect(html).toContain(`/findings/${finding}`);
    expect(html).toContain("does not prove that a path executes or is exploitable");
    expect(html).not.toMatch(/attacker profit|protocol loss|most exploitable/i);
  });
  it("keeps server path order in selector and exposes a source-backed connection explanation", () => {
    const html = render(result(), { initialPathId: pathA.id, initialEdgeId: edgeB, initialMode: "researcher" });
    expect(html.indexOf(`value="${pathB.id}"`)).toBeLessThan(html.indexOf(`value="${pathA.id}"`));
    expect(html).toContain("WHY THIS CONNECTION EXISTS"); expect(html).toContain("EXTERNAL CALL");
    expect(html).toContain("View connection source"); expect(html).toContain(edgeB);
    expect(html).toContain("ast:42"); expect(html).toContain("Derivation:");
  });
  it("renders unresolved as terminal and truncated coverage as a bounded warning", () => {
    const unresolved = path(`ip:${"c".repeat(64)}`, "local-context", [target, external], [edgeB], "unresolved");
    const value = result([unresolved]); value.coverage = "truncated"; value.warnings = ["path-limit-reached", "unresolved-call-target", "static-only"];
    const html = render(value);
    expect(html).toContain("TARGET UNRESOLVED"); expect(html).toContain("No target continuation is established");
    expect(html).toContain("PATH TRUNCATED"); expect(html).not.toContain("complete path");
  });
  it("uses only exact evidence for contextual labels and map/security navigation", () => {
    const oracle = path(`ip:${"d".repeat(64)}`, "oracle-context", [target, helper], [edgeA]);
    const html = render(result([oracle]));
    expect(html).toContain("Oracle dependency"); expect(html).toContain("Open Oracle Flow");
    expect(html).toContain(`node=${encodeURIComponent(contractB)}`);
    expect(relationshipLabel("calls", nodes[0], nodes[1])).toBe("INTERNAL CALL");
    expect(relationshipLabel("controls")).toBe("CONTROL"); expect(relationshipLabel("delegates")).toBe("DELEGATECALL");
  });
  it("shows asset, permission and upgrade context only when those path kinds are returned", () => {
    const asset = path(`ip:${"d".repeat(64)}`, "asset-operation-context", [target], []);
    asset.securityViews = ["money-flow"];
    const permission = path(`ip:${"e".repeat(64)}`, "privilege-context", [helper, target], [edgeA]);
    permission.steps[1].relationship = "controls"; permission.securityViews = ["permissions"];
    const upgrade = path(`ip:${"f".repeat(64)}`, "upgrade-context", [target, helper], [edgeB]);
    upgrade.steps[1].relationship = "upgrades"; upgrade.securityViews = ["upgradeability"];
    const value = result([asset, permission, upgrade]);
    expect(render(value, { initialPathId: asset.id })).toContain("Open Money Flow");
    const permissionHtml = render(value, { initialPathId: permission.id });
    expect(permissionHtml).toContain("CONTROL · Why this connection?"); expect(permissionHtml).toContain("Open Permissions");
    expect(permissionHtml).not.toContain("bypass");
    const upgradeHtml = render(value, { initialPathId: upgrade.id });
    expect(upgradeHtml).toContain("UPGRADE RELATIONSHIP · Why this connection?");
    expect(upgradeHtml).toContain("Open Upgradeability");
    expect(upgradeHtml).not.toContain("proven proxy");
  });
  it("keeps modes presentational, and escapes hostile labels", () => {
    const value = result([pathB]); value.paths[0].steps[0].label = "<script>alert(1)</script>";
    const beginner = render(value), researcher = render(value, { initialMode: "researcher" });
    expect(beginner).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(beginner).not.toContain("<script>");
    expect(beginner).toContain("Why this step matters"); expect(researcher).toContain("Node:");
    expect(beginner).toContain(`value="${pathB.id}"`); expect(researcher).toContain(`value="${pathB.id}"`);
  });
  it("shows unmapped fallback without a fabricated path or authority action", () => {
    const value = result([]); value.mapping = "unmapped"; value.coverage = "partial"; value.targetNodeIds = [];
    const html = render(value);
    expect(html).toContain("Finding is not mapped to a canonical ProtocolGraph target");
    expect(html).toContain("No static Investigation Path could be derived");
    expect(html).not.toContain("FINDING ATTACHED HERE"); expect(html).not.toContain("Open in Impact Lab");
  });
});
