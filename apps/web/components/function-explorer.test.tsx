import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import type { FunctionExplorerModel, FunctionOperation } from "@contracthunter/core";
import type { FunctionExplorerResponse } from "@/lib/function-explorer-server";
import { filterFunctionOperations, functionHref, functionSourceHref, FunctionExplorer } from "./function-explorer";

const scanId = "00000000-0000-4000-8000-000000000001", contractId = `pn:${"a".repeat(64)}`;
const functionId = `pn:${"b".repeat(64)}`, oracleId = `pn:${"c".repeat(64)}`, oracleFnId = `pn:${"d".repeat(64)}`;
const source = (start: number) => ({ sourceUnitName: "src/core/Vault.sol", startLine: start,
  endLine: start, startColumn: 0, endColumn: 15, startByte: start * 10, endByte: start * 10 + 15 });
const op = (kind: FunctionOperation["kind"], ordinal: number, detail: string | null = null,
  extras: Partial<FunctionOperation> = {}): FunctionOperation => ({ id: `fo:${ordinal.toString(16).padStart(64, "0")}`,
  kind, identityKey: `fixture:${ordinal}`, source: source(11 + ordinal), ordinal, detail,
  detailSha256: null, detailTruncated: false, targetFunctionId: null, targetContractId: null,
  resolution: "not-applicable", origin: "compiler-ast", ...extras });
function fixture(): FunctionExplorerResponse {
  const operations: FunctionOperation[] = [op("modifier", 0, "onlyOwner"), op("condition", 1, "amount > 0"),
    op("state-read", 2, "balances"), op("internal-call", 3, "_calculateShares()", {
      targetFunctionId: `pn:${"e".repeat(64)}`, targetContractId: contractId, resolution: "resolved" }),
    op("external-call", 4, "getPrice()", { targetFunctionId: oracleFnId, targetContractId: oracleId,
      resolution: "resolved" }), op("state-write", 5, "balances"),
    op("external-call", 6, "call", { resolution: "unresolved" }),
    op("delegatecall", 7, "delegatecall", { resolution: "unresolved" }),
    op("token-transfer-like", 8, null, { resolution: "unresolved" }),
    op("native-transfer", 9, null, { resolution: "unresolved" }), op("event-emission", 10, "Withdrawn"),
    op("assembly", 11, "inline assembly"), op("branch", 12, "if"), op("loop", 13, "while"),
    op("try-catch", 14, "try"), op("revert", 15, "BadAmount")];
  const relationship = (edgeId: string, fromFunctionId: string | null, toFunctionId: string | null) => ({
    edgeId: `pe:${edgeId.repeat(64)}`, kind: "calls" as const, fromFunctionId, toFunctionId,
    source: source(16), targetStatus: "resolved" as const, evidenceOrigins: ["compiler"] });
  const model = { schema: "contracthunter-function-explorer-v1", scanId, graphId: `pg:${"f".repeat(64)}`,
    contractId, functionId, contract: { name: "Vault", kind: "contract", source: source(1) },
    function: { name: "withdraw", signature: "withdraw(uint256)", visibility: "external",
      mutability: "nonpayable", entryPoint: "yes", source: source(10) },
    analysisStatus: "partial", sourceOrderOnly: true, cfgStatus: "unavailable",
    modifiers: [{ name: "onlyOwner", declarationId: 1, source: source(11) }], operations,
    callers: [relationship("1", `pn:${"9".repeat(64)}`, functionId)],
    callees: [relationship("2", functionId, oracleFnId)],
    controls: [relationship("3", null, functionId)], stateReads: [], stateWrites: [],
    findings: ["11111111-1111-4111-8111-111111111111"],
    reviewCues: ["state-write-after-external-call-source-order", "delegatecall-present", "unresolved-external-call",
      "finding-linked", "privileged"],
    summary: { modifiers: 1, conditions: 1, stateReads: 1, stateWrites: 1, internalCalls: 1,
      externalCalls: 2, unresolvedCalls: 2, lowLevelCalls: 1, delegatecalls: 1, tokenTransfers: 1,
      nativeTransfers: 1, eventEmissions: 1, findings: 1 }, provenance: [{ origin: "compiler", version: "0.8.24" }],
    warnings: ["source-order-only", "state-access-sites-collapsed"], contentSha256: "f".repeat(64),
  } as FunctionExplorerModel;
  return { model, sourcePreview: "function withdraw(uint256 amount) external {\nrequire(amount > 0);\n}",
    sourcePreviewTruncated: false, provenProxy: false,
    relatedNodes: [{ id: contractId, kind: "contract", name: "Vault", signature: null, contractId: null },
      { id: oracleId, kind: "contract", name: "Oracle", signature: null, contractId: null },
      { id: oracleFnId, kind: "function", name: "getPrice", signature: "getPrice()", contractId: oracleId },
      { id: `pn:${"e".repeat(64)}`, kind: "function", name: "_calculateShares", signature: "_calculateShares()", contractId },
      { id: `pn:${"9".repeat(64)}`, kind: "function", name: "deposit", signature: "deposit()", contractId }],
    controls: [{ roleId: `pn:${"8".repeat(64)}`, roleName: "owner", edgeId: `pe:${"3".repeat(64)}` }] };
}
const finding = { id: "11111111-1111-4111-8111-111111111111", title: "Exact finding", source: "slither",
  detectorId: "reentrancy", status: "open" };
const render = (data = fixture(), options: { initialOperation?: string; initialMode?: string; initialFilter?: string } = {}) =>
  renderToStaticMarkup(<FunctionExplorer data={data} findings={[finding]} repositoryName="Fixture" {...options} />);

describe("visual Function Explorer", () => {
  it("renders exact identity, ordered source cards, summary, links and an unmistakable source-order warning", () => {
    const html = render();
    expect(html).toContain("Vault.withdraw(uint256)");
    expect(html).toContain("SOURCE-ORDER VIEW");
    expect(html).toContain("not an execution trace or a control-flow graph");
    expect(html).toContain("amount &gt; 0");
    expect(html).toContain("state write");
    expect(html).toContain("src%2Fcore%2FVault.sol");
    expect(html).toContain("Showing 16 of 16 operations");
    expect(html).toContain("Partial analysis");
    expect(html).toContain("External entry point");
  });
  it("links resolved internal and external functions by canonical IDs and exposes unresolved targets", () => {
    const html = render();
    expect(html).toContain(functionHref(scanId, contractId, `pn:${"e".repeat(64)}`));
    expect(html).toContain(functionHref(scanId, oracleId, oracleFnId));
    expect(html).toContain("Show target on Protocol Map");
    expect(html).toContain("External call — target unresolved");
    expect(html).toContain("Target not statically resolved");
  });
  it("shows review cues, delegatecall without proxy claim, transfer types, permissions and exact finding", () => {
    const html = render();
    expect(html).toContain("State write after external call in source order");
    expect(html).not.toContain("Reentrancy vulnerability");
    expect(html).toContain("delegatecall");
    expect(html).toContain("Token transfer-like operation");
    expect(html).toContain("native transfer");
    expect(html).toContain("Proven control relationship");
    expect(html).toContain("Exact finding");
    expect(html).toContain(`/findings/${finding.id}`);
    expect(html).toContain("No operation-level source mapping is claimed");
    const selected = render(fixture(), { initialOperation: fixture().model.operations[7].id });
    expect(selected).toContain("No proxy relationship proven from current static evidence");
  });
  it("keeps overload routes distinct and filters without mutating the source operations", () => {
    expect(functionHref(scanId, contractId, functionId)).not.toBe(functionHref(scanId, contractId, oracleFnId));
    const data = fixture(), original = JSON.stringify(data.model.operations);
    expect(filterFunctionOperations(data.model.operations, "calls", "getPrice", false)).toHaveLength(1);
    expect(filterFunctionOperations(data.model.operations, "state", "", false).map((item) => item.kind)).toEqual(["state-read", "state-write"]);
    expect(filterFunctionOperations(data.model.operations, "findings", "", false)).toHaveLength(0);
    expect(JSON.stringify(data.model.operations)).toBe(original);
    expect(functionSourceHref(scanId, source(12))).toContain("unit=src%2Fcore%2FVault.sol&line=12");
  });
  it("bounds large functions and renders hostile content as escaped text with keyboard controls", () => {
    const data = fixture();
    data.model.operations = Array.from({ length: 140 }, (_, index) => op("state-write", index, '<script>alert("x")</script>'));
    const html = render(data);
    expect(html).toContain("Showing 80 of 140 operations");
    expect(html.match(/class="fe-step"/g)?.length).toBe(80);
    expect(html).toContain("&lt;script&gt;");
    expect(html).not.toContain('<script>alert("x")</script>');
    expect(html).toContain("Show all 140 matching operations");
    expect(html).toContain("aria-label=\"Display mode\"");
    expect(html).toContain("aria-label=\"Select state write at line");
    expect(html).toContain("aria-label=\"Selected operation details\"");
  });
});
