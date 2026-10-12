import { afterEach, describe, expect, it } from "vitest";
import { createHash, randomUUID } from "node:crypto";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { mapRepository } from "./repository-mapper";
import { generateStaticProtocolGraph } from "./static-protocol-graph";

const created: string[] = [], commit = "a".repeat(40);
afterEach(async () => { await Promise.all(created.splice(0).map((root) => rm(root, { recursive: true, force: true }))); });
async function fixture(sources: Record<string, string>) {
  const root = await mkdtemp(path.join(tmpdir(), "ch-static-graph-")); created.push(root);
  const scanId = randomUUID();
  const snapshotFiles = [];
  for (const [sourceKey, source] of Object.entries(sources)) {
    await mkdir(path.dirname(path.join(root, sourceKey)), { recursive: true });
    await writeFile(path.join(root, sourceKey), source);
    const rawBytes = Buffer.from(source);
    snapshotFiles.push({ sourceKey, rawBytes, rawSha256: createHash("sha256").update(rawBytes).digest("hex"), byteLength: rawBytes.length });
  }
  const repositoryMap = await mapRepository({ scanId, resolvedCommit: commit, repositoryPath: root, snapshotFiles });
  return { repositoryMap, snapshotFiles };
}
const src = (text: string, needle: string, nth = 0) => {
  let index = -1; for (let i = 0; i <= nth; i++) index = text.indexOf(needle, index + 1);
  if (index < 0) throw Error(`missing fixture token: ${needle}`);
  return `${Buffer.byteLength(text.slice(0, index))}:${Buffer.byteLength(needle)}:0`;
};
const fn = (text: string, needle: string, id: number, name: string, visibility: string, stateMutability: string,
  parameters: string[] = [], body: object[] = []) => ({ nodeType: "FunctionDefinition", id, kind: "function", name,
    visibility, stateMutability, src: src(text, needle), parameters: { parameters: parameters.map((typeString) => ({ typeDescriptions: { typeString } })) },
    modifiers: [], body: { nodeType: "Block", src: src(text, needle), statements: body } });
const call = (text: string, needle: string, id: number, expression: object, nth = 0) => ({
  nodeType: "FunctionCall", id, src: src(text, needle, nth), expression, arguments: [] });

describe("static ProtocolGraph extraction", () => {
  it("captures bounded source-backed function syntax without claiming CFG", async () => {
    const source = `contract Vault { function withdraw(uint256 amount) external {
      require(amount > 0); if (amount > 1) { emit Used(amount); }
      revert BadAmount();
    } event Used(uint256); error BadAmount(); }`;
    const f = await fixture({ "src/Vault.sol": source });
    const body = [
      { nodeType: "FunctionCall", id: 101, src: src(source, "require(amount > 0)"),
        expression: { nodeType: "Identifier", name: "require" },
        arguments: [{ nodeType: "BinaryOperation", id: 102, src: src(source, "amount > 0") }] },
      { nodeType: "IfStatement", id: 103, src: src(source, "if (amount > 1)"),
        condition: { nodeType: "BinaryOperation", id: 104, src: src(source, "amount > 1") },
        trueBody: { nodeType: "Block", statements: [{ nodeType: "EmitStatement", id: 105,
          src: src(source, "emit Used(amount)"), eventCall: { nodeType: "FunctionCall", id: 106,
            src: src(source, "Used(amount)"), expression: { nodeType: "Identifier", name: "Used" } } }] } },
      { nodeType: "RevertStatement", id: 107, src: src(source, "revert BadAmount()"),
        errorCall: { nodeType: "FunctionCall", id: 108, src: src(source, "BadAmount()"),
          expression: { nodeType: "Identifier", name: "BadAmount" } } },
    ];
    const ast = { "src/Vault.sol": { nodeType: "SourceUnit", nodes: [{ nodeType: "ContractDefinition",
      id: 1, name: "Vault", contractKind: "contract", src: src(source, "contract Vault"),
      nodes: [fn(source, "function withdraw(uint256 amount)", 2, "withdraw", "external", "nonpayable", ["uint256"], body)] }] } };
    const graph = generateStaticProtocolGraph({ ...f, astBySourceUnit: ast, compilerVersion: "0.8.24" });
    const syntax = graph.functionSyntax?.[0];
    expect(syntax?.truncated).toBe(false);
    expect(syntax?.operations.map((item) => item.kind)).toEqual(["condition", "branch", "event-emission", "revert"]);
    expect(syntax?.operations.every((item) => item.source.sourceUnitName === "src/Vault.sol" &&
      item.expressionSha256?.length === 64)).toBe(true);
  });
  it("builds source-backed basic/internal calls, inheritance, interface and library edges", async () => {
    const oracle = "interface Oracle { function getPrice() external view returns(uint256); }";
    const math = "library Mathish { function add(uint256 a) internal pure returns(uint256) { return a; } }";
    const vault = `import "./Oracle.sol";
import "./Mathish.sol";
contract BaseVault {}
contract Vault is BaseVault, Oracle {
  using Mathish for uint256;
  function getPrice() external view returns(uint256) { return 1; }
  function _calculateShares() internal view returns(uint256) { return Oracle(address(0)).getPrice(); }
  function withdraw() external payable { _calculateShares(); _calculateShares(); }
}`;
    const f = await fixture({ "src/Oracle.sol": oracle, "src/Mathish.sol": math, "src/Vault.sol": vault });
    const ast = {
      "src/Oracle.sol": { nodeType: "SourceUnit", absolutePath: "src/Oracle.sol", nodes: [{ nodeType: "ContractDefinition", id: 1, name: "Oracle", contractKind: "interface", src: src(oracle, "interface Oracle"), nodes: [fn(oracle, "function getPrice()", 11, "getPrice", "external", "view")] }] },
      "src/Mathish.sol": { nodeType: "SourceUnit", absolutePath: "src/Mathish.sol", nodes: [{ nodeType: "ContractDefinition", id: 2, name: "Mathish", contractKind: "library", src: src(math, "library Mathish"), nodes: [fn(math, "function add(uint256 a)", 12, "add", "internal", "pure", ["uint256"])] }] },
      "src/Vault.sol": { nodeType: "SourceUnit", absolutePath: "src/Vault.sol", nodes: [
        { nodeType: "ContractDefinition", id: 3, name: "BaseVault", contractKind: "contract", src: src(vault, "contract BaseVault"), nodes: [] },
        { nodeType: "ContractDefinition", id: 4, name: "Vault", contractKind: "contract", src: src(vault, "contract Vault"),
          baseContracts: [
            { baseName: { referencedDeclaration: 3, src: src(vault, "BaseVault, Oracle") } },
            { baseName: { referencedDeclaration: 1, src: src(vault, "Oracle {") } },
          ], nodes: [
            { nodeType: "UsingForDirective", id: 41, src: src(vault, "using Mathish for uint256"), libraryName: { referencedDeclaration: 2 } },
            fn(vault, "function getPrice() external", 13, "getPrice", "external", "view"),
            fn(vault, "function _calculateShares()", 14, "_calculateShares", "internal", "view", [], [
              call(vault, ".getPrice()", 51, { nodeType: "MemberAccess", memberName: "getPrice", referencedDeclaration: 11,
                expression: { typeDescriptions: { typeString: "contract Oracle" } } })]),
            fn(vault, "function withdraw()", 15, "withdraw", "external", "payable", [], [
              call(vault, "_calculateShares();", 52, { nodeType: "Identifier", name: "_calculateShares", referencedDeclaration: 14 }),
              call(vault, "_calculateShares();", 53, { nodeType: "Identifier", name: "_calculateShares", referencedDeclaration: 14 }, 1)]),
          ] },
      ] },
    };
    const result = generateStaticProtocolGraph({ ...f, astBySourceUnit: ast, compilerVersion: "0.8.24",
      alignedFindings: [{ id: randomUUID(), sourceUnitName: "src/Vault.sol", contract: "Vault", functionName: "withdraw", startLine: 8 }] });
    expect(result.summary).toMatchObject({ contracts: 2, interfaces: 1, libraries: 1, functions: 5,
      entryPoints: 3, findingsLinkedNodes: 1 });
    expect(result.graph.edges.filter((e) => e.kind === "calls")).toHaveLength(3);
    expect(result.graph.edges.filter((e) => e.kind === "external-call")).toHaveLength(1);
    expect(result.graph.edges.filter((e) => e.kind === "inherits")).toHaveLength(1);
    expect(result.graph.edges.filter((e) => e.kind === "implements")).toHaveLength(1);
    expect(result.graph.edges.filter((e) => e.kind === "uses-library")).toHaveLength(1);
    expect(new Set(result.graph.edges.filter((e) => e.kind === "calls").map((e) => e.source?.startByte)).size).toBe(3);
    expect(result.graph.edges.find((e) => e.toFunctionId === result.graph.nodes.find((n) => n.kind === "function" && n.name === "getPrice" && n.source?.sourceUnitName === "src/Oracle.sol")?.id)?.source?.sourceUnitName).toBe("src/Vault.sol");
    expect(generateStaticProtocolGraph({ ...f, astBySourceUnit: ast, compilerVersion: "0.8.24",
      alignedFindings: [{ id: result.findingLinks[0].findingId, sourceUnitName: "src/Vault.sol", contract: "Vault", functionName: "withdraw", startLine: 8 }] })).toEqual(result);
  });

  it("keeps overloads distinct and leaves dynamic low-level targets unresolved", async () => {
    const source = `contract Vault {
function foo(uint256 x) public {}
function foo(address x) public {}
function run(address payable recipient, uint256 amount) external {
  recipient.call{value: amount}("");
  recipient.delegatecall("");
}}`;
    const f = await fixture({ "src/Vault.sol": source });
    const ast = { "src/Vault.sol": { nodeType: "SourceUnit", absolutePath: "src/Vault.sol", nodes: [
      { nodeType: "ContractDefinition", id: 1, name: "Vault", contractKind: "contract", src: src(source, "contract Vault"), nodes: [
        fn(source, "function foo(uint256 x)", 11, "foo", "public", "nonpayable", ["uint256"]),
        fn(source, "function foo(address x)", 12, "foo", "public", "nonpayable", ["address"]),
        fn(source, "function run(address", 13, "run", "external", "nonpayable", ["address payable", "uint256"], [
          call(source, "recipient.call{value: amount}", 21, { nodeType: "FunctionCallOptions", names: ["value"], expression: { nodeType: "MemberAccess", memberName: "call" } }),
          call(source, "recipient.delegatecall", 22, { nodeType: "MemberAccess", memberName: "delegatecall" }),
        ]),
      ] },
    ] } };
    const result = generateStaticProtocolGraph({ ...f, astBySourceUnit: ast, compilerVersion: "0.8.24" });
    const overloads = result.graph.nodes.filter((node) => node.kind === "function" && node.name === "foo");
    expect(overloads).toHaveLength(2); expect(new Set(overloads.map((node) => node.id)).size).toBe(2);
    expect(result.summary).toMatchObject({ externalCalls: 1, delegatecalls: 1, proxies: 0, unresolvedRelationships: 2 });
    expect(result.graph.nodes.some((node) => node.kind === "external-actor" && node.identityState === "unknown")).toBe(true);
    expect(result.functionFacts.find((fact) => fact.lowLevelCalls.includes("call"))).toMatchObject({ nativeValueTransfer: true });
  });

  it("finalizes map-only graph without inventing calls or compiler-backed functions", async () => {
    const f = await fixture({ "src/Unknown.sol": "contract Unknown {}" });
    const result = generateStaticProtocolGraph(f);
    expect(result.summary).toMatchObject({ contracts: 1, functions: 0, edges: 0 });
    expect(result.graph.warnings).toContainEqual({ code: "lexical-contract-unverified", sourceUnitName: "src/Unknown.sol" });
    expect(result.graph.sourceUnits[0].identityStatus).toBe("authoritative");
  });

  it("accepts a cyclic exact call graph and preserves both directed call sites", async () => {
    const source = "contract Cycle { function a() public { b(); } function b() public { a(); } }";
    const f = await fixture({ "src/Cycle.sol": source });
    const ast = { "src/Cycle.sol": { nodeType: "SourceUnit", absolutePath: "src/Cycle.sol", nodes: [
      { nodeType: "ContractDefinition", id: 1, name: "Cycle", contractKind: "contract", src: src(source, "contract Cycle"), nodes: [
        fn(source, "function a()", 11, "a", "public", "nonpayable", [], [
          call(source, "b();", 21, { nodeType: "Identifier", name: "b", referencedDeclaration: 12 })]),
        fn(source, "function b()", 12, "b", "public", "nonpayable", [], [
          call(source, "a();", 22, { nodeType: "Identifier", name: "a", referencedDeclaration: 11 })]),
      ] },
    ] } };
    const result = generateStaticProtocolGraph({ ...f, astBySourceUnit: ast, compilerVersion: "0.8.24" });
    const calls = result.graph.edges.filter((edge) => edge.kind === "calls");
    expect(calls).toHaveLength(2);
    expect(calls[0].from).toBe(calls[1].to);
    expect(calls[0].to).toBe(calls[1].from);
  });

  it("orders and validates a representative map-only graph deterministically", async () => {
    const sources = Object.fromEntries(Array.from({ length: 100 }, (_, index) =>
      [`src/C${index}.sol`, `contract C${index} {}`]));
    const f = await fixture(sources);
    const first = generateStaticProtocolGraph(f);
    expect(first.graph.nodes).toHaveLength(100);
    expect(new Set(first.graph.nodes.map((node) => node.id)).size).toBe(100);
    expect(generateStaticProtocolGraph(f)).toEqual(first);
  });

  it("requires exact proxy and owner-guard evidence while retaining state and token syntax", async () => {
    const source = `interface IToken { function transfer(address to, uint256 amount) external returns(bool); }
contract Vault {
  address private _owner;
  uint256 public count;
  bytes32 private constant IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
  modifier onlyOwner() { require(msg.sender == _owner); _; }
  function act(IToken token) external onlyOwner { count = count + 1; token.transfer(msg.sender, 1); }
  function dispatch(address target) external { IMPLEMENTATION_SLOT; target.delegatecall(""); }
}`;
    const f = await fixture({ "src/Vault.sol": source });
    const ast = { "src/Vault.sol": { nodeType: "SourceUnit", absolutePath: "src/Vault.sol", nodes: [
      { nodeType: "ContractDefinition", id: 1, name: "IToken", contractKind: "interface", src: src(source, "interface IToken"),
        nodes: [fn(source, "function transfer(address", 11, "transfer", "external", "nonpayable", ["address", "uint256"])] },
      { nodeType: "ContractDefinition", id: 2, name: "Vault", contractKind: "contract", src: src(source, "contract Vault"), nodes: [
        { nodeType: "VariableDeclaration", id: 21, name: "_owner", stateVariable: true,
          typeDescriptions: { typeString: "address" }, src: src(source, "_owner;") },
        { nodeType: "VariableDeclaration", id: 22, name: "count", stateVariable: true,
          typeDescriptions: { typeString: "uint256" }, src: src(source, "count;") },
        { nodeType: "VariableDeclaration", id: 23, name: "IMPLEMENTATION_SLOT", stateVariable: true,
          src: src(source, "IMPLEMENTATION_SLOT"), value: { value: "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc" } },
        { nodeType: "ModifierDefinition", id: 31, name: "onlyOwner", src: src(source, "modifier onlyOwner"),
          body: { nodeType: "Block", statements: [{ nodeType: "FunctionCall", expression: { nodeType: "Identifier", name: "require" },
            arguments: [{ nodeType: "BinaryOperation", operator: "==",
              leftExpression: { nodeType: "MemberAccess", memberName: "sender", expression: { nodeType: "Identifier", name: "msg" } },
              rightExpression: { nodeType: "Identifier", referencedDeclaration: 21 } }] }] } },
        { ...fn(source, "function act(", 12, "act", "external", "nonpayable", ["contract IToken"], [
          { nodeType: "Assignment", operator: "=", leftHandSide: { nodeType: "Identifier", referencedDeclaration: 22,
            src: src(source, "count =") }, rightHandSide: { nodeType: "BinaryOperation", operator: "+",
            leftExpression: { nodeType: "Identifier", referencedDeclaration: 22, src: src(source, "count +") } } },
          call(source, "token.transfer", 41, { nodeType: "MemberAccess", memberName: "transfer",
            referencedDeclaration: 11, expression: { typeDescriptions: { typeString: "contract IToken" } } }),
        ]), modifiers: [{ src: src(source, "onlyOwner {"), modifierName: { referencedDeclaration: 31, name: "onlyOwner" } }] },
        fn(source, "function dispatch(", 13, "dispatch", "external", "nonpayable", ["address"], [
          { nodeType: "Identifier", referencedDeclaration: 23, src: src(source, "IMPLEMENTATION_SLOT", 1) },
          call(source, "target.delegatecall", 42, { nodeType: "MemberAccess", memberName: "delegatecall" })]),
      ] },
    ] } };
    const result = generateStaticProtocolGraph({ ...f, astBySourceUnit: ast, compilerVersion: "0.8.24" });
    expect(result.summary.proxies).toBe(1);
    expect(result.graph.edges.some((edge) => edge.kind === "controls" && edge.reasons.includes("msg-sender-owner-guard"))).toBe(true);
    expect(result.graph.edges.some((edge) => edge.kind === "delegates" && edge.reasons.includes("eip1967-slot-and-delegatecall"))).toBe(true);
    const act = result.graph.nodes.find((node) => node.kind === "function" && node.name === "act");
    expect(act?.characteristics.some((trait) => trait.kind === "token-transfer")).toBe(true);
    const facts = result.functionFacts.find((item) => item.functionId === act?.id);
    expect(facts?.stateWrites.map((item) => item.variable)).toContain("count");
    expect(facts?.stateReads.map((item) => item.variable)).toContain("count");
  });
});
