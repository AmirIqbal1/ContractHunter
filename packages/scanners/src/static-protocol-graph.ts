import { createHash } from "node:crypto";
import { TextDecoder } from "node:util";
import { contractGraphKey, functionGraphKey, protocolEdgeId, protocolGraphId, protocolNodeId,
  PROTOCOL_GRAPH_LIMITS, PROTOCOL_GRAPH_SCHEMA, REPOSITORY_MAPPER_RULESET,
  STATIC_GRAPH_EXTRACTOR_VERSION, STATIC_PROTOCOL_GRAPH_SCHEMA, staticProtocolGraphContentHash,
  validateProtocolGraph, validateRepositoryMap, validateStaticProtocolGraphArtifact,
  type GraphEvidence, type ProtocolGraph, type ProtocolGraphEdge, type ProtocolGraphNode,
  type ProtocolSourceLocation, type RepositoryMap, type RepositoryMapFile,
  type StaticFunctionFacts, type StaticFunctionSyntax, type StaticProtocolGraphArtifact, type StaticUnresolvedRelationship,
} from "@contracthunter/core";

export interface StaticProtocolGraphInput {
  repositoryMap: RepositoryMap;
  /** A trusted standard-JSON compiler AST, produced from matching immutable snapshot bytes. */
  astBySourceUnit?: Readonly<Record<string, unknown>>;
  compilerVersion?: string;
  snapshotFiles?: readonly { sourceKey: string; rawBytes: Buffer; rawSha256: string; byteLength: number }[];
  alignedFindings?: readonly { id: string; sourceUnitName: string; contract: string | null;
    functionName: string | null; startLine: number | null }[];
}
type Ast = Record<string, unknown>;
const object = (value: unknown): Ast | null => value && typeof value === "object" && !Array.isArray(value) ? value as Ast : null;
const objects = (value: unknown): Ast[] => Array.isArray(value) ? value.map(object).filter((x): x is Ast => !!x) : [];
const number = (value: unknown): number | null => Number.isInteger(value) && Number(value) >= 0 ? Number(value) : null;
const string = (value: unknown): string | null => typeof value === "string" ? value : null;
const sort = (a: string, b: string) => a < b ? -1 : a > b ? 1 : 0;
const sha = (bytes: Buffer) => createHash("sha256").update(bytes).digest("hex");
const SLOT = "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";

class SourceIndex {
  readonly lineStarts = [0];
  constructor(readonly unit: string, readonly bytes: Buffer) {
    for (let i = 0; i < bytes.length; i++) if (bytes[i] === 10) this.lineStarts.push(i + 1);
  }
  location(src: unknown): ProtocolSourceLocation | null {
    if (typeof src !== "string") return null;
    const match = /^(\d+):(\d+):(\d+)$/.exec(src);
    if (!match) return null;
    const start = Number(match[1]), length = Number(match[2]);
    if (!Number.isSafeInteger(start) || !Number.isSafeInteger(length) || start + length > this.bytes.length) return null;
    const lineAt = (offset: number) => {
      let low = 0, high = this.lineStarts.length;
      while (low + 1 < high) { const mid = (low + high) >>> 1; if (this.lineStarts[mid] <= offset) low = mid; else high = mid; }
      return { line: low + 1, column: offset - this.lineStarts[low] };
    };
    const first = lineAt(start), last = lineAt(start + length);
    return { sourceUnitName: this.unit, startLine: first.line, endLine: last.line,
      startColumn: first.column, endColumn: last.column, startByte: start, endByte: start + length };
  }
}
const mapLocation = (file: RepositoryMapFile, declaration: RepositoryMapFile["declarations"][number]): ProtocolSourceLocation => ({
  sourceUnitName: file.path, startLine: declaration.location.line, endLine: declaration.location.line,
  startColumn: declaration.location.column - 1, endColumn: declaration.location.column - 1,
  startByte: null, endByte: null,
});
function walkAst(root: Ast, visit: (node: Ast, parent: Ast | null) => void, limit = 100_000): void {
  const stack: Array<{ node: Ast; parent: Ast | null; depth: number }> = [{ node: root, parent: null, depth: 0 }];
  let seen = 0;
  while (stack.length) {
    const { node, parent, depth } = stack.pop()!;
    if (++seen > limit || depth > 96) throw Error("static_ast_bounds_exceeded");
    visit(node, parent);
    for (const [key, value] of Object.entries(node)) {
      if (["typeDescriptions", "documentation", "scope"].includes(key)) continue;
      if (Array.isArray(value)) for (let i = value.length - 1; i >= 0; i--) {
        const child = object(value[i]); if (child && typeof child.nodeType === "string") stack.push({ node: child, parent: node, depth: depth + 1 });
      }
      else { const child = object(value); if (child && typeof child.nodeType === "string") stack.push({ node: child, parent: node, depth: depth + 1 }); }
    }
  }
}
function canonicalType(parameter: Ast): string | null {
  const description = object(parameter.typeDescriptions), raw = string(description?.typeString) ?? string(object(parameter.typeName)?.name);
  if (!raw || raw.length > 120 || /[\x00-\x1f]/.test(raw)) return null;
  return raw.replace(/\s+(memory|storage|calldata)(\s+ref)?\b/g, "").replace(/^uint$/, "uint256").replace(/^int$/, "int256").trim();
}
function functionSignature(node: Ast): { name: string; signature: string } | null {
  const kind = string(node.kind) ?? "function";
  const name = kind === "function" ? string(node.name) : kind;
  if (!name || !/^[A-Za-z_$][A-Za-z0-9_$]{0,199}$/.test(name)) return null;
  const parameters = objects(object(node.parameters)?.parameters);
  const types = parameters.map(canonicalType);
  if (types.some((type) => !type)) return null;
  const signature = `${name}(${types.join(",")})`;
  return signature.length <= 256 ? { name, signature } : null;
}
function expressionRef(value: unknown): number | null {
  let node = object(value);
  for (let i = 0; i < 3 && node?.nodeType === "FunctionCallOptions"; i++) node = object(node.expression);
  return number(node?.referencedDeclaration);
}
function expressionCore(value: unknown): Ast | null {
  let node = object(value);
  for (let i = 0; i < 3 && node?.nodeType === "FunctionCallOptions"; i++) node = object(node.expression);
  return node;
}
function hasValueOption(value: unknown): boolean {
  const node = object(value);
  return node?.nodeType === "FunctionCallOptions" && Array.isArray(node.names) && node.names.includes("value");
}
function evidence(origin: "repository-mapper" | "compiler" | "contracthunter-parser", version: string,
  source: ProtocolSourceLocation | null, referenceId: string | null = null): GraphEvidence {
  return { origin, producerVersion: version, source, referenceId };
}
function isMsgSender(value: Ast | null): boolean {
  return value?.nodeType === "MemberAccess" && value.memberName === "sender" && object(value.expression)?.name === "msg";
}
function ownerGuard(modifier: Ast, ownerVarId: number): boolean {
  let guarded = false;
  const body = object(modifier.body); if (!body) return false;
  walkAst(body, (node) => {
    if (node.nodeType !== "FunctionCall" || object(node.expression)?.name !== "require") return;
    const condition = object(objects(node.arguments)[0]);
    if (condition?.nodeType !== "BinaryOperation" || condition.operator !== "==") return;
    const left = object(condition.leftExpression), right = object(condition.rightExpression);
    if ((isMsgSender(left) && expressionRef(right) === ownerVarId) ||
      (isMsgSender(right) && expressionRef(left) === ownerVarId)) guarded = true;
  });
  return guarded;
}

export function generateStaticProtocolGraph(input: StaticProtocolGraphInput): StaticProtocolGraphArtifact {
  const map = validateRepositoryMap(input.repositoryMap);
  const compilerVersion = input.astBySourceUnit ? input.compilerVersion : undefined;
  if (input.astBySourceUnit && (!compilerVersion || !input.snapshotFiles)) throw Error("static_ast_provenance_missing");
  const snapshots = new Map((input.snapshotFiles ?? []).map((file) => [file.sourceKey, file]));
  const mapFiles = new Map(map.files.map((file) => [file.path, file]));
  const astUnits = new Map<string, { ast: Ast; index: SourceIndex }>();
  for (const [unit, rawAst] of Object.entries(input.astBySourceUnit ?? {})) {
    const file = mapFiles.get(unit);
    const snapshot = snapshots.get(unit), ast = object(rawAst);
    if (!file || file.source.authority !== "snapshot" || !snapshot || !ast || ast.nodeType !== "SourceUnit" ||
      ast.absolutePath !== undefined && ast.absolutePath !== unit ||
      file.source.rawSha256 !== snapshot.rawSha256 || snapshot.rawSha256 !== sha(snapshot.rawBytes) ||
      snapshot.byteLength !== snapshot.rawBytes.length) throw Error("static_ast_source_identity_invalid");
    astUnits.set(unit, { ast, index: new SourceIndex(unit, snapshot.rawBytes) });
  }
  const producers: ProtocolGraph["producers"] = [
    { origin: "repository-mapper" as const, version: REPOSITORY_MAPPER_RULESET },
    ...(compilerVersion ? [{ origin: "compiler" as const, version: compilerVersion }] : []),
    { origin: "contracthunter-parser" as const, version: STATIC_GRAPH_EXTRACTOR_VERSION },
  ].sort((a, b) => sort(a.origin, b.origin));
  const extractorVersion = `${STATIC_GRAPH_EXTRACTOR_VERSION}:${map.id}`;
  const graph: ProtocolGraph = { schema: PROTOCOL_GRAPH_SCHEMA,
    id: protocolGraphId(map.scanId, map.resolvedCommit, extractorVersion, producers), scanId: map.scanId,
    resolvedCommit: map.resolvedCommit, extractorVersion, producers,
    sourceUnits: map.files.filter((file) => file.kind === "solidity").map((file) => ({
      sourceUnitName: file.path, snapshotSourceKey: file.source.authority === "snapshot" ? file.path : null,
      rawSha256: file.source.authority === "snapshot" ? file.source.rawSha256 : null,
      byteLength: file.source.authority === "snapshot" ? file.source.byteLength : null,
      identityStatus: file.source.authority === "snapshot" ? "authoritative" as const : "reported" as const,
    })).sort((a, b) => sort(a.sourceUnitName, b.sourceUnitName)),
    nodes: [], edges: [], classifications: map.files.filter((file) => file.kind === "solidity")
      .map((file) => ({ repositoryPath: file.path, value: file.classification })).sort((a, b) => sort(a.repositoryPath, b.repositoryPath)),
    warnings: [],
  };
  const warnings = new Set<string>();
  const addWarning = (code: string, unit: string | null) => {
    const key = `${code}\0${unit ?? ""}`;
    if (warnings.has(key)) return;
    if (graph.warnings.length >= PROTOCOL_GRAPH_LIMITS.warnings) throw Error("static_graph_warning_limit_exceeded");
    warnings.add(key); graph.warnings.push({ code, sourceUnitName: unit });
  };
  const nodeByAstId = new Map<number, ProtocolGraphNode>();
  const contractByUnitName = new Map<string, ProtocolGraphNode>();
  const contractAst = new Map<string, Ast>();
  const functionAst = new Map<string, { ast: Ast; index: SourceIndex; owner: ProtocolGraphNode }>();
  const nodes = new Map<string, ProtocolGraphNode>(), edges = new Map<string, ProtocolGraphEdge>();
  const addNode = (node: ProtocolGraphNode) => {
    if (nodes.has(node.id)) throw Error("static_graph_duplicate_node");
    if (nodes.size >= PROTOCOL_GRAPH_LIMITS.nodes && !nodes.has(node.id)) throw Error("static_graph_node_limit_exceeded");
    nodes.set(node.id, node);
  };
  const addEdge = (edge: ProtocolGraphEdge) => {
    const prior = edges.get(edge.id);
    if (prior) {
      for (const item of edge.evidence) if (!prior.evidence.some((old) => JSON.stringify(old) === JSON.stringify(item))) {
        if (prior.evidence.length >= PROTOCOL_GRAPH_LIMITS.evidencePerFact) throw Error("static_graph_evidence_limit_exceeded");
        prior.evidence.push(item);
      }
      return;
    }
    if (edges.size >= PROTOCOL_GRAPH_LIMITS.edges) throw Error("static_graph_edge_limit_exceeded");
    edges.set(edge.id, edge);
  };
  const edge = (kind: ProtocolGraphEdge["kind"], from: ProtocolGraphNode, to: ProtocolGraphNode,
    at: ProtocolSourceLocation, reason: string, ref: string, extra: GraphEvidence[] = []) => {
    const key = JSON.stringify([at.sourceUnitName, at.startByte ?? at.startLine,
      at.startColumn, kind, from.id, to.id, ref]);
    const item: ProtocolGraphEdge = { id: protocolEdgeId(map.scanId, kind, from.id, to.id, key), key,
      kind, from: from.id, to: to.id, origin: "static", reasons: [reason],
      evidence: [evidence("compiler", compilerVersion ?? STATIC_GRAPH_EXTRACTOR_VERSION, at, ref), ...extra],
      source: at, fromFunctionId: from.kind === "function" ? from.id : null,
      toFunctionId: to.kind === "function" ? to.id : null };
    addEdge(item);
  };
  for (const file of map.files) {
    if (file.kind !== "solidity") continue;
    const unit = astUnits.get(file.path);
    const contracts = unit ? objects(unit.ast.nodes).filter((node) => node.nodeType === "ContractDefinition") : [];
    for (const declaration of file.declarations) {
      const kind = declaration.kind === "interface" ? "interface" : declaration.kind === "library" ? "library" : "contract";
      const match = contracts.find((item) => item.name === declaration.name && item.contractKind === kind);
      const at = match && unit?.index.location(match.src) || mapLocation(file, declaration);
      const key = contractGraphKey(file.path, declaration.name);
      const node: ProtocolGraphNode = { kind, id: protocolNodeId(map.scanId, kind, key), key,
        name: declaration.name, qualifiedName: `${file.path}:${declaration.name}`, contractKind: kind,
        abstract: declaration.kind === "abstract-contract" || match?.abstract === true,
        repositoryClassification: file.classification, source: at,
        evidence: [evidence("repository-mapper", REPOSITORY_MAPPER_RULESET, mapLocation(file, declaration), declaration.id),
          ...(match && unit ? [evidence("compiler", compilerVersion!, at, String(match.id))] : [])],
        characteristics: [] };
      addNode(node); contractByUnitName.set(`${file.path}\0${declaration.name}`, node);
      if (match && unit) {
        const astId = number(match.id); if (astId === null || nodeByAstId.has(astId)) throw Error("static_ast_contract_id_invalid");
        nodeByAstId.set(astId, node); contractAst.set(node.id, match);
      } else addWarning("lexical-contract-unverified", file.path);
    }
  }
  for (const [contractId, ast] of contractAst) {
    const owner = nodes.get(contractId)!;
    const unit = astUnits.get(owner.source!.sourceUnitName)!;
    for (const fn of objects(ast.nodes).filter((item) => item.nodeType === "FunctionDefinition")) {
      const identity = functionSignature(fn);
      if (!identity) { addWarning("function-signature-unsupported", owner.source!.sourceUnitName); continue; }
      const at = unit.index.location(fn.src);
      if (!at) { addWarning("function-location-unsupported", owner.source!.sourceUnitName); continue; }
      const key = functionGraphKey(owner.key, identity.signature), id = protocolNodeId(map.scanId, "function", key);
      if (nodes.has(id)) throw Error("static_ast_duplicate_function_identity");
      const visibility = ["public", "external", "internal", "private"].includes(String(fn.visibility)) ?
        fn.visibility as "public" | "external" | "internal" | "private" : "unknown";
      const mutability = ["pure", "view", "payable", "nonpayable"].includes(String(fn.stateMutability)) ?
        fn.stateMutability as "pure" | "view" | "payable" | "nonpayable" : "unknown";
      const entryPoint = ["public", "external"].includes(visibility) || ["receive", "fallback"].includes(String(fn.kind)) ? "yes" :
        ["internal", "private"].includes(visibility) ? "no" : "unknown";
      const modifiers = objects(fn.modifiers).map((mod) => string(object(mod.modifierName)?.name) ?? "").filter(Boolean);
      const ev = evidence("compiler", compilerVersion!, at, String(fn.id));
      const characteristics: Extract<ProtocolGraphNode, { kind: "function" }>["characteristics"] = [];
      if (entryPoint === "yes") characteristics.push({ kind: "external-entry-point", evidence: [ev] });
      if (mutability === "payable") characteristics.push({ kind: "payable", evidence: [ev] });
      const node: ProtocolGraphNode = { kind: "function", id, key, name: identity.name, signature: identity.signature,
        contractId: owner.id, source: at, evidence: [ev], characteristics, visibility, mutability,
        modifiers: [...new Set(modifiers)].slice(0, 32), entryPoint };
      addNode(node);
      const astId = number(fn.id); if (astId === null || nodeByAstId.has(astId)) throw Error("static_ast_function_id_invalid");
      nodeByAstId.set(astId, node); functionAst.set(node.id, { ast: fn, index: unit.index, owner });
    }
  }
  const addTrait = (node: ProtocolGraphNode, kind: ProtocolGraphNode["characteristics"][number]["kind"], ev: GraphEvidence) => {
    const prior = node.characteristics.find((item) => item.kind === kind);
    if (prior) { if (!prior.evidence.some((item) => JSON.stringify(item) === JSON.stringify(ev))) prior.evidence.push(ev); }
    else node.characteristics.push({ kind, evidence: [ev] });
    if (node.characteristics.length > PROTOCOL_GRAPH_LIMITS.characteristicsPerNode ||
      (prior?.evidence.length ?? 0) > PROTOCOL_GRAPH_LIMITS.evidencePerFact) throw Error("static_graph_trait_limit_exceeded");
  };
  const unresolved: StaticUnresolvedRelationship[] = [];
  const addUnresolved = (caller: ProtocolGraphNode, at: ProtocolSourceLocation, kind: StaticUnresolvedRelationship["kind"],
    reason: StaticUnresolvedRelationship["reason"], expression: string | null) => {
    if (unresolved.length >= PROTOCOL_GRAPH_LIMITS.edges) throw Error("static_graph_unresolved_limit_exceeded");
    unresolved.push({ callerFunctionId: caller.id, source: at, kind, reason, expression: expression?.slice(0, 200) ?? null });
  };
  const unknownTarget = (caller: ProtocolGraphNode): ProtocolGraphNode => {
    const key = JSON.stringify(["unresolved-external-target", caller.key]);
    const id = protocolNodeId(map.scanId, "external-actor", key);
    const prior = nodes.get(id); if (prior) return prior;
    const node: ProtocolGraphNode = { kind: "external-actor", id, key, name: "Unresolved external target",
      source: null, evidence: [evidence("contracthunter-parser", STATIC_GRAPH_EXTRACTOR_VERSION, caller.source)],
      characteristics: [], identityState: "unknown", representedContractId: null };
    addNode(node); return node;
  };
  const stateVars = new Map<number, { name: string; owner: ProtocolGraphNode }>();
  for (const [contractId, contract] of contractAst) for (const variable of objects(contract.nodes).filter((node) => node.nodeType === "VariableDeclaration" && node.stateVariable === true)) {
    const id = number(variable.id), name = string(variable.name);
    if (id !== null && name) stateVars.set(id, { name, owner: nodes.get(contractId)! });
  }
  // Inheritance and explicit using-for relationships use compiler declaration references.
  for (const [contractId, ast] of contractAst) {
    const derived = nodes.get(contractId)!, unit = astUnits.get(derived.source!.sourceUnitName)!;
    for (const base of objects(ast.baseContracts)) {
      const baseName = object(base.baseName), target = nodeByAstId.get(number(baseName?.referencedDeclaration) ?? -1);
      const at = unit.index.location(baseName?.src ?? base.src);
      if (!at) continue;
      if (!target || !["contract", "interface", "library"].includes(target.kind)) {
        addWarning("inheritance-target-unresolved", derived.source!.sourceUnitName); continue;
      }
      edge(target.kind === "interface" && derived.kind !== "interface" ? "implements" : "inherits",
        derived, target, at, "explicit-base-declaration", String(baseName?.referencedDeclaration),
        [evidence("repository-mapper", REPOSITORY_MAPPER_RULESET, derived.source)]);
    }
    for (const directive of objects(ast.nodes).filter((item) => item.nodeType === "UsingForDirective")) {
      const lib = object(directive.libraryName), target = nodeByAstId.get(number(lib?.referencedDeclaration) ?? -1);
      const at = unit.index.location(directive.src);
      if (target?.kind === "library" && at) edge("uses-library", derived, target, at, "explicit-using-directive", String(directive.id));
      else addWarning("library-target-unresolved", derived.source!.sourceUnitName);
    }
  }
  const facts: StaticFunctionFacts[] = [], syntax: StaticFunctionSyntax[] = [];
  for (const [functionId, item] of functionAst) {
    const caller = nodes.get(functionId)!, body = object(item.ast.body);
    const syntaxOperations: StaticFunctionSyntax["operations"] = [];
    let syntaxTruncated = false;
    const recordSyntax = (kind: StaticFunctionSyntax["operations"][number]["kind"], node: Ast,
      sourceNode: Ast | null = null, label: string | null = null) => {
      const target = sourceNode ?? node, at = item.index.location(target.src), astNodeId = number(node.id);
      if (!at || astNodeId === null || at.startByte === null || at.endByte === null) { syntaxTruncated = true; return; }
      if (syntaxOperations.length >= 256) { syntaxTruncated = true; return; }
      const raw = item.index.bytes.subarray(at.startByte, at.endByte);
      let excerpt: string | null = null;
      try { excerpt = new TextDecoder("utf-8", { fatal: true }).decode(raw); }
      catch { syntaxTruncated = true; }
      syntaxOperations.push({ kind, source: at, astNodeId, label: label?.slice(0, 160) ?? null,
        expressionSha256: sha(raw), excerpt: excerpt?.slice(0, 160) ?? null,
        excerptTruncated: excerpt !== null && excerpt.length > 160 });
    };
    if (body) walkAst(body, (node, parent) => {
      const kind = string(node.nodeType);
      if (kind === "IfStatement") recordSyntax("branch", node, object(node.condition), "if");
      else if (["ForStatement", "WhileStatement", "DoWhileStatement"].includes(kind ?? ""))
        recordSyntax("loop", node, object(node.condition) ?? node, kind);
      else if (kind === "TryStatement") recordSyntax("try-catch", node, object(node.externalCall) ?? node, "try");
      else if (kind === "EmitStatement") {
        const call = object(node.eventCall), target = object(call?.expression);
        recordSyntax("event-emission", node, call, string(target?.name) ?? string(target?.memberName) ?? "event");
      } else if (kind === "Return") recordSyntax("return", node);
      else if (kind === "InlineAssembly") recordSyntax("assembly", node, node, "inline assembly");
      else if (kind === "RevertStatement") {
        const call = object(node.errorCall), target = object(call?.expression);
        recordSyntax("revert", node, call, string(target?.name) ?? string(target?.memberName) ?? "custom error");
      } else if (kind === "FunctionCall" && parent?.nodeType !== "RevertStatement") {
        const name = string(object(node.expression)?.name);
        if (name === "require" || name === "assert") recordSyntax("condition", node, objects(node.arguments)[0] ?? node, name);
        else if (name === "revert") recordSyntax("revert", node, node, "revert");
      }
    });
    syntaxOperations.sort((a, b) => (a.source.startByte ?? 0) - (b.source.startByte ?? 0) ||
      sort(a.kind, b.kind) || a.astNodeId - b.astNodeId);
    syntax.push({ functionId, truncated: syntaxTruncated, operations: syntaxOperations });
    const reads = new Map<string, StaticFunctionFacts["stateReads"][number]>(), writes = new Map<string, StaticFunctionFacts["stateWrites"][number]>();
    const lowLevel: StaticFunctionFacts["lowLevelCalls"] = [];
    const modifierInvocations = objects(item.ast.modifiers).flatMap((invocation) => {
      const name = string(object(invocation.modifierName)?.name) ?? string(object(invocation.modifierName)?.memberName);
      const at = item.index.location(invocation.src);
      return name && at ? [{ name, declarationId: number(object(invocation.modifierName)?.referencedDeclaration), source: at }] : [];
    });
    let tokenTransferLike = false, nativeValueTransfer = false;
    if (body) walkAst(body, (node, parent) => {
      const at = item.index.location(node.src);
      const state = stateVars.get(number(node.referencedDeclaration) ?? -1);
      if (state && at && ["Identifier", "MemberAccess"].includes(String(node.nodeType))) {
        const key = `${state.owner.id}:${state.name}`;
        const fact = { variable: state.name, contractId: state.owner.id,
          declarationId: number(node.referencedDeclaration)!, source: at };
        const assignment = parent?.nodeType === "Assignment" && parent.leftHandSide === node;
        const increment = parent?.nodeType === "UnaryOperation" && ["++", "--", "delete"].includes(String(parent.operator));
        if (assignment || increment) writes.set(key, fact);
        if (!assignment || parent?.operator !== "=") reads.set(key, fact);
      }
      if (node.nodeType !== "FunctionCall" || !at) return;
      const core = expressionCore(node.expression), member = string(core?.memberName), ref = expressionRef(node.expression);
      const expressionType = string(object(object(core?.expression)?.typeDescriptions)?.typeString) ?? "";
      const low = member && ["call", "staticcall", "delegatecall", "callcode"].includes(member) ?
        member as StaticFunctionFacts["lowLevelCalls"][number] : null;
      const ev = evidence("compiler", compilerVersion!, at, String(node.id));
      if (low) {
        if (lowLevel.length >= 128) throw Error("static_low_level_call_limit_exceeded");
        lowLevel.push(low); addTrait(caller, "low-level-call", ev);
        if (low === "delegatecall") addTrait(caller, "delegatecall", ev);
        addTrait(caller, "external-call", ev);
        const target = unknownTarget(caller);
        edge(low === "delegatecall" ? "delegates" : "external-call", caller, target, at,
          `low-level-${low}`, String(node.id));
        addUnresolved(caller, at, "external-call", "dynamic-target", member);
        if (low === "call" && hasValueOption(node.expression)) { nativeValueTransfer = true; addTrait(caller, "native-transfer", ev); }
        return;
      }
      if (member && ["transfer", "send"].includes(member) && /^address payable\b/.test(expressionType)) {
        nativeValueTransfer = true; addTrait(caller, "native-transfer", ev);
      }
      const target = nodeByAstId.get(ref ?? -1);
      if (target?.kind === "function") {
        edge("calls", caller, target, at, "compiler-reference", String(node.id));
        const targetOwner = nodes.get(target.contractId);
        if (targetOwner?.kind === "library") edge("uses-library", item.owner, targetOwner, at,
          "direct-library-function-call", String(node.id));
        if (member && /^contract\b/.test(expressionType) && targetOwner?.kind !== "library") {
          edge("external-call", caller, target, at, "typed-contract-member-call", String(node.id));
          addTrait(caller, "external-call", ev);
        }
        if (member && ["transfer", "transferFrom", "safeTransfer", "safeTransferFrom", "mint", "burn"].includes(member) &&
          !/^address\b/.test(expressionType)) { tokenTransferLike = true; addTrait(caller, "token-transfer", ev); }
        return;
      }
      if (core?.nodeType === "MemberAccess") {
        addTrait(caller, "external-call", ev);
        const unknown = unknownTarget(caller);
        edge("external-call", caller, unknown, at, "unresolved-member-call", String(node.id));
        addUnresolved(caller, at, "external-call", ref !== null ? "outside-source-universe" : "dynamic-target", member);
      } else if (core?.nodeType === "Identifier" && !["require", "assert", "revert", "keccak256", "abi", "type"].includes(String(core.name))) {
        addUnresolved(caller, at, "internal-call", "unresolved-reference", string(core.name));
      }
    });
    facts.push({ functionId, stateReads: [...reads.values()].sort((a, b) => sort(a.variable, b.variable)),
      stateWrites: [...writes.values()].sort((a, b) => sort(a.variable, b.variable)),
      tokenTransferLike, nativeValueTransfer, modifierInvocations, lowLevelCalls: lowLevel });
  }
  // A proxy requires both the exact EIP-1967 implementation slot and a delegatecall.
  for (const [contractId, ast] of contractAst) {
    const contract = nodes.get(contractId)!;
    const slot = objects(ast.nodes).find((node) => node.nodeType === "VariableDeclaration" &&
      String(object(node.value)?.value ?? "").replace(/^0x/, "").toLowerCase() === SLOT);
    const delegateFunction = [...functionAst].find(([id, item]) => item.owner.id === contractId &&
      facts.find((fact) => fact.functionId === id)?.lowLevelCalls.includes("delegatecall"));
    let slotReferenced = false;
    if (slot && delegateFunction?.[1].ast.body)
      walkAst(object(delegateFunction[1].ast.body)!, (node) => {
        if (number(node.referencedDeclaration) === number(slot.id)) slotReferenced = true;
      });
    if (!slot || !delegateFunction || !slotReferenced) continue;
    const at = astUnits.get(contract.source!.sourceUnitName)!.index.location(slot.src);
    if (!at) continue;
    const ev = evidence("compiler", compilerVersion!, at, String(slot.id));
    addTrait(contract, "proxy", ev); addTrait(contract, "upgradeable", ev);
    const implementation = unknownTarget(contract);
    edge("delegates", contract, implementation, at, "eip1967-slot-and-delegatecall", String(slot.id),
      [evidence("compiler", compilerVersion!, delegateFunction[1].index.location(delegateFunction[1].ast.src), String(delegateFunction[1].ast.id))]);
  }
  // Exact owner guard: an address state variable compared with msg.sender in a modifier.
  const guardedModifiers = new Map<number, ProtocolGraphNode>();
  for (const [contractId, ast] of contractAst) {
    const owner = nodes.get(contractId)!;
    const ownerVar = objects(ast.nodes).find((node) => node.nodeType === "VariableDeclaration" &&
      node.stateVariable === true && node.name === "_owner" &&
      /^address\b/.test(String(object(node.typeDescriptions)?.typeString ?? "")));
    const ownerId = number(ownerVar?.id);
    if (ownerId === null) continue;
    for (const modifier of objects(ast.nodes).filter((node) => node.nodeType === "ModifierDefinition")) {
      const modifierId = number(modifier.id);
      if (modifierId === null || !ownerGuard(modifier, ownerId)) continue;
      const roleKey = JSON.stringify(["owner-role", owner.key]);
      const role: ProtocolGraphNode = { kind: "role", id: protocolNodeId(map.scanId, "role", roleKey), key: roleKey,
        name: "owner", source: owner.source, evidence: [evidence("compiler", compilerVersion!,
          astUnits.get(owner.source!.sourceUnitName)!.index.location(modifier.src), String(modifierId))],
        characteristics: [], identityState: "known", representedContractId: owner.id };
      const existingRole = nodes.get(role.id);
      if (existingRole) {
        if (existingRole.evidence.length >= PROTOCOL_GRAPH_LIMITS.evidencePerFact) throw Error("static_graph_role_evidence_limit_exceeded");
        existingRole.evidence.push(role.evidence[0]);
      } else addNode(role);
      guardedModifiers.set(modifierId, existingRole ?? role);
    }
  }
  for (const [functionId, item] of functionAst) {
    const fn = nodes.get(functionId)!;
    for (const invocation of objects(item.ast.modifiers)) {
      const modifierId = number(object(invocation.modifierName)?.referencedDeclaration), role = guardedModifiers.get(modifierId ?? -1);
      const at = item.index.location(invocation.src);
      if (!role || !at) continue;
      edge("controls", role, fn, at, "msg-sender-owner-guard", String(modifierId));
      addTrait(fn, "privileged-operation", evidence("compiler", compilerVersion!, at, String(modifierId)));
    }
  }
  const findingLinks: StaticProtocolGraphArtifact["findingLinks"] = [];
  for (const finding of input.alignedFindings ?? []) {
    const contract = finding.contract && contractByUnitName.get(`${finding.sourceUnitName}\0${finding.contract}`);
    if (!contract) continue;
    const candidates = [...nodes.values()].filter((node) => node.kind === "function" && node.contractId === contract.id &&
      node.name === finding.functionName && finding.startLine !== null && node.source &&
      node.source.startLine <= finding.startLine && node.source.endLine >= finding.startLine);
    const target = candidates.length === 1 ? candidates[0] : contract;
    findingLinks.push({ findingId: finding.id, nodeId: target.id });
  }
  graph.nodes = [...nodes.values()].sort((a, b) => sort(a.id, b.id));
  graph.edges = [...edges.values()].map((item) => ({ ...item, evidence: item.evidence.sort((a, b) =>
    sort(`${a.origin}:${a.referenceId ?? ""}`, `${b.origin}:${b.referenceId ?? ""}`)) })).sort((a, b) => sort(a.id, b.id));
  graph.warnings.sort((a, b) => sort(`${a.code}:${a.sourceUnitName ?? ""}`, `${b.code}:${b.sourceUnitName ?? ""}`));
  validateProtocolGraph(graph);
  facts.sort((a, b) => sort(a.functionId, b.functionId));
  syntax.sort((a, b) => sort(a.functionId, b.functionId));
  findingLinks.sort((a, b) => sort(`${a.nodeId}:${a.findingId}`, `${b.nodeId}:${b.findingId}`));
  unresolved.sort((a, b) => sort(`${a.callerFunctionId}:${a.source.startByte ?? 0}:${a.kind}`,
    `${b.callerFunctionId}:${b.source.startByte ?? 0}:${b.kind}`));
  const count = (kind: string) => graph.nodes.filter((node) => node.kind === kind).length;
  const summary = { contracts: count("contract"), interfaces: count("interface"), libraries: count("library"),
    functions: count("function"), edges: graph.edges.length,
    externalCalls: graph.edges.filter((item) => item.kind === "external-call").length,
    entryPoints: graph.nodes.filter((node) => node.kind === "function" && node.entryPoint === "yes").length,
    proxies: graph.nodes.filter((node) => node.kind === "contract" && node.characteristics.some((trait) => trait.kind === "proxy")).length,
    delegatecalls: facts.reduce((sum, fact) => sum + fact.lowLevelCalls.filter((kind) => kind === "delegatecall").length, 0),
    findingsLinkedNodes: new Set(findingLinks.map((link) => link.nodeId)).size,
    unresolvedRelationships: unresolved.length };
  const content = { schema: STATIC_PROTOCOL_GRAPH_SCHEMA, repositoryMapId: map.id, graph,
    functionFacts: facts, functionSyntax: syntax, findingLinks, unresolved, summary };
  return validateStaticProtocolGraphArtifact({ ...content, contentSha256: staticProtocolGraphContentHash(content) });
}
