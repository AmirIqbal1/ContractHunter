import type { ProtocolGraphEdge, ProtocolGraphNode, StaticProtocolGraphArtifact,
  StaticFunctionFacts, StaticUnresolvedRelationship } from "@contracthunter/core";

type ContractNode = Extract<ProtocolGraphNode, { kind: "contract" | "interface" | "library" }>;
type FunctionNode = Extract<ProtocolGraphNode, { kind: "function" }>;
export type ContractFinding = { id: string; title: string; source: string; detectorId: string | null;
  status: string; filePath: string | null; startLine: number | null };
export type ExplorerFunction = { node: FunctionNode; facts: StaticFunctionFacts | null; findings: ContractFinding[] };
export type ExplorerRelation = { edge: ProtocolGraphEdge; from: ProtocolGraphNode; to: ProtocolGraphNode;
  fromFunction: FunctionNode | null; toFunction: FunctionNode | null };
export type ContractExplorerView = { scanId: string; contract: ContractNode; functions: ExplorerFunction[];
  incoming: ExplorerRelation[]; outgoing: ExplorerRelation[]; localCalls: ExplorerRelation[];
  inheritance: ExplorerRelation[]; interfaces: ExplorerRelation[]; libraries: ExplorerRelation[];
  control: ExplorerRelation[]; proxy: ExplorerRelation[]; unresolved: Array<StaticUnresolvedRelationship & { caller: FunctionNode }>;
  findings: ContractFinding[]; counts: { functions: number; entryPoints: number; callers: number; callees: number;
    externalCalls: number; inheritance: number; libraries: number; controls: number; findings: number; unresolved: number };
  cues: string[]; state: Array<{ variable: string; contractId: string; declarationId: number;
    readers: string[]; writers: string[] }>;
  limited: boolean };

const MAX_FUNCTIONS = 2_000, MAX_RELATIONS = 1_000, MAX_FACTS = 500;

const isContract = (node: ProtocolGraphNode | undefined): node is ContractNode =>
  !!node && (node.kind === "contract" || node.kind === "interface" || node.kind === "library");
const isFunction = (node: ProtocolGraphNode | undefined): node is FunctionNode => node?.kind === "function";
const compare = (a: string, b: string) => a.localeCompare(b);

/** The validated artifact is the sole structural authority. No name/path fallback is used. */
export function contractExplorerView(artifact: StaticProtocolGraphArtifact, contractId: string,
  scanFindings: readonly ContractFinding[]): ContractExplorerView | null {
  const { graph } = artifact;
  const nodes = new Map(graph.nodes.map((node) => [node.id, node]));
  const contract = nodes.get(contractId);
  if (!isContract(contract)) return null;
  const owner = (node: ProtocolGraphNode) => isFunction(node) ? node.contractId : node.id;
  const findingById = new Map(scanFindings.map((finding) => [finding.id, finding]));
  const links = new Map<string, ContractFinding[]>();
  for (const link of artifact.findingLinks) {
    const finding = findingById.get(link.findingId);
    if (finding) links.set(link.nodeId, [...(links.get(link.nodeId) ?? []), finding]);
  }
  const facts = new Map(artifact.functionFacts.map((fact) => [fact.functionId, fact]));
  const allFunctions = graph.nodes.filter(isFunction).filter((node) => node.contractId === contractId)
    .map((node) => ({ node, facts: facts.get(node.id) ?? null, findings: links.get(node.id) ?? [] }))
    .sort((a, b) => Number(b.node.entryPoint === "yes") - Number(a.node.entryPoint === "yes") ||
      compare(a.node.signature, b.node.signature) || compare(a.node.id, b.node.id));
  const functions = allFunctions.slice(0, MAX_FUNCTIONS);
  const relations = graph.edges.map((edge) => ({ edge, from: nodes.get(edge.from)!, to: nodes.get(edge.to)!,
    fromFunction: isFunction(nodes.get(edge.fromFunctionId ?? "")) ? nodes.get(edge.fromFunctionId!) as FunctionNode :
      isFunction(nodes.get(edge.from)) ? nodes.get(edge.from) as FunctionNode : null,
    toFunction: isFunction(nodes.get(edge.toFunctionId ?? "")) ? nodes.get(edge.toFunctionId!) as FunctionNode :
      isFunction(nodes.get(edge.to)) ? nodes.get(edge.to) as FunctionNode : null,
  })).filter((item) => owner(item.from) === contractId || owner(item.to) === contractId)
    .sort((a, b) => compare(a.edge.kind, b.edge.kind) || compare(a.edge.id, b.edge.id));
  const callKinds = new Set(["calls", "external-call"]);
  const incoming = relations.filter((item) => callKinds.has(item.edge.kind) &&
    owner(item.to) === contractId && owner(item.from) !== contractId);
  const outgoing = relations.filter((item) => callKinds.has(item.edge.kind) &&
    owner(item.from) === contractId && owner(item.to) !== contractId);
  const localCalls = relations.filter((item) => owner(item.from) === contractId && owner(item.to) === contractId &&
    ["calls", "external-call"].includes(item.edge.kind));
  const inheritance = relations.filter((item) => item.edge.kind === "inherits");
  const interfaces = relations.filter((item) => item.edge.kind === "implements");
  const libraries = relations.filter((item) => item.edge.kind === "uses-library");
  const control = relations.filter((item) => item.edge.kind === "controls");
  const proxy = relations.filter((item) => ["upgrades", "delegates"].includes(item.edge.kind) &&
    (contract.characteristics.some((trait) => trait.kind === "proxy" || trait.kind === "implementation") ||
      item.edge.kind === "upgrades"));
  const unresolved = artifact.unresolved.flatMap((item) => {
    const caller = nodes.get(item.callerFunctionId);
    return isFunction(caller) && caller.contractId === contractId ? [{ ...item, caller }] : [];
  });
  const allFindings = [...new Map([...(links.get(contractId) ?? []), ...allFunctions.flatMap((item) => item.findings)]
    .map((finding) => [finding.id, finding])).values()].sort((a, b) => compare(a.id, b.id));
  const findings = allFindings.slice(0, MAX_FACTS);
  const externalCalls = outgoing.filter((item) => item.edge.kind === "external-call").length;
  const counts = { functions: allFunctions.length, entryPoints: allFunctions.filter((item) => item.node.entryPoint === "yes").length,
    callers: new Set(incoming.map((item) => owner(item.from))).size,
    callees: new Set(outgoing.map((item) => owner(item.to))).size, externalCalls,
    inheritance: inheritance.length, libraries: libraries.length, controls: control.length,
    findings: allFindings.length, unresolved: unresolved.length };
  const cues = [counts.entryPoints ? `${counts.entryPoints} externally callable entry points` : null,
    externalCalls ? `${externalCalls} external-call indicators` : null,
    counts.unresolved ? `${counts.unresolved} statically unresolved relationships` : null,
    allFunctions.some((item) => item.facts?.tokenTransferLike || item.node.characteristics.some((trait) => trait.kind === "token-transfer")) ? "Token-transfer-like operations" : null,
    allFunctions.some((item) => item.facts?.lowLevelCalls.includes("delegatecall")) ? "Delegatecall present" : null,
    counts.controls ? `${counts.controls} control relationships` : null,
    proxy.length ? "Proven upgrade/proxy relationship" : null,
    counts.findings ? `${counts.findings} exact finding references` : null].filter((value): value is string => !!value);
  const stateMap = new Map<string, { variable: string; contractId: string; declarationId: number;
    readers: Set<string>; writers: Set<string> }>();
  for (const item of functions) for (const [mode, accesses] of [["readers", item.facts?.stateReads ?? []],
    ["writers", item.facts?.stateWrites ?? []]] as const) for (const access of accesses) {
    const key = `${access.contractId}:${access.declarationId}`;
    const entry = stateMap.get(key) ?? { variable: access.variable, contractId: access.contractId,
      declarationId: access.declarationId,
      readers: new Set<string>(), writers: new Set<string>() };
    if (stateMap.size < MAX_FACTS || stateMap.has(key)) { entry[mode].add(item.node.signature); stateMap.set(key, entry); }
  }
  const state = [...stateMap.values()].map((item) => ({ variable: item.variable, contractId: item.contractId,
    declarationId: item.declarationId,
    readers: [...item.readers].sort(compare), writers: [...item.writers].sort(compare) }))
    .sort((a, b) => compare(a.variable, b.variable) || compare(a.contractId, b.contractId));
  const limited = allFunctions.length > MAX_FUNCTIONS || allFindings.length > MAX_FACTS ||
    [incoming, outgoing, localCalls, inheritance, interfaces, libraries, control, proxy, unresolved]
      .some((list) => list.length > MAX_RELATIONS) || stateMap.size >= MAX_FACTS;
  return { scanId: graph.scanId, contract, functions, incoming: incoming.slice(0, MAX_RELATIONS),
    outgoing: outgoing.slice(0, MAX_RELATIONS), localCalls: localCalls.slice(0, MAX_RELATIONS),
    inheritance: inheritance.slice(0, MAX_RELATIONS), interfaces: interfaces.slice(0, MAX_RELATIONS),
    libraries: libraries.slice(0, MAX_RELATIONS), control: control.slice(0, MAX_RELATIONS),
    proxy: proxy.slice(0, MAX_RELATIONS), unresolved: unresolved.slice(0, MAX_RELATIONS),
    findings, counts, cues, state, limited };
}
