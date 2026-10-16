import dagre from "@dagrejs/dagre";
import type { Edge, Node } from "@xyflow/react";
import type { ProtocolGraphEdge, ProtocolGraphNode, SecurityViewResult, StaticProtocolGraphArtifact } from "@contracthunter/core";

export type MapPreset = "all" | "core" | "external" | "upgrade" | "findings";
export type MapDirection = "both" | "callers" | "callees";
export type MapOptions = { preset: MapPreset; hideInterfaces: boolean; hideLibraries: boolean;
  hideDependencies: boolean; findingOnly: boolean; relationshipKinds: ReadonlySet<string> };
export type MapNodeData = { label: string; kind: string; classification: string; badges: string[];
  findingCount: number; source: string | null; selected: boolean; dimmed: boolean };
export type MapEdgeData = { kind: string; sourceLocation: string | null; dimmed: boolean };
export type MapView = { nodes: Node<MapNodeData>[]; edges: Edge<MapEdgeData>[];
  totalNodes: number; totalEdges: number; clipped: boolean; hiddenFunctionNodes: number };

const MAX_RENDER_NODES = 600, MAX_RENDER_EDGES = 1600;
export const MAP_RENDER_LIMITS = { nodes: MAX_RENDER_NODES, edges: MAX_RENDER_EDGES } as const;
export const relationshipGroups = {
  calls: ["calls"], inheritance: ["inherits"], interfaces: ["implements"], libraries: ["uses-library"],
  controls: ["controls"], upgrades: ["upgrades"], delegation: ["delegates"], external: ["external-call"],
} as const;
export const defaultOptions = (artifact: StaticProtocolGraphArtifact): MapOptions => {
  const count = artifact.graph.nodes.filter((node) => node.kind !== "function").length;
  return { preset: count > 240 ? "core" : "all", hideInterfaces: count > 90,
    hideLibraries: count > 90, hideDependencies: count > 240, findingOnly: false,
    relationshipKinds: new Set(Object.values(relationshipGroups).flat()) };
};
export function mapOwner(node: ProtocolGraphNode, byId: ReadonlyMap<string, ProtocolGraphNode>): ProtocolGraphNode {
  return node.kind === "function" ? byId.get(node.contractId) ?? node : node;
}
export function findingIds(artifact: StaticProtocolGraphArtifact, nodeId: string): string[] {
  const byId = new Map(artifact.graph.nodes.map((node) => [node.id, node]));
  return [...new Set(artifact.findingLinks.filter((link) => {
    const target = byId.get(link.nodeId);
    return link.nodeId === nodeId || target?.kind === "function" && target.contractId === nodeId;
  }).map((link) => link.findingId))].sort();
}
export function searchMap(artifact: StaticProtocolGraphArtifact, query: string, limit = 30): ProtocolGraphNode[] {
  const term = query.trim().toLocaleLowerCase();
  if (!term) return [];
  const byId = new Map(artifact.graph.nodes.map((node) => [node.id, node]));
  const seen = new Set<string>();
  const matches: ProtocolGraphNode[] = [];
  for (const node of artifact.graph.nodes) {
    if (![node.name, node.source?.sourceUnitName, node.kind === "function" ? node.signature : null]
      .some((value) => value?.toLocaleLowerCase().includes(term))) continue;
    const owner = mapOwner(node, byId);
    if (!seen.has(owner.id)) { seen.add(owner.id); matches.push(owner); }
    if (matches.length >= limit) break;
  }
  return matches.sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
}
function classify(node: ProtocolGraphNode): string {
  if ("repositoryClassification" in node) return node.repositoryClassification.effective;
  return node.kind === "external-actor" || node.kind === "external-protocol" ? "dependency" : node.kind;
}
function trait(node: ProtocolGraphNode, kind: string): boolean {
  return node.characteristics.some((item) => item.kind === kind);
}
export function visibleModel(artifact: StaticProtocolGraphArtifact, options: MapOptions,
  selectedId: string | null = null, direction: MapDirection = "both", projection: SecurityViewResult | null = null): MapView {
  const all = artifact.graph.nodes, byId = new Map(all.map((node) => [node.id, node]));
  const projectedNodeIds = projection && projection.scanId === artifact.graph.scanId &&
    projection.protocolGraphId === artifact.graph.id && projection.graphContentSha256 === artifact.contentSha256 ?
    new Set(projection.nodes.map((item) => item.id)) : projection ? new Set<string>() : null;
  const projectedOwners = projectedNodeIds && new Set([...projectedNodeIds].flatMap((id) => {
    const node = byId.get(id);
    return node ? [mapOwner(node, byId).id] : [];
  }));
  const projectedEdges = projection ? new Set(projection.edges.map((item) => item.id)) : null;
  const conceptual = all.filter((node) => node.kind !== "function" && (!projectedOwners || projectedOwners.has(node.id)));
  const functionsByContract = new Map<string, Extract<ProtocolGraphNode, { kind: "function" }>[]>();
  for (const node of all) if (node.kind === "function") {
    const list = functionsByContract.get(node.contractId) ?? [];
    list.push(node); functionsByContract.set(node.contractId, list);
  }
  const findings = new Set(artifact.findingLinks.map((link) => mapOwner(byId.get(link.nodeId)!, byId).id));
  const structural = artifact.graph.edges.filter((edge) => {
    if (projectedEdges && !projectedEdges.has(edge.id)) return false;
    const from = byId.get(edge.from), to = byId.get(edge.to);
    return from && to && mapOwner(from, byId).id !== mapOwner(to, byId).id;
  });
  const connectedToCore = new Set<string>();
  const externalNodes = new Set<string>(), upgradeNodes = new Set<string>();
  for (const edge of structural) {
    const from = mapOwner(byId.get(edge.from)!, byId), to = mapOwner(byId.get(edge.to)!, byId);
    if (classify(from) === "core") connectedToCore.add(to.id);
    if (classify(to) === "core") connectedToCore.add(from.id);
    if (edge.kind === "external-call") { externalNodes.add(from.id); externalNodes.add(to.id); }
    if (["delegates", "upgrades", "controls"].includes(edge.kind)) {
      upgradeNodes.add(from.id); upgradeNodes.add(to.id);
    }
  }
  const findingCounts = new Map<string, Set<string>>();
  for (const link of artifact.findingLinks) {
    const target = byId.get(link.nodeId);
    if (!target) continue;
    const ownerId = mapOwner(target, byId).id;
    const ids = findingCounts.get(ownerId) ?? new Set<string>();
    ids.add(link.findingId); findingCounts.set(ownerId, ids);
  }
  const selected = selectedId && byId.has(selectedId) ? mapOwner(byId.get(selectedId)!, byId).id : null;
  const candidates = conceptual.filter((node) => {
    if (options.hideInterfaces && node.kind === "interface" && node.id !== selected) return false;
    if (options.hideLibraries && node.kind === "library" && node.id !== selected) return false;
    if (options.hideDependencies && ["dependency", "external-actor", "external-protocol"].includes(classify(node)) && node.id !== selected) return false;
    if (options.findingOnly && !findings.has(node.id) && node.id !== selected) return false;
    if (projection) return true;
    if (node.id === selected) return true;
    if (options.preset === "core") return ["core", "periphery"].includes(classify(node)) || connectedToCore.has(node.id) || findings.has(node.id);
    if (options.preset === "findings") return findings.has(node.id);
    if (options.preset === "external") return externalNodes.has(node.id);
    if (options.preset === "upgrade") return trait(node, "proxy") || trait(node, "upgradeable") ||
      upgradeNodes.has(node.id);
    return true;
  });
  const selectedEdges = structural.filter((edge) => options.relationshipKinds.has(edge.kind));
  const priority = (node: ProtocolGraphNode) => (node.id === selected ? 0 : findings.has(node.id) ? 1 : classify(node) === "core" ? 2 :
    classify(node) === "periphery" ? 3 : 4);
  candidates.sort((a, b) => priority(a) - priority(b) || a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
  const shown = candidates.slice(0, MAX_RENDER_NODES), shownIds = new Set(shown.map((node) => node.id));
  const mappedEdges = selectedEdges.flatMap((edge) => {
    const source = mapOwner(byId.get(edge.from)!, byId).id, target = mapOwner(byId.get(edge.to)!, byId).id;
    return shownIds.has(source) && shownIds.has(target) ? [{ edge, source, target }] : [];
  }).sort((a, b) => a.edge.id.localeCompare(b.edge.id)).slice(0, MAX_RENDER_EDGES);
  const neighborhood = new Set<string>(selected ? [selected] : []);
  if (selected) for (const { source, target } of mappedEdges) {
    if (direction !== "callers" && source === selected) neighborhood.add(target);
    if (direction !== "callees" && target === selected) neighborhood.add(source);
  }
  const nodes: Node<MapNodeData>[] = shown.map((node) => {
    const functions = functionsByContract.get(node.id) ?? [];
    const has = (kind: string) => trait(node, kind) || functions.some((fn) => trait(fn, kind));
    const badges = [has("proxy") ? "PROXY" : null, has("implementation") ? "IMPL" : null,
      has("delegatecall") ? "DELEGATE" : null, has("external-call") ? "EXT CALL" : null,
      functions.some((fn) => fn.entryPoint === "yes") ? "ENTRY" : null,
      has("payable") ? "PAYABLE" : null].filter((value): value is string => !!value).slice(0, 3);
    const findingCount = findingCounts.get(node.id)?.size ?? 0;
    return { id: node.id, type: "protocol", position: { x: 0, y: 0 }, selectable: true,
      draggable: false, data: { label: node.name, kind: node.kind, classification: classify(node),
        badges, findingCount, source: node.source?.sourceUnitName ?? null,
        selected: node.id === selected, dimmed: !!selected && !neighborhood.has(node.id) },
      ariaLabel: `${node.kind} ${node.name}, ${classify(node)}${findingCount ? `, ${findingCount} findings` : ""}` };
  });
  const edges: Edge<MapEdgeData>[] = mappedEdges.map(({ edge, source, target }) => ({
    id: edge.id, source, target, type: "smoothstep", label: edge.kind,
    data: { kind: edge.kind, sourceLocation: edge.source ? `${edge.source.sourceUnitName}:${edge.source.startLine}` : null,
      dimmed: !!selected && !(source === selected || target === selected) },
    animated: false, selectable: true,
    style: { stroke: edge.kind === "controls" ? "#d7aa63" : edge.kind === "delegates" ? "#ad91df" : "#72879a",
      strokeWidth: ["controls", "delegates", "upgrades"].includes(edge.kind) ? 2.2 : 1.4,
      opacity: selected && !(source === selected || target === selected) ? 0.22 : 0.8,
      strokeDasharray: ["inherits", "implements", "uses-library"].includes(edge.kind) ? "5 5" : undefined },
  }));
  return { nodes, edges, totalNodes: conceptual.length, totalEdges: structural.length,
    clipped: candidates.length > MAX_RENDER_NODES || mappedEdges.length < selectedEdges.filter((edge) => {
      const source = mapOwner(byId.get(edge.from)!, byId).id, target = mapOwner(byId.get(edge.to)!, byId).id;
      return shownIds.has(source) && shownIds.has(target);
    }).length, hiddenFunctionNodes: all.length - conceptual.length };
}
export function layoutMap(view: MapView): MapView {
  const graph = new dagre.graphlib.Graph({ multigraph: true });
  graph.setGraph({ rankdir: "LR", nodesep: 38, ranksep: 130, marginx: 32, marginy: 32 });
  graph.setDefaultEdgeLabel(() => ({}));
  for (const node of view.nodes) graph.setNode(node.id, { width: 210, height: 106 });
  for (const edge of view.edges) graph.setEdge(edge.source, edge.target, {}, edge.id);
  dagre.layout(graph);
  return { ...view, nodes: view.nodes.map((node) => {
    const placed = graph.node(node.id);
    return { ...node, position: { x: placed.x - 105, y: placed.y - 53 } };
  }) };
}
export function nodeDetails(artifact: StaticProtocolGraphArtifact, nodeId: string) {
  const byId = new Map(artifact.graph.nodes.map((node) => [node.id, node]));
  const node = byId.get(nodeId);
  if (!node) return null;
  const owner = mapOwner(node, byId);
  const related = artifact.graph.edges.filter((edge) => [edge.from, edge.to].some((id) => mapOwner(byId.get(id)!, byId).id === owner.id));
  const callers = related.filter((edge) => mapOwner(byId.get(edge.to)!, byId).id === owner.id)
    .map((edge) => mapOwner(byId.get(edge.from)!, byId)).filter((item) => item.id !== owner.id);
  const callees = related.filter((edge) => mapOwner(byId.get(edge.from)!, byId).id === owner.id)
    .map((edge) => mapOwner(byId.get(edge.to)!, byId)).filter((item) => item.id !== owner.id);
  const unique = (items: ProtocolGraphNode[]) => [...new Map(items.map((item) => [item.id, item])).values()]
    .sort((a, b) => a.name.localeCompare(b.name));
  const functions = artifact.graph.nodes.filter((item) => item.kind === "function" && item.contractId === owner.id)
    .sort((a, b) => (a.kind === "function" && b.kind === "function" ?
      Number(b.entryPoint === "yes") - Number(a.entryPoint === "yes") || a.signature.localeCompare(b.signature) : 0));
  const unresolved = artifact.unresolved.filter((item) => byId.get(item.callerFunctionId)?.kind === "function" &&
    (byId.get(item.callerFunctionId) as Extract<ProtocolGraphNode, { kind: "function" }>).contractId === owner.id);
  return { node: owner, callers: unique(callers), callees: unique(callees), functions,
    related, unresolved, findingIds: findingIds(artifact, owner.id) };
}
export function edgeDetails(artifact: StaticProtocolGraphArtifact, edgeId: string): {
  edge: ProtocolGraphEdge; from: ProtocolGraphNode; to: ProtocolGraphNode;
  fromFunction: ProtocolGraphNode | null; toFunction: ProtocolGraphNode | null;
} | null {
  const edge = artifact.graph.edges.find((item) => item.id === edgeId);
  if (!edge) return null;
  const byId = new Map(artifact.graph.nodes.map((node) => [node.id, node]));
  return { edge, from: mapOwner(byId.get(edge.from)!, byId), to: mapOwner(byId.get(edge.to)!, byId),
    fromFunction: edge.fromFunctionId ? byId.get(edge.fromFunctionId) ?? null : null,
    toFunction: edge.toFunctionId ? byId.get(edge.toFunctionId) ?? null : null };
}
