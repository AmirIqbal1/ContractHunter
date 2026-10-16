import { buildFunctionExplorerModel, type InvestigationPathResult, type ProtocolSourceLocation,
  type StaticProtocolGraphArtifact } from "@contracthunter/core";

export type PathNodeDetail = { id: string; kind: string; name: string; contractId: string | null;
  contractName: string | null; entryPoint: boolean; source: ProtocolSourceLocation | null;
  reviewCues: string[] };

/** Presentation facts are looked up only for canonical nodes already selected by Phase 9A. */
export function investigationPathNodeDetails(artifact: StaticProtocolGraphArtifact,
  result: InvestigationPathResult): PathNodeDetail[] {
  const byId = new Map(artifact.graph.nodes.map((node) => [node.id, node]));
  const ids = new Set(result.paths.flatMap((path) => path.nodeIds));
  const targets = new Set(result.targetNodeIds);
  return [...ids].sort().flatMap((id) => {
    const node = byId.get(id);
    if (!node) return [];
    const owner = node.kind === "function" ? byId.get(node.contractId) : null;
    const model = node.kind === "function" && targets.has(node.id) ?
      buildFunctionExplorerModel(artifact, node.contractId, node.id) : null;
    return [{ id, kind: node.kind, name: node.name, contractId: node.kind === "function" ? node.contractId : null,
      contractName: owner?.name ?? null, entryPoint: node.kind === "function" && node.entryPoint === "yes",
      source: node.source, reviewCues: model?.reviewCues ?? [] }];
  });
}
