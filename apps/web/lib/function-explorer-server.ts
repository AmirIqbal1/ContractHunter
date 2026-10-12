import { buildFunctionExplorerModel, FUNCTION_EXPLORER_LIMITS, type FunctionExplorerModel } from "@contracthunter/core";
import { getScanSource, readStaticProtocolGraph, type DatabaseClient } from "@contracthunter/db";

export type FunctionExplorerResponse = { model: FunctionExplorerModel; sourcePreview: string | null;
  sourcePreviewTruncated: boolean; relatedNodes: Array<{ id: string; kind: string; name: string;
    signature: string | null; contractId: string | null }>;
  controls: Array<{ roleId: string; roleName: string; edgeId: string }>;
  provenProxy: boolean };

/** Exact graph IDs and the immutable scan snapshot are the only authorities. */
export function readFunctionExplorer(database: DatabaseClient, scanId: string, contractId: string,
  functionId: string): FunctionExplorerResponse | null {
  const artifact = readStaticProtocolGraph(database, scanId);
  if (!artifact) return null;
  const model = buildFunctionExplorerModel(artifact, contractId, functionId);
  if (!model || model.scanId !== scanId) return null;
  const nodes = new Map(artifact.graph.nodes.map((node) => [node.id, node]));
  const referenced = new Set<string>([contractId, ...model.operations.flatMap((item) =>
    [item.targetContractId, item.targetFunctionId].filter((id): id is string => id !== null)),
    ...model.callers.flatMap((item) => [item.fromFunctionId, item.toFunctionId].filter((id): id is string => id !== null)),
    ...model.callees.flatMap((item) => [item.fromFunctionId, item.toFunctionId].filter((id): id is string => id !== null))]);
  const controlEdges = new Map(artifact.graph.edges.filter((edge) => edge.kind === "controls")
    .map((edge) => [edge.id, edge]));
  const controls = model.controls.flatMap((item) => {
    const edge = controlEdges.get(item.edgeId), role = edge && nodes.get(edge.from);
    return role?.kind === "role" ? [{ roleId: role.id, roleName: role.name, edgeId: item.edgeId }] : [];
  });
  for (const control of controls) referenced.add(control.roleId);
  const relatedNodes = [...referenced].sort().flatMap((id) => {
    const node = nodes.get(id);
    return node ? [{ id, kind: node.kind, name: node.name,
      signature: node.kind === "function" ? node.signature : null,
      contractId: node.kind === "function" ? node.contractId : null }] : [];
  });
  const contract = nodes.get(contractId);
  const extras = { relatedNodes, controls, provenProxy: Boolean(contract?.characteristics.some((item) => item.kind === "proxy")) };
  const location = model.function.source;
  const unit = artifact.graph.sourceUnits.find((item) => item.sourceUnitName === location.sourceUnitName &&
    item.identityStatus === "authoritative" && item.snapshotSourceKey === location.sourceUnitName);
  if (!unit || location.startByte === null || location.endByte === null) return { model, sourcePreview: null,
    sourcePreviewTruncated: false, ...extras };
  const source = getScanSource(database, scanId, unit.snapshotSourceKey!);
  if (!source.available || source.rawSha256 !== unit.rawSha256 || location.endByte > source.rawBytes.length)
    return { model, sourcePreview: null, sourcePreviewTruncated: false, ...extras };
  const bytes = source.rawBytes.subarray(location.startByte,
    Math.min(location.endByte, location.startByte + FUNCTION_EXPLORER_LIMITS.previewBytes));
  try { return { model, sourcePreview: new TextDecoder("utf-8", { fatal: true }).decode(bytes),
    sourcePreviewTruncated: location.endByte - location.startByte > bytes.length, ...extras }; }
  catch { return { model, sourcePreview: null, sourcePreviewTruncated: false, ...extras }; }
}
