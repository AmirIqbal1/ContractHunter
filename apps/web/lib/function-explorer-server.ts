import { buildFunctionExplorerModel, FUNCTION_EXPLORER_LIMITS, type FunctionExplorerModel } from "@contracthunter/core";
import { getScanSource, readStaticProtocolGraph, type DatabaseClient } from "@contracthunter/db";

export type FunctionExplorerResponse = { model: FunctionExplorerModel; sourcePreview: string | null;
  sourcePreviewTruncated: boolean };

/** Exact graph IDs and the immutable scan snapshot are the only authorities. */
export function readFunctionExplorer(database: DatabaseClient, scanId: string, contractId: string,
  functionId: string): FunctionExplorerResponse | null {
  const artifact = readStaticProtocolGraph(database, scanId);
  if (!artifact) return null;
  const model = buildFunctionExplorerModel(artifact, contractId, functionId);
  if (!model || model.scanId !== scanId) return null;
  const location = model.function.source;
  const unit = artifact.graph.sourceUnits.find((item) => item.sourceUnitName === location.sourceUnitName &&
    item.identityStatus === "authoritative" && item.snapshotSourceKey === location.sourceUnitName);
  if (!unit || location.startByte === null || location.endByte === null) return { model, sourcePreview: null,
    sourcePreviewTruncated: false };
  const source = getScanSource(database, scanId, unit.snapshotSourceKey!);
  if (!source.available || source.rawSha256 !== unit.rawSha256 || location.endByte > source.rawBytes.length)
    return { model, sourcePreview: null, sourcePreviewTruncated: false };
  const bytes = source.rawBytes.subarray(location.startByte,
    Math.min(location.endByte, location.startByte + FUNCTION_EXPLORER_LIMITS.previewBytes));
  try { return { model, sourcePreview: new TextDecoder("utf-8", { fatal: true }).decode(bytes),
    sourcePreviewTruncated: location.endByte - location.startByte > bytes.length }; }
  catch { return { model, sourcePreview: null, sourcePreviewTruncated: false }; }
}
